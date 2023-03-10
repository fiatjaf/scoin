package scoin

import java.io.{ByteArrayInputStream, ByteArrayOutputStream}
import java.math.BigInteger
import scodec.bits.ByteVector

object Crypto extends CryptoPlatform {
  lazy val halfCurveOrder = N.shiftRight(1)

  def fixSize(data: ByteVector): ByteVector32 = ByteVector32(data.padLeft(32))

  /** 160 bits bitcoin hash, used mostly for address encoding hash160(input) =
    * RIPEMD160(SHA256(input))
    *
    * @param input
    *   array of byte
    * @return
    *   the 160 bits BTC hash of input
    */
  def hash160(input: ByteVector): ByteVector = ripemd160(sha256(input))

  /** 256 bits bitcoin hash hash256(input) = SHA256(SHA256(input))
    *
    * @param input
    *   array of byte
    * @return
    *   the 256 bits BTC hash of input
    */
  def hash256(input: ByteVector): ByteVector32 = ByteVector32(
    sha256(sha256(input))
  )

  private def encodeSignatureCompact(
      r: BigInteger,
      s: BigInteger
  ): ByteVector64 = {
    ByteVector64(
      ByteVector.view(r.toByteArray.dropWhile(_ == 0)).padLeft(32) ++ ByteVector
        .view(s.toByteArray.dropWhile(_ == 0))
        .padLeft(32)
    )
  }

  def isDERSignature(sig: ByteVector): Boolean = {
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    // * total-length: 1-byte length descriptor of everything that follows,
    //   excluding the sighash byte.
    // * R-length: 1-byte length descriptor of the R value that follows.
    // * R: arbitrary-length big-endian encoded R value. It must use the shortest
    //   possible encoding for a positive integers (which means no null bytes at
    //   the start, except a single one when the next byte has its highest bit set).
    // * S-length: 1-byte length descriptor of the S value that follows.
    // * S: arbitrary-length big-endian encoded S value. The same rules apply.
    // * sighash: 1-byte value indicating what data is hashed (not part of the DER
    //   signature)

    // Minimum and maximum size constraints.
    if (sig.size < 9) false
    else if (sig.size > 73) false

    // A signature is of type 0x30 (compound).
    else if (sig(0) != 0x30.toByte) false

    // Make sure the length covers the entire signature.
    else if (sig(1) != sig.size - 3) false
    else {
      // Extract the length of the R element.
      val lenR = sig(3)

      // Make sure the length of the S element is still inside the signature.
      if (5 + lenR >= sig.size) false
      else {
        // Extract the length of the S element.
        val lenS = sig(5 + lenR)

        // Verify that the length of the signature matches the sum of the length
        // of the elements.
        if (lenR + lenS + 7 != sig.size) false

        // Check whether the R element is an integer.
        else if (sig(2) != 0x02) false

        // Zero-length integers are not allowed for R.
        else if (lenR == 0) false

        // Negative numbers are not allowed for R.
        else if ((sig(4) & 0x80.toByte) != 0) false

        // Null bytes at the start of R are not allowed, unless R would
        // otherwise be interpreted as a negative number.
        else if (lenR > 1 && (sig(4) == 0x00) && (sig(5) & 0x80) == 0) false

        // Check whether the S element is an integer.
        else if (sig(lenR + 4) != 0x02.toByte) false

        // Zero-length integers are not allowed for S.
        else if (lenS == 0) false

        // Negative numbers are not allowed for S.
        else if ((sig(lenR + 6) & 0x80) != 0) false

        // Null bytes at the start of S are not allowed, unless S would otherwise be
        // interpreted as a negative number.
        else if (
          lenS > 1 && (sig(lenR + 6) == 0x00) && (sig(lenR + 7) & 0x80) == 0
        )
          false
        else
          true
      }
    }
  }

  def isLowDERSignature(sig: ByteVector): Boolean = isDERSignature(sig) && {
    val (_, s) = decodeSignatureFromDER(sig)
    s.compareTo(halfCurveOrder) <= 0
  }

  def normalizeSignature(
      r: BigInteger,
      s: BigInteger
  ): (BigInteger, BigInteger) = {
    val s1 =
      if (s.compareTo(halfCurveOrder) > 0) N.subtract(s) else s
    (r, s1)
  }

  def checkSignatureEncoding(sig: ByteVector, flags: Int): Boolean = {
    import ScriptFlags._
    // Empty signature. Not strictly DER encoded, but allowed to provide a
    // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
    if (sig.isEmpty) true
    else if (
      (flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) != 0 && !isDERSignature(
        sig
      )
    ) false
    else if ((flags & SCRIPT_VERIFY_LOW_S) != 0 && !isLowDERSignature(sig))
      false
    else if (
      (flags & SCRIPT_VERIFY_STRICTENC) != 0 && !isDefinedHashtypeSignature(sig)
    ) false
    else true
  }

  def checkPubKeyEncoding(
      key: ByteVector,
      flags: Int,
      sigVersion: Int
  ): Boolean = {
    if ((flags & ScriptFlags.SCRIPT_VERIFY_STRICTENC) != 0)
      require(isPubKeyCompressedOrUncompressed(key), "invalid public key")
    // Only compressed keys are accepted in segwit
    if (
      (flags & ScriptFlags.SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) != 0 && sigVersion == SigVersion.SIGVERSION_WITNESS_V0
    )
      require(
        isPubKeyCompressed(key),
        "public key must be compressed in segwit"
      )
    true
  }

  /** @param key
    *   serialized public key
    * @return
    *   true if the key is valid. Please not that this performs very basic tests
    *   and does not check that the point represented by this key is actually
    *   valid.
    */
  def isPubKeyValidLax(key: ByteVector): Boolean = key.length match {
    case 65 if key(0) == 4 || key(0) == 6 || key(0) == 7 => true
    case 33 if key(0) == 2 || key(0) == 3                => true
    case _                                               => false
  }

  def isPubKeyCompressedOrUncompressed(key: ByteVector): Boolean =
    key.length match {
      case 65 if key(0) == 4                => true
      case 33 if key(0) == 2 || key(0) == 3 => true
      case _                                => false
    }

  def isPubKeyCompressed(key: ByteVector): Boolean = key.length match {
    case 33 if key(0) == 2 || key(0) == 3 => true
    case _                                => false
  }

  def isDefinedHashtypeSignature(sig: ByteVector): Boolean = if (sig.isEmpty)
    false
  else {
    val hashType = (sig.last & 0xff) & (~(SIGHASH_ANYONECANPAY))
    if (hashType < SIGHASH_ALL || hashType > SIGHASH_SINGLE) false else true
  }

  /** An ECDSA signature is a (r, s) pair. Bitcoin uses DER encoded signatures
    *
    * @param blob
    *   sigbyte data
    * @return
    *   the decoded (r, s) signature
    */
  private def decodeSignatureFromDER(
      blob: ByteVector
  ): (BigInteger, BigInteger) = {
    decodeSignatureFromDERLax(blob)
  }

  private def decodeSignatureFromDERLax(
      input: ByteArrayInputStream
  ): (BigInteger, BigInteger) = {
    require(input.read() == 0x30)

    def readLength: Int = {
      val len = input.read()
      if ((len & 0x80) == 0) len
      else {
        var n = len - 0x80
        var len1 = 0
        while (n > 0) {
          len1 = (len1 << 8) + input.read()
          n = n - 1
        }
        len1
      }
    }

    readLength
    require(input.read() == 0x02)
    val lenR = readLength
    val r = new Array[Byte](lenR)
    input.read(r)
    require(input.read() == 0x02)
    val lenS = readLength
    val s = new Array[Byte](lenS)
    input.read(s)
    (new BigInteger(1, r), new BigInteger(1, s))
  }

  private def decodeSignatureFromDERLax(
      input: ByteVector
  ): (BigInteger, BigInteger) = decodeSignatureFromDERLax(
    new ByteArrayInputStream(input.toArray)
  )

  def decodeSignatureCompact(sig: ByteVector64): (BigInteger, BigInteger) = {
    val r = new BigInteger(1, sig.take(32).toArray)
    val s = new BigInteger(1, sig.takeRight(32).toArray)
    (r, s)
  }

  def der2compact(signature: ByteVector): ByteVector64 = {
    val (r, s) = decodeSignatureFromDERLax(signature)
    val (r1, s1) = normalizeSignature(r, s)
    ByteVector64(
      ByteVector
        .view(r1.toByteArray.dropWhile(_ == 0))
        .padLeft(32) ++ ByteVector
        .view(s1.toByteArray.dropWhile(_ == 0))
        .padLeft(32)
    )
  }

  def signatureToDER(r: BigInt, s: BigInt): ByteVector = {
    def sliceDER(s: String): String =
      if (ByteVector.fromValidHex(s.substring(0, 1)).head.toInt >= 8) "00" + s
      else s

    def toPaddedHex(num: BigInt): String = {
      val hex = num.toString(16)
      if ((hex.length & 1) == 1) "0" + hex else hex
    }

    val sHex = sliceDER(toPaddedHex(s));
    val rHex = sliceDER(toPaddedHex(r));
    val rLen = toPaddedHex(rHex.length / 2);
    val sLen = toPaddedHex(sHex.length / 2);
    val length = toPaddedHex(rHex.length / 2 + sHex.length / 2 + 4);
    val hex = s"30${length}02${rLen}${rHex}02${sLen}${sHex}"

    ByteVector.fromValidHex(hex)
  }

  /** @param data
    *   data
    * @param signature
    *   signature
    * @param publicKey
    *   public key
    * @return
    *   true is signature is valid for this data with this public key
    */
  def verifySignature(
      data: ByteVector,
      signature: ByteVector64,
      publicKey: PublicKey
  ): Boolean = verifySignature(data.toArray, signature.bytes.toArray, publicKey)

  /** Sign data with a private key, using RCF6979 deterministic signatures
    *
    * @param data
    *   data to sign
    * @param privateKey
    *   private key. If you are using bitcoin "compressed" private keys make
    *   sure to only use the first 32 bytes of the key (there is an extra "1"
    *   appended to the key)
    * @return
    *   a signature in compact format (64 bytes)
    */
  def sign(data: ByteVector, privateKey: PrivateKey): ByteVector64 =
    sign(data.toArray, privateKey)

  /** BIP340 / Schnorr
    * https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
    */

  /** Tagged hash of input as defined in BIP340
    */
  def taggedHash(input: ByteVector, tag: String): ByteVector32 = {
    val hashedTag = sha256(ByteVector(tag.getBytes("UTF-8")))
    sha256(hashedTag ++ hashedTag ++ input)
  }

  /** Sign according to BIP340 specification
    * https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
    *
    * @param data
    *   data to sign (32 bytes)
    * @param privateKey
    *   private key
    * @param auxrand32
    * @return
    */
  def signSchnorr(
      data: ByteVector32,
      privateKey: PrivateKey,
      auxrand32: Option[ByteVector32] = None
  ): ByteVector64 =
    auxrand32 match {
      case None => signSchnorrImpl(data, privateKey, Some(ByteVector32.Zeroes))
      case Some(bv32) => signSchnorrImpl(data, privateKey, Some(bv32))
    }

  /** Verify a BIP340 schnorr signature
    *
    * @param data
    * @param signature
    * @param publicKey
    * @return
    */
  def verifySignatureSchnorr(
      signature: ByteVector64,
      data: ByteVector32,
      publicKey: XOnlyPublicKey
  ): Boolean =
    verifySignatureSchnorrImpl(data, signature, publicKey)

  /** Find the value of `k` which would be used to construct a valid BIP340
    * schnorr signature. A schnorr signature is 64-bytes given by `(R,s)` where
    * the first 32 bytes are `R = k*G`. This function returns the value `k`.
    *
    * @param data,
    *   the message to be signed
    * @param privateKey
    * @return
    *   k, the private nonce to be used in a BIP340 schnorr signature
    */
  def calculateBip340nonce(
      data: ByteVector32,
      privateKey: PrivateKey,
      auxrand32: Option[ByteVector32]
  ): ByteVector32 = {
    // https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
    val xonlyPub = privateKey.publicKey.xonly
    val t = auxrand32 match {
      case None =>
        privateKey.value.xor(taggedHash(ByteVector32.Zeroes, "BIP0340/aux"))
      case Some(a) => privateKey.value.xor(taggedHash(a, "BIP0340/aux"))
    }
    val rand = taggedHash(t ++ xonlyPub.value ++ data, "BIP0340/nonce")
    val kPrime = PrivateKey(rand)
    val pointR = G * kPrime
    val k = if (pointR.isEven) kPrime else kPrime.negate
    k.value
  }

  /** Convenience method which calculates the parts of the signature that are
    * public knowledge (can be reconstructed) by anybody. Basically a tagged
    * hash turned into a private key see: BIP340/challenge
    *
    * @param data
    * @param noncePointR
    * @param publicKey
    * @return
    */
  def calculateBip340challenge(
      data: ByteVector,
      noncePointR: XOnlyPublicKey,
      publicKey: XOnlyPublicKey
  ): ByteVector32 = PrivateKey(
    taggedHash(
      noncePointR.value ++ publicKey.value ++ data,
      "BIP0340/challenge"
    )
  ).value

  /** (Unsafe) Sign according to BIP340 specification
    * https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki Note: this
    * is unsafe! It is uses a less-tested, inefficient, but platform-independent
    * implementation to do the signing. Prefer `signSchnorr` for anything in
    * production.
    *
    * @param data
    *   data to sign (32 bytes)
    * @param privateKey
    *   private key
    * @param auxrand32
    * @return
    *
    * @param data
    * @param privateKey
    * @param auxrand32
    * @return
    */
  def unsafeSignSchnorr(
      data: ByteVector32,
      privateKey: PrivateKey,
      auxrand32: Option[ByteVector32]
  ): ByteVector64 = {
    // variable names below mostly follow from
    // https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
    val k = PrivateKey(calculateBip340nonce(data, privateKey, auxrand32))
    val e = calculateBip340challenge(
      data.bytes,
      k.publicKey.xonly,
      privateKey.publicKey.xonly
    )
    val ed = PrivateKey(e) * privateKey
    val ourSig = ByteVector64(k.publicKey.xonly.value ++ (k + ed).value)
    ourSig
  }

  /** (Unsafe) verification of signature according to BIP340 specification
    * https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki Note: this
    * is unsafe! It is a uses less-tested, inefficient, but platform-independent
    * implementation. Prefer `verifySignatureSchnorr` for anything in
    * production.
    *
    * @param signature
    * @param data
    * @param publicKey
    * @return
    */
  def unsafeVerifySignatureSchnorr(
      signature: ByteVector64,
      data: ByteVector32,
      xonlyPubKey: XOnlyPublicKey
  ): Boolean = {
    val (pointR, s) = (
      XOnlyPublicKey(ByteVector32(signature.take(32))),
      PrivateKey(ByteVector32(signature.drop(32)))
    )
    require(pointR.publicKey.isValid, "point R not on the curve")
    require(xonlyPubKey.publicKey.isValid, "invalid public key")
    val h = PrivateKey(
      calculateBip340challenge(data.bytes, pointR, xonlyPubKey)
    )
    G * s == (pointR.publicKey + (xonlyPubKey.publicKey * h))
  }

  /** Tweak an otherwise valid BIP340 signature with a curve point `tweakPoint`.
    * The result is an "Adaptor Signature". Somebody with knowledge of the
    * discrete logarithm (the private key) for `tweakPoint` will be able to
    * repair the adaptor signature to reconstruct a valid BIP340 signature. See:
    * BIP340 https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki See:
    * https://suredbits.com/schnorr-applications-scriptless-scripts/
    *
    * @param data
    * @param privateKey
    *   private key used for signing
    * @param tweakPoint
    *   the curve point by which to "tweak" the signature
    * @return
    *   (R',s',T) as a 96-byte ByteVector
    */
  def computeSchnorrAdaptorSignatureForPoint(
      data: ByteVector32,
      privateKey: PrivateKey,
      tweakPoint: PublicKey
  ): ByteVector = {
    val k = PrivateKey(calculateBip340nonce(data, privateKey, None))
    val xonlyPointR = k.publicKey.xonly
    val challenge = calculateBip340challenge(
      data.bytes,
      (xonlyPointR.pointAdd(tweakPoint))._1,
      privateKey.publicKey.xonly
    )
    val sPrime = k + (PrivateKey(challenge) * privateKey)
    k.publicKey.xonly.value ++ sPrime.value ++ tweakPoint.xonly.value
  }

  /** Tweak a valid schnorr signature `(R,s)` with a scalar value `t` to create
    * an adaptor signature `(R - t*G, s - t, t*G). Anybody with knowledge of `t`
    * will be able to repair the resulting adaptor signature to reconstruct the
    * valid original signature. Because knowledge of the signing key was not
    * necessary to create the adaptor signature, this shows that adaptor
    * signatures posess a denaibility property. see:
    * https://suredbits.com/schnorr-applications-scriptless-scripts/
    *
    * @param sig
    * @param scalarTweak
    * @return
    */
  def tweakSchnorrSignatureWithScalar(
      sig: ByteVector64,
      scalarTweak: ByteVector32
  ): ByteVector = {
    val (pointR, s) = (
      XOnlyPublicKey(ByteVector32(sig.take(32))),
      PrivateKey(ByteVector32(sig.drop(32)))
    )
    val t = PrivateKey(scalarTweak)
    val tweakPoint = t.publicKey
    (pointR.publicKey - tweakPoint).xonly.value ++
      (s - t).value ++
      tweakPoint.xonly.value
  }

  /** Verify an "Adaptor Signature." If verification is successful and the
    * verifier knows the discrete logarithm (private key) for the `tweakPoint`,
    * then verifier will be able to repair the adaptor signature into a complete
    * and valid BIP340 schnorr signature by calling
    * `repairSchnorrAdaptorSignature`. See: BIP340
    * https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki See:
    * https://suredbits.com/schnorr-applications-scriptless-scripts/
    *
    * @param adaptorSig
    *   a 96-byte `ByteVector` `(R', s', T)` where each component is 32-bytes
    *   `R'` is the expected nonce point for a final (repaired) signature `s'`
    *   is `k’ + H(X, R’ + T, m)*x` where `k'*G = R` `T` is the `tweakPoint`
    * @param data
    *   the message which is signed (usually a hash of a bitcoin transaction)
    * @param publicKey
    *   the public key of the signer
    * @return
    */
  def verifySchnorrAdaptorSignature(
      adaptorSig: ByteVector,
      data: ByteVector32,
      publicKey: PublicKey
  ): Boolean = {
    val pointRprime = XOnlyPublicKey(ByteVector32(adaptorSig.take(32)))
    val sPrime = PrivateKey(ByteVector32(adaptorSig.drop(32).take(32)))
    val tweakPoint = XOnlyPublicKey(ByteVector32(adaptorSig.drop(64))).publicKey

    val challenge = calculateBip340challenge(
      data,
      (pointRprime.pointAdd(tweakPoint))._1,
      publicKey.xonly
    )
    G * sPrime == (pointRprime.publicKey + (publicKey * PrivateKey(challenge)))
  }

  /** Repair an "Adaptor Signature" using knowledge of the discrete logarithm of
    * the `tweakPoint`. Note, this does not first check whether the adaptor
    * signature is valid. For that you should first call
    * `verifySchnorrAdaptorSignature`. See: BIP340
    * https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki See:
    * https://suredbits.com/schnorr-applications-scriptless-scripts/
    *
    * @param adaptorSig
    *   a 96-byte `ByteVector` `(R', s', T)` where each component is 32-bytes
    *   `R'` is the expected nonce point for a final (repaired) signature `s'`
    *   is `k’ + H(X, R’ + T, m)*x` where `k'*G = R` `T` is the `tweakPoint`
    * @param data
    *   the message which is signed (usually a hash of a bitcoin transaction)
    * @param publicKey
    *   the public key of the signer
    * @param scalarTweak
    *   the discrete logarithm of the `tweakPoint` (`scalarTweak*G ==
    *   tweakPoint`)
    * @return
    */
  def repairSchnorrAdaptorSignature(
      adaptorSig: ByteVector,
      data: ByteVector32,
      publicKey: PublicKey,
      scalarTweak: ByteVector32
  ): ByteVector64 = {
    val pointRprime = XOnlyPublicKey(ByteVector32(adaptorSig.take(32)))
    val sPrime = PrivateKey(ByteVector32(adaptorSig.drop(32).take(32)))
    val tweakPoint = XOnlyPublicKey(ByteVector32(adaptorSig.drop(64))).publicKey

    val s = sPrime + PrivateKey(scalarTweak)
    val pointR = (pointRprime.pointAdd(tweakPoint))._1
    ByteVector64(pointR.value ++ s.value)
  }

}
