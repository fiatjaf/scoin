package scoin

import java.io.{ByteArrayInputStream, ByteArrayOutputStream}
import java.math.BigInteger
import scodec.bits.ByteVector

object Crypto extends CryptoPlatform {
  lazy val halfCurveOrder = N.shiftRight(1)

  def fixSize(data: ByteVector): ByteVector32 = ByteVector32(data.padLeft(32))

  /** Secp256k1 private key, which a 32 bytes value We assume that private keys
    * are compressed i.e. that the corresponding public key is compressed
    *
    * @param value
    *   value to initialize this key with
    */
  case class PrivateKey(value: ByteVector32) extends PrivateKeyPlatform(value) {
    def +(that: PrivateKey): PrivateKey = add(that)
    def -(that: PrivateKey): PrivateKey = subtract(that)
    def *(that: PrivateKey): PrivateKey = multiply(that)

    /** Negate a private key This is a naive slow implementation but works on
      * every platform
      * @return
      *   negation of private key
      */
    def negate: PrivateKey = PrivateKey(
      (BigInt(N) - BigInt(value.toHex, 16)).mod(N)
    )

    def xOnlyPublicKey: XOnlyPublicKey = XOnlyPublicKey(publicKey)

    /** @param prefix
      *   Private key prefix
      * @return
      *   the private key in Base58 (WIF) compressed format
      */
    def toBase58(prefix: Byte) =
      Base58Check.encode(prefix, value.bytes :+ 1.toByte)

    /** Tweak this private key with the scalar value of `tweak32`
      *
      * @param tweak32
      *   the value (possibly a merkleRoot) used to tweak the private key
      * @return
      *   tweaked private key
      */
    def tweak(tweak32: ByteVector32): PrivateKey = {
      val key = if (publicKey.isEven) this else this.negate
      key + PrivateKey(tweak32)
    }
  }

  object PrivateKey {
    def apply(data: ByteVector): PrivateKey = new PrivateKey(
      ByteVector32(data.take(32))
    )

    def apply(data: BigInteger): PrivateKey = {
      new PrivateKey(
        fixSize(ByteVector.view(data.toByteArray.dropWhile(_ == 0.toByte)))
      )
    }

    def apply(data: BigInt): PrivateKey = {
      require(data >= 0, "only non-negative integers mod N allowed")
      PrivateKey(fixSize(ByteVector.fromValidHex(data.mod(N).toString(16))))
    }

    /** @param data
      *   serialized private key in bitcoin format
      * @return
      *   the de-serialized key
      */
    def fromBin(data: ByteVector): (PrivateKey, Boolean) = {
      val compressed = data.length match {
        case 32                          => false
        case 33 if data.last == 1.toByte => true
      }
      (PrivateKey(data.take(32)), compressed)
    }

    def fromBase58(value: String, prefix: Byte): (PrivateKey, Boolean) = {
      require(
        Set(
          Base58.Prefix.SecretKey,
          Base58.Prefix.SecretKeyTestnet,
          Base58.Prefix.SecretKeySegnet
        ).contains(prefix),
        "invalid base58 prefix for a private key"
      )
      val (prf, data) = Base58Check.decode(value)
      require(prf == prefix, "private key base58 prefix doesn't match")

      fromBin(data)
    }
  }

  /** Secp256k1 Public key We assume that public keys are always compressed
    *
    * @param value
    *   serialized public key, in compressed format (33 bytes)
    */
  case class PublicKey(value: ByteVector) extends PublicKeyPlatform(value) {
    require(
      value.length == 33,
      s"pubkey is ${value.length} bytes but should be 33 bytes"
    )
    require(isPubKeyValidLax(value), "pubkey is not valid")

    def hash160: ByteVector = Crypto.hash160(value)
    def xonly: XOnlyPublicKey = XOnlyPublicKey(this)
    def isValid: Boolean = isPubKeyValidStrict(this.value)
    def isEven: Boolean = value(0) == 2.toByte
    def isOdd: Boolean = !isEven

    def +(that: PublicKey): PublicKey = add(that)
    def -(that: PublicKey): PublicKey = subtract(that)
    def *(that: PrivateKey): PublicKey = multiply(that)

    override def toString = value.toHex
  }

  object PublicKey {

    /** @param raw
      *   serialized value of this public key (a point)
      * @param checkValid
      *   indicates whether or not we check that this is a valid public key;
      *   this should be used carefully for optimization purposes
      * @return
      */
    def apply(raw: ByteVector, checkValid: Boolean): PublicKey =
      fromBin(raw, checkValid)

    def fromBin(input: ByteVector, checkValid: Boolean = true): PublicKey = {
      if (checkValid) require(isPubKeyValidStrict(input))

      input.length match {
        case 33 => PublicKey(input)
        case 65 => toCompressedUnsafe(input.toArray)
      }
    }

    /**
      * Returns a provably unspendable public key `H` by hashing the uncompressed
      * encoding of the generator point `G` and taking the result to be the 
      * x-coordinate of a new public key `H` with unknown discrete logarithm.
      * 
      * The compressed form of `H` is:
      * `0x0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0`
      * 
      * For further privacy, it is recommended to add `r*G` to `H` where 
      * `r` is  a fresh integer in the range 0..n-1.
      * 
      * `r` can be furnished to a verifier to prove that key path spending is
      *  effectively not possible for a taproot output which uses `H + r*G` as
      *  its internal public key.
      * 
      * @see https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
      * @see https://bitcoin.stackexchange.com/questions/99722/taproot-eliminating-key-path
      *
      * @return
      */
    def unspendable: PublicKey = XOnlyPublicKey(sha256(G.toUncompressedBin)).publicKey

    /** This function initializes a public key from a compressed/uncompressed
      * representation without doing validity checks.
      *
      * This will always convert the key to its compressed representation
      *
      * Note that this mutates the input array!
      *
      * @param key
      *   33 or 65 bytes public key (will be mutated)
      * @return
      *   an immutable compressed public key
      */
    private def toCompressedUnsafe(key: Array[Byte]): PublicKey = {
      key.length match {
        case 65 if key(0) == 4 || key(0) == 6 || key(0) == 7 =>
          key(0) = if ((key(64) & 0x01) != 0) 0x03.toByte else 0x02.toByte
          new PublicKey(ByteVector(key, 0, 33))
        case 33 if key(0) == 2 || key(0) == 3 =>
          new PublicKey(ByteVector(key, 0, 33))
        case _ =>
          throw new IllegalArgumentException(s"key must be 33 or 65 bytes")
      }
    }
  }

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

  /** @param privateKey
    *   private key
    * @return
    *   the corresponding public key
    */
  def publicKeyFromPrivateKey(privateKey: ByteVector) = PrivateKey(
    privateKey
  ).publicKey

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

  case class XOnlyPublicKey(value: ByteVector32) {
    def toHex: String = value.toHex

    lazy val publicKey: PublicKey = PublicKey(ByteVector(2) ++ value)

    /** Calculates a `taggedHash(m,"TapTweak")` where `m:ByteVector32` is
      * calculated as: val m = if(!merkleRoot.isEmpty) thisXOnlyPublicKey.value
      * ++ merkleRoot else thisXOnlyPublicKey.value
      * @param merkleRoot
      * @return
      *   a unique "tweak" corresponding to
      */
    def tweak(merkleRoot: Option[ByteVector32]): ByteVector32 =
      merkleRoot match {
        case None       => taggedHash(value, "TapTweak")
        case Some(bv32) => taggedHash(value ++ bv32, "TapTweak")
      }

    /** Construct a new `XOnlyPublicKey` by (optionally) tweaking this one with
      * a `merkleRoot` (the tweak). The tweak is used to create a private key
      * `t` with corresponding public key `T` and the returned public key is
      * `this.pointAdd(T)`.
      *
      * @param merkleRoot
      * @return
      *   tweaked XOnlyPublicKey
      */
    def outputKey(merkleRoot: Option[ByteVector32] = None): XOnlyPublicKey =
      this.pointAdd(PrivateKey(tweak(merkleRoot)).publicKey)

    override def toString = s"XOnlyPublicKey($toHex)"
  }
  object XOnlyPublicKey {
    def apply(pubKey: PublicKey): XOnlyPublicKey = XOnlyPublicKey(
      ByteVector32(ByteVector.view(pubKey.value.drop(1).toArray))
    )

    implicit class xonlyOps(lhs: XOnlyPublicKey) {
      def pointAdd(rhs: PublicKey): XOnlyPublicKey = XOnlyPublicKey(
        lhs.publicKey + rhs
      )
      def plus(rhs: PublicKey): XOnlyPublicKey = pointAdd(rhs)
      def +(rhs: PublicKey): XOnlyPublicKey = pointAdd(rhs)
    }
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

  sealed trait SchnorrTweak
  case object NoTweak extends SchnorrTweak
  case object NoScriptPathsTweak extends SchnorrTweak
  case class KeyPathTweak(merkleRoot: ByteVector32) extends SchnorrTweak
  case class Tweak(merkleRoot: ByteVector32) extends SchnorrTweak

  /**
    * Sign according to BIP340 specification but first "tweak" the private
    * key using the merkleRoot.
    *
    * @param data
    * @param privateKey
    * @param merkleRoot
    * @param auxrand32
    * @return
    */
  def signSchnorrWithTweak(
      data: ByteVector32,
      privateKey: PrivateKey,
      merkleRoot: Option[ByteVector32],
      auxrand32: Option[ByteVector32] = None
  ): ByteVector64 = {
    val priv = merkleRoot match {
      case None => privateKey
      case Some(ByteVector32.Zeroes) =>
        privateKey.tweak(privateKey.xOnlyPublicKey.tweak(None))
      case _ => privateKey.tweak(privateKey.xOnlyPublicKey.tweak(merkleRoot))
    }
    val sig = signSchnorr(data, priv, auxrand32)
    require(
      verifySignatureSchnorr(sig, data, priv.xOnlyPublicKey),
      "Cannot create Schnorr signature"
    )
    sig
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

  /** Find the value of `k` which would be used to construct
    * a valid BIP340 schnorr signature. A schnorr signature
    * is 64-bytes given by `(R,s)` where the first 32 bytes
    * are `R = k*G`. This function returns the value `k`.
    * 
    * @param data, the message to be signed
    * @param privateKey
    * @return k, the private nonce to be used in a BIP340 schnorr signature
    */
  def calculateBip340nonce(
      data: ByteVector32,
      privateKey: PrivateKey,
      auxrand32: Option[ByteVector32]
  ): ByteVector32 = {
    // https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
    val xonlyPub = privateKey.publicKey.xonly
    val t = auxrand32 match {
      case None => privateKey.value.xor(taggedHash(ByteVector32.Zeroes,"BIP0340/aux"))
      case Some(a) => privateKey.value.xor(taggedHash(a,"BIP0340/aux"))
    }
    val rand = taggedHash(t ++ xonlyPub.value ++ data, "BIP0340/nonce")
    val kPrime = PrivateKey(rand)
    val pointR = G * kPrime
    val k = if(pointR.isEven) kPrime else kPrime.negate
    k.value
  }

  /**
    * Convenience method which calculates the parts of the signature 
    * that are public knowledge (can be reconstructed) by anybody.
    * Basically a tagged hash turned into a private key
    * see: BIP340/challenge
    *
    * @param data
    * @param noncePointR
    * @param publicKey
    * @return
    */
  def calculateBip340challenge(
      data: ByteVector32,
      noncePointR: XOnlyPublicKey,
      publicKey: XOnlyPublicKey
  ): ByteVector32 = PrivateKey(taggedHash(noncePointR.value ++ publicKey.value ++ data,"BIP0340/challenge")).value
  /**
    * Convenience method which calculates the parts of the signature 
    * that are public knowledge (can be reconstructed) by anybody.
    * Basically a tagged hash turned into a private key
    * see: BIP340/challenge
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
  ): ByteVector32 = PrivateKey(taggedHash(noncePointR.value ++ publicKey.value ++ data,"BIP0340/challenge")).value

  /** (Unsafe) Sign according to BIP340 specification
    * https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
    * Note: this is unsafe! It is uses a less-tested, inefficient, but 
    * platform-independent implementation to do the signing.
    * Prefer `signSchnorr` for anything in production.
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
      val k = PrivateKey(calculateBip340nonce(data,privateKey,auxrand32))
      val e = calculateBip340challenge(data, k.publicKey.xonly, privateKey.publicKey.xonly)
      val ed = PrivateKey(e)*privateKey
      val ourSig = ByteVector64(k.publicKey.xonly.value ++ (k + ed).value)
      ourSig
  }

  /**
    * (Unsafe) verification of signature according to BIP340 specification
    * https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
    * Note: this is unsafe! It is a uses less-tested, inefficient, but 
    * platform-independent implementation.
    * Prefer `verifySignatureSchnorr` for anything in production.
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
    val (pointR,s) = (XOnlyPublicKey(ByteVector32(signature.take(32))),PrivateKey(ByteVector32(signature.drop(32))))
    require(pointR.publicKey.isValid, "point R not on the curve")
    require(xonlyPubKey.publicKey.isValid, "invalid public key")
    val h = PrivateKey(calculateBip340challenge(data,pointR,xonlyPubKey))
    G*s == ( pointR.publicKey + (xonlyPubKey.publicKey*h) )
  }

  /**
    * Tweak an otherwise valid BIP340 signature with a curve point `tweakPoint`.
    * The result is an "Adaptor Signature". Somebody with knowledge
    * of the discrete logarithm (the private key) for `tweakPoint` will be able 
    * to repair the adaptor signature to reconstruct a valid BIP340 signature.
    * See: BIP340 https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
    * See: https://suredbits.com/schnorr-applications-scriptless-scripts/
    *
    * @param data
    * @param privateKey private key used for signing 
    * @param tweakPoint the curve point by which to "tweak" the signature
    * @return (R',s',T) as a 96-byte ByteVector
    */
  def computeSchnorrAdaptorSignatureForPoint(
    data: ByteVector32,
    privateKey: PrivateKey,
    tweakPoint: PublicKey
  ): ByteVector = {
    val k = PrivateKey(calculateBip340nonce(data,privateKey,None))
    val xonlyPointR = k.publicKey.xonly
    val challenge = calculateBip340challenge(
        data,
        xonlyPointR + tweakPoint,
        privateKey.publicKey.xonly
    )
    val sPrime = k + (PrivateKey(challenge)*privateKey)
    k.publicKey.xonly.value ++ sPrime.value ++ tweakPoint.xonly.value
  }

  /**
    * Tweak a valid schnorr signature `(R,s)` with a scalar value `t`
    * to create an adaptor signature `(R - t*G, s - t, t*G). Anybody
    * with knowledge of `t` will be able to repair the resulting adaptor
    * signature to reconstruct the valid original signature. Because
    * knowledge of the signing key was not necessary to create the adaptor
    * signature, this shows that adaptor signatures posess a denaibility
    * property.
    * see: https://suredbits.com/schnorr-applications-scriptless-scripts/ 
    *
    * @param sig
    * @param scalarTweak
    * @return
    */
  def tweakSchnorrSignatureWithScalar(
    sig: ByteVector64,
    scalarTweak: ByteVector32
  ): ByteVector = {
    val (pointR,s) = (
      XOnlyPublicKey(ByteVector32(sig.take(32))),
      PrivateKey(ByteVector32(sig.drop(32)))
    )
    val t = PrivateKey(scalarTweak)
    val tweakPoint = t.publicKey
    (pointR.publicKey - tweakPoint).xonly.value ++
    (s - t).value ++
    tweakPoint.xonly.value
  }

  /**
    * Verify an "Adaptor Signature." If verification is successful and the
    * verifier knows the discrete logarithm (private key) for the `tweakPoint`,
    * then verifier will be able to repair the adaptor signature into a complete
    * and valid BIP340 schnorr signature by calling `repairSchnorrAdaptorSignature`.
    * See: BIP340 https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
    * See: https://suredbits.com/schnorr-applications-scriptless-scripts/
    *
    * @param adaptorSig 
    *   a 96-byte `ByteVector` `(R', s', T)` where each component is 32-bytes
    *         `R'` is the expected nonce point for a final (repaired) signature
    *         `s'` is `k’ + H(X, R’ + T, m)*x` where `k'*G = R`
    *         `T` is the `tweakPoint` 
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
    val (pointRprime, sPrime, tweakPoint) = (
      XOnlyPublicKey(ByteVector32(adaptorSig.take(32))),
      PrivateKey(ByteVector32(adaptorSig.drop(32).take(32))),
      XOnlyPublicKey(ByteVector32(adaptorSig.drop(64))).publicKey
    )
    val challenge = calculateBip340challenge(
      data,
      pointRprime + tweakPoint,
      publicKey.xonly
    )
    G*sPrime == (pointRprime.publicKey + (publicKey*PrivateKey(challenge)))
  }

  /**
    * Repair an "Adaptor Signature" using knowledge of the discrete logarithm
    * of the `tweakPoint`. Note, this does not first check whether the adaptor
    * signature is valid. For that you should first call `verifySchnorrAdaptorSignature`.
    * See: BIP340 https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
    * See: https://suredbits.com/schnorr-applications-scriptless-scripts/
    *
    * @param adaptorSig 
    *   a 96-byte `ByteVector` `(R', s', T)` where each component is 32-bytes
    *         `R'` is the expected nonce point for a final (repaired) signature
    *         `s'` is `k’ + H(X, R’ + T, m)*x` where `k'*G = R`
    *         `T` is the `tweakPoint` 
    * @param data
    *   the message which is signed (usually a hash of a bitcoin transaction)
    * @param publicKey
    *   the public key of the signer
    * @param scalarTweak
    *   the discrete logarithm of the `tweakPoint` (`scalarTweak*G == tweakPoint`)
    * @return
    */
  def repairSchnorrAdaptorSignature(
    adaptorSig: ByteVector,
    data: ByteVector32,
    publicKey: PublicKey,
    scalarTweak: ByteVector32
  ): ByteVector64 = {
    val (pointRprime, sPrime, tweakPoint) = (
      XOnlyPublicKey(ByteVector32(adaptorSig.take(32))),
      PrivateKey(ByteVector32(adaptorSig.drop(32).take(32))),
      XOnlyPublicKey(ByteVector32(adaptorSig.drop(64))).publicKey
    )
    val s = sPrime + PrivateKey(scalarTweak)
    val pointR = pointRprime + tweakPoint
    ByteVector64(pointR.value ++ s.value)
  }

}
