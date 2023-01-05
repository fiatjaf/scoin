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

    /**
      * Negate a private key
      * This is a naive slow implementation but works on every platform
      * @return the multiplicative inverse of the private key
      */
    def negate: PrivateKey = PrivateKey((BigInt(N)-BigInt(value.toHex,16)).mod(N))

    /** @param prefix
      *   Private key prefix
      * @return
      *   the private key in Base58 (WIF) compressed format
      */
    def toBase58(prefix: Byte) =
      Base58Check.encode(prefix, value.bytes :+ 1.toByte)

    def tweak(tweak: ByteVector32): PrivateKey = {
      val key = if (publicKey.isEven) this else this.negate
      key + PrivateKey(tweak)
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

  /**
    * Tagged hash of input as defined in BIP340
    */
  def taggedHash(input: ByteVector, tag: String): ByteVector32 = {
    val hashedTag = sha256(ByteVector(tag.getBytes("UTF-8")))
    sha256(hashedTag ++ hashedTag ++ input)
  }

  case class XOnlyPublicKey(value: ByteVector32) {
    def toHex: String = value.toHex

    lazy val publicKey: PublicKey = PublicKey(ByteVector(2) ++ value)

    def tweak(merkleRoot: Option[ByteVector32]): ByteVector32 = merkleRoot match {
      case None => taggedHash(value, "TapTweak")
      case Some(bv32) => taggedHash(value ++ bv32, "TapTweak")
    }

    def outputKey(merkleRoot: Option[ByteVector32] = None): XOnlyPublicKey = 
      this.pointAdd(PrivateKey(tweak(merkleRoot)).publicKey)

    override def toString = s"XOnlyPublicKey($toHex)"
  }
  object XOnlyPublicKey {
    def apply(pubKey: PublicKey): XOnlyPublicKey = XOnlyPublicKey(
      ByteVector32(ByteVector.view(pubKey.value.drop(1).toArray))
    )

    implicit class xonlyOps(lhs: XOnlyPublicKey) {
      def pointAdd(rhs: PublicKey): XOnlyPublicKey = XOnlyPublicKey(lhs.publicKey + rhs)
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
      case Some(bv32) => signSchnorrImpl(data,privateKey,Some(bv32))
    }

  /** Verify a BIP340 schnorr signature
    *
    * @param data
    * @param signature
    * @param publicKey
    * @return
    */
  def verifySignatureSchnorr(
      data: ByteVector32,
      signature: ByteVector64,
      publicKey: XOnlyPublicKey
  ): Boolean =
    verifySignatureSchnorrImpl(data, signature, publicKey)

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
}
