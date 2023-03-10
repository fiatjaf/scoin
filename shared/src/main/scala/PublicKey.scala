package scoin

import scodec.bits._

import Crypto._

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
  def xonly: XOnlyPublicKey = XOnlyPublicKey(ByteVector32(this.value.drop(1)))
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
    *   indicates whether or not we check that this is a valid public key; this
    *   should be used carefully for optimization purposes
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

  /** Returns a provably unspendable public key `H` by hashing the uncompressed
    * encoding of the generator point `G` and taking the result to be the
    * x-coordinate of a new public key `H` with unknown discrete logarithm.
    *
    * The compressed form of `H` is:
    * `0x0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0`
    *
    * For further privacy, it is recommended to add `r*G` to `H` where `r` is a
    * fresh integer in the range 0..n-1.
    *
    * `r` can be furnished to a verifier to prove that key path spending is
    * effectively not possible for a taproot output which uses `H + r*G` as its
    * internal public key.
    *
    * @see
    *   https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
    * @see
    *   https://bitcoin.stackexchange.com/questions/99722/taproot-eliminating-key-path
    *
    * @return
    */
  def unspendable: PublicKey = XOnlyPublicKey(
    sha256(G.toUncompressedBin)
  ).publicKey

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

case class XOnlyPublicKey(value: ByteVector32) {
  def toHex: String = value.toHex

  lazy val publicKey: PublicKey = PublicKey(ByteVector(2) ++ value)

  /** Construct a new `XOnlyPublicKey` with a commitment to a taproot merkle
    * root inside according to BIP-341. The result of this is the taproot
    * external (output) key.
    *
    * @param merkleRoot
    * @return
    *   tweaked XOnlyPublicKey
    * @return
    *   parity (true if y is odd)
    */
  def tapTweak(
      merkleRoot: Option[ByteVector32] = None
  ): (XOnlyPublicKey, Boolean) = {
    val tweak = merkleRoot match {
      case None       => taggedHash(value, "TapTweak")
      case Some(bv32) => taggedHash(value ++ bv32, "TapTweak")
    }
    val point = PrivateKey(tweak).publicKey
    this.pointAdd(point)
  }

  override def toString = s"XOnlyPublicKey($toHex)"
}

object XOnlyPublicKey {
  implicit class xonlyOps(lhs: XOnlyPublicKey) {
    // this returns the parity as a boolean == isOdd
    def pointAdd(rhs: PublicKey): (XOnlyPublicKey, Boolean) = {
      val combined = lhs.publicKey + rhs
      (combined.xonly, combined.isOdd)
    }
    def +(rhs: PublicKey): (XOnlyPublicKey, Boolean) = pointAdd(rhs)
  }
}
