package scoin

import java.math.BigInteger
import scodec.bits._

import Crypto._

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

  /** @param prefix
    *   Private key prefix
    * @return
    *   the private key in Base58 (WIF) compressed format
    */
  def toBase58(prefix: Byte) =
    Base58Check.encode(prefix, value.bytes :+ 1.toByte)

  /** Counterparty to XOnlyPublicKey.tapTweak -- takes the same taproot merkle
    * root and outputs a private key that can sign for the corresponding taproot
    * external (output) public key.
    *
    * @param tweak32
    *   the value (possibly a merkleRoot) used to tweak the private key
    * @return
    *   tweaked private key
    */
  def tapTweak(
      merkleRoot: Option[ByteVector32] = None
  ): PrivateKey = {
    val tweak = merkleRoot match {
      case None       => taggedHash(publicKey.xonly.value, "TapTweak")
      case Some(bv32) => taggedHash(publicKey.xonly.value ++ bv32, "TapTweak")
    }
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
