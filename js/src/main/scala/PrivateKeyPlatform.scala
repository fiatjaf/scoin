package scoin

import scodec.bits.ByteVector

private[scoin] class PrivateKeyPlatform(value: ByteVector32) {
  import Crypto._

  def add(that: PrivateKey): PrivateKey = PrivateKey {
    (BigInt(value.toHex, 16) + BigInt(that.value.toHex, 16)).mod(N)
  }

  def subtract(that: PrivateKey): PrivateKey = PrivateKey {
    val negThat = BigInt(N) - BigInt(that.value.toHex, 16)
    (BigInt(value.toHex, 16) + negThat).mod(N)
  }

  def multiply(that: PrivateKey): PrivateKey =
    PrivateKey(
      (BigInt(value.toHex, 16) * BigInt(that.value.toHex, 16)).mod(N)
    )

  def publicKey: PublicKey = PublicKey(
    ByteVector.view(Secp256k1.getPublicKey(value.bytes.toUint8Array, true))
  )
}
