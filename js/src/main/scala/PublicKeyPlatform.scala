package scoin

import scodec.bits.ByteVector

private[scoin] class PublicKeyPlatform(value: ByteVector) {
  import Secp256k1._
  import Crypto._

  lazy val point = Point.fromHex(value.toUint8Array)

  def add(that: PublicKey): PublicKey = PublicKey(
    ByteVector.view(
      point.add(that.asInstanceOf[PublicKeyPlatform].point).toRawBytes(true)
    )
  )

  def add(that: PrivateKey): PublicKey =
    PublicKey(
      ByteVector.view(
        utils.pointAddScalar(
          value.toUint8Array,
          that.value.toUint8Array
        )
      )
    )

  def subtract(that: PublicKey): PublicKey = PublicKey(
    ByteVector.view(
      point
        .subtract(that.asInstanceOf[PublicKeyPlatform].point)
        .toRawBytes(true)
    )
  )

  def multiply(that: PrivateKey): PublicKey = PublicKey(
    ByteVector.view(
      point
        .multiply(that.value.bytes)
        .toRawBytes(true)
    )
  )

  def toUncompressedBin: ByteVector = ByteVector.view(point.toRawBytes(false))
}
