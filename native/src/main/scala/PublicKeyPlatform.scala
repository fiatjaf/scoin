package scoin

import scala.scalanative.unsigned._
import scodec.bits.ByteVector

private[scoin] class PublicKeyPlatform(value: ByteVector) {
  import Crypto._

  lazy val underlying =
    secp256k1.loadPublicKey(value.toArray.map(_.toUByte)).toOption.get

  def add(that: PublicKey): PublicKey = PublicKey(
    ByteVector(
      underlying
        .add(
          secp256k1
            .loadPublicKey(that.value.toArray.map(_.toUByte))
            .toOption
            .get
        )
        .value
        .map(_.toByte)
    )
  )

  def add(that: PrivateKey): PublicKey =
    PublicKey(
      ByteVector.view(
        underlying
          .add(
            that.value.toArray.map(_.toUByte)
          )
          .value
          .map(_.toByte)
      )
    )

  def subtract(that: PublicKey): PublicKey =
    PublicKey(
      ByteVector.view(
        underlying
          .add(
            secp256k1
              .loadPublicKey(that.value.toArray.map(_.toUByte))
              .toOption
              .get
              .negate()
          )
          .value
          .map(_.toByte)
      )
    )

  def multiply(that: PrivateKey): PublicKey = PublicKey(
    ByteVector(
      underlying
        .multiply(that.value.toArray.map(_.toUByte))
        .value
        .map(_.toByte)
    )
  )

  def toUncompressedBin: ByteVector = ByteVector.view(
    underlying.toUncompressed().map(_.toByte)
  )
}
