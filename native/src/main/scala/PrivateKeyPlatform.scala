package scoin

import scala.scalanative.unsigned._
import scodec.bits.ByteVector

private[scoin] class PrivateKeyPlatform(value: ByteVector32) {
  import Crypto._

  lazy val underlying =
    secp256k1.loadPrivateKey(value.toArray.map(_.toUByte)).toOption.get

  def add(that: PrivateKey): PrivateKey =
    PrivateKey(
      ByteVector32(
        ByteVector.view(
          underlying
            .add(that.value.toArray.map(_.toUByte))
            .value
            .map(_.toByte)
        )
      )
    )

  def subtract(that: PrivateKey): PrivateKey =
    PrivateKey(
      ByteVector32(
        ByteVector.view(
          underlying
            .add(
              secp256k1
                .loadPrivateKey(that.value.toArray.map(_.toUByte))
                .toOption
                .get
                .negate()
                .value
            )
            .value
            .map(_.toByte)
        )
      )
    )

  def multiply(that: PrivateKey): PrivateKey =
    PrivateKey(
      ByteVector32(
        ByteVector.view(
          underlying
            .multiply(that.value.toArray.map(_.toUByte))
            .value
            .map(_.toByte)
        )
      )
    )

  def publicKey: PublicKey =
    PublicKey(
      ByteVector.view(underlying.publicKey().value.map(_.toByte))
    )
}
