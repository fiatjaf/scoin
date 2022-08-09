package scoin

import java.io.{ByteArrayInputStream, ByteArrayOutputStream}
import java.math.BigInteger
import scala.scalanative.unsigned._
import scodec.bits.ByteVector
import sha256.{hash => sha256sum}
import sha512.{hash => sha512sum}
import hmac256.{hmac => hmac256sum}
import hmac512.{hmac => hmac512sum}
import ripemd160.{hash => ripemd160sum}
import secp256k1.Secp256k1

private[scoin] trait CryptoPlatform {
  import Crypto._

  def randomBytes(length: Int): ByteVector = {
    ByteVector(
      (1 to (length.toDouble / 32).ceil.toInt).iterator
        .map(_ => secp256k1.createPrivateKey().value.map(_.toByte))
        .reduce(_ ++ _)
        .take(length)
    )
  }

  def G = PublicKey(
    ByteVector(
      Secp256k1.G.value.toArray.map[Byte](_.toByte)
    )
  )
  def N: BigInteger = Secp256k1.N

  private[scoin] class PrivateKeyPlatform(value: ByteVector32) {
    lazy val underlying =
      secp256k1.loadPrivateKey(value.toArray.map(_.toUByte)).toOption.get

    def add(that: PrivateKey): PrivateKey =
      PrivateKey(
        ByteVector32(
          ByteVector(
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
          ByteVector(
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
          ByteVector(
            underlying
              .multiply(that.value.toArray.map(_.toUByte))
              .value
              .map(_.toByte)
          )
        )
      )

    def publicKey: PublicKey =
      PublicKey(
        ByteVector(underlying.publicKey().value.map(_.toByte))
      )
  }

  private[scoin] class PublicKeyPlatform(value: ByteVector) {
    lazy val underlying =
      secp256k1.loadPublicKey(value.toArray.map(_.toUByte)).toOption.get

    def add(that: PublicKey): PublicKey =
      PublicKey(
        ByteVector(
          underlying
            .add(
              that.value.toArray.map(_.toUByte)
            )
            .value
            .map(_.toByte)
        )
      )

    def add(that: PrivateKey): PublicKey =
      PublicKey(
        ByteVector(
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
        ByteVector(
          underlying
            .add(
              secp256k1
                .loadPrivateKey(that.value.toArray.map(_.toUByte))
                .toOption
                .get
                .negate()
                .value
                .toArray
                .map(_.toUByte)
            )
            .value
            .map(_.toByte)
        )
      )

    def multiply(that: PrivateKey): PublicKey =
      PublicKey(
        ByteVector(
          underlying
            .multiply(that.value.toArray.map(_.toUByte))
            .value
            .map(_.toByte)
        )
      )

    def toUncompressedBin: ByteVector = ByteVector(
      underlying.toUncompressed().map(_.toByte)
    )
  }

  def sha1(x: ByteVector): ByteVector32 =
    throw new NotImplementedError("not implemented")

  def sha256(x: ByteVector): ByteVector32 =
    ByteVector32(
      ByteVector(
        sha256sum(x.toArray.map[UByte](_.toUByte))
          .map[Byte](_.toByte)
      )
    )

  def sha512(x: ByteVector): ByteVector =
    ByteVector(
      sha512sum(x.toArray.map[UByte](_.toUByte)).map[Byte](_.toByte)
    )

  def hmac512(key: ByteVector, data: ByteVector): ByteVector =
    ByteVector(
      hmac512sum(
        key.toArray.map[UByte](_.toUByte),
        data.toArray.map[UByte](_.toUByte)
      )
        .map[Byte](_.toByte)
    )

  def hmac256(key: ByteVector, message: ByteVector): ByteVector32 =
    ByteVector32(
      ByteVector(
        hmac256sum(
          key.toArray.map[UByte](_.toUByte),
          message.toArray.map[UByte](_.toUByte)
        )
          .map[Byte](_.toByte)
      )
    )

  def ripemd160(input: ByteVector): ByteVector =
    ByteVector(
      ripemd160sum(input.toArray.map[UByte](_.toUByte))
        .map[Byte](_.toByte)
    )

  /** @param key
    *   serialized public key
    * @return
    *   true if the key is valid. This check is much more expensive than its lax
    *   version since here we check that the public key is a valid point on the
    *   secp256k1 curve
    */
  def isPubKeyValidStrict(key: ByteVector): Boolean = isPubKeyValidLax(key) &&
    secp256k1.loadPublicKey(key.toArray.map(_.toUByte)).toOption.isDefined

  // copied from noble-secp256k1
  def compact2der(signature: ByteVector64): ByteVector = {
    val (r, s) = decodeSignatureCompact(signature)
    signatureToDER(r, s)
  }

  def verifySignature(
      data: Array[Byte],
      signature: Array[Byte],
      publicKey: PublicKey
  ): Boolean =
    publicKey.underlying
      .verify(data.map(_.toUByte), signature.map(_.toUByte))
      .toOption
      .getOrElse(false)

  def sign(data: Array[Byte], privateKey: PrivateKey): ByteVector64 =
    ByteVector64(
      ByteVector(
        privateKey.underlying
          .sign(data.map(_.toUByte))
          .toOption
          .get
          .map(_.toByte)
      )
    )

  /** Recover public keys from a signature and the message that was signed. This
    * method will return 2 public keys, and the signature can be verified with
    * both, but only one of them matches that private key that was used to
    * generate the signature.
    *
    * @param signature
    *   signature
    * @param message
    *   message that was signed
    * @return
    *   a recovered public key
    */
  def recoverPublicKey(
      signature: ByteVector64,
      message: ByteVector,
      recoveryId: Int
  ): PublicKey =
    PublicKey(
      ByteVector64(
        ByteVector(
          secp256k1
            .recoverPublicKey(
              message.toArray.map(_.toUByte),
              signature.bytes.toArray.map(_.toUByte),
              recoveryId
            )
            .toOption
            .get
            .value
            .map(_.toByte)
        )
      )
    )
}
