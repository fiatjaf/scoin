package scoin

import java.io.{ByteArrayInputStream, ByteArrayOutputStream}
import java.math.BigInteger
import scala.scalanative.unsigned._
import scodec.bits.ByteVector
import sha256.{Hmac, Sha256}

trait CryptoPlatform {
  import Crypto._

  def G = PublicKey(
    ByteVector(
      secp256k1.Secp256k1.G.value.toArray.map[Byte](_.toByte)
    )
  )
  def N: BigInteger =
    throw new NotImplementedError("must update sn-secp256k1")

  private[scoin] class PrivateKeyPlatform(value: ByteVector32) {
    lazy val underlying =
      secp256k1.Keys
        .loadPrivateKey(value.toArray.map(_.toUByte))
        .toOption
        .get

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
                secp256k1.Keys
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
      secp256k1.Keys.loadPublicKey(value.toArray.map(_.toUByte)).toOption.get

    def add(that: PublicKey): PublicKey =
      throw new NotImplementedError("must update sn-secp256k1")

    def add(that: PrivateKey): PublicKey =
      PublicKey(
        ByteVector(
          underlying.add(that.value.toArray.map(_.toUByte)).value.map(_.toByte)
        )
      )

    def subtract(that: PublicKey): PublicKey =
      throw new NotImplementedError("must update sn-secp256k1")

    def multiply(that: PrivateKey): PublicKey =
      PublicKey(
        ByteVector(
          underlying
            .multiply(that.value.toArray.map(_.toUByte))
            .value
            .map(_.toByte)
        )
      )

    def toUncompressedBin: ByteVector =
      throw new NotImplementedError("must update sn-secp256k1")
  }

  def sha1(x: ByteVector): ByteVector32 =
    throw new NotImplementedError("not implemented")

  def sha256(x: ByteVector): ByteVector32 =
    ByteVector32(
      ByteVector(
        Sha256.sha256(x.toArray.map[UByte](_.toUByte)).map[Byte](_.toByte)
      )
    )

  def hmac512(key: ByteVector, data: ByteVector): ByteVector =
    throw new NotImplementedError("not implemented")

  def hmac256(key: ByteVector, message: ByteVector): ByteVector32 =
    ByteVector32(
      ByteVector(
        Hmac
          .hmac(
            key.toArray.map[UByte](_.toUByte),
            message.toArray.map[UByte](_.toUByte)
          )
          .map[Byte](_.toByte)
      )
    )

  def ripemd160(input: ByteVector): ByteVector =
    throw new NotImplementedError("not implemented")

  /** @param key
    *   serialized public key
    * @return
    *   true if the key is valid. This check is much more expensive than its lax
    *   version since here we check that the public key is a valid point on the
    *   secp256k1 curve
    */
  def isPubKeyValidStrict(key: ByteVector): Boolean = isPubKeyValidLax(key) &&
    secp256k1.Keys.loadPublicKey(key.toArray.map(_.toUByte)).toOption.isDefined

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
    throw new NotImplementedError("must update sn-secp256k1")
}
