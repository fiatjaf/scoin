package scoin

import java.io.{ByteArrayInputStream, ByteArrayOutputStream}
import java.math.BigInteger
import java.security.SecureRandom
import scala.scalajs.js
import scala.scalajs.js.typedarray.Uint8Array
import scala.util.Try
import scala.language.implicitConversions
import scodec.bits.ByteVector

private[scoin] trait CryptoPlatform {
  import Crypto._
  import Secp256k1._

  monkeyPatch.init()

  private val secureRandom = new SecureRandom
  def randomBytes(length: Int): ByteVector = {
    val buffer = new Array[Byte](length)
    secureRandom.nextBytes(buffer)
    ByteVector.view(buffer)
  }

  def G = PublicKey(
    ByteVector.view(new Point(CURVE.Gx, CURVE.Gy).toRawBytes(true))
  )
  def N = bigint2biginteger(CURVE.n)

  private implicit def bigint2biginteger(x: js.BigInt): BigInteger =
    new BigInteger(x.toString(10), 10)

  private implicit def bytevector2biginteger(x: ByteVector): BigInteger =
    new BigInteger(x.toHex, 16)

  private val zero = BigInteger.valueOf(0)
  private val one = BigInteger.valueOf(1)

  private[scoin] class PrivateKeyPlatform(value: ByteVector32) {
    def add(that: PrivateKey): PrivateKey = PrivateKey(
      ByteVector32(
        ByteVector.view(
          utils.privateAdd(
            value.bytes.toUint8Array,
            that.value.bytes.toUint8Array
          )
        )
      )
    )

    def subtract(that: PrivateKey): PrivateKey = PrivateKey(
      ByteVector32(
        ByteVector.view(
          utils.privateAdd(
            value.bytes.toUint8Array,
            utils.privateNegate(that.value.bytes.toUint8Array)
          )
        )
      )
    )

    def multiply(that: PrivateKey): PrivateKey =
      PrivateKey(
        ByteVector32(
          ByteVector.fromValidHex(
            utils
              .mod(
                js.BigInt(
                  bytevector2biginteger(value.bytes)
                    .multiply(bytevector2biginteger(that.value.bytes))
                    .toString(10)
                )
              )
              .toString(16)
          )
        )
      )

    def publicKey: PublicKey = PublicKey(
      ByteVector.view(Secp256k1.getPublicKey(value.bytes.toUint8Array, true))
    )
  }

  private[scoin] class PublicKeyPlatform(value: ByteVector) {
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
        point.add(that.asInstanceOf[PublicKeyPlatform].point).toRawBytes(true)
      )
    )

    def multiply(that: PrivateKey): PublicKey = PublicKey(
      ByteVector.view(point.multiply(that.value.toUint8Array).toRawBytes(true))
    )

    def toUncompressedBin: ByteVector = ByteVector.view(point.toRawBytes(false))
  }

  def sha1(input: ByteVector): ByteVector =
    ByteVector.fromValidHex(
      HashJS.sha1().update(input.toHex, "hex").digest("hex")
    )

  def sha256(input: ByteVector): ByteVector32 =
    ByteVector32(
      ByteVector.fromValidHex(
        HashJS.sha256().update(input.toHex, "hex").digest("hex")
      )
    )

  def sha512(input: ByteVector): ByteVector =
    ByteVector.fromValidHex(
      HashJS.sha512().update(input.toHex, "hex").digest("hex")
    )

  def hmac512(key: ByteVector, data: ByteVector): ByteVector =
    ByteVector.fromValidHex(
      HashJS
        .hmac(HashJS.sha512, key.toHex, "hex")
        .update(data.toHex, "hex")
        .digest("hex")
    )

  def hmac256(key: ByteVector, data: ByteVector): ByteVector32 =
    ByteVector32(
      ByteVector.fromValidHex(
        HashJS
          .hmac(HashJS.sha256, key.toHex, "hex")
          .update(data.toHex, "hex")
          .digest("hex")
      )
    )

  def ripemd160(input: ByteVector): ByteVector =
    ByteVector.fromValidHex(
      HashJS.ripemd160().update(input.toHex, "hex").digest("hex")
    )

  /** @param key
    *   serialized public key
    * @return
    *   true if the key is valid. This check is much more expensive than its lax
    *   version since here we check that the public key is a valid point on the
    *   secp256k1 curve
    */
  def isPubKeyValidStrict(key: ByteVector): Boolean = isPubKeyValidLax(key) &&
    Try(Point.fromHex(key.toUint8Array).assertValidity())
      .map(_ => true)
      .getOrElse(false)

  def compact2der(signature: ByteVector64): ByteVector = {
    val (r, s) = decodeSignatureCompact(signature)
    signatureToDER(r, s)
  }

  def verifySignature(
      data: Array[Byte],
      signature: Array[Byte],
      publicKey: PublicKey
  ): Boolean =
    Secp256k1.verify(
      ByteVector.view(signature).toUint8Array,
      ByteVector.view(data).toUint8Array,
      publicKey.value.toUint8Array
    )

  def sign(data: Array[Byte], privateKey: PrivateKey): ByteVector64 =
    ByteVector64(
      ByteVector.view(
        Secp256k1.signSync(
          ByteVector.view(data).toUint8Array,
          privateKey.value.bytes.toUint8Array,
          js.Dictionary(("der" -> false))
        )
      )
    )

  def signSchnorrImpl(
      data: ByteVector32,
      privateKey: PrivateKey,
      auxrand32: Option[ByteVector32]
  ): ByteVector64 = {
    ByteVector64(
      ByteVector.view(
        Secp256k1.schnorr.signSync(
          data.toUint8Array,
          privateKey.value.bytes.toUint8Array,
          auxrand32.map(_.toUint8Array).getOrElse(js.undefined)
        )
      )
    )
  }

  def verifySignatureSchnorrImpl(
      data: ByteVector32,
      signature: ByteVector64,
      publicKey: XOnlyPublicKey
  ): Boolean = {
    Secp256k1.schnorr.verifySync(
      signature.bytes.toUint8Array,
      data.toUint8Array,
      publicKey.value.toUint8Array
    )
  }

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
  ): PublicKey = PublicKey(
    ByteVector.view(
      Secp256k1.recoverPublicKey(
        message.toUint8Array,
        signature.bytes.toUint8Array,
        recoveryId,
        true
      )
    )
  )

  def chacha20(
      input: ByteVector,
      key: ByteVector,
      nonce: ByteVector
  ): ByteVector = {
    val c = ChaCha.chacha(
      Buffer.from(key.toUint8Array),
      Buffer.from(nonce.toUint8Array)
    )
    c.update(Buffer.from(key.toUint8Array))
    ByteVector.fromUint8Array(c.`final`().asInstanceOf[Uint8Array])
  }

  object ChaCha20Poly1305 {
    def encrypt(
        plaintext: ByteVector,
        key: ByteVector,
        nonce: ByteVector,
        aad: ByteVector
    ): ByteVector = {
      val c = ChaCha.createCipher(
        Buffer.from(key.toUint8Array),
        Buffer.from(nonce.toUint8Array)
      )
      c.setAAD(Buffer.from(aad.toUint8Array))
      c.update(Buffer.from(plaintext.toUint8Array))
      val encrypted =
        ByteVector.fromUint8Array(c.`final`().asInstanceOf[Uint8Array])
      val mac =
        ByteVector.fromUint8Array(c.getAuthTag().asInstanceOf[Uint8Array])
      encrypted ++ mac
    }

    def decrypt(
        ciphertext: ByteVector,
        key: ByteVector,
        nonce: ByteVector,
        aad: ByteVector
    ): ByteVector = {
      val c = ChaCha.createDecipher(
        Buffer.from(key.toUint8Array),
        Buffer.from(nonce.toUint8Array)
      )
      c.setAAD(Buffer.from(aad.toUint8Array))
      c.setAuthTag(Buffer.from(ciphertext.takeRight(16).toUint8Array))
      c.update(Buffer.from(ciphertext.dropRight(16).toUint8Array))
      ByteVector.fromUint8Array(c.`final`().asInstanceOf[Uint8Array])
    }
  }
}
