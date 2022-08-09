package scoin

import java.io.{ByteArrayInputStream, ByteArrayOutputStream}
import java.math.BigInteger
import java.security.SecureRandom
import scala.util.Try
import scala.language.implicitConversions
import scala.scalajs.js
import scala.scalajs.js.annotation.JSGlobal
import scala.scalajs.js.typedarray.Uint8Array
import scodec.bits.ByteVector

private[scoin] trait CryptoPlatform {
  import Crypto._

  private val secureRandom = new SecureRandom
  def randomBytes(length: Int): ByteVector = {
    val buffer = new Array[Byte](length)
    secureRandom.nextBytes(buffer)
    ByteVector.view(buffer)
  }

  def G = PublicKey(
    ByteVector.view(new Point(Curve.Gx, Curve.Gy).toRawBytes(true))
  )
  def N = bigint2biginteger(Curve.n)

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
          Secp256k1Utils.privateAdd(
            value.bytes.toUint8Array,
            that.value.bytes.toUint8Array
          )
        )
      )
    )

    def subtract(that: PrivateKey): PrivateKey = PrivateKey(
      ByteVector32(
        ByteVector.view(
          Secp256k1Utils.privateAdd(
            value.bytes.toUint8Array,
            Secp256k1Utils.privateNegate(that.value.bytes.toUint8Array)
          )
        )
      )
    )

    def multiply(that: PrivateKey): PrivateKey =
      PrivateKey(
        ByteVector32(
          ByteVector.fromValidHex(
            Secp256k1Utils
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
      ByteVector.view(Secp256k1.getPublicKey(value.bytes.toUint8Array))
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
          Secp256k1Utils.pointAddScalar(
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
}

@js.native
@JSGlobal
object Secp256k1 extends js.Object {
  def getPublicKey(
      privateKey: Uint8Array,
      compressed: Boolean = true
  ): Uint8Array = js.native
  def signSync(
      msgHash: Uint8Array,
      privateKey: Uint8Array,
      options: js.Dictionary[Boolean]
  ): Uint8Array = js.native
  def verify(
      sig: Uint8Array,
      msgHash: Uint8Array,
      publicKey: Uint8Array
  ): Boolean =
    js.native
  def recoverPublicKey(
      msgHash: Uint8Array,
      sig: Uint8Array,
      rec: Integer,
      compressed: Boolean
  ): Uint8Array = js.native
}

@js.native
@JSGlobal
object Curve extends js.Object {
  def Gx: js.BigInt = js.native
  def Gy: js.BigInt = js.native
  def n: js.BigInt = js.native
}

@js.native
@JSGlobal
object Point extends js.Object {
  def fromHex(bytes: Uint8Array): Point = js.native
}

@js.native
@JSGlobal
class Point(x: js.BigInt, y: js.BigInt) extends js.Object {
  def negate(): Point = js.native
  def add(point: Point): Point = js.native
  def subtract(point: Point): Point = js.native
  def multiply(scalar: Uint8Array): Point = js.native
  def toRawBytes(compressed: Boolean): Uint8Array = js.native
  def assertValidity(): Unit = js.native
}

@js.native
@JSGlobal
object Secp256k1Utils extends js.Object {
  def privateNegate(privateKey: Uint8Array): Uint8Array = js.native
  def privateAdd(privateKey: Uint8Array, tweak: Uint8Array): Uint8Array =
    js.native
  def pointAddScalar(point: Uint8Array, tweak: Uint8Array): Uint8Array =
    js.native
  def mod(number: js.BigInt): js.BigInt = js.native
}

object monkeyPatch {
  def sha256Sync(msg: Uint8Array): Uint8Array =
    ByteVector
      .fromValidHex(
        HashJS.sha256().update(ByteVector.view(msg).toHex, "hex").digest("hex")
      )
      .toUint8Array

  def hmacSha256Sync(key: Uint8Array, msg: Uint8Array): Uint8Array =
    ByteVector
      .fromValidHex(
        HashJS
          .hmac(HashJS.sha256, ByteVector.view(key).toHex, "hex")
          .update(ByteVector.view(msg).toHex, "hex")
          .digest("hex")
      )
      .toUint8Array

  Secp256k1Utils.asInstanceOf[js.Dynamic].sha256Sync = sha256Sync
  Secp256k1Utils.asInstanceOf[js.Dynamic].hmacSha256Sync = hmacSha256Sync
}

@js.native
@JSGlobal
object HashJS extends js.Object {
  def sha1(): Hash = js.native
  def sha256(): Hash = js.native
  def sha512(): Hash = js.native
  def ripemd160(): Hash = js.native
  def hmac(hash: () => Hash, key: String, enc: String): Hash = js.native
}

@js.native
trait Hash extends js.Object {
  def update(msg: String, enc: String): Hash = js.native
  def digest(enc: String): String = js.native
}
