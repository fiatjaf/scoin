package scoin

import scala.scalajs.js
import scala.scalajs.js.annotation.JSImport
import scala.scalajs.js.typedarray.Uint8Array
import scodec.bits.ByteVector

@js.native
@JSImport("@noble/secp256k1", JSImport.Namespace)
object Secp256k1 extends js.Object {
  def getPublicKey(
      privateKey: Uint8Array,
      compressed: Boolean
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

  @js.native
  object utils extends js.Object {
    def privateNegate(privateKey: Uint8Array): Uint8Array = js.native
    def privateAdd(privateKey: Uint8Array, tweak: Uint8Array): Uint8Array =
      js.native
    def pointAddScalar(point: Uint8Array, tweak: Uint8Array): Uint8Array =
      js.native
    def mod(number: js.BigInt): js.BigInt = js.native
  }

  @js.native
  object CURVE extends js.Object {
    def Gx: js.BigInt = js.native
    def Gy: js.BigInt = js.native
    def n: js.BigInt = js.native
  }

  @js.native
  object Point extends js.Object {
    def fromHex(bytes: Uint8Array): Point = js.native
  }

  @js.native
  class Point(x: js.BigInt, y: js.BigInt) extends js.Object {
    def negate(): Point = js.native
    def add(point: Point): Point = js.native
    def subtract(point: Point): Point = js.native
    def multiply(scalar: Uint8Array): Point = js.native
    def toRawBytes(compressed: Boolean): Uint8Array = js.native
    def assertValidity(): Unit = js.native
  }

  @js.native
  object schnorr extends js.Object {
    def signSync(msg: Uint8Array, privateKey: Uint8Array, auxRandom: Uint8Array = null): Uint8Array
      = js.native

    def verifySync(sig: Uint8Array, msg: Uint8Array, pub: Uint8Array): Boolean
      = js.native
  }
}

object monkeyPatch {
  trait HmacSha256SyncFunctionType extends js.Function {
    def apply(key: Uint8Array, msgs: Uint8Array*): Uint8Array
  }

  def hmacSha256Sync(key: Uint8Array, msgs: Seq[Uint8Array]): Uint8Array = {
    ByteVector
      .fromValidHex(
        HashJS
          .hmac(HashJS.sha256, ByteVector.view(key).toHex, "hex")
          .update(
            ByteVector
              .concat(msgs.map(ByteVector.view(_)))
              .toHex,
            "hex"
          )
          .digest("hex")
      )
      .toUint8Array
  }

  trait Sha256SyncFunctionType extends js.Function {
    def apply(msgs: Uint8Array*):Uint8Array
  }

  def init(): Unit = {

    Secp256k1.utils.asInstanceOf[js.Dynamic].hmacSha256Sync = ({ (key, msgs) =>
      hmacSha256Sync(key, msgs)
    }: HmacSha256SyncFunctionType)

    Secp256k1.utils.asInstanceOf[js.Dynamic].sha256Sync = ({ (msgs) =>
      Crypto.sha256(ByteVector.concat(msgs.map(ByteVector.view(_)))).toUint8Array
    }: Sha256SyncFunctionType)
  }
}

@js.native
@JSImport("hash.js", JSImport.Default)
object HashJS extends js.Object {
  @js.native
  object sha1 extends js.Object with HashProvider {
    def apply(): Hash = js.native
  }

  @js.native
  object sha256 extends js.Object with HashProvider {
    def apply(): Hash = js.native
  }

  @js.native
  object sha512 extends js.Object with HashProvider {
    def apply(): Hash = js.native
  }

  @js.native
  object ripemd160 extends js.Object with HashProvider {
    def apply(): Hash = js.native
  }

  def hmac(hash: HashProvider, key: String, enc: String): Hash = js.native
}

@js.native
trait HashProvider extends js.Object {
  def apply(): Hash
  val blockSize: Int = js.native
  val outSize: Int = js.native
  val hmacStrength: Int = js.native
  val padLength: Int = js.native
}

@js.native
trait Hash extends js.Object {
  def update(msg: String, enc: String): Hash = js.native
  def digest(enc: String): String = js.native
}

@js.native
@JSImport("chacha", JSImport.Default)
object ChaCha extends js.Object {
  def chacha(key: NodeBuffer, nonce: NodeBuffer): NodeCipherBase = js.native
  def createCipher(key: NodeBuffer, nonce: NodeBuffer): NodeCipher = js.native
  def createDecipher(key: NodeBuffer, nonce: NodeBuffer): NodeDecipher =
    js.native
}

@js.native
trait NodeCipherBase extends js.Object {
  def update(data: NodeBuffer): Unit = js.native
  def `final`(): NodeBuffer = js.native
}

@js.native
trait NodeCipher extends NodeCipherBase {
  def setAAD(aad: NodeBuffer): Unit = js.native
  def getAuthTag(): NodeBuffer = js.native
}

@js.native
trait NodeDecipher extends NodeCipherBase {
  def setAAD(aad: NodeBuffer): Unit = js.native
  def setAuthTag(tag: NodeBuffer): Unit = js.native
}

@js.native
@JSImport("buffer", JSImport.Default)
object Buffer extends js.Object {
  def from(bytes: Uint8Array): NodeBuffer = js.native
}

@js.native
trait NodeBuffer extends js.Object
