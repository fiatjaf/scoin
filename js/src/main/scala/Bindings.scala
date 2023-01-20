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
      js.native // note: it seems there is no such method in undelrying javascript library
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
    def multiply(scalar: js.BigInt): Point = js.native
    def toRawBytes(compressed: Boolean): Uint8Array = js.native
    def assertValidity(): Unit = js.native
  }

  @js.native
  object schnorr extends js.Object {
    def signSync(
        msg: Uint8Array,
        privateKey: Uint8Array,
        auxRandom: js.UndefOr[Uint8Array]
    ): Uint8Array = js.native

    def verifySync(sig: Uint8Array, msg: Uint8Array, pub: Uint8Array): Boolean =
      js.native
  }
}

object monkeyPatch {
  trait HmacSha256SyncFunctionType extends js.Function {
    def apply(key: Uint8Array, msgs: Uint8Array*): Uint8Array
  }

  def hmacSha256Sync(key: Uint8Array, msgs: Seq[Uint8Array]): Uint8Array = {
    var hmac = NobleHmac.create(nobleSha256, key)
    msgs.foreach { data =>
      hmac = hmac.update(data)
    }
    hmac.digest()
  }

  trait Sha256SyncFunctionType extends js.Function {
    def apply(msgs: Uint8Array*): Uint8Array
  }

  def init(): Unit = {

    Secp256k1.utils.asInstanceOf[js.Dynamic].hmacSha256Sync = ({ (key, msgs) =>
      hmacSha256Sync(key, msgs)
    }: HmacSha256SyncFunctionType)

    Secp256k1.utils.asInstanceOf[js.Dynamic].sha256Sync = ({ (msgs) =>
      Crypto
        .sha256(ByteVector.concat(msgs.map(ByteVector.view(_))))
        .toUint8Array
    }: Sha256SyncFunctionType)
  }
}

@js.native
@JSImport("@noble/hashes/sha256", "sha256")
object nobleSha256 extends js.Object {
  def apply(bytes: Uint8Array): Uint8Array = js.native
}

@js.native
@JSImport("@noble/hashes/sha1", "sha1")
object nobleSha1 extends js.Object {
  def apply(bytes: Uint8Array): Uint8Array = js.native
}

@js.native
@JSImport("@noble/hashes/sha512", "sha512")
object nobleSha512 extends js.Object {
  def apply(bytes: Uint8Array): Uint8Array = js.native
}

@js.native
@JSImport("@noble/hashes/ripemd160", "ripemd160")
object nobleRipeMd160 extends js.Object {
  def apply(bytes: Uint8Array): Uint8Array = js.native
}

@js.native
@JSImport("@noble/hashes/hmac", "hmac")
object NobleHmac extends js.Object {
  def create(hash: js.Object, key: Uint8Array): Hmac = js.native
}

@js.native
trait Hmac extends js.Object {
  def update(data: Uint8Array): Hmac = js.native
  def digest(): Uint8Array = js.native
}

@js.native
@JSImport("@stablelib/chacha", "streamXOR")
object chachaStream extends js.Object {
  def apply(
      key: Uint8Array,
      nonce: Uint8Array,
      src: Uint8Array,
      dst: Uint8Array
  ): Uint8Array =
    js.native
}

@js.native
@JSImport("@stablelib/chacha20poly1305", "ChaCha20Poly1305")
class ChaCha20Poly1305Sealer(key: Uint8Array) extends js.Object {
  def seal(
      nonce: Uint8Array,
      plaintext: Uint8Array,
      associatedData: Uint8Array
  ): Uint8Array = js.native
  def open(
      nonce: Uint8Array,
      ciphertext: Uint8Array,
      associatedData: Uint8Array
  ): js.UndefOr[Uint8Array] = js.native
}
