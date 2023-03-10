package scoin

import scodec.bits.ByteVector

private[scoin] class PublicKeyPlatform(value: ByteVector) {
  import Crypto._

  def add(that: PublicKey): PublicKey =
    PublicKey.fromBin(
      ByteVector.view(
        nativeSecp256k1.pubKeyCombine(
          Array(value.toArray, that.value.toArray)
        )
      )
    )

  def add(that: PrivateKey): PublicKey =
    PublicKey.fromBin(
      ByteVector.view(
        nativeSecp256k1.privKeyTweakAdd(value.toArray, that.value.toArray)
      )
    )

  def subtract(that: PublicKey): PublicKey =
    PublicKey.fromBin(
      ByteVector.view(
        nativeSecp256k1.pubKeyCombine(
          Array(
            value.toArray,
            nativeSecp256k1.pubKeyNegate(that.value.toArray)
          )
        )
      )
    )

  def multiply(that: PrivateKey): PublicKey =
    PublicKey.fromBin(
      ByteVector.view(
        nativeSecp256k1.pubKeyTweakMul(value.toArray, that.value.toArray)
      )
    )

  def toUncompressedBin: ByteVector =
    ByteVector.view(nativeSecp256k1.pubkeyParse(value.toArray))
}
