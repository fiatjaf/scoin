package scoin

import scodec.bits.ByteVector

private[scoin] class PrivateKeyPlatform(value: ByteVector32) {
  import Crypto._

  def add(that: PrivateKey): PrivateKey =
    PrivateKey(
      ByteVector32(
        ByteVector.view(
          nativeSecp256k1.privKeyTweakAdd(value.toArray, that.value.toArray)
        )
      )
    )

  def subtract(that: PrivateKey): PrivateKey =
    PrivateKey(
      ByteVector32(
        ByteVector.view(
          nativeSecp256k1.privKeyTweakAdd(
            value.toArray,
            nativeSecp256k1.privKeyNegate(that.value.toArray)
          )
        )
      )
    )

  def multiply(that: PrivateKey): PrivateKey =
    PrivateKey(
      ByteVector32(
        ByteVector.view(
          nativeSecp256k1.privKeyTweakMul(value.toArray, that.value.toArray)
        )
      )
    )

  def publicKey: PublicKey =
    PublicKey.fromBin(
      ByteVector.view(nativeSecp256k1.pubkeyCreate(value.toArray))
    )
}
