package scoin.ln

import scodec.bits.ByteVector
import scoin.{ByteVector32, PublicKey, PrivateKey, Crypto}

object Generators {
  def fixSize(data: ByteVector): ByteVector32 = data.length match {
    case 32                    => ByteVector32(data)
    case length if length < 32 => ByteVector32(data.padLeft(32))
  }

  def perCommitSecret(seed: ByteVector32, index: Long): PrivateKey = PrivateKey(
    ShaChain.shaChainFromSeed(seed, 0xffffffffffffL - index)
  )

  def perCommitPoint(seed: ByteVector32, index: Long): PublicKey =
    perCommitSecret(seed, index).publicKey

  def derivePrivKey(
      secret: PrivateKey,
      perCommitPoint: PublicKey
  ): PrivateKey = {
    // secretkey = basepoint-secret + SHA256(per-commitment-point || basepoint)
    secret.add(
      PrivateKey(Crypto.sha256(perCommitPoint.value ++ secret.publicKey.value))
    )
  }

  def derivePubKey(
      basePoint: PublicKey,
      perCommitPoint: PublicKey
  ): PublicKey = {
    // pubkey = basepoint + SHA256(per-commitment-point || basepoint)*G
    val a = PrivateKey(Crypto.sha256(perCommitPoint.value ++ basePoint.value))
    basePoint.add(a.publicKey)
  }

  def revocationPubKey(
      basePoint: PublicKey,
      perCommitPoint: PublicKey
  ): PublicKey = {
    val a = PrivateKey(Crypto.sha256(basePoint.value ++ perCommitPoint.value))
    val b = PrivateKey(Crypto.sha256(perCommitPoint.value ++ basePoint.value))
    basePoint.multiply(a).add(perCommitPoint.multiply(b))
  }

  def revocationPrivKey(
      secret: PrivateKey,
      perCommitSecret: PrivateKey
  ): PrivateKey = {
    val a = PrivateKey(
      Crypto.sha256(secret.publicKey.value ++ perCommitSecret.publicKey.value)
    )
    val b = PrivateKey(
      Crypto.sha256(perCommitSecret.publicKey.value ++ secret.publicKey.value)
    )
    secret.multiply(a).add(perCommitSecret.multiply(b))
  }
}
