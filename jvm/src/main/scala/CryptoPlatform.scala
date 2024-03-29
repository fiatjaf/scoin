package scoin

import java.security.SecureRandom
import java.io.{ByteArrayInputStream, ByteArrayOutputStream}
import java.math.BigInteger
import fr.acinq.secp256k1.Secp256k1
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.asn1.{ASN1Integer, DERSequenceGenerator}
import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.digests.{
  RIPEMD160Digest,
  SHA1Digest,
  SHA256Digest,
  SHA512Digest
}
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.{ECDomainParameters, KeyParameter}
import org.bouncycastle.crypto.signers.{ECDSASigner, HMacDSAKCalculator}
import org.bouncycastle.math.ec.ECPoint
import scodec.bits.ByteVector

import ChaCha20Poly1305.{encrypt => c20p1305encrypt, decrypt => c20p1305decrypt}

private[scoin] trait CryptoPlatform {
  import Crypto._

  private val secureRandom = new SecureRandom
  def randomBytes(length: Int): ByteVector = {
    val buffer = new Array[Byte](length)
    secureRandom.nextBytes(buffer)
    ByteVector.view(buffer)
  }

  def G = PublicKey(ByteVector.view(curve.getG().getEncoded(true)))
  def N: BigInteger = curve.getN

  private val params = SECNamedCurves.getByName("secp256k1")
  private val curve = new ECDomainParameters(
    params.getCurve,
    params.getG,
    params.getN,
    params.getH
  )

  private val zero = BigInteger.valueOf(0)
  private val one = BigInteger.valueOf(1)
  lazy val nativeSecp256k1: Secp256k1 = Secp256k1.get()

  private def hash(digest: Digest)(input: ByteVector): ByteVector = {
    digest.update(input.toArray, 0, input.length.toInt)
    val out = new Array[Byte](digest.getDigestSize)
    digest.doFinal(out, 0)
    ByteVector.view(out)
  }

  def sha1 = hash(new SHA1Digest) _

  def sha256 = (x: ByteVector) => ByteVector32(hash(new SHA256Digest)(x))

  def sha512 = (x: ByteVector) => hash(new SHA512Digest)(x)

  def hmac512(key: ByteVector, data: ByteVector): ByteVector = {
    val mac = new HMac(new SHA512Digest())
    mac.init(new KeyParameter(key.toArray))
    mac.update(data.toArray, 0, data.length.toInt)
    val out = new Array[Byte](64)
    mac.doFinal(out, 0)
    ByteVector.view(out)
  }

  def hmac256(key: ByteVector, data: ByteVector): ByteVector32 = {
    val mac = new HMac(new SHA256Digest())
    mac.init(new KeyParameter(key.toArray))
    mac.update(data.toArray, 0, data.length.toInt)
    val out = new Array[Byte](32)
    mac.doFinal(out, 0)
    ByteVector32(ByteVector.view(out))
  }

  def ripemd160 = hash(new RIPEMD160Digest) _

  /** @param key
    *   serialized public key
    * @return
    *   true if the key is valid. This check is much more expensive than its lax
    *   version since here we check that the public key is a valid point on the
    *   secp256k1 curve
    */
  def isPubKeyValidStrict(key: ByteVector): Boolean =
    isPubKeyValidLax(key) &&
      nativeSecp256k1.pubkeyParse(key.toArray).length == 65

  def compact2der(signature: ByteVector64): ByteVector = {
    val r = new BigInteger(1, signature.take(32).toArray)
    val s = new BigInteger(1, signature.takeRight(32).toArray)
    val (r1, s1) = normalizeSignature(r, s)
    val bos = new ByteArrayOutputStream(73)
    val seq = new DERSequenceGenerator(bos)
    seq.addObject(new ASN1Integer(r1))
    seq.addObject(new ASN1Integer(s1))
    seq.close()
    ByteVector.view(bos.toByteArray)
  }

  def verifySignature(
      data: Array[Byte],
      signature: Array[Byte],
      publicKey: PublicKey
  ): Boolean =
    nativeSecp256k1.verify(
      signature,
      data,
      publicKey.value.toArray
    )

  /** This is the platform specific (jvm) signining function called by
    * Crypto.sign(..)
    *
    * @param data
    * @param privateKey
    * @return
    */
  def sign(data: Array[Byte], privateKey: PrivateKey): ByteVector64 =
    ByteVector64(
      ByteVector.view(nativeSecp256k1.sign(data, privateKey.value.toArray))
    )

  def signSchnorrImpl(
      data: ByteVector32,
      privateKey: PrivateKey,
      auxrand32: Option[ByteVector32]
  ): ByteVector64 = {
    ByteVector64(
      ByteVector.view(
        nativeSecp256k1.signSchnorr(
          data.toArray,
          privateKey.value.toArray,
          auxrand32.map(_.toArray).getOrElse(Array.empty)
        )
      )
    )
  }

  def verifySignatureSchnorrImpl(
      data: ByteVector32,
      signature: ByteVector64,
      publicKey: XOnlyPublicKey
  ): Boolean = {
    // note argument order nativeSecp256k1(sig, data, pub) which is different than ours
    nativeSecp256k1.verifySchnorr(
      signature.toArray,
      data.toArray,
      publicKey.value.toArray
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
  ): PublicKey = {
    val bin = nativeSecp256k1.ecdsaRecover(
      signature.toArray,
      message.toArray,
      recoveryId
    )
    PublicKey.fromBin(ByteVector.view(bin))
  }

  def chacha20(
      input: ByteVector,
      key: ByteVector,
      nonce: ByteVector
  ): ByteVector = ChaCha20.xor(input, key, nonce)

  object ChaCha20Poly1305 {
    def encrypt(
        plaintext: ByteVector,
        key: ByteVector,
        nonce: ByteVector,
        aad: ByteVector
    ): ByteVector = {
      val (payload, mac) = c20p1305encrypt(plaintext, key, nonce, aad)
      payload ++ mac
    }

    def decrypt(
        ciphertext: ByteVector,
        key: ByteVector,
        nonce: ByteVector,
        aad: ByteVector
    ): ByteVector = c20p1305decrypt(
      ciphertext.dropRight(16),
      key,
      nonce,
      aad,
      ciphertext.takeRight(16)
    )
  }
}
