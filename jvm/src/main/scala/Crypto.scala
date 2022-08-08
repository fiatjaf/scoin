package scoin

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

trait CryptoPlatform {
  import Crypto._

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
  private lazy val nativeSecp256k1: Secp256k1 = Secp256k1.get()

  private[scoin] class PrivateKeyPlatform(value: ByteVector32) {
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

  private[scoin] class PublicKeyPlatform(value: ByteVector) {
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

  private def hash(digest: Digest)(input: ByteVector): ByteVector = {
    digest.update(input.toArray, 0, input.length.toInt)
    val out = new Array[Byte](digest.getDigestSize)
    digest.doFinal(out, 0)
    ByteVector.view(out)
  }

  def sha1 = hash(new SHA1Digest) _

  def sha256 = (x: ByteVector) => ByteVector32(hash(new SHA256Digest)(x))

  def hmac512(key: ByteVector, data: ByteVector): ByteVector = {
    val mac = new HMac(new SHA512Digest())
    mac.init(new KeyParameter(key.toArray))
    mac.update(data.toArray, 0, data.length.toInt)
    val out = new Array[Byte](64)
    mac.doFinal(out, 0)
    ByteVector.view(out)
  }

  def hmac256(key: ByteVector, data: ByteVector): ByteVector = {
    val mac = new HMac(new SHA256Digest())
    mac.init(new KeyParameter(key.toArray))
    mac.update(data.toArray, 0, data.length.toInt)
    val out = new Array[Byte](32)
    mac.doFinal(out, 0)
    ByteVector.view(out)
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

  def sign(data: Array[Byte], privateKey: PrivateKey): ByteVector64 =
    ByteVector64(
      ByteVector.view(nativeSecp256k1.sign(data, privateKey.value.toArray))
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
  ): PublicKey = {
    val bin = nativeSecp256k1.ecdsaRecover(
      signature.toArray,
      message.toArray,
      recoveryId
    )
    PublicKey.fromBin(ByteVector.view(bin))
  }

  private[this] def recoverPoint(x: BigInteger): (PublicKey, PublicKey) = {
    val x1 = curve.getCurve.fromBigInteger(x)
    val square = x1
      .square()
      .add(curve.getCurve.getA)
      .multiply(x1)
      .add(curve.getCurve.getB)
    val y1 = square.sqrt()
    val y2 = y1.negate()
    val R1 = curve.getCurve
      .createPoint(x1.toBigInteger, y1.toBigInteger)
      .normalize()
    val R2 = curve.getCurve
      .createPoint(x1.toBigInteger, y2.toBigInteger)
      .normalize()
    if (y1.testBitZero())
      (
        PublicKey(ByteVector.view(R2.getEncoded(true))),
        PublicKey(ByteVector.view(R1.getEncoded(true)))
      )
    else
      (
        PublicKey(ByteVector.view(R1.getEncoded(true))),
        PublicKey(ByteVector.view(R2.getEncoded(true)))
      )
  }

  def recoverPublicKey(
      signature: ByteVector64,
      message: ByteVector
  ): (PublicKey, PublicKey) = {
    val (r, s) = decodeSignatureCompact(signature)
    val m = new BigInteger(1, message.toArray)

    val (p1, p2) = recoverPoint(r)
    val Q1 = (p1
      .multiply(PrivateKey(s))
      .subtract(
        PublicKey(ByteVector.view(curve.getG.multiply(m).getEncoded(true)))
      ))
      .multiply(PrivateKey(r.modInverse(curve.getN)))
    val Q2 = (p2
      .multiply(PrivateKey(s))
      .subtract(
        PublicKey(ByteVector.view(curve.getG.multiply(m).getEncoded(true)))
      ))
      .multiply(PrivateKey(r.modInverse(curve.getN)))

    (Q1, Q2)
  }
}
