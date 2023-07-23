package scoin

import Crypto._
import scodec.bits.ByteVector

object AdaptorSig {

 /** Tweak an otherwise valid BIP340 signature with a curve point `tweakPoint`.
    * The result is an "Adaptor Signature". Somebody with knowledge of the
    * discrete logarithm (the private key) for `tweakPoint` will be able to
    * repair the adaptor signature to reconstruct a valid BIP340 signature. See:
    * BIP340 https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki See:
    * https://suredbits.com/schnorr-applications-scriptless-scripts/
    * and: https://github.com/t-bast/lightning-docs/blob/master/schnorr.md#adaptor-signatures
    *
    * @param data
    * @param privateKey
    *   private key used for signing
    * @param tweakPoint
    *   the curve point by which to "tweak" the signature
    * @return
    *   (R,s,T) as a 97-byte ByteVector
    */
  def computeSchnorrAdaptorSignatureForPoint(
      data: ByteVector32,
      privateKey: PrivateKey,
      tweakPoint: PublicKey
  ): ByteVector = {
    val r = PrivateKey(calculateBip340nonce(data, privateKey, None))
    val pointR = r.publicKey
    val pointRprime = pointR + tweakPoint
    //require(pointRprime.isEven, "(R + T) must be even for adaptor signature to verify properly")
    val pointP = privateKey.publicKey
    val e = calculateBip340challenge(
      data.bytes,
      pointRprime.xonly,
      pointP.xonly
    )
    // negate the private key for signing if necessary
    val d = if(pointP.isOdd) privateKey.negate else privateKey
    // negate r if (R + T) is odd
    val s = ((if(pointRprime.isOdd) r.negate else r) + (PrivateKey(e) * d))
    pointR.xonly.value ++ s.value ++ tweakPoint.value
  }

  /** Verify an "Adaptor Signature." If verification is successful and the
    * verifier knows the discrete logarithm (private key) for the `tweakPoint`,
    * then verifier will be able to repair the adaptor signature into a complete
    * and valid BIP340 schnorr signature by calling
    * `repairSchnorrAdaptorSignature`. See: BIP340
    * https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki See:
    * https://suredbits.com/schnorr-applications-scriptless-scripts/
    *
    * @param adaptorSig
    *   a 97-byte `ByteVector` `(R,s,T)` where `R` and `s` are 32-bytes,
    *   and `T` is a 33-byte compressed public key.
    *   `e = H(R + T || P || m)`
    *   `if R == R' = s*G - e*P, the adaptorSig is valid
    * @param data
    *   the message which is signed (usually a hash of a bitcoin transaction)
    * @param publicKey
    *   the public key of the signer
    * @return
    */
  def verifySchnorrAdaptorSignature(
      adaptorSig: ByteVector,
      data: ByteVector32,
      xonlyPublicKey: XOnlyPublicKey
  ): Boolean = {
    val pointR = XOnlyPublicKey(ByteVector32(adaptorSig.take(32)))
    val s = PrivateKey(ByteVector32(adaptorSig.drop(32).take(32)))
    val tweakPoint = PublicKey(adaptorSig.drop(64))
    val challenge = calculateBip340challenge(
      data,
      (pointR.publicKey + tweakPoint).xonly,
      xonlyPublicKey
    )
    val pointRprime = (G * s) - (xonlyPublicKey.publicKey * PrivateKey(challenge))
    pointR.publicKey.xonly == pointRprime.xonly
  }

  /** Repair an "Adaptor Signature" using knowledge of the discrete logarithm of
    * the `tweakPoint`. Note, this does not first check whether the adaptor
    * signature is valid. For that you should first call
    * `verifySchnorrAdaptorSignature`. See: BIP340
    * https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki See:
    * https://suredbits.com/schnorr-applications-scriptless-scripts/
    *
    * @param adaptorSig
    *   a 97-byte `ByteVector` `(R,s,T)` where `R` and `s` are 32-bytes,
    *   and `T` is a 33-byte compressed public key.
    * @param data
    *   the message which is signed (usually a hash of a bitcoin transaction)
    * @param publicKey
    *   the public key of the signer
    * @param scalarTweak
    *   the discrete logarithm of the `tweakPoint` (`scalarTweak*G ==
    *   tweakPoint`)
    * @return
    */
  def repairSchnorrAdaptorSignature(
      adaptorSig: ByteVector,
      data: ByteVector32,
      scalarTweak: ByteVector32
  ): ByteVector64 = {
    val pointR = XOnlyPublicKey(ByteVector32(adaptorSig.take(32)))
    val s = PrivateKey(ByteVector32(adaptorSig.drop(32).take(32)))
    val tweakPoint = PublicKey(adaptorSig.drop(64))
    val pointRprime = pointR.publicKey + tweakPoint
    // negate scalarTweak if (R + T) is odd
    val t = if(pointRprime.isOdd) PrivateKey(scalarTweak).negate else PrivateKey(scalarTweak)
    val sPrime = (s + t)
    ByteVector64(pointRprime.xonly.value ++ sPrime.value)
  }
  
  /**
    * Extract the discrete log of the adaptor point T given
    * an adaptor signaure (R,s,T) and repaired signature (R',s').
    * 
    * @param adaptorSig
    * @param repairedSig
    * @return
    */
  def extractScalar( 
    adaptorSig: ByteVector, 
    repairedSig: ByteVector64
  ): ByteVector32 = {
    val pointR = XOnlyPublicKey(ByteVector32(adaptorSig.take(32)))
    val s = PrivateKey(ByteVector32(adaptorSig.drop(32).take(32)))
    val tweakPoint = PublicKey(adaptorSig.drop(64))
    val pointRprime = pointR.publicKey + tweakPoint
    val sPrime = PrivateKey(ByteVector32(repairedSig.drop(32)))
    // negate the extracted value if (R + T) is odd
    if(pointRprime.isOdd)
      (sPrime - s).negate.value
    else
      (sPrime - s).value
  }
}