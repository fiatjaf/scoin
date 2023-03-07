package scoin

import scoin._
import utest._
import scodec.bits._

object AdaptorSigsTest extends TestSuite {
  val tests = Tests {
    test("can calculate bip340 private nonce") {
      import Crypto._
      val priv = PrivateKey(
        ByteVector32.fromValidHex(
          "67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530"
        )
      )

      // normally the message to be signed is (the hash of) a bitcoin transaction
      val msg = sha256(ByteVector("abc".getBytes))

      // prepare a normal signature which will then be "tweaked"
      val sig = signSchnorr(msg, priv)

      // extract R, s from the signature
      val (pointR, s) =
        (XOnlyPublicKey(ByteVector32(sig.take(32))), sig.drop(32))
      val k = PrivateKey(calculateBip340nonce(msg, priv, None))

      assert((k.publicKey.xonly.value) == (pointR.value))
    }

    test("can reconstruct schnorr sig") {
      // to do adaptor signatures we pretty much need to know the internals
      // of schnorr signatures, so endedup creating a `unsafeSignSchnorr` method
      import Crypto._
      val priv = PrivateKey(
        ByteVector32.fromValidHex(
          "67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530"
        )
      )
      val msg = sha256(ByteVector("abc".getBytes))
      val ourSig = unsafeSignSchnorr(msg, priv, None)
      // check that oursig is same as calculated by proper libraries
      assert(ourSig == signSchnorr(msg, priv))
      // check that our unsafe verification method also works
      assert(unsafeVerifySignatureSchnorr(ourSig, msg, priv.publicKey.xonly))
    }

    test("create and verify adaptor sig") {
      // https://suredbits.com/schnorr-applications-scriptless-scripts/
      import Crypto._

      val priv = PrivateKey(
        ByteVector32.fromValidHex(
          "67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530"
        )
      )

      // normally the message to be signed is (the hash of) a bitcoin transaction
      val msg = sha256(ByteVector("abc".getBytes))

      // a scalar value which is the discrete logarithm of the "tweakPoint"
      // Knowledge of this value is necessary in order to repair the adaptor
      // signature into a valid BIP340 schnorr signature.
      val tweak = sha256(ByteVector("efg".getBytes))

      // the point on the curve corresponding to this tweak value
      val tweakPoint = PrivateKey(tweak).publicKey

      val adaptorSig = computeSchnorrAdaptorSignatureForPoint(
        data = msg,
        privateKey = priv,
        tweakPoint = tweakPoint
      )
      assert(adaptorSig.size == 96) // 32-bytes for each of (R',s',T)

      // verify the adaptor signature "could be" repaired
      assert(verifySchnorrAdaptorSignature(adaptorSig, msg, priv.publicKey))

      // repair the signature using  our knowledge of the scalar tweak value
      val repairedSig = repairSchnorrAdaptorSignature(
        adaptorSig = adaptorSig,
        data = msg,
        publicKey = priv.publicKey,
        scalarTweak = tweak
      )
      assert(verifySignatureSchnorr(repairedSig, msg, priv.publicKey.xonly))
    }

    test("adaptor signature deniability") {
      import Crypto._

      val priv = PrivateKey(
        ByteVector32.fromValidHex(
          "67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530"
        )
      )

      // normally the message to be signed is (the hash of) a bitcoin transaction
      val data = sha256(ByteVector("abc".getBytes))

      // create normal signature
      val sig = signSchnorr(data, priv, auxrand32 = None)

      // a scalar value which is the discrete logarithm of the "tweakPoint"
      // Knowledge of this value is necessary in order to repair the adaptor
      // signature into a valid BIP340 schnorr signature.
      val tweak = sha256(ByteVector("efg".getBytes))

      // turn the original signature into an adaptor signature
      // notice how we did not need the signer's private key to do this,
      // so this demonstrates a deniability property of adaptor signatures
      // anybody can make them! (if you have a valid signature to start with first)
      val adaptorSig = tweakSchnorrSignatureWithScalar(sig, tweak)

      val repairedSig = repairSchnorrAdaptorSignature(
        adaptorSig,
        data,
        priv.publicKey,
        tweak
      )
      // repaired signature is valid
      assert(verifySignatureSchnorr(repairedSig, data, priv.publicKey.xonly))

      // repaired signature is the same as the original
      assert(repairedSig == sig)
    }
  }
}
