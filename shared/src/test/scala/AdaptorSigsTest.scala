package scoin

import scoin._
import utest._
import scodec.bits._

object AdaptorSigsTest extends TestSuite {
  val tests = Tests {
    test("can calculate bip340 private nonce") {
      import Crypto._ 
      (0 to 100).foreach{i => 
        val priv = PrivateKey(randomBytes32())

        // normally the message to be signed is (the hash of) a bitcoin transaction
        val msg = randomBytes32() //sha256(ByteVector("abc".getBytes))

        // prepare a normal signature which will then be "tweaked"
        val sig = signSchnorr(msg, priv)

        // extract R, s from the signature
        val (pointR, s) =
          (XOnlyPublicKey(ByteVector32(sig.take(32))), sig.drop(32))
        val k = PrivateKey(calculateBip340nonce(msg, priv, None))

        assert((k.publicKey.xonly.value) == (pointR.value))
      }
    }

    test("can reconstruct schnorr sig") {
      // to do adaptor signatures we pretty much need to know the internals
      // of schnorr signatures, so endedup creating a `unsafeSignSchnorr` method
      import Crypto._, AdaptorSig._
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

    test("recover discrete log of tweakPoint") {
      // https://suredbits.com/schnorr-applications-scriptless-scripts/
      import Crypto._, AdaptorSig._

      val priv = PrivateKey(sha256(ByteVector("priv4".getBytes)))

      // normally the message to be signed is (the hash of) a bitcoin transaction
      val msg = sha256(ByteVector("msg4".getBytes))

      // a scalar value which is the discrete logarithm of the "tweakPoint"
      // Knowledge of this value is necessary in order to repair the adaptor
      // signature into a valid BIP340 schnorr signature.

      // here we are using the private key itself as the tweak
      val tweak = priv.value // using private key itself as tweak!

      // the point on the curve corresponding to this tweak value
      val tweakPoint = PrivateKey(tweak).publicKey

      val adaptorSig = computeSchnorrAdaptorSignatureForPoint(
        data = msg,
        privateKey = priv,
        tweakPoint = tweakPoint
      )
      // 97 bytes == (32 bytes, 32 bytes, 33 bytes) == (R',s',T)
      assert(adaptorSig.size == 97)

      // verify the adaptor signature "could be" repaired
      assert(verifySchnorrAdaptorSignature(adaptorSig, msg, priv.publicKey.xonly))

      // repair the signature using  our knowledge of the scalar tweak value
      val repairedSig = repairSchnorrAdaptorSignature(
        adaptorSig = adaptorSig,
        data = msg,
        scalarTweak = tweak
      )
      assert(verifySignatureSchnorr(repairedSig, msg, priv.publicKey.xonly))
      
      val t = extractScalar(adaptorSig,repairedSig)
      assert(t == tweak)
    }

    test("a bunch of random adaptor sigs") {
      import Crypto._, AdaptorSig._
      val num_trials = 150
      (0 until num_trials).foreach{ i =>
        //println(s"index $i started")
        val priv = PrivateKey(sha256(ByteVector(s"priv$i".getBytes)))
        val msg = sha256(ByteVector(s"msg$i".getBytes))
        val tweak = sha256(ByteVector(s"tweak$i".getBytes))
        val tweakPoint = PrivateKey(tweak).publicKey
        val adaptorSig = computeSchnorrAdaptorSignatureForPoint(
          data = msg,
          privateKey = priv,
          tweakPoint = tweakPoint
        )
        require(XOnlyPublicKey(ByteVector32(adaptorSig.take(32))) == PrivateKey(calculateBip340nonce(data = msg, privateKey = priv, auxrand32 = None)).publicKey.xonly, "R does not match")
        require(PublicKey(adaptorSig.drop(64)).value == tweakPoint.value, "tweakPoint does not match")
        assert(verifySchnorrAdaptorSignature(adaptorSig, msg, priv.publicKey.xonly))
        val repairedSig = repairSchnorrAdaptorSignature(
          adaptorSig = adaptorSig,
          data = msg,
          scalarTweak = tweak
        )
        assert(verifySignatureSchnorr(repairedSig, msg, priv.publicKey.xonly))

        val extractedScalar = extractScalar(adaptorSig, repairedSig)
        assert(extractedScalar == tweak)
        //println(s"index $i succeeded!")
        
      }
    }
  }
}
