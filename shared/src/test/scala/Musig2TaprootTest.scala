package scoin

import utest._
import scoin._
import Crypto._
import scodec.bits._

object Musig2TaprootTest extends TestSuite {
  val tests = Tests {
    test("musig2 with taproot - create and spend via keypath") {
      // GOAL: create a pay2tr output which is 2of2 (musig2)
      //       - fund the output
      //       - spend the output via keypath spend
      val alice_priv = PrivateKey(BigInt(21)) // super great secret choice, Alice.
      val alice_pub = alice_priv.publicKey

      val bob_priv = PrivateKey(BigInt(52)) // also really secure. Way to go Bob!
      val bob_pub = bob_priv.publicKey

      // create an aggregate public key (pointQ) in a KeyGenCtx
      // keygenctx.pointQ is the aggregate public key
      val keygenctx = Musig2.keyAgg(List(alice_pub,bob_pub))
      val pointQ = keygenctx.pointQ

      // construct the output public key for the taproot output
      val outputXOnlyPubKey = pointQ.xonly.outputKey(merkleRoot = None)

      // fund a pay2tr output locked to
      val fundingTx = Transaction(
        version = 2,
        txIn = List(
          TxIn.coinbase(OP_1 :: OP_1 :: Nil) // bogus coinbase
        ),
        txOut = List(
          TxOut(
            amount = Satoshi(1_000_000L),
            publicKeyScript = Script.pay2tr(outputXOnlyPubKey)
          )
        ),
        lockTime = 0L
      )

      // Alice and Bob agree to send the funds solely to Bob
      // Normally Bob would provide a fresh public key, but here
      // we just reuse his existing one.
      // 
      // Bob creates an unsigned spending transaction.
      val unsignedSpendingTx = Transaction(
        version = 2,
        txIn = List(
          TxIn(
            outPoint = OutPoint(fundingTx,0),
            signatureScript = ByteVector.empty,
            sequence = TxIn.SEQUENCE_FINAL,
            witness = ScriptWitness.empty
          )
        ),
        txOut = List(
          TxOut(
            amount = fundingTx.txOut(0).amount - Satoshi(5000), // 5000 sat fee
            publicKeyScript = Script.pay2tr(bob_pub.xonly.outputKey(merkleRoot = None)) // to Bob only
          )
        ),
        lockTime = 0L
      )

      // now we need to construct the message to be signed
      // sometimes people use `z` to represent the message which is constructed
      // by hashing the spending transaction in a special way
      val z = Transaction.hashForSigningSchnorr(
        tx = unsignedSpendingTx,
        inputIndex = 0,
        inputs = List(fundingTx.txOut(0)),
        sighashType = SIGHASH_DEFAULT, // (0x00),
        sigVersion = SigVersion.SIGVERSION_TAPROOT,
        codeSeparatorPos = 0xffffffffL
      )

      // Now Alice and Bob need to share their public nonce points.
      // It is IMPORTANT they each use fresh randomness for their nonce points.
      // Here we use terrible randomness for demonstration purposes.
      // Alice and Bob each run the `Musig2.nonceGen` algorithm and then exchange
      // their public nonces.
      val (alice_secnonce, alice_pubnonce) = Musig2.nonceGen(
        secretSigningKey = Some(alice_priv.value),
        pubKey = alice_pub,
        aggregateXOnlyPublicKey = Some(outputXOnlyPubKey),
        message = Some(z),
        extraIn = None,
        nextRand32 = ByteVector32.fromValidHex("01"*32) // not secure
      )

      // Note: other than the public key and fresh randomnesss,
      // the other fields are optional for nonce generation. Supplying them
      // just provides some "added protection" in case the available randomness
      // is not the best (think constrained hardware device).
      val (bob_secnonce, bob_pubnonce) = Musig2.nonceGen(
        secretSigningKey = Some(alice_priv.value),
        pubKey = bob_pub,
        aggregateXOnlyPublicKey = Some(outputXOnlyPubKey),
        message = Some(z.bytes),
        extraIn = None,
        nextRand32 = ByteVector32.fromValidHex("02"*32) // not secure
      )

      // combine their respective pubnonces
      val aggnonce = Musig2.nonceAgg(List(alice_pubnonce, bob_pubnonce))

      // Create a signing session context
      // The context can be re-created by either of Alice or Bob
      val ctx = Musig2.SessionCtx(
          aggNonce = aggnonce,
          numPubKeys = 2,
          pubKeys = List(alice_pub.value, bob_pub.value),
          numTweaks = 0, // default: no tweaks
          tweaks = List(), // default: no tweaks
          isXonlyTweak = List(), // default: no tweaks
          message = z // the (hash of) the spending transaction
      )

      // Alice and Bob each independently sign using the Musig2 signing algorithm.
      // The resulting partial signatures are 32-bytes each.
      val alice_psig = Musig2.sign(alice_secnonce,alice_priv,ctx)
      val bob_psig = Musig2.sign(bob_secnonce,bob_priv,ctx)

      // Combine the partial signatures into a complete, valid BIP340 signature.
      val sig = Musig2.partialSigAgg(List(alice_psig,bob_psig),ctx)

      // Update our transaction to include the signature in the witness.
      val signedTx = unsignedSpendingTx.updateWitness(0,ScriptWitness(List(sig)))

      // Verify that our spending transaction is valid. The below would throw
      // an exception if not.
      Transaction.correctlySpends(signedTx,List(fundingTx),ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS)
    }
  }
}