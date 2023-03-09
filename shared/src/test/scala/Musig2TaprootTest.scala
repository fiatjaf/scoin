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
      val alice_priv =
        PrivateKey(BigInt(21)) // super great secret choice, Alice.
      val alice_pub = alice_priv.publicKey

      val bob_priv =
        PrivateKey(BigInt(52)) // also really secure. Way to go Bob!
      val bob_pub = bob_priv.publicKey

      // create an aggregate public key (pointQ) in a KeyAggCtx
      // keyaggctx.pointQ is the aggregate public key
      val keyaggctx = Musig2.keyAgg(List(alice_pub, bob_pub))
      val pointQ = keyaggctx.pointQ

      // construct the output public key for the taproot output
      // since this is a keypath spend, we do not need to `.tapTweak`
      val outputXOnlyPubKey = pointQ.xonly

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
            outPoint = OutPoint(fundingTx, 0),
            signatureScript = ByteVector.empty,
            sequence = TxIn.SEQUENCE_FINAL,
            witness = ScriptWitness.empty
          )
        ),
        txOut = List(
          TxOut(
            amount = fundingTx.txOut(0).amount - Satoshi(5000), // 5000 sat fee
            // to Bob only
            publicKeyScript =
              Script.pay2tr(bob_pub.xonly.tapTweak(merkleRoot = None)._1)
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
        nextRand32 = ByteVector32.fromValidHex("01" * 32) // not secure
      )

      // Note: other than the public key and fresh randomnesss,
      // the other fields are optional for nonce generation. Supplying them
      // just provides some "added protection" in case the available randomness
      // is not the best (think constrained hardware device).
      val (bob_secnonce, bob_pubnonce) = Musig2.nonceGen(
        secretSigningKey = Some(bob_priv.value),
        pubKey = bob_pub,
        aggregateXOnlyPublicKey = Some(outputXOnlyPubKey),
        message = Some(z.bytes),
        extraIn = None,
        nextRand32 = ByteVector32.fromValidHex("02" * 32) // not secure
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
      val alice_psig = Musig2.sign(alice_secnonce, alice_priv, ctx)
      val bob_psig = Musig2.sign(bob_secnonce, bob_priv, ctx)

      // Combine the partial signatures into a complete, valid BIP340 signature.
      val sig = Musig2.partialSigAgg(List(alice_psig, bob_psig), ctx)

      // Update our transaction to include the signature in the witness.
      val signedTx =
        unsignedSpendingTx.updateWitness(0, ScriptWitness(List(sig)))

      // Verify that our spending transaction is valid. The below would throw
      // an exception if not.
      assert(
        Transaction
          .correctlySpends(
            signedTx,
            List(fundingTx),
            ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS
          )
          .isSuccess
      )
    }

    test("musig2 with taproot - adaptor sigs") {
      /**
        * GOAL: Bob gives a secret to Alice by repairing an adaptor
        *       signature and publishing the resulting valid musig2
        *       signature.
        */
      val alice_priv =
        PrivateKey(BigInt(21)) // super great secret choice, Alice.
      val alice_pub = alice_priv.publicKey

      val bob_priv =
        PrivateKey(BigInt(52)) // also really secure. Way to go Bob!
      val bob_pub = bob_priv.publicKey

      // the message we will musig2 sign and then build adaptor signatures for
      val msg = ByteVector32.fromValidHex("07"*32)

      // create an aggregate public key (pointQ) in a KeyAggCtx
      // keyaggctx.pointQ is the aggregate public key
      val keyaggctx = Musig2.keyAgg(List(alice_pub, bob_pub))
      val pointQ = keyaggctx.pointQ

      // Bob chooses the adaptor point `T` by choosing publishing secret `t`
      val t = PrivateKey(BigInt(42)) // the answer is always 42
      val pointT = t.publicKey.xonly

      val (alice_secnonce, alice_pubnonce) = Musig2.nonceGen(
        secretSigningKey = Some(alice_priv.value),
        pubKey = alice_pub,
        aggregateXOnlyPublicKey = Some(pointQ.xonly),
        message = Some(msg),
        extraIn = None,
        nextRand32 = ByteVector32.fromValidHex("01" * 32) // not secure
      )

      val (bob_secnonce, bob_pubnonce) = Musig2.nonceGen(
        secretSigningKey = Some(bob_priv.value),
        pubKey = bob_pub,
        aggregateXOnlyPublicKey = Some(pointQ.xonly),
        message = Some(msg),
        extraIn = None,
        nextRand32 = ByteVector32.fromValidHex("02" * 32) // not secure
      )

      // aggregate the public nonces
      val aggnonce = Musig2.nonceAgg(List(alice_pubnonce,bob_pubnonce))

      // create a signing context (Alice and Bob can each do independently)
      val ctx = Musig2.SessionCtx(
        aggNonce = aggnonce,
        numPubKeys = 2,
        pubKeys = Musig2.keySort(List(alice_pub,bob_pub)).map(_.value),
        numTweaks = 0,
        tweaks = List.empty,
        isXonlyTweak = List.empty,
        message = msg
      )

      // from: https://github.com/t-bast/lightning-docs/blob/master/schnorr.md#musig2-adaptor-signatures
      val pointRplusT = ctx.sessionValues(Some(pointT)).pointR + pointT.publicKey
      val alice_psig = Musig2.sign(
        secnonce = alice_secnonce,
        privateKey = alice_priv,
        ctx = ctx,
        adaptorPoint = Some(pointT)
      )
      // Alice's partial signature is the pair (alice_psig, pointRplusT).

      val bob_psig = Musig2.sign(
        secnonce = bob_secnonce,
        privateKey = bob_priv,
        ctx = ctx,
        adaptorPoint = Some(pointT)
      )
      // Bob's adaptor sig is the pair (bob_psig, pointR, pointT)

      // Alice can verify Bob's adaptor signature before sending him her
      // partial signature.
      val sagg = (Musig2.intModN(alice_psig) + Musig2.intModN(bob_psig)).mod(N)
      val Musig2.SessionValues(_,_,_,_,pointR,e) = ctx.sessionValues(Some(pointT))
      assert(
        (G*PrivateKey(sagg)) == (pointR + pointQ*PrivateKey(e))
      )
      // same assertion as above, but wrapped in a function (so we do not need
      // to remember the math!)
      assert(
        Musig2.verifyAdaptorSignature(
          verifier_psig = alice_psig,
          prover_psig = bob_psig,
          ctx = ctx,
          adaptorPointT = pointT
        )
      )

      // With the above check done, Alice can now send Bob her partial signature.
      // Bob can then repair her partial signature to create a valid BIP340
      // schnorr signature `sig`.
      val sigTheHardWay = ByteVector64(
        pointRplusT.xonly.value ++ (PrivateKey(sagg) + t).value
      )
      assert(verifySignatureSchnorr(sigTheHardWay,msg,pointQ.xonly))
      
      // repeat the above, but using the functions
      // notice how the message and aggregate pubkey do not need to be
      // provided -- they can be reconstructed from the `ctx`
      val sig = Musig2.repairAdaptorSignature(
          partialSigs = List(alice_psig, bob_psig),
          ctx = ctx,
          adaptorSecret = t.value,
          checkValid = true // if true, then verify the schnorr sig, or throw
      )

      // If Bob ever publishes `sig`, Alice can now easiy extract `t` from it.
      assert(
        Musig2.int(t.value) == (Musig2.intModN(sig.drop(32)) - sagg).mod(N)
      )
      val recoveredAdaptorSecret = Musig2.recoverAdaptorSecret(
        sig = sig,
        partialSigs = List(alice_psig, bob_psig)
      )
      assert(recoveredAdaptorSecret == t.value)
      // fin!
    }

    test("musig2 with taproot - create and spend via scriptpath") {
      /**
        * GOAL: construct a p2tr output which is spent via script path
        *       using musig2.
        */
      val alice_priv =
        PrivateKey(BigInt(21)) // super great secret choice, Alice.
      val alice_pub = alice_priv.publicKey

      val bob_priv =
        PrivateKey(BigInt(52)) // also really secure. Way to go Bob!
      val bob_pub = bob_priv.publicKey

      // create an aggregate public key (pointQ) in a KeyAggCtx
      // keyaggctx.pointQ is the aggregate public key
      val keyaggctx = Musig2.keyAgg(List(alice_pub, bob_pub))
      val pointQ = keyaggctx.pointQ

      // simple script that locks the output the the aggregate pubkey
      val script = OP_PUSHDATA(pointQ.xonly) :: OP_CHECKSIG :: Nil

      // simple script tree with a single element
      val scriptTree = ScriptTree.Leaf(
        ScriptLeaf(0, Script.write(script), Script.TAPROOT_LEAF_TAPSCRIPT)
      )

      val merkleRoot = scriptTree.hash

      // we choose an internal pubkey that does not have a corresponding private key:
      // our funding tx cannot only by spend through the script path, not the key path
      val internalPubKey = PublicKey.unspendable.xonly

      val (tweakedKey, parity) = internalPubKey.tapTweak(Some(merkleRoot))

      // funding tx sends to our tapscript
      val fundingTx = Transaction(
        version = 2,
        txIn = List.empty,
        txOut =
          List(TxOut(Satoshi(1000000), Script.pay2tr(tweakedKey))),
        lockTime = 0
      )

      // create an unsigned transaction
      val tmp = Transaction(
        version = 2,
        txIn = List(
          TxIn(
            OutPoint(fundingTx, 0),
            signatureScript = ByteVector.empty,
            TxIn.SEQUENCE_FINAL,
            witness = ScriptWitness.empty
          )
        ),
        txOut = List(
          TxOut(
            fundingTx.txOut(0).amount - Satoshi(5000),
            Script.pay2wpkh(bob_pub) // send the funds to Bob
          )
        ),
        lockTime = 0
      )

      val hash = Transaction.hashForSigningSchnorr(
        tmp,
        0,
        List(fundingTx.txOut(0)),
        SIGHASH_DEFAULT,
        SigVersion.SIGVERSION_TAPSCRIPT,
        annex = None,
        tapleafHash = Some(merkleRoot)
      )

      // do the musig2 signing
      val (alice_secnonce, alice_pubnonce) = Musig2.nonceGen(
        secretSigningKey = Some(alice_priv.value),
        pubKey = alice_pub,
        aggregateXOnlyPublicKey = Some(pointQ.xonly),
        message = Some(hash),
        extraIn = None,
        nextRand32 = ByteVector32.fromValidHex("01" * 32) // not secure
      )

      val (bob_secnonce, bob_pubnonce) = Musig2.nonceGen(
        secretSigningKey = Some(bob_priv.value),
        pubKey = bob_pub,
        aggregateXOnlyPublicKey = Some(pointQ.xonly),
        message = Some(hash),
        extraIn = None,
        nextRand32 = ByteVector32.fromValidHex("02" * 32) // not secure
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
        message = hash // the (hash of) the spending transaction
      )

      // Alice and Bob each independently sign using the Musig2 signing algorithm.
      // The resulting partial signatures are 32-bytes each.
      val alice_psig = Musig2.sign(alice_secnonce, alice_priv, ctx)
      val bob_psig = Musig2.sign(bob_secnonce, bob_priv, ctx)

      // Combine the partial signatures into a complete, valid BIP340 signature.
      val sig = Musig2.partialSigAgg(List(alice_psig, bob_psig), ctx)

      // Simple control block, no specific merkle hashes to provide.
      val controlBlock = ByteVector(
        (Script.TAPROOT_LEAF_TAPSCRIPT + (if (parity) 1 else 0)).toByte
      ) ++ internalPubKey.value

      // construct the final signed transaction
      val tx = tmp.updateWitness(
        0,
        ScriptWitness(
          List(sig, Script.write(script), controlBlock)
        )
      )
      
      assert(
        Transaction.correctlySpends(
          tx = tx,
          inputs = List(fundingTx),
          scriptFlags = ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS
        ).isSuccess
      )
    }
  }
}
