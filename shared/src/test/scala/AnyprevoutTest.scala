package scoin

import scoin._
import utest._
import scodec.bits._
import scoin.DeterministicWallet
import scoin.DeterministicWallet.KeyPath
import scoin.Crypto.XOnlyPublicKey
import scoin.Crypto.PrivateKey
import scoin.Crypto.PublicKey
import scala.util.Failure
import scala.util.Success
import scoin.ScriptElt.elt2code

object AnyprevoutTest extends TestSuite {
  val tests = Tests {
    test("build spacechain bmm of length 1") {
      /*
       * tx1[_: [ANYPREVOUT <sig> <G> CHECKSIG]] -> tx2[_: OP_RETURN the end]
       *                     this sig signs tx2 which spends tx1
       * https://gist.githubusercontent.com/RubenSomsen/5e4be6d18e5fa526b17d8b34906b16a5/raw/eb7779f0ce48f84956d1be25a94f63371ff6090a/BMM.svg
       * https://youtu.be/N2ow4Q34Jeg?t=2214
       */
      // now we the sig we can do the magic described at

      val priv = Crypto.PrivateKey(1)
      val pub = priv.publicKey

      assert(pub == Crypto.G)

      val (tx2, sig2) = {
        val tx = Transaction(
          version = 2,
          txIn = List(TxIn.placeholder(1)),
          txOut = List(
            TxOut(
              Satoshi(0),
              Script.write(
                List(
                  OP_RETURN,
                  OP_PUSHDATA(ByteVector.view("the end".getBytes()))
                )
              )
            )
          ),
          lockTime = 0
        )

        // compute the tx hash. since we're using anyprevoutanyscript we don't care about the inputs
        val hash = Transaction.hashForSigningSchnorr(
          tx,
          0,
          List(tx.txOut(0)),
          SIGHASH_ANYPREVOUTANYSCRIPT | SIGHASH_SINGLE,
          SigVersion.SIGVERSION_TAPSCRIPT,
          annex = None,
          tapleafHash = None // because of anyprevoutanyscript this can be None
        )

        val sig = Crypto.signSchnorr(hash, priv, None)

        (tx, sig)
      }

      val script1 = List(
        OP_PUSHDATA(
          sig2 ++ ByteVector
            .fromInt((SIGHASH_ANYPREVOUTANYSCRIPT | SIGHASH_SINGLE), 1)
        ),
        OP_1,
        OP_CHECKSIG
      )

      val (tweakedKey2, controlBlock2) = {
        // simple script tree with a single element
        val scriptTree = ScriptTree.Leaf(
          ScriptLeaf(0, Script.write(script1), Script.TAPROOT_LEAF_TAPSCRIPT)
        )
        val merkleRoot = ScriptTree.hash(scriptTree)

        val internalPubkey = XOnlyPublicKey(pub)
        val tweakedKey = internalPubkey.outputKey(Some(merkleRoot))
        val parity = tweakedKey.publicKey.isOdd

        val controlBlock = ByteVector(
          (Script.TAPROOT_LEAF_TAPSCRIPT + (if (parity) 1 else 0)).toByte
        ) ++ internalPubkey.value

        (tweakedKey, controlBlock)
      }

      val tx1 = Transaction(
        version = 2,
        txIn = List.empty, // irrelevant for this test
        txOut =
          List(TxOut(Satoshi(1000000), List(OP_1, OP_PUSHDATA(tweakedKey2)))),
        lockTime = 0
      )

      val updatedTx2 = tx2.copy(txIn =
        List(
          TxIn(
            OutPoint(tx1, 0),
            signatureScript = ByteVector.empty,
            1,
            witness = ScriptWitness(
              List(
                Script.write(script1),
                controlBlock2
              )
            )
          )
        )
      )

      Transaction.correctlySpends(
        updatedTx2,
        List(tx1),
        ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS | ScriptFlags.SCRIPT_VERIFY_ANYPREVOUT
      )
    }

    test("test anyprevout tx from bitcoin core") {
      val tx = Transaction.read(
        "0200000003e829065a8fd64effda7c9594f69b081ae7a9c7be409febbe7d0c2e58f98e28e38d0000000035f3c2def654f9e7c38287bf0c6c5063373f586fd2ac616d5493bfede3e81e387097237b2602000000cac81eb9ade232d72dd5b7db1f05e1c554568d0a4ccac5ed58bf4a7557f330ee35007f273900000000a1f7ee8d04cd9fce00000000001976a9144f958f5c26468454b69371c6d87cf28e82abd2f988ac580200000000000017a914a4393d67fc274c97516a4485ca28b80d4b3841bb8758020000000000001976a9144f958f5c26468454b69371c6d87cf28e82abd2f988ac580200000000000017a9145604c2ca6e2885c3b910c40dfe32b8061d0391d7878d3b2031"
      )
      val prevouts = List(
        "c9445d0000000000225120f23bc61131c0ac2ea89f0da22436d997d8c652699595c35782ac14031cda51e6",
        "2c7b500000000000225120cb685fedefd1ec5d3840edd599c4b1b5b41ae6344c867acf64a5eee0d2fdd983",
        "8b7a2300000000002251209fbe5b1f1d931841d27039dde19a7d5788edac4c78385598b78e2b87f874a036"
      ).map(ByteVector.fromValidHex(_)).map { bytes =>
        val amount = Satoshi(
          bytes
            .take(8)
            .toLong(signed = false, ordering = ByteOrdering.LittleEndian)
        )
        val scriptpubkey = bytes.drop(8)
        TxOut(amount, scriptpubkey)
      }

      Transaction.correctlySpends(
        tx.updateWitness(
          0,
          ScriptWitness(
            Seq(
              hex"2cff94196c3aff46587a32a0912bd714e1911a9dddc9cbd6354366283fe42cb928e9b4770d2b21fe8725e42078b0c7f5c1439bb1a491fbbfe93b44023b90e416",
              hex"21012fb71bb52006d3ee7ba33ebde4d9b51ffb591164de77904e1e539665ec293c8aac",
              hex"c0588cc77bf9a7f8ee775555198695d84869c65b3e851e1f57b2eb77234b61983529db27987037304adfdb102d3cb61b54ae8bfadb94bdc16826c95f59d5d912dea695d86cd4530169ad2062da5a41fcb536a518b92c6f7d6dc2b85c6e9fa5c279"
            )
          )
        ),
        tx.txIn.zipWithIndex
          .map((vin, i) => (vin.outPoint -> prevouts(i)))
          .toMap,
        ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS | ScriptFlags.SCRIPT_VERIFY_ANYPREVOUT
      )

      assertFails {
        Transaction.correctlySpends(
          tx.updateWitness(
            0,
            ScriptWitness(
              Seq(
                hex"fcf8af63eef1ed3506f4540904604664703a1dc37de86c1d1f8ec91ac8ede7c72cb8b82f1059ed41cc1e131ca407a194078e83909b2ca18bde983d77e323153a8100",
                hex"2101d8eb0bef7e626ca279d89d5d08853ca64f582c4c8365d01fb9e5c4b411390118ac",
                hex"c01956f80262744377be3d5335758b33ce33ed3876f71aa30ad7174c033bfc62acc9480d8a0f90cbab609791834477d738d70edc1830979b2bc60c24475c61e59d8f9e2f79f6a62852e4872903803b01bb3c95996aacf5d15f8224bfaa8cdde3e0934e5c9de419cb968cf8b98103c7865e02f72242a8c1fcb4574b43b5d80a07ff"
              )
            )
          ),
          tx.txIn.zipWithIndex
            .map((vin, i) => (vin.outPoint -> prevouts(i)))
            .toMap,
          ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS | ScriptFlags.SCRIPT_VERIFY_ANYPREVOUT
        )
      }
    }
  }

  // helper function so we can copy/paste easier from ACINQ's test code
  def assertEquals[A, B](p1: A, p2: B): Unit = assert(p1 == p2)
  def assertTrue(p1: Boolean) = assert(p1)
  def assertFails[A](f: => A) = scala.util.Try(f) match {
    case Failure(exception) => () // horray, it failed as expected!
    case Success(value) =>
      throw new IllegalArgumentException(
        "test was not supposed to pass, but did!"
      )
  }
}
