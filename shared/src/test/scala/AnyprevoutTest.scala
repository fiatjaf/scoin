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

      assertFails {
        Transaction.correctlySpends(
          tx2,
          List(tx1),
          ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS | ScriptFlags.SCRIPT_VERIFY_ANYPREVOUT
        )
      }

      Transaction.correctlySpends(
        tx2.copy(txIn =
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
        ),
        List(tx1),
        ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS | ScriptFlags.SCRIPT_VERIFY_ANYPREVOUT
      )

    }

    test("test eltoo transactions from instagibbs") {
      val update = Transaction.read(
        "02000000000101a3c416668a0b114bb7fc594fd52608b77d44d72259d505bbb04c161d5e99d2750100000000fdffffff0140420f0000000000225120d1102755f5d0700003ff4a486b02f390f8b6bd9ce2dbc12429cceafde44289cb0441a5f0c640b307803cffc0ce0f205c8acef84ec4a4bb0267b224d2b42baca18737a40b65b549a3c44b6038cf713acf273a08fb63b8a80c4e33acbdc97de730dd02c30251ac21c14c2ef50ba924c2d69bdb070db119ed4fa8be451a39f272579215820ee55eb518215004ad094f7fcde24d22e1b773bd665c134378449bc0d34212eb8e2fbc242c23cc0065cd1d"
      )

      val settlement = Transaction.read(
        "020000000001011b669edfbcb703e6c52fe315b6b532bb1fd5a0ed4232b5bd3d1d1e0e550565b8000000000005000000020000000000000000015140420f00000000002251202dbc0053dd6f3310d84e55eebaacfad53fe3e3ec3c2cecb1cffebdd95fa8063f026541cc5a574bbbc57400177c6e97d8447dd35c150c9d2b91d03361e11e23baf6ecd6527e04ecfee8b0f741489713c12e757ca46f28f4c38e869e7cf2f458ad175234c1210179be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac41c04c2ef50ba924c2d69bdb070db119ed4fa8be451a39f272579215820ee55eb518b4d868d7231ff3d15775dbd01acf0051b86eccd1f1139772222152b32986c4df0065cd1d"
      )

      Transaction.correctlySpends(
        settlement,
        List(update),
        ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS | ScriptFlags.SCRIPT_VERIFY_ANYPREVOUT
      )

      assertFails {
        Transaction.correctlySpends(
          settlement.updateWitness(0, ScriptWitness(Seq.empty)),
          List(update),
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
