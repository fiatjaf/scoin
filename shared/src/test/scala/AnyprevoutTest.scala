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
        OP_PUSHDATA(sig2), // covenant here (magic)
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
        ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS
      )
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
