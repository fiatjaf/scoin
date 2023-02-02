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

object AnyprevoutTest extends TestSuite {
  val tests = Tests {
    test("build anyprevout tx") {
      val priv = Crypto.PrivateKey(1)
      val pub = priv.publicKey

      assert(pub == Crypto.G)

      val script = List(
        // OP_PUSHDATA(ByteVector.view),
        OP_PUSHDATA(ByteVector.view(Array[Byte](0x01))),
        OP_CHECKSIG
      )

      // simple script tree with a single element
      val scriptTree = ScriptTree.Leaf(
        ScriptLeaf(0, Script.write(script), Script.TAPROOT_LEAF_TAPSCRIPT)
      )
      val merkleRoot = ScriptTree.hash(scriptTree)

      val internalPubkey = XOnlyPublicKey(pub)
      val tweakedKey = internalPubkey.outputKey(Some(merkleRoot))
      val parity = tweakedKey.publicKey.isOdd

      // funding tx sends to our tapscript
      val fundingTx = Transaction(
        version = 2,
        txIn = List.empty,
        txOut =
          List(TxOut(Satoshi(1000000), List(OP_1, OP_PUSHDATA(tweakedKey)))),
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
