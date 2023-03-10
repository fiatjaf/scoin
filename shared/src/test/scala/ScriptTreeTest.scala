package scoin

import scoin._
import utest._
import scodec.bits._

object ScriptTreeTest extends TestSuite {
  val tests = Tests {
    test("ScriptTree - construct tree from 3 element list") {
      // just some bogus scripts, pushing an unspendable key
      val scripts = List.fill(3)(
        List(OP_PUSHDATA(PublicKey.unspendable.xonly), OP_CHECKSIG)
      )
      val leaves = scripts.zipWithIndex.map { case (script, idx) =>
        ScriptTree.Leaf(
          ScriptLeaf(idx, Script.write(script), Script.TAPROOT_LEAF_TAPSCRIPT)
        )
      }
      //     root
      //    /   \
      //  /  \   #3
      // #1  #2
      val scriptTree1 = ScriptTree.Branch(
        ScriptTree.Branch(leaves(0), leaves(1)),
        leaves(2)
      )
      val merkleRoot1 = ScriptTree.hash(scriptTree1)

      val leaves2 = scripts.zipWithIndex.map { case (script, idx) =>
        ScriptLeaf(idx, Script.write(script), Script.TAPROOT_LEAF_TAPSCRIPT)
      }
      val scriptTree2 = ScriptTree.naiveFromList(leaves2)
      val merkleRoot2 = scriptTree2.hash
      assert(merkleRoot1 == merkleRoot2)
    }

    test("ScriptTree - construct tree from 4 element list ") {
      // just some bogus scripts, pushing an unspendable key
      val scripts = List.fill(4)(
        List(OP_PUSHDATA(PublicKey.unspendable.xonly), OP_CHECKSIG)
      )
      val leaves = scripts.zipWithIndex.map { case (script, idx) =>
        ScriptTree.Leaf(
          ScriptLeaf(idx, Script.write(script), Script.TAPROOT_LEAF_TAPSCRIPT)
        )
      }
      //     root
      //    /   \
      //  /  \  / \
      // #1  #2 #3 #4
      val scriptTree1 = ScriptTree.Branch(
        ScriptTree.Branch(leaves(0), leaves(1)),
        ScriptTree.Branch(leaves(2), leaves(3))
      )
      val merkleRoot1 = ScriptTree.hash(scriptTree1)

      val leaves2 = scripts.zipWithIndex.map { case (script, idx) =>
        ScriptLeaf(idx, Script.write(script), Script.TAPROOT_LEAF_TAPSCRIPT)
      }
      val scriptTree2 = ScriptTree.naiveFromList(leaves2)
      val merkleRoot2 = ScriptTree.hash(scriptTree2)
      assert(merkleRoot1 == merkleRoot2)
    }

    test("ScriptTree - calculate and verify merkle proofs") {
      // just some bogus scripts, pushing an unspendable key
      val scripts = List(
        List(OP_1),
        List(OP_2),
        List(OP_3)
      )
      val leaves = scripts.zipWithIndex.map { case (script, idx) =>
        ScriptLeaf(idx, Script.write(script), Script.TAPROOT_LEAF_TAPSCRIPT)
      }
      val scriptTree = ScriptTree.naiveFromList(leaves)
      //     root
      //    /   \
      //  /  \   #3
      // #1  #2

      // useful for visualizing
      // println(scriptTree.prettyString)

      val merkleRoot = scriptTree.hash

      val proofs = scriptTree.merkleProofs

      // now to reconstruct the merkle root from a given leaf and path
      proofs.foreach { case (leaf, proof) =>
        assert(scriptTree.verifyProof(leaf, proof))
      }

    }
  }
}
