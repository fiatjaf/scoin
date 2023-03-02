package scoin

import scala.scalajs.js
import scala.scalajs.js.annotation._
import scodec.bits._
import scala.scalajs.js.typedarray.Uint8Array
import scala.scalajs.js.JSConverters._

import Crypto._

object ScoinJS {
  @JSExportTopLevel("Transaction")
  object TransactionJS {
    @JSExport
    def read(hex: String) = TransactionJS(Transaction.read(hex))
  }

  @JSExportAll
  class TransactionJS(tx: Transaction) {
    def version = tx.version.toInt
  }

  @JSExportTopLevel("Script")
  object ScriptJS {
    /**
      * Construct a taproot output spendable by owner of `xOnlyPublicKey`.
      * No tweaking of the key is done.
      * 
      * @param xOnlyPublicKey (as hex string)
      * @return 
          a scriptPubKey (in hex) for a taproot output
      */
    @JSExport
    def pay2tr(xOnlyPublicKey: String): String =
      Script.write(Script.pay2tr(Crypto.XOnlyPublicKey(ByteVector32.fromValidHex(xOnlyPublicKey)))).toHex

    /**
      * Construct a taproot output spendable by the owner of `internalXOnlyPublicKey`
      * (the key path spend) but which is tweaked by `merkleRoot` thereby allowing
      * also script path spends. To disable key path spends, use an internalPublicKey
      * with an unknown discrete logarithm such as the one provided 
      * by `Crypto.PublicKey.unspendable` which is (in x-only hex):
      * 
      * 0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0
      *
      * @param internalXOnlyPublicKey
      * @param merkleRoot
      * @return
      *   a scriptPubKey (in hex) for a taproot output
      */
    @JSExport
    def pay2tr(internalXOnlyPublicKey: String, merkleRoot:String): String = {
      val internal = XOnlyPublicKey(ByteVector32.fromValidHex(internalXOnlyPublicKey))
      val tweak = ByteVector32.fromValidHex(merkleRoot)
      val tweakedKey = internal.outputKey(Some(tweak))
      pay2tr(tweakedKey.value.toHex)
    }

    /**
      * Construct a taproot output spendable by the owner of `internalXOnlyPublicKey`
      * (the key path spend) but which is tweaked by `merkleRoot` thereby allowing
      * also script path spends. 
      * 
      * A list of scripts, (aka TapLeafs) can be provided and this function will
      * turn them into a merkle tree accorrding to BIP341/342 specs. Spending via
      * a script path spend requires furnishing a "control block" which includes
      * a merkle proof that the script is committed to by the output.
      * 
      * To construct a taproot merkle tree from a list of scripts, 
      * use `ScriptTree.naiveFromList(tapLeafScripts)`
      * 
      * To disable key path spends, use an internalPublicKey
      * with an unknown discrete logarithm such as the one provided 
      * by `Crypto.PublicKey.unspendable` which is (in x-only hex):
      * 
      * 0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0
      * 
      * @param internalXOnlyPublicKey
      * @param tapLeafScripts
      *   the (hex encoded) tapscripts which constitute the script paths
      *  
      * @return
      */
    @JSExport
    def pay2tr(internalXOnlyPublicKey: String, tapLeafScripts:js.Array[String]): String = {
      val leaves = tapLeafScripts.zipWithIndex.map { case (script, idx) =>
          ScriptLeaf(idx, ByteVector.fromValidHex(script), Script.TAPROOT_LEAF_TAPSCRIPT)
      }
      val merkleRoot = ScriptTree.naiveFromList(leaves.toList).hash
      pay2tr(internalXOnlyPublicKey, merkleRoot.toHex)
    }
  }

  @JSExportTopLevel("ScriptTree")
  object ScriptTreeJS {

    @JSExport
    def naiveFromList(tapLeafScripts:js.Array[String]): ScriptTreeJS = 
      ScriptTreeJS(
        ScriptTree.naiveFromList(
          tapLeafScripts.toList.zipWithIndex.map { case (script, idx) =>
            ScriptLeaf(idx, ByteVector.fromValidHex(script), Script.TAPROOT_LEAF_TAPSCRIPT)
          }
        )
      )
  }

  @JSExportAll
  class ScriptTreeJS(tree: ScriptTree[ScriptLeaf]) {
    def hash: String = tree.hash.toHex

    def merkleProofs = tree.merkleProofs.map{
      case(leaf,proof) =>
                    Map(
                      "script" -> leaf.script.toHex,
                      "proof" -> proof.map(_.toHex).toJSArray
                    )
    }.toJSArray.map(_.toJSDictionary)
    
    def verifyProof(scriptLeaf: String, merkleProof: js.Array[String]): Boolean =
      tree.verifyProof(
        leaf = ScriptLeaf(
          id = 0, // id is not included in hash, so can be any integer here
          script = ByteVector.fromValidHex(scriptLeaf),
          leafVersion = Script.TAPROOT_LEAF_TAPSCRIPT
        ),
        proof = merkleProof.toList.map(ByteVector32.fromValidHex(_))
      )
  }
}
