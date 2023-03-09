package scoin
import scodec.bits._
import java.io.ByteArrayOutputStream
import scoin.ScriptTree.Branch
import scoin.ScriptTree.Leaf
import scala.annotation.tailrec

/** leaf of a script tree used to create and spend tapscript transactions
  * @param id
  *   leaf id
  * @param script
  *   serialized bitcoin script
  * @param leafVersion
  *   tapscript version
  */
case class ScriptLeaf(
    val id: Int,
    val script: ByteVector,
    val leafVersion: Int
) {

  /** tapleaf hash of this leaf
    */
  val hash: ByteVector32 = {
    val buffer = new ByteArrayOutputStream()
    buffer.write(leafVersion)
    Protocol.writeScript(script.toArray, buffer)
    Crypto.taggedHash(ByteVector(buffer.toByteArray()), "TapLeaf")
  }
}

/** Simple binary tree structure
  */
sealed abstract class ScriptTree[T]

object ScriptTree {
  case class Leaf[T](value: T) extends ScriptTree[T]
  case class Branch[T](left: ScriptTree[T], right: ScriptTree[T])
      extends ScriptTree[T]

  /** @return
    *   the hash of the input merkle tree
    */
  def hash(tree: ScriptTree[ScriptLeaf]): ByteVector32 = tree match {
    case Leaf(value) => value.hash
    case Branch(left, right) => {
      val h1 = hash(left)
      val h2 = hash(right)
      Crypto.taggedHash(
        (if (LexicographicalOrdering.isLessThan(h1, h2)) h1 ++ h2
         else h2 ++ h1),
        "TapBranch"
      )
    }
  }

  /** Calculate the merkle path-to-root for each of the leaves according to
    * BIP341 specifications.
    *
    * Warning: This function is very inefficient. If the merkle tree is large it
    * may run out of memory.
    *
    * Reminder: Inner nodes lexographically sort their children before hashing.
    *
    * @see
    *   BIP341 https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
    * @param tree
    * @return
    *   a mapping of `ScriptLeaf` -> `List[ByteVector32]` where elements of the
    *   list are the hashes of the corresponding merkle nodes necessary to
    *   reconstruct the root hash.
    *
    * root / \ AB CDE / \ / \ A B CD E / \ C D
    *
    * The proofs for leafs in the tree above are: A -> B,CDE B -> A,CDE C ->
    * D,E,AB D -> C,E,AB E -> CD,AB
    */
  def merkleProofs(
      tree: ScriptTree[ScriptLeaf]
  ): Map[ScriptLeaf, List[ByteVector32]] = {

    def inner(
        subtree: ScriptTree[ScriptLeaf],
        path: List[ByteVector32]
    ): Map[ScriptLeaf, List[ByteVector32]] = subtree match {
      case Leaf(value) => Map(value -> path)
      case Branch(left, right) =>
        inner(left, right.hash :: path) ++ inner(right, left.hash :: path)
    }
    inner(tree, List.empty)
  }

  def verifyProof(
      tree: ScriptTree[ScriptLeaf],
      leaf: ScriptLeaf,
      proof: List[ByteVector32]
  ): Boolean = {
    val merkleRoot = proof.foldLeft(leaf.hash) { case (a, b) =>
      Crypto.taggedHash(
        if (LexicographicalOrdering.isLessThan(a, b)) a ++ b
        else b ++ a,
        "TapBranch"
      )
    }
    merkleRoot == tree.hash
  }

  /** Build a naive merkle tree from a list of leaves
    *
    * @param scripts
    * @return
    */
  def naiveFromList[A](leaves: List[A]): ScriptTree[A] = {
    require(leaves.nonEmpty, "cannot have empty list of scripts")

    @tailrec
    def buildTree(nodes: List[ScriptTree[A]]): List[ScriptTree[A]] =
      nodes match {
        case ns if (ns.size <= 1) => ns // we are at the root. Done.
        case ns =>
          val pairedNodes = ns
            .grouped(2)
            .map {
              case List(lhs, rhs) => Branch[A](lhs, rhs)
              case List(lhs)      => lhs
              case _ =>
                throw new IllegalArgumentException("should never be here!")
            }
            .toList
          buildTree(pairedNodes)
      }

    buildTree(
      leaves
        .grouped(2)
        .map {
          case List(lhs, rhs) => Branch[A](Leaf(lhs), Leaf(rhs))
          case List(lhs)      => Leaf[A](lhs)
          case _ => throw new IllegalArgumentException("should never be here!")
        }
        .toList
    ).head
  }

  // helpful syntax
  implicit class scriptTreeOps(tree: ScriptTree[ScriptLeaf]) {
    def hash = ScriptTree.hash(tree)
    def merkleProofs = ScriptTree.merkleProofs(tree)
    def verifyProof(leaf: ScriptLeaf, proof: List[ByteVector32]) =
      ScriptTree.verifyProof(tree, leaf, proof)
    def prettyString: String = tree match {
      case Branch(left, right) => {
        (s"${tree.hash.toHex.take(5)}... -> hashOf(${left.hash.toHex.take(5)}..., ${right.hash.toHex.take(5)}...)\n")
        .concat(s"${left.prettyString}\n")
        .concat(s"${right.prettyString}\n")
      }
      case Leaf(value) => s"${value.hash.toHex.take(5)}... -> hashOf(${value})"
    }
  }
}
