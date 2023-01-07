package scoin
import scodec.bits._
import java.io.ByteArrayOutputStream

/**
 * leaf of a script tree used to create and spend tapscript transactions
 * @param id leaf id
 * @param script serialized bitcoin script
 * @param leafVersion tapscript version
 */
class ScriptLeaf(val id: Int, val script: ByteVector, val leafVersion: Int) {
    /**
     * tapleaf hash of this leaf
     */
    val hash: ByteVector32 = {
            val buffer = new ByteArrayOutputStream()
            buffer.write(leafVersion)
            Protocol.writeScript(script.toArray, buffer)
            Crypto.taggedHash(ByteVector(buffer.toByteArray()), "TapLeaf")
        }
}

/**
 * Simple binary tree structure
 */
sealed abstract class ScriptTree[T] {
    case class Leaf[T](value: T) extends ScriptTree[T]
    case class Branch[T](left: ScriptTree[T], right: ScriptTree[T]) extends ScriptTree[T]
}

object ScriptTree {
    /**
     * @return the hash of the input merkle tree
     */
    def hash(tree: ScriptTree[ScriptLeaf]): ByteVector32 = tree match {
        case tree.Leaf(value) => value.hash
        case tree.Branch(left,right) => {
            val h1 = hash(left)
            val h2 = hash(right)
            Crypto.taggedHash((if (LexicographicalOrdering.isLessThan(h1, h2)) h1 ++ h2 else h2 ++ h1), "TapBranch")
        }
    }
}