package scoin

import scoin._
import utest._
import scodec.bits._

object MnemonicCodeTest extends TestSuite {
  val tests = Tests {
    test("MnemonicCode - ByteVector32 to/from BIP39"){
      val toMnemonics: ByteVector32 => List[String] = 
        entropy => MnemonicCode.toMnemonics(entropy)

      val fromMnemonics: List[String] => Option[ByteVector32] = words =>
        MnemonicCode.recoverEntropy(words).map(ByteVector32(_)).toOption

      val entropy = Crypto.sha256(ByteVector("abc".getBytes))
      val words = toMnemonics(entropy)
      val recovered = fromMnemonics(words)
      assert(recovered.isDefined && recovered.get == entropy)      
    }
  }
}