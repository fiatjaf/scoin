package scoin.instances

import scoin._

import cats.Id
import scala.io.Source

/**
  * A default implementation of the `Resources` trait, but for the
  * `Id` type
  */

object ResourcesId extends Resources[Id] {
  override def bip39_english_wordlist: Seq[String] = {
    val stream =
      MnemonicCode.getClass.getResourceAsStream("/bip39_english_wordlist.txt")
    Source.fromInputStream(stream, "UTF-8").getLines().toSeq
  }
}