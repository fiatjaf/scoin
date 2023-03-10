package scoin.instances

import scoin._

import cats.Id

/**
  * A default implementation of the `Resources` trait, but for the
  * `Id` type
  */
object ResourcesId extends Resources[Id] {
  override def bip39_english_wordlist: Id[Seq[String]] = 
    reckless.BIP39EnglishWordlist.words
}