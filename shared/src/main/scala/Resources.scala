package scoin

/**
  * Abstract trait detailing which resources should be accesssible across
  * all platforms.
  * 
  * Each platform provides a concrete instance of this trait in 
  * the form a `class` and and an implicit object which instantiates
  * that class.
  * 
  * The advantage of this setup, which is currently slightly different than
  * the other cross-platform objects such as `Crypto` is that one can easily
  * make platform-specific down at the platform-specific level by overriding
  * *only* that platform's implementation.
  * 
  */

trait Resources[F[_]] {

  def bip39_english_wordlist: F[Seq[String]]

}

object Resources {

  def apply[F[_]: Resources]: Resources[F] = implicitly

}