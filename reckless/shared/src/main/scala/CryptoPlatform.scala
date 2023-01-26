package scoin
import scodec.bits._
import scoin._

private[scoin] trait CryptoPlatform extends reckless.CryptoPlatformImpl {
  /**
    * This trait only exists here as a stub so that it has the correct
    * name (CryptoPlatform) which is the name of the trait which the `Crypto`
    * object extends.
    * 
    * All platform-independent implementations are provided in
    * `reckless.CryptoPlatformImpl`
    */
}