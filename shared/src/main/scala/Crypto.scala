package scoin

import java.security.SecureRandom
import scodec.bits.ByteVector

object Crypto extends CryptoPlatform {
  val secureRandom = new SecureRandom

  def randomBytes(length: Int): ByteVector = {
    val buffer = new Array[Byte](length)
    secureRandom.nextBytes(buffer)
    ByteVector.view(buffer)
  }

  val halfCurveOrder = N.shiftRight(1)
}
