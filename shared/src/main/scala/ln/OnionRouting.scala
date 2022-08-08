package scoin.ln

import scodec.bits.ByteVector
import scodec.codecs._
import scodec.{Codec, Err}
import scoin._
import scoin.ln.CommonCodecs.bytes32

case class OnionRoutingPacket(
    version: Int,
    publicKey: ByteVector,
    payload: ByteVector,
    hmac: ByteVector32
)

object OnionRoutingCodecs {
  case class MissingRequiredTlv(tag: UInt64) extends Err {
    val failureMessage: FailureMessage = InvalidOnionPayload(tag, 0)
    override def message = failureMessage.message
    override def context: List[String] = Nil
    override def pushContext(ctx: String): Err = this
  }

  case class ForbiddenTlv(tag: UInt64) extends Err {
    val failureMessage: FailureMessage = InvalidOnionPayload(tag, 0)
    override def message = failureMessage.message
    override def context: List[String] = Nil
    override def pushContext(ctx: String): Err = this
  }

  def onionRoutingPacketCodec(payloadLength: Int): Codec[OnionRoutingPacket] =
    (("version" | uint8) ::
      ("publicKey" | bytes(33)) ::
      ("onionPayload" | bytes(payloadLength)) ::
      ("hmac" | bytes32)).as[OnionRoutingPacket]
}
