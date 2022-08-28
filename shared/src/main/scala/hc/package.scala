package scoin

import java.io.ByteArrayInputStream
import java.nio.ByteOrder
import scodec.bits.ByteVector
import scoin._

/** Types, utils and wire codecs related to the Hosted Channels protocol.
  */
package object hc {
  def hostedNodesCombined(
      pubkey1: ByteVector,
      pubkey2: ByteVector
  ): ByteVector = {
    val pubkey1First: Boolean =
      LexicographicalOrdering.isLessThan(pubkey1, pubkey2)
    if (pubkey1First) pubkey1 ++ pubkey2 else pubkey2 ++ pubkey1
  }

  def hostedChannelId(
      pubkey1: ByteVector,
      pubkey2: ByteVector
  ): ByteVector32 = {
    val nodesCombined = hostedNodesCombined(pubkey1, pubkey2)
    Crypto.sha256(nodesCombined)
  }

  def hostedShortChannelId(
      pubkey1: ByteVector,
      pubkey2: ByteVector
  ): ShortChannelId = {
    val stream = new ByteArrayInputStream(
      hostedNodesCombined(pubkey1, pubkey2).toArray
    )
    def getChunk(): Long = Protocol.uint64(stream, ByteOrder.BIG_ENDIAN)
    val sid = List.fill(8)(getChunk()).sum
    ShortChannelId(sid)
  }
}
