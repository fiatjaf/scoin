package scoin.hc

import java.io.ByteArrayInputStream
import java.nio.ByteOrder
import scodec.bits.ByteVector
import scoin._

object HostedChannelHelpers {
  def lcssEmpty = LastCrossSignedState(
    isHost = false,
    refundScriptPubKey = ByteVector.empty,
    initHostedChannel = InitHostedChannel(
      maxHtlcValueInFlightMsat = UInt64(0),
      htlcMinimumMsat = MilliSatoshi(0),
      maxAcceptedHtlcs = 0,
      channelCapacityMsat = MilliSatoshi(0),
      initialClientBalanceMsat = MilliSatoshi(0)
    ),
    blockDay = 0,
    localBalanceMsat = MilliSatoshi(0),
    remoteBalanceMsat = MilliSatoshi(0),
    localUpdates = 0,
    remoteUpdates = 0,
    incomingHtlcs = List.empty,
    outgoingHtlcs = List.empty,
    remoteSigOfLocal = ByteVector64.Zeroes,
    localSigOfRemote = ByteVector64.Zeroes
  )

  def hostedNodesCombined(
      pubkey1: ByteVector,
      pubkey2: ByteVector
  ): ByteVector = {
    if (LexicographicalOrdering.isLessThan(pubkey1, pubkey2))
      pubkey1 ++ pubkey2
    else pubkey2 ++ pubkey1
  }

  def getChannelId(
      pubkey1: ByteVector,
      pubkey2: ByteVector
  ): ByteVector32 = {
    val nodesCombined = hostedNodesCombined(pubkey1, pubkey2)
    Crypto.sha256(nodesCombined)
  }

  def getShortChannelId(
      pubkey1: ByteVector,
      pubkey2: ByteVector
  ): ShortChannelId = {
    val stream = new ByteArrayInputStream(
      hostedNodesCombined(pubkey1, pubkey2).toArray
    )
    def getChunk(): Long = Protocol.uint64(stream, ByteOrder.BIG_ENDIAN)
    val idLong = List.fill(8)(getChunk()).sum
    ShortChannelId(idLong)
  }
}
