package scoin.hc

import scala.util.Try
import scodec.codecs._
import scodec.bits._
import scodec.{Attempt, Err}

import scoin.CommonCodecs._
import scoin.ln._
import scoin.ln.LightningMessageCodecs._

object HostedChannelCodecs {
  val invokeHostedChannelCodec = (
    ("chainHash" | bytes32) ::
      ("refundScriptPubKey" | varsizebinarydata) ::
      ("secret" | varsizebinarydata)
  ).as[InvokeHostedChannel]

  val initHostedChannelCodec = (
    ("maxHtlcValueInFlightMsat" | uint64) ::
      ("htlcMinimumMsat" | millisatoshi) ::
      ("maxAcceptedHtlcs" | uint16) ::
      ("channelCapacityMsat" | millisatoshi) ::
      ("initialClientBalanceMsat" | millisatoshi) ::
      ("features" | listOfN(uint16, uint16))
  ).as[InitHostedChannel]

  val hostedChannelBrandingCodec = (
    ("rgbColor" | rgb) ::
      ("pngIcon" | optional(bool8, varsizebinarydata)) ::
      ("contactInfo" | variableSizeBytes(uint16, utf8))
  ).as[HostedChannelBranding]

  lazy val lastCrossSignedStateCodec = (
    ("isHost" | bool8) ::
      ("refundScriptPubKey" | varsizebinarydata) ::
      ("initHostedChannel" | lengthDelimited(initHostedChannelCodec)) ::
      ("blockDay" | uint32) ::
      ("localBalanceMsat" | millisatoshi) ::
      ("remoteBalanceMsat" | millisatoshi) ::
      ("localUpdates" | uint32) ::
      ("remoteUpdates" | uint32) ::
      ("incomingHtlcs" | listOfN(
        uint16,
        lengthDelimited(updateAddHtlcCodec)
      )) ::
      ("outgoingHtlcs" | listOfN(
        uint16,
        lengthDelimited(updateAddHtlcCodec)
      )) ::
      ("remoteSigOfLocal" | bytes64) ::
      ("localSigOfRemote" | bytes64)
  ).as[LastCrossSignedState]

  val stateUpdateCodec = (
    ("blockDay" | uint32) ::
      ("localUpdates" | uint32) ::
      ("remoteUpdates" | uint32) ::
      ("localSigOfRemoteLCSS" | bytes64)
  ).as[StateUpdate]

  val stateOverrideCodec = (
    ("blockDay" | uint32) ::
      ("localBalanceMsat" | millisatoshi) ::
      ("localUpdates" | uint32) ::
      ("remoteUpdates" | uint32) ::
      ("localSigOfRemoteLCSS" | bytes64)
  ).as[StateOverride]

  val announcementSignatureCodec = (
    ("nodeSignature" | bytes64) ::
      ("wantsReply" | bool8)
  ).as[AnnouncementSignature]

  val resizeChannelCodec = (
    ("newCapacity" | satoshi) ::
      ("clientSig" | bytes64)
  ).as[ResizeChannel]

  val askBrandingInfoCodec =
    ("chainHash" | bytes32).as[AskBrandingInfo]

  val queryPublicHostedChannelsCodec =
    ("chainHash" | bytes32).as[QueryPublicHostedChannels]

  val replyPublicHostedChannelsEndCodec =
    ("chainHash" | bytes32).as[ReplyPublicHostedChannelsEnd]

  val queryPreimagesCodec =
    ("hashes" | listOfN(uint16, bytes32)).as[QueryPreimages]

  val replyPreimagesCodec =
    ("preimages" | listOfN(uint16, bytes32)).as[ReplyPreimages]

  val hostedMessageCodec = discriminated[LightningMessage]
    .by(uint16)
    .typecase(65535, invokeHostedChannelCodec)
    .typecase(65533, initHostedChannelCodec)
    .typecase(65531, lastCrossSignedStateCodec)
    .typecase(65529, stateUpdateCodec)
    .typecase(65527, stateOverrideCodec)
    .typecase(65525, hostedChannelBrandingCodec)
    .typecase(65523, announcementSignatureCodec)
    .typecase(65521, resizeChannelCodec)
    .typecase(65519, queryPublicHostedChannelsCodec)
    .typecase(65517, replyPublicHostedChannelsEndCodec)
    .typecase(65515, queryPreimagesCodec)
    .typecase(65513, replyPreimagesCodec)
    .typecase(65511, askBrandingInfoCodec)
    .typecase(64513, channelAnnouncementCodec) // PHC gossip
    .typecase(64511, channelAnnouncementCodec) // PHC sync
    .typecase(64509, channelUpdateCodec) // PHC gossip
    .typecase(64507, channelUpdateCodec) // PHC sync
    .typecase(63505, updateAddHtlcCodec)
    .typecase(63503, updateFulfillHtlcCodec)
    .typecase(63501, updateFailHtlcCodec)
    .typecase(63499, updateFailMalformedHtlcCodec)
    .typecase(63497, errorCodec)
}
