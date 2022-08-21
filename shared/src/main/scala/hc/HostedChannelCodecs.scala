package scoin.hc

import scala.util.Try
import scodec.codecs._
import scodec.bits._
import scodec.{Attempt, Err}

import scoin.ln._
import scoin.ln.CommonCodecs._
import scoin.ln.LightningMessageCodecs._
import scoin.hc.HostedChannelTags._

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

  def decodeHostedMessage(
      tag: Int,
      data: ByteVector
  ): Try[LightningMessage] = {
    val bitVector = data.toBitVector
    val decodeAttempt = tag match {
      case HC_STATE_UPDATE_TAG      => stateUpdateCodec.decode(bitVector)
      case HC_RESIZE_CHANNEL_TAG    => resizeChannelCodec.decode(bitVector)
      case HC_ASK_BRANDING_INFO_TAG => askBrandingInfoCodec.decode(bitVector)
      case HC_INVOKE_HOSTED_CHANNEL_TAG =>
        invokeHostedChannelCodec.decode(bitVector)
      case HC_STATE_OVERRIDE_TAG => stateOverrideCodec.decode(bitVector)
      case HC_INIT_HOSTED_CHANNEL_TAG =>
        initHostedChannelCodec.decode(bitVector)
      case HC_HOSTED_CHANNEL_BRANDING_TAG =>
        hostedChannelBrandingCodec.decode(bitVector)
      case HC_LAST_CROSS_SIGNED_STATE_TAG =>
        lastCrossSignedStateCodec.decode(bitVector)
      case HC_ERROR_TAG            => errorCodec.decode(bitVector)
      case HC_UPDATE_ADD_HTLC_TAG  => updateAddHtlcCodec.decode(bitVector)
      case HC_UPDATE_FAIL_HTLC_TAG => updateFailHtlcCodec.decode(bitVector)
      case HC_UPDATE_FULFILL_HTLC_TAG =>
        updateFulfillHtlcCodec.decode(bitVector)
      case HC_UPDATE_FAIL_MALFORMED_HTLC_TAG =>
        updateFailMalformedHtlcCodec.decode(bitVector)
      case tag =>
        Attempt failure Err(s"unknown tag for hosted message: $tag")
    }

    decodeAttempt.map(_.value).toTry
  }

  def encodeHostedMessage(message: LightningMessage): (Int, ByteVector) = {
    val (tag, result) = message match {
      case msg: InvokeHostedChannel =>
        (HC_INVOKE_HOSTED_CHANNEL_TAG, invokeHostedChannelCodec.encode(msg))
      case msg: AskBrandingInfo =>
        (HC_ASK_BRANDING_INFO_TAG, askBrandingInfoCodec.encode(msg))
      case msg: ResizeChannel =>
        (HC_RESIZE_CHANNEL_TAG, resizeChannelCodec.encode(msg))
      case msg: InitHostedChannel =>
        (HC_INIT_HOSTED_CHANNEL_TAG, initHostedChannelCodec.encode(msg))
      case msg: HostedChannelBranding =>
        (HC_HOSTED_CHANNEL_BRANDING_TAG, hostedChannelBrandingCodec.encode(msg))
      case msg: StateUpdate =>
        (HC_STATE_UPDATE_TAG, stateUpdateCodec.encode(msg))
      case msg: StateOverride =>
        (HC_STATE_OVERRIDE_TAG, stateOverrideCodec.encode(msg))
      case msg: LastCrossSignedState =>
        (HC_LAST_CROSS_SIGNED_STATE_TAG, lastCrossSignedStateCodec.encode(msg))
      case msg: Error =>
        (HC_ERROR_TAG, errorCodec.encode(msg))
      case msg: UpdateAddHtlc =>
        (HC_UPDATE_ADD_HTLC_TAG, updateAddHtlcCodec.encode(msg))
      case msg: UpdateFulfillHtlc =>
        (HC_UPDATE_FULFILL_HTLC_TAG, updateFulfillHtlcCodec.encode(msg))
      case msg: UpdateFailHtlc =>
        (HC_UPDATE_FAIL_HTLC_TAG, updateFailHtlcCodec.encode(msg))
      case msg: UpdateFailMalformedHtlc =>
        (
          HC_UPDATE_FAIL_MALFORMED_HTLC_TAG,
          updateFailMalformedHtlcCodec.encode(msg)
        )
      case msg: ChannelUpdate =>
        (PHC_UPDATE_SYNC_TAG, channelUpdateCodec.encode(msg))
    }

    (tag, result.require.toByteVector)
  }
}
