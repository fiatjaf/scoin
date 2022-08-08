package scoin.ln

import scodec.bits.{BitVector, ByteVector}
import scodec.codecs._
import scodec.{Attempt, Codec}

import scoin._
import scoin.ln._
import scoin.ln.CommonCodecs._

object LightningMessageCodecs extends LightningMessageCodecsVersionCompat {
  val featuresCodec: Codec[Features[Feature]] =
    varsizebinarydata.xmap[Features[Feature]](
      { bytes => Features(bytes) },
      { features => features.toByteVector }
    )

  val initFeaturesCodec: Codec[Features[InitFeature]] =
    featuresCodec.xmap[Features[InitFeature]](_.initFeatures(), _.unscoped())

  /** For historical reasons, features are divided into two feature bitmasks. We
    * only send from the second one, but we allow receiving in both.
    */
  val combinedFeaturesCodec: Codec[Features[InitFeature]] =
    (("globalFeatures" | varsizebinarydata) ::
      ("localFeatures" | varsizebinarydata))
      .as[(ByteVector, ByteVector)]
      .xmap[Features[InitFeature]](
        { case (gf, lf) =>
          val length = gf.length.max(lf.length)
          Features(gf.padLeft(length) | lf.padLeft(length)).initFeatures()
        },
        { features => (ByteVector.empty, features.toByteVector) }
      )

  val initCodec: Codec[Init] =
    (("features" | combinedFeaturesCodec) :: ("tlvStream" | InitTlvCodecs.initTlvCodec))
      .as[Init]

  val errorCodec: Codec[Error] = (("channelId" | bytes32) ::
    ("data" | varsizebinarydata) ::
    ("tlvStream" | ErrorTlv.errorTlvCodec)).as[Error]

  val warningCodec: Codec[Warning] = (("channelId" | bytes32) ::
    ("data" | varsizebinarydata) ::
    ("tlvStream" | WarningTlv.warningTlvCodec)).as[Warning]

  val pingCodec: Codec[Ping] = (("pongLength" | uint16) ::
    ("data" | varsizebinarydata) ::
    ("tlvStream" | PingTlv.pingTlvCodec)).as[Ping]

  val pongCodec: Codec[Pong] = (("data" | varsizebinarydata) ::
    ("tlvStream" | PongTlv.pongTlvCodec)).as[Pong]

  val channelReestablishCodec: Codec[ChannelReestablish] =
    (("channelId" | bytes32) ::
      ("nextLocalCommitmentNumber" | uint64overflow) ::
      ("nextRemoteRevocationNumber" | uint64overflow) ::
      ("yourLastPerCommitmentSecret" | privateKey) ::
      ("myCurrentPerCommitmentPoint" | publicKey) ::
      ("tlvStream" | ChannelReestablishTlv.channelReestablishTlvCodec))
      .as[ChannelReestablish]

  val openChannelCodec: Codec[OpenChannel] = (("chainHash" | bytes32) ::
    ("temporaryChannelId" | bytes32) ::
    ("fundingSatoshis" | satoshi) ::
    ("pushMsat" | millisatoshi) ::
    ("dustLimitSatoshis" | satoshi) ::
    ("maxHtlcValueInFlightMsat" | uint64) ::
    ("channelReserveSatoshis" | satoshi) ::
    ("htlcMinimumMsat" | millisatoshi) ::
    ("feeratePerKw" | feeratePerKw) ::
    ("toSelfDelay" | cltvExpiryDelta) ::
    ("maxAcceptedHtlcs" | uint16) ::
    ("fundingPubkey" | publicKey) ::
    ("revocationBasepoint" | publicKey) ::
    ("paymentBasepoint" | publicKey) ::
    ("delayedPaymentBasepoint" | publicKey) ::
    ("htlcBasepoint" | publicKey) ::
    ("firstPerCommitmentPoint" | publicKey) ::
    ("channelFlags" | (ignore(7) dropLeft bool).as[OpenChannel.ChannelFlags]) ::
    ("tlvStream" | OpenChannelTlv.openTlvCodec)).as[OpenChannel]

  val acceptChannelCodec: Codec[AcceptChannel] =
    (("temporaryChannelId" | bytes32) ::
      ("dustLimitSatoshis" | satoshi) ::
      ("maxHtlcValueInFlightMsat" | uint64) ::
      ("channelReserveSatoshis" | satoshi) ::
      ("htlcMinimumMsat" | millisatoshi) ::
      ("minimumDepth" | uint32) ::
      ("toSelfDelay" | cltvExpiryDelta) ::
      ("maxAcceptedHtlcs" | uint16) ::
      ("fundingPubkey" | publicKey) ::
      ("revocationBasepoint" | publicKey) ::
      ("paymentBasepoint" | publicKey) ::
      ("delayedPaymentBasepoint" | publicKey) ::
      ("htlcBasepoint" | publicKey) ::
      ("firstPerCommitmentPoint" | publicKey) ::
      ("tlvStream" | AcceptChannelTlv.acceptTlvCodec)).as[AcceptChannel]

  val fundingCreatedCodec: Codec[FundingCreated] =
    (("temporaryChannelId" | bytes32) ::
      ("fundingTxid" | bytes32) ::
      ("fundingOutputIndex" | uint16) ::
      ("signature" | bytes64) ::
      ("tlvStream" | FundingCreatedTlv.fundingCreatedTlvCodec))
      .as[FundingCreated]

  val fundingSignedCodec: Codec[FundingSigned] = (("channelId" | bytes32) ::
    ("signature" | bytes64) ::
    ("tlvStream" | FundingSignedTlv.fundingSignedTlvCodec)).as[FundingSigned]

  val fundingLockedCodec: Codec[FundingLocked] = (("channelId" | bytes32) ::
    ("nextPerCommitmentPoint" | publicKey) ::
    ("tlvStream" | FundingLockedTlv.fundingLockedTlvCodec)).as[FundingLocked]

  val shutdownCodec: Codec[Shutdown] = (("channelId" | bytes32) ::
    ("scriptPubKey" | varsizebinarydata) ::
    ("tlvStream" | ShutdownTlv.shutdownTlvCodec)).as[Shutdown]

  val closingSignedCodec: Codec[ClosingSigned] = (("channelId" | bytes32) ::
    ("feeSatoshis" | satoshi) ::
    ("signature" | bytes64) ::
    ("tlvStream" | ClosingSignedTlv.closingSignedTlvCodec)).as[ClosingSigned]

  val updateAddHtlcCodec: Codec[UpdateAddHtlc] = (("channelId" | bytes32) ::
    ("id" | uint64overflow) ::
    ("amountMsat" | millisatoshi) ::
    ("paymentHash" | bytes32) ::
    ("expiry" | cltvExpiry) ::
    ("onionRoutingPacket" | PaymentOnionCodecs.paymentOnionPacketCodec) ::
    ("tlvStream" | UpdateAddHtlcTlv.addHtlcTlvCodec)).as[UpdateAddHtlc]

  val updateFulfillHtlcCodec: Codec[UpdateFulfillHtlc] =
    (("channelId" | bytes32) ::
      ("id" | uint64overflow) ::
      ("paymentPreimage" | bytes32) ::
      ("tlvStream" | UpdateFulfillHtlcTlv.updateFulfillHtlcTlvCodec))
      .as[UpdateFulfillHtlc]

  val updateFailHtlcCodec: Codec[UpdateFailHtlc] = (("channelId" | bytes32) ::
    ("id" | uint64overflow) ::
    ("reason" | varsizebinarydata) ::
    ("tlvStream" | UpdateFailHtlcTlv.updateFailHtlcTlvCodec)).as[UpdateFailHtlc]

  val updateFailMalformedHtlcCodec
      : Codec[UpdateFailMalformedHtlc] = (("channelId" | bytes32) ::
    ("id" | uint64overflow) ::
    ("onionHash" | bytes32) ::
    ("failureCode" | uint16) ::
    ("tlvStream" | UpdateFailMalformedHtlcTlv.updateFailMalformedHtlcTlvCodec))
    .as[UpdateFailMalformedHtlc]

  val commitSigCodec: Codec[CommitSig] = (("channelId" | bytes32) ::
    ("signature" | bytes64) ::
    ("htlcSignatures" | listofsignatures) ::
    ("tlvStream" | CommitSigTlv.commitSigTlvCodec)).as[CommitSig]

  val revokeAndAckCodec: Codec[RevokeAndAck] = (("channelId" | bytes32) ::
    ("perCommitmentSecret" | privateKey) ::
    ("nextPerCommitmentPoint" | publicKey) ::
    ("tlvStream" | RevokeAndAckTlv.revokeAndAckTlvCodec)).as[RevokeAndAck]

  val updateFeeCodec: Codec[UpdateFee] = (("channelId" | bytes32) ::
    ("feeratePerKw" | feeratePerKw) ::
    ("tlvStream" | UpdateFeeTlv.updateFeeTlvCodec)).as[UpdateFee]

  val announcementSignaturesCodec: Codec[AnnouncementSignatures] =
    (("channelId" | bytes32) ::
      ("shortChannelId" | shortchannelid) ::
      ("nodeSignature" | bytes64) ::
      ("bitcoinSignature" | bytes64) ::
      ("tlvStream" | AnnouncementSignaturesTlv.announcementSignaturesTlvCodec))
      .as[AnnouncementSignatures]

  val channelAnnouncementWitnessCodec =
    ("features" | featuresCodec) ::
      ("chainHash" | bytes32) ::
      ("shortChannelId" | shortchannelid) ::
      ("nodeId1" | publicKey) ::
      ("nodeId2" | publicKey) ::
      ("bitcoinKey1" | publicKey) ::
      ("bitcoinKey2" | publicKey) ::
      ("tlvStream" | ChannelAnnouncementTlv.channelAnnouncementTlvCodec)

  val channelAnnouncementCodec: Codec[ChannelAnnouncement] =
    (("nodeSignature1" | bytes64) ::
      ("nodeSignature2" | bytes64) ::
      ("bitcoinSignature1" | bytes64) ::
      ("bitcoinSignature2" | bytes64) ::
      channelAnnouncementWitnessCodec).as[ChannelAnnouncement]

  val nodeAnnouncementWitnessCodec =
    ("features" | featuresCodec) ::
      ("timestamp" | timestampSecond) ::
      ("nodeId" | publicKey) ::
      ("rgbColor" | rgb) ::
      ("alias" | zeropaddedstring(32)) ::
      ("addresses" | listofnodeaddresses) ::
      ("tlvStream" | NodeAnnouncementTlv.nodeAnnouncementTlvCodec)

  val nodeAnnouncementCodec: Codec[NodeAnnouncement] =
    (("signature" | bytes64) ::
      nodeAnnouncementWitnessCodec).as[NodeAnnouncement]

  case class MessageFlags(optionChannelHtlcMax: Boolean)

  val messageFlagsCodec =
    ("messageFlags" | (ignore(7) :: bool)).as[MessageFlags]

  val reverseBool: Codec[Boolean] = bool.xmap[Boolean](b => !b, b => !b)

  /** BOLT 7 defines a 'disable' bit and a 'direction' bit, but it's easier to
    * understand if we take the reverse.
    */
  val channelFlagsCodec =
    ("channelFlags" | (ignore(6) :: reverseBool :: reverseBool))
      .as[ChannelUpdate.ChannelFlags]

  // val channelUpdateChecksumCodec defined on LightningMessageCodecsVersionCompat
  // val channelUpdateWitnessCodec defined on LightningMessageCodecsVersionCompat

  val channelUpdateCodec: Codec[ChannelUpdate] = (("signature" | bytes64) ::
    channelUpdateWitnessCodec).as[ChannelUpdate]

  val encodedShortChannelIdsCodec: Codec[EncodedShortChannelIds] =
    discriminated[EncodedShortChannelIds]
      .by(byte)
      .subcaseP(0) {
        case a @ EncodedShortChannelIds(_, Nil) =>
          a // empty list is always encoded with encoding type 'uncompressed' for compatibility with other implementations
        case a @ EncodedShortChannelIds(EncodingType.UNCOMPRESSED, _) => a
      }(
        (provide[EncodingType](EncodingType.UNCOMPRESSED) :: list(
          shortchannelid
        )).as[EncodedShortChannelIds]
      )

  val queryShortChannelIdsCodec: Codec[QueryShortChannelIds] =
    (("chainHash" | bytes32) ::
      ("shortChannelIds" | variableSizeBytes(
        uint16,
        encodedShortChannelIdsCodec
      )) ::
      ("tlvStream" | QueryShortChannelIdsTlv.codec)).as[QueryShortChannelIds]

  val replyShortChanelIdsEndCodec
      : Codec[ReplyShortChannelIdsEnd] = (("chainHash" | bytes32) ::
    ("complete" | byte) ::
    ("tlvStream" | ReplyShortChannelIdsEndTlv.replyShortChannelIdsEndTlvCodec))
    .as[ReplyShortChannelIdsEnd]

  val queryChannelRangeCodec: Codec[QueryChannelRange] =
    (("chainHash" | bytes32) ::
      ("firstBlock" | blockHeight) ::
      ("numberOfBlocks" | uint32) ::
      ("tlvStream" | QueryChannelRangeTlv.codec)).as[QueryChannelRange]

  val replyChannelRangeCodec: Codec[ReplyChannelRange] =
    (("chainHash" | bytes32) ::
      ("firstBlock" | blockHeight) ::
      ("numberOfBlocks" | uint32) ::
      ("complete" | byte) ::
      ("shortChannelIds" | variableSizeBytes(
        uint16,
        encodedShortChannelIdsCodec
      )) ::
      ("tlvStream" | ReplyChannelRangeTlv.codec)).as[ReplyChannelRange]

  val gossipTimestampFilterCodec: Codec[GossipTimestampFilter] =
    (("chainHash" | bytes32) ::
      ("firstTimestamp" | timestampSecond) ::
      ("timestampRange" | uint32) ::
      ("tlvStream" | GossipTimestampFilterTlv.gossipTimestampFilterTlvCodec))
      .as[GossipTimestampFilter]

  val unknownMessageCodec: Codec[UnknownMessage] = (
    ("tag" | uint16) ::
      ("message" | varsizebinarydata)
  ).as[UnknownMessage]

  val lightningMessageCodec = discriminated[LightningMessage]
    .by(uint16)
    .typecase(1, warningCodec)
    .typecase(16, initCodec)
    .typecase(17, errorCodec)
    .typecase(18, pingCodec)
    .typecase(19, pongCodec)
    .typecase(32, openChannelCodec)
    .typecase(33, acceptChannelCodec)
    .typecase(34, fundingCreatedCodec)
    .typecase(35, fundingSignedCodec)
    .typecase(36, fundingLockedCodec)
    .typecase(38, shutdownCodec)
    .typecase(39, closingSignedCodec)
    .typecase(128, updateAddHtlcCodec)
    .typecase(130, updateFulfillHtlcCodec)
    .typecase(131, updateFailHtlcCodec)
    .typecase(132, commitSigCodec)
    .typecase(133, revokeAndAckCodec)
    .typecase(134, updateFeeCodec)
    .typecase(135, updateFailMalformedHtlcCodec)
    .typecase(136, channelReestablishCodec)
    .typecase(256, channelAnnouncementCodec)
    .typecase(257, nodeAnnouncementCodec)
    .typecase(258, channelUpdateCodec)
    .typecase(259, announcementSignaturesCodec)
    .typecase(261, queryShortChannelIdsCodec)
    .typecase(262, replyShortChanelIdsEndCodec)
    .typecase(263, queryChannelRangeCodec)
    .typecase(264, replyChannelRangeCodec)
    .typecase(265, gossipTimestampFilterCodec)

  val lightningMessageCodecWithFallback: Codec[LightningMessage] =
    discriminatorWithDefault(lightningMessageCodec, unknownMessageCodec.upcast)
}
