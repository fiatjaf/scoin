package scoin.ln

import java.nio.charset.StandardCharsets
import scala.util.Try
import scodec.bits.ByteVector
import com.comcast.ip4s.{Ipv4Address, Ipv6Address, IpAddress}

import scoin._

// @formatter:off
trait LightningMessage extends Serializable
sealed trait SetupMessage extends LightningMessage
sealed trait ChannelMessage extends LightningMessage
sealed trait HtlcMessage extends LightningMessage
sealed trait RoutingMessage extends LightningMessage
sealed trait AnnouncementMessage extends RoutingMessage // <- not in the spec
sealed trait HasTimestamp extends LightningMessage { def timestamp: TimestampSecond }
sealed trait HasTemporaryChannelId extends LightningMessage { def temporaryChannelId: ByteVector32 } // <- not in the spec
sealed trait HasChannelId extends LightningMessage { def channelId: ByteVector32 } // <- not in the spec
sealed trait HasChainHash extends LightningMessage { def chainHash: ByteVector32 } // <- not in the spec
sealed trait UpdateMessage extends HtlcMessage // <- not in the spec
sealed trait HtlcSettlementMessage extends UpdateMessage { def id: Long } // <- not in the spec
// @formatter:on

case class Init(
    features: Features[InitFeature],
    tlvStream: TlvStream[InitTlv] = TlvStream.empty
) extends SetupMessage {
  val networks =
    tlvStream.get[InitTlv.Networks].map(_.chainHashes).getOrElse(Nil)
  val remoteAddressOpt = tlvStream.get[InitTlv.RemoteAddress].map(_.address)
}

case class Warning(
    channelId: ByteVector32,
    data: ByteVector,
    tlvStream: TlvStream[WarningTlv] = TlvStream.empty
) extends SetupMessage
    with HasChannelId {
  val isGlobal: Boolean = channelId == ByteVector32.Zeroes
  def toAscii: String =
    if (data.toArray.forall(ch => ch >= 32 && ch < 127))
      new String(data.toArray, StandardCharsets.US_ASCII)
    else "n/a"
  def asText: String = new String(data.toArray, StandardCharsets.UTF_8)
}

object Warning {
  def apply(channelId: ByteVector32, msg: String): Warning =
    Warning(channelId, ByteVector.view(msg.getBytes(StandardCharsets.US_ASCII)))
  def apply(msg: String): Warning = Warning(
    ByteVector32.Zeroes,
    ByteVector.view(msg.getBytes(StandardCharsets.US_ASCII))
  )
}

case class Error(
    channelId: ByteVector32,
    data: ByteVector,
    tlvStream: TlvStream[ErrorTlv] = TlvStream.empty
) extends SetupMessage
    with HasChannelId {
  def toAscii: String =
    if (data.toArray.forall(ch => ch >= 32 && ch < 127))
      new String(data.toArray, StandardCharsets.US_ASCII)
    else "n/a"
  def asText: String = new String(data.toArray, StandardCharsets.UTF_8)
}

object Error {
  def apply(channelId: ByteVector32, msg: String): Error =
    Error(channelId, ByteVector.view(msg.getBytes(StandardCharsets.US_ASCII)))
}

case class Ping(
    pongLength: Int,
    data: ByteVector,
    tlvStream: TlvStream[PingTlv] = TlvStream.empty
) extends SetupMessage

case class Pong(
    data: ByteVector,
    tlvStream: TlvStream[PongTlv] = TlvStream.empty
) extends SetupMessage

case class ChannelReestablish(
    channelId: ByteVector32,
    nextLocalCommitmentNumber: Long,
    nextRemoteRevocationNumber: Long,
    yourLastPerCommitmentSecret: PrivateKey,
    myCurrentPerCommitmentPoint: PublicKey,
    tlvStream: TlvStream[ChannelReestablishTlv] = TlvStream.empty
) extends ChannelMessage
    with HasChannelId

case class OpenChannel(
    chainHash: ByteVector32,
    temporaryChannelId: ByteVector32,
    fundingSatoshis: Satoshi,
    pushMsat: MilliSatoshi,
    dustLimitSatoshis: Satoshi,
    maxHtlcValueInFlightMsat: UInt64, // this is not MilliSatoshi because it can exceed the total amount of MilliSatoshi
    channelReserveSatoshis: Satoshi,
    htlcMinimumMsat: MilliSatoshi,
    feeratePerKw: FeeratePerKw,
    toSelfDelay: CltvExpiryDelta,
    maxAcceptedHtlcs: Int,
    fundingPubkey: PublicKey,
    revocationBasepoint: PublicKey,
    paymentBasepoint: PublicKey,
    delayedPaymentBasepoint: PublicKey,
    htlcBasepoint: PublicKey,
    firstPerCommitmentPoint: PublicKey,
    channelFlags: OpenChannel.ChannelFlags,
    tlvStream: TlvStream[OpenChannelTlv] = TlvStream.empty
) extends ChannelMessage
    with HasTemporaryChannelId
    with HasChainHash {
  val upfrontShutdownScriptOpt: Option[ByteVector] =
    tlvStream.get[ChannelTlv.UpfrontShutdownScriptTlv].map(_.script)
}

object OpenChannel {
  case class ChannelFlags(announceChannel: Boolean)
}

case class AcceptChannel(
    temporaryChannelId: ByteVector32,
    dustLimitSatoshis: Satoshi,
    maxHtlcValueInFlightMsat: UInt64, // this is not MilliSatoshi because it can exceed the total amount of MilliSatoshi
    channelReserveSatoshis: Satoshi,
    htlcMinimumMsat: MilliSatoshi,
    minimumDepth: Long,
    toSelfDelay: CltvExpiryDelta,
    maxAcceptedHtlcs: Int,
    fundingPubkey: PublicKey,
    revocationBasepoint: PublicKey,
    paymentBasepoint: PublicKey,
    delayedPaymentBasepoint: PublicKey,
    htlcBasepoint: PublicKey,
    firstPerCommitmentPoint: PublicKey,
    tlvStream: TlvStream[AcceptChannelTlv] = TlvStream.empty
) extends ChannelMessage
    with HasTemporaryChannelId {
  val upfrontShutdownScriptOpt: Option[ByteVector] =
    tlvStream.get[ChannelTlv.UpfrontShutdownScriptTlv].map(_.script)
}

case class FundingCreated(
    temporaryChannelId: ByteVector32,
    fundingTxid: ByteVector32,
    fundingOutputIndex: Int,
    signature: ByteVector64,
    tlvStream: TlvStream[FundingCreatedTlv] = TlvStream.empty
) extends ChannelMessage
    with HasTemporaryChannelId

case class FundingSigned(
    channelId: ByteVector32,
    signature: ByteVector64,
    tlvStream: TlvStream[FundingSignedTlv] = TlvStream.empty
) extends ChannelMessage
    with HasChannelId

case class FundingLocked(
    channelId: ByteVector32,
    nextPerCommitmentPoint: PublicKey,
    tlvStream: TlvStream[FundingLockedTlv] = TlvStream.empty
) extends ChannelMessage
    with HasChannelId

case class Shutdown(
    channelId: ByteVector32,
    scriptPubKey: ByteVector,
    tlvStream: TlvStream[ShutdownTlv] = TlvStream.empty
) extends ChannelMessage
    with HasChannelId

case class ClosingSigned(
    channelId: ByteVector32,
    feeSatoshis: Satoshi,
    signature: ByteVector64,
    tlvStream: TlvStream[ClosingSignedTlv] = TlvStream.empty
) extends ChannelMessage
    with HasChannelId {
  val feeRangeOpt = tlvStream.get[ClosingSignedTlv.FeeRange]
}

case class UpdateAddHtlc(
    channelId: ByteVector32,
    id: Long,
    amountMsat: MilliSatoshi,
    paymentHash: ByteVector32,
    cltvExpiry: CltvExpiry,
    onionRoutingPacket: OnionRoutingPacket,
    tlvStream: TlvStream[UpdateAddHtlcTlv] = TlvStream.empty
) extends HtlcMessage
    with UpdateMessage
    with HasChannelId {
  val blindingOpt: Option[PublicKey] =
    tlvStream.get[UpdateAddHtlcTlv.BlindingPoint].map(_.publicKey)
}

case class UpdateFulfillHtlc(
    channelId: ByteVector32,
    id: Long,
    paymentPreimage: ByteVector32,
    tlvStream: TlvStream[UpdateFulfillHtlcTlv] = TlvStream.empty
) extends HtlcMessage
    with UpdateMessage
    with HasChannelId
    with HtlcSettlementMessage {
  lazy val paymentHash: ByteVector32 = Crypto.sha256(paymentPreimage)
}

case class UpdateFailHtlc(
    channelId: ByteVector32,
    id: Long,
    reason: ByteVector,
    tlvStream: TlvStream[UpdateFailHtlcTlv] = TlvStream.empty
) extends HtlcMessage
    with UpdateMessage
    with HasChannelId
    with HtlcSettlementMessage

case class UpdateFailMalformedHtlc(
    channelId: ByteVector32,
    id: Long,
    onionHash: ByteVector32,
    failureCode: Int,
    tlvStream: TlvStream[UpdateFailMalformedHtlcTlv] = TlvStream.empty
) extends HtlcMessage
    with UpdateMessage
    with HasChannelId
    with HtlcSettlementMessage

case class CommitSig(
    channelId: ByteVector32,
    signature: ByteVector64,
    htlcSignatures: List[ByteVector64],
    tlvStream: TlvStream[CommitSigTlv] = TlvStream.empty
) extends HtlcMessage
    with HasChannelId

case class RevokeAndAck(
    channelId: ByteVector32,
    perCommitmentSecret: PrivateKey,
    nextPerCommitmentPoint: PublicKey,
    tlvStream: TlvStream[RevokeAndAckTlv] = TlvStream.empty
) extends HtlcMessage
    with HasChannelId

case class UpdateFee(
    channelId: ByteVector32,
    feeratePerKw: FeeratePerKw,
    tlvStream: TlvStream[UpdateFeeTlv] = TlvStream.empty
) extends ChannelMessage
    with UpdateMessage
    with HasChannelId

case class AnnouncementSignatures(
    channelId: ByteVector32,
    shortChannelId: ShortChannelId,
    nodeSignature: ByteVector64,
    bitcoinSignature: ByteVector64,
    tlvStream: TlvStream[AnnouncementSignaturesTlv] = TlvStream.empty
) extends RoutingMessage
    with HasChannelId

case class ChannelAnnouncement(
    nodeSignature1: ByteVector64,
    nodeSignature2: ByteVector64,
    bitcoinSignature1: ByteVector64,
    bitcoinSignature2: ByteVector64,
    features: Features[Feature],
    chainHash: ByteVector32,
    shortChannelId: ShortChannelId,
    nodeId1: PublicKey,
    nodeId2: PublicKey,
    bitcoinKey1: PublicKey,
    bitcoinKey2: PublicKey,
    tlvStream: TlvStream[ChannelAnnouncementTlv] = TlvStream.empty
) extends RoutingMessage
    with AnnouncementMessage
    with HasChainHash

case class Color(r: Byte, g: Byte, b: Byte) {
  override def toString: String =
    f"#$r%02x$g%02x$b%02x" // to hexa s"#  ${r}%02x ${r & 0xFF}${g & 0xFF}${b & 0xFF}"
}

sealed trait NodeAddress {
  def host: String; def port: Int;
  override def toString: String = s"$host:$port"
}
sealed trait OnionAddress extends NodeAddress
sealed trait IPAddress extends NodeAddress

object NodeAddress {
  def fromParts(host: String, port: Int): Try[NodeAddress] = Try {
    host match {
      case _ if host.endsWith(".onion") && host.length == 22 =>
        Tor2(host.dropRight(6), port)
      case _ if host.endsWith(".onion") && host.length == 62 =>
        Tor3(host.dropRight(6), port)
      case _ => IPAddress(IpAddress.fromString(host).get, port)
    }
  }
}

object IPAddress {
  def apply(ipAddress: IpAddress, port: Int): IPAddress =
    ipAddress match {
      case address: Ipv4Address => IPv4(address, port)
      case address: Ipv6Address => IPv6(address, port)
    }
}

case class IPv4(ipv4: Ipv4Address, port: Int) extends IPAddress {
  override def host: String = ipv4.toString()
}
case class IPv6(ipv6: Ipv6Address, port: Int) extends IPAddress {
  override def host: String = ipv6.toString()
}
case class Tor2(tor2: String, port: Int) extends OnionAddress {
  override def host: String = tor2 + ".onion"
}
case class Tor3(tor3: String, port: Int) extends OnionAddress {
  override def host: String = tor3 + ".onion"
}

case class NodeAnnouncement(
    signature: ByteVector64,
    features: Features[Feature],
    timestamp: TimestampSecond,
    nodeId: PublicKey,
    rgbColor: Color,
    alias: String,
    addresses: List[NodeAddress],
    tlvStream: TlvStream[NodeAnnouncementTlv] = TlvStream.empty
) extends RoutingMessage
    with AnnouncementMessage
    with HasTimestamp

case class ChannelUpdate(
    signature: ByteVector64,
    chainHash: ByteVector32,
    shortChannelId: ShortChannelId,
    timestamp: TimestampSecond,
    channelFlags: ChannelUpdate.ChannelFlags,
    cltvExpiryDelta: CltvExpiryDelta,
    htlcMinimumMsat: MilliSatoshi,
    feeBaseMsat: MilliSatoshi,
    feeProportionalMillionths: Long,
    htlcMaximumMsat: MilliSatoshi,
    tlvStream: TlvStream[ChannelUpdateTlv] = TlvStream.empty
) extends RoutingMessage
    with AnnouncementMessage
    with HasTimestamp
    with HasChainHash {

  def messageFlags: Byte = 1

  def toStringShort: String =
    s"cltvExpiryDelta=$cltvExpiryDelta,feeBase=$feeBaseMsat,feeProportionalMillionths=$feeProportionalMillionths"
}

object ChannelUpdate {
  case class ChannelFlags(isEnabled: Boolean, isNode1: Boolean)
  case class Checksum(
      chainHash: ByteVector32,
      shortChannelId: ShortChannelId,
      channelFlags: ChannelUpdate.ChannelFlags,
      cltvExpiryDelta: CltvExpiryDelta,
      htlcMinimumMsat: MilliSatoshi,
      feeBaseMsat: MilliSatoshi,
      feeProportionalMillionths: Long,
      htlcMaximumMsat: MilliSatoshi
  )
}

sealed trait EncodingType
object EncodingType {
  case object UNCOMPRESSED extends EncodingType
  case object COMPRESSED_ZLIB extends EncodingType
}

case class EncodedShortChannelIds(
    encoding: EncodingType,
    array: List[ShortChannelId]
) {

  /** custom toString because it can get huge in logs */
  override def toString: String =
    s"EncodedShortChannelIds($encoding,${array.headOption
        .getOrElse("")}->${array.lastOption.getOrElse("")} size=${array.size})"
}

case class QueryShortChannelIds(
    chainHash: ByteVector32,
    shortChannelIds: EncodedShortChannelIds,
    tlvStream: TlvStream[QueryShortChannelIdsTlv] = TlvStream.empty
) extends RoutingMessage
    with HasChainHash {
  val queryFlagsOpt: Option[QueryShortChannelIdsTlv.EncodedQueryFlags] =
    tlvStream.get[QueryShortChannelIdsTlv.EncodedQueryFlags]
}

case class ReplyShortChannelIdsEnd(
    chainHash: ByteVector32,
    complete: Byte,
    tlvStream: TlvStream[ReplyShortChannelIdsEndTlv] = TlvStream.empty
) extends RoutingMessage
    with HasChainHash

case class QueryChannelRange(
    chainHash: ByteVector32,
    firstBlock: BlockHeight,
    numberOfBlocks: Long,
    tlvStream: TlvStream[QueryChannelRangeTlv] = TlvStream.empty
) extends RoutingMessage {
  val queryFlagsOpt: Option[QueryChannelRangeTlv.QueryFlags] =
    tlvStream.get[QueryChannelRangeTlv.QueryFlags]
}

case class ReplyChannelRange(
    chainHash: ByteVector32,
    firstBlock: BlockHeight,
    numberOfBlocks: Long,
    syncComplete: Byte,
    shortChannelIds: EncodedShortChannelIds,
    tlvStream: TlvStream[ReplyChannelRangeTlv] = TlvStream.empty
) extends RoutingMessage {
  val timestampsOpt: Option[ReplyChannelRangeTlv.EncodedTimestamps] =
    tlvStream.get[ReplyChannelRangeTlv.EncodedTimestamps]
  val checksumsOpt: Option[ReplyChannelRangeTlv.EncodedChecksums] =
    tlvStream.get[ReplyChannelRangeTlv.EncodedChecksums]
}

object ReplyChannelRange {
  def apply(
      chainHash: ByteVector32,
      firstBlock: BlockHeight,
      numberOfBlocks: Long,
      syncComplete: Byte,
      shortChannelIds: EncodedShortChannelIds,
      timestamps: Option[ReplyChannelRangeTlv.EncodedTimestamps],
      checksums: Option[ReplyChannelRangeTlv.EncodedChecksums]
  ): ReplyChannelRange = {
    timestamps.foreach(ts =>
      require(ts.timestamps.length == shortChannelIds.array.length)
    )
    checksums.foreach(cs =>
      require(cs.checksums.length == shortChannelIds.array.length)
    )
    new ReplyChannelRange(
      chainHash,
      firstBlock,
      numberOfBlocks,
      syncComplete,
      shortChannelIds,
      TlvStream(timestamps.toList ::: checksums.toList)
    )
  }
}

case class GossipTimestampFilter(
    chainHash: ByteVector32,
    firstTimestamp: TimestampSecond,
    timestampRange: Long,
    tlvStream: TlvStream[GossipTimestampFilterTlv] = TlvStream.empty
) extends RoutingMessage
    with HasChainHash

case class UnknownMessage(tag: Int, data: ByteVector) extends LightningMessage
