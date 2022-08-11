package codecs

import java.nio.{ByteBuffer, ByteOrder}
import java.nio.charset.StandardCharsets
import scala.scalanative.unsigned._
import scodec.bits._
import scodec.codecs._
import scodec.Codec
import scoin._
import scoin.ln._
import scoin.ln.TlvCodecs._
import scoin.ln.CommonCodecs._
import scoin.Crypto.{PublicKey, PrivateKey}

import codecs.HostedChannelTags._
import codecs.HostedChannelCodecs._

sealed trait HostedClientMessage
sealed trait HostedServerMessage
sealed trait HostedGossipMessage
sealed trait HostedPreimageMessage
sealed trait ChannelModifier
    extends HostedClientMessage
    with HostedServerMessage

case class InvokeHostedChannel(
    chainHash: ByteVector32,
    refundScriptPubKey: ByteVector,
    secret: ByteVector = ByteVector.empty
) extends HostedClientMessage {
  val finalSecret: ByteVector = secret.take(128)
  override def toString(): String = s"InvokeHostedChannel()"
}

case class InitHostedChannel(
    maxHtlcValueInFlightMsat: ULong,
    htlcMinimumMsat: MilliSatoshi,
    maxAcceptedHtlcs: Int,
    channelCapacityMsat: MilliSatoshi,
    initialClientBalanceMsat: MilliSatoshi,
    features: List[Int] = Nil
) extends HostedServerMessage {
  override def toString(): String =
    s"InitHostedChannel(${channelCapacityMsat})"
}

case class HostedChannelBranding(
    rgbColor: Color,
    pngIcon: Option[ByteVector],
    contactInfo: String
) extends HostedServerMessage

object LastCrossSignedState {
  def empty = LastCrossSignedState(
    isHost = false,
    refundScriptPubKey = ByteVector.empty,
    initHostedChannel = InitHostedChannel(
      maxHtlcValueInFlightMsat = 0.toULong,
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
}

case class LastCrossSignedState(
    isHost: Boolean,
    refundScriptPubKey: ByteVector,
    initHostedChannel: InitHostedChannel,
    blockDay: Long,
    localBalanceMsat: MilliSatoshi,
    remoteBalanceMsat: MilliSatoshi,
    localUpdates: Long,
    remoteUpdates: Long,
    incomingHtlcs: List[UpdateAddHtlc],
    outgoingHtlcs: List[UpdateAddHtlc],
    remoteSigOfLocal: ByteVector64,
    localSigOfRemote: ByteVector64
) extends HostedServerMessage
    with HostedClientMessage {
  override def toString(): String =
    s"LastCrossSignedState($blockDay, balances=${localBalanceMsat}/${remoteBalanceMsat}, updates=$localUpdates/$remoteUpdates, incomingHtlcs=$incomingHtlcs, outgoingHtlcs=$outgoingHtlcs)"

  def isEmpty: Boolean = initHostedChannel.channelCapacityMsat.toLong == 0

  lazy val reverse: LastCrossSignedState =
    copy(
      isHost = !isHost,
      localUpdates = remoteUpdates,
      remoteUpdates = localUpdates,
      localBalanceMsat = remoteBalanceMsat,
      remoteBalanceMsat = localBalanceMsat,
      remoteSigOfLocal = localSigOfRemote,
      localSigOfRemote = remoteSigOfLocal,
      incomingHtlcs = outgoingHtlcs,
      outgoingHtlcs = incomingHtlcs
    )

  lazy val hostedSigHash: ByteVector32 = {
    val inPayments = incomingHtlcs.map(add =>
      LightningMessageCodecs.updateAddHtlcCodec
        .encode(add)
        .require
        .toByteVector
    )
    val outPayments = outgoingHtlcs.map(add =>
      LightningMessageCodecs.updateAddHtlcCodec
        .encode(add)
        .require
        .toByteVector
    )
    val hostFlag = if (isHost) 1 else 0

    val message = refundScriptPubKey ++
      Protocol.writeUInt64(
        initHostedChannel.channelCapacityMsat.toLong,
        ByteOrder.LITTLE_ENDIAN
      ) ++
      Protocol.writeUInt64(
        initHostedChannel.initialClientBalanceMsat.toLong,
        ByteOrder.LITTLE_ENDIAN
      ) ++
      Protocol.writeUInt32(blockDay, ByteOrder.LITTLE_ENDIAN) ++
      Protocol
        .writeUInt64(localBalanceMsat.toLong, ByteOrder.LITTLE_ENDIAN) ++
      Protocol
        .writeUInt64(remoteBalanceMsat.toLong, ByteOrder.LITTLE_ENDIAN) ++
      Protocol.writeUInt32(localUpdates, ByteOrder.LITTLE_ENDIAN) ++
      Protocol.writeUInt32(remoteUpdates, ByteOrder.LITTLE_ENDIAN) ++
      inPayments.foldLeft(ByteVector.empty) { case (acc, htlc) =>
        acc ++ htlc
      } ++
      outPayments.foldLeft(ByteVector.empty) { case (acc, htlc) =>
        acc ++ htlc
      } :+
      hostFlag.toByte

    Crypto.sha256(message)
  }

  def verifyRemoteSig(pubkey: PublicKey): Boolean =
    Crypto.verifySignature(hostedSigHash, remoteSigOfLocal, pubkey)

  def withCurrentBlockDay(blockDay: Long): LastCrossSignedState =
    copy(blockDay = blockDay)

  def withLocalSigOfRemote(priv: PrivateKey): LastCrossSignedState =
    copy(localSigOfRemote = Crypto.sign(reverse.hostedSigHash, priv))

  def stateUpdate: StateUpdate =
    StateUpdate(blockDay, localUpdates, remoteUpdates, localSigOfRemote)

  def stateOverride: StateOverride =
    StateOverride(
      blockDay,
      localBalanceMsat,
      localUpdates,
      remoteUpdates,
      localSigOfRemote
    )
}

case class StateUpdate(
    blockDay: Long,
    localUpdates: Long,
    remoteUpdates: Long,
    localSigOfRemoteLCSS: ByteVector64
) extends HostedServerMessage
    with HostedClientMessage {
  override def toString(): String =
    s"StateUpdate($blockDay, updates=$localUpdates/$remoteUpdates)"
}

case class StateOverride(
    blockDay: Long,
    localBalanceMsat: MilliSatoshi,
    localUpdates: Long,
    remoteUpdates: Long,
    localSigOfRemoteLCSS: ByteVector64
) extends HostedServerMessage

case class AnnouncementSignature(
    nodeSignature: ByteVector64,
    wantsReply: Boolean
) extends HostedGossipMessage

case class ResizeChannel(
    newCapacity: Satoshi,
    clientSig: ByteVector64 = ByteVector64.Zeroes
) extends HostedClientMessage {
  def isRemoteResized(remote: LastCrossSignedState): Boolean =
    newCapacity.toMilliSatoshi == remote.initHostedChannel.channelCapacityMsat

  def sign(priv: PrivateKey): ResizeChannel = ResizeChannel(
    clientSig = Crypto.sign(Crypto.sha256(sigMaterial), priv),
    newCapacity = newCapacity
  )

  def verifyClientSig(pubKey: PublicKey): Boolean =
    Crypto.verifySignature(Crypto.sha256(sigMaterial), clientSig, pubKey)

  lazy val sigMaterial: ByteVector = {
    val bin = new Array[Byte](8)
    val buffer = ByteBuffer.wrap(bin).order(ByteOrder.LITTLE_ENDIAN)
    buffer.putLong(newCapacity.toLong)
    ByteVector.view(bin)
  }
  lazy val newCapacityMsatU64: ULong = newCapacity.toMilliSatoshi.toLong.toULong
}

case class AskBrandingInfo(chainHash: ByteVector32) extends HostedClientMessage

case class QueryPublicHostedChannels(chainHash: ByteVector32)
    extends HostedGossipMessage {}

case class ReplyPublicHostedChannelsEnd(chainHash: ByteVector32)
    extends HostedGossipMessage {}

// Queries
case class QueryPreimages(hashes: List[ByteVector32] = Nil)
    extends HostedPreimageMessage {}

case class ReplyPreimages(preimages: List[ByteVector32] = Nil)
    extends HostedPreimageMessage {}

object HostedError {
  final val ERR_HOSTED_WRONG_BLOCKDAY = "0001"
  final val ERR_HOSTED_WRONG_LOCAL_SIG = "0002"
  final val ERR_HOSTED_WRONG_REMOTE_SIG = "0003"
  final val ERR_HOSTED_CLOSED_BY_REMOTE_PEER = "0004"
  final val ERR_HOSTED_TIMED_OUT_OUTGOING_HTLC = "0005"
  final val ERR_HOSTED_HTLC_EXTERNAL_FULFILL = "0006"
  final val ERR_HOSTED_CHANNEL_DENIED = "0007"
  final val ERR_HOSTED_MANUAL_SUSPEND = "0008"
  final val ERR_HOSTED_INVALID_RESIZE = "0009"
  final val ERR_MISSING_CHANNEL = "0010"

  val knownHostedCodes: Map[String, String] = Map(
    ERR_HOSTED_WRONG_BLOCKDAY -> "ERR_HOSTED_WRONG_BLOCKDAY",
    ERR_HOSTED_WRONG_LOCAL_SIG -> "ERR_HOSTED_WRONG_LOCAL_SIG",
    ERR_HOSTED_WRONG_REMOTE_SIG -> "ERR_HOSTED_WRONG_REMOTE_SIG",
    ERR_HOSTED_CLOSED_BY_REMOTE_PEER -> "ERR_HOSTED_CLOSED_BY_REMOTE_PEER",
    ERR_HOSTED_TIMED_OUT_OUTGOING_HTLC -> "ERR_HOSTED_TIMED_OUT_OUTGOING_HTLC",
    ERR_HOSTED_HTLC_EXTERNAL_FULFILL -> "ERR_HOSTED_HTLC_EXTERNAL_FULFILL",
    ERR_HOSTED_CHANNEL_DENIED -> "ERR_HOSTED_CHANNEL_DENIED",
    ERR_HOSTED_MANUAL_SUSPEND -> "ERR_HOSTED_MANUAL_SUSPEND",
    ERR_HOSTED_INVALID_RESIZE -> "ERR_HOSTED_INVALID_RESIZE",
    ERR_MISSING_CHANNEL -> "ERR_MISSING_CHANNEL"
  )
}
