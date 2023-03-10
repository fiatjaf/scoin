package scoin.hc

import java.nio.{ByteBuffer, ByteOrder}
import java.nio.charset.StandardCharsets
import scodec.bits._
import scodec.codecs._
import scodec.Codec

import scoin._
import scoin.ln._
import scoin.ln.TlvCodecs._
import scoin.CommonCodecs._
import scoin.hc.HostedChannelCodecs._

sealed trait HostedChannelMessage extends LightningMessage

case class InvokeHostedChannel(
    chainHash: ByteVector32,
    refundScriptPubKey: ByteVector,
    secret: ByteVector = ByteVector.empty
) extends HostedChannelMessage {
  val finalSecret: ByteVector = secret.take(128)
  override def toString(): String = {
    val chainHashFirstChars = chainHash.toHex.take(6)
    val secretFirstChars =
      if (secret.size > 0) secret.toHex.take(6) else "<no-secret>"
    s"InvokeHostedChannel($chainHashFirstChars / $secretFirstChars)"
  }
}

case class InitHostedChannel(
    maxHtlcValueInFlight: MilliSatoshi,
    htlcMinimum: MilliSatoshi,
    maxAcceptedHtlcs: Int,
    channelCapacity: MilliSatoshi,
    initialClientBalance: MilliSatoshi,
    features: List[Int] = Nil
) extends HostedChannelMessage {
  override def toString(): String =
    s"InitHostedChannel(${channelCapacity})"
}

case class HostedChannelBranding(
    rgbColor: Color,
    pngIcon: Option[ByteVector],
    contactInfo: String
) extends HostedChannelMessage

case class LastCrossSignedState(
    isHost: Boolean,
    refundScriptPubKey: ByteVector,
    initHostedChannel: InitHostedChannel,
    blockDay: Long,
    localBalance: MilliSatoshi,
    remoteBalance: MilliSatoshi,
    localUpdates: Long,
    remoteUpdates: Long,
    incomingHtlcs: List[UpdateAddHtlc],
    outgoingHtlcs: List[UpdateAddHtlc],
    remoteSigOfLocal: ByteVector64,
    localSigOfRemote: ByteVector64
) extends HostedChannelMessage {
  override def toString(): String =
    s"LastCrossSignedState($blockDay, balances=${localBalance}/${remoteBalance}, updates=$localUpdates/$remoteUpdates, incomingHtlcs=$incomingHtlcs, outgoingHtlcs=$outgoingHtlcs)"

  def isEmpty: Boolean = initHostedChannel.channelCapacity.toLong == 0

  lazy val reverse: LastCrossSignedState =
    copy(
      isHost = !isHost,
      localUpdates = remoteUpdates,
      remoteUpdates = localUpdates,
      localBalance = remoteBalance,
      remoteBalance = localBalance,
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
        initHostedChannel.channelCapacity.toLong,
        ByteOrder.LITTLE_ENDIAN
      ) ++
      Protocol.writeUInt64(
        initHostedChannel.initialClientBalance.toLong,
        ByteOrder.LITTLE_ENDIAN
      ) ++
      Protocol.writeUInt32(blockDay, ByteOrder.LITTLE_ENDIAN) ++
      Protocol
        .writeUInt64(localBalance.toLong, ByteOrder.LITTLE_ENDIAN) ++
      Protocol
        .writeUInt64(remoteBalance.toLong, ByteOrder.LITTLE_ENDIAN) ++
      Protocol.writeUInt32(localUpdates, ByteOrder.LITTLE_ENDIAN) ++
      Protocol.writeUInt32(remoteUpdates, ByteOrder.LITTLE_ENDIAN) ++
      ByteVector.concat(inPayments) ++
      ByteVector.concat(outPayments) ++
      ByteVector.view(Array(hostFlag.toByte))

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
      localBalance,
      localUpdates,
      remoteUpdates,
      localSigOfRemote
    )
}

object LastCrossSignedState {
  def empty = LastCrossSignedState(
    isHost = false,
    refundScriptPubKey = ByteVector.empty,
    initHostedChannel = InitHostedChannel(
      maxHtlcValueInFlight = MilliSatoshi(0),
      htlcMinimum = MilliSatoshi(0),
      maxAcceptedHtlcs = 0,
      channelCapacity = MilliSatoshi(0),
      initialClientBalance = MilliSatoshi(0)
    ),
    blockDay = 0,
    localBalance = MilliSatoshi(0),
    remoteBalance = MilliSatoshi(0),
    localUpdates = 0,
    remoteUpdates = 0,
    incomingHtlcs = List.empty,
    outgoingHtlcs = List.empty,
    remoteSigOfLocal = ByteVector64.Zeroes,
    localSigOfRemote = ByteVector64.Zeroes
  )
}

case class StateUpdate(
    blockDay: Long,
    localUpdates: Long,
    remoteUpdates: Long,
    localSigOfRemoteLCSS: ByteVector64
) extends HostedChannelMessage {
  override def toString(): String =
    s"StateUpdate($blockDay, updates=$localUpdates/$remoteUpdates)"
}

case class StateOverride(
    blockDay: Long,
    localBalance: MilliSatoshi,
    localUpdates: Long,
    remoteUpdates: Long,
    localSigOfRemoteLCSS: ByteVector64
) extends HostedChannelMessage

case class AnnouncementSignature(
    nodeSignature: ByteVector64,
    wantsReply: Boolean
) extends HostedChannelMessage

case class ResizeChannel(
    newCapacity: Satoshi,
    clientSig: ByteVector64 = ByteVector64.Zeroes
) extends HostedChannelMessage {
  def isRemoteResized(remote: LastCrossSignedState): Boolean =
    newCapacity.toMilliSatoshi == remote.initHostedChannel.channelCapacity

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
}

case class AskBrandingInfo(chainHash: ByteVector32) extends HostedChannelMessage

case class QueryPublicHostedChannels(chainHash: ByteVector32)
    extends HostedChannelMessage {}

case class ReplyPublicHostedChannelsEnd(chainHash: ByteVector32)
    extends HostedChannelMessage {}

// Queries
case class QueryPreimages(hashes: List[ByteVector32] = Nil)
    extends HostedChannelMessage {}

case class ReplyPreimages(preimages: List[ByteVector32] = Nil)
    extends HostedChannelMessage {}
