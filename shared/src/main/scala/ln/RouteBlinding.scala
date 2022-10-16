package scoin.ln

import scala.util.Try
import scodec.Attempt
import scodec.bits.ByteVector

import scoin._
import scoin.CommonCodecs.{cltvExpiry, cltvExpiryDelta}
import scoin.Crypto.{PrivateKey, PublicKey}
import scoin.ln._
import scoin.ln.LightningMessageCodecs.featuresCodec
import scoin.ln.OnionRoutingCodecs.{ForbiddenTlv, MissingRequiredTlv}
import scoin.ln.TlvCodecs.{tmillisatoshi, tmillisatoshi32}

sealed trait RouteBlindingEncryptedDataTlv extends Tlv

object RouteBlindingEncryptedDataTlv {

  /** Some padding can be added to ensure all payloads are the same size to
    * improve privacy.
    */
  case class Padding(dummy: ByteVector) extends RouteBlindingEncryptedDataTlv

  /** Id of the outgoing channel, used to identify the next node. */
  case class OutgoingChannelId(shortChannelId: ShortChannelId)
      extends RouteBlindingEncryptedDataTlv

  /** Id of the next node. */
  case class OutgoingNodeId(nodeId: PublicKey)
      extends RouteBlindingEncryptedDataTlv

  /** The final recipient may store some data in the encrypted payload for
    * itself to avoid storing it locally. It can for example put a payment_hash
    * to verify that the route is used for the correct invoice. It should use
    * that field to detect when blinded routes are used outside of their
    * intended use (malicious probing) and react accordingly (ignore the message
    * or send an error depending on the use-case).
    */
  case class PathId(data: ByteVector) extends RouteBlindingEncryptedDataTlv

  /** Blinding override for the rest of the route. */
  case class NextBlinding(blinding: PublicKey)
      extends RouteBlindingEncryptedDataTlv

  /** Information for the relaying node to build the next HTLC. */
  case class PaymentRelay(
      cltvExpiryDelta: CltvExpiryDelta,
      feeProportionalMillionths: Long,
      feeBase: MilliSatoshi
  ) extends RouteBlindingEncryptedDataTlv

  /** Constraints for the relaying node to enforce to prevent probing. */
  case class PaymentConstraints(
      maxCltvExpiry: CltvExpiry,
      minAmount: MilliSatoshi
  ) extends RouteBlindingEncryptedDataTlv

  /** Blinded routes constrain the features that can be used by relaying nodes
    * to prevent probing. Without this mechanism nodes supporting features that
    * aren't widely supported could easily be identified.
    */
  case class AllowedFeatures(features: Features[Feature])
      extends RouteBlindingEncryptedDataTlv

}

object BlindedRouteData {

  import RouteBlindingEncryptedDataTlv._

  sealed trait Data {
    val records: TlvStream[RouteBlindingEncryptedDataTlv]
  }

  /** Data contained in the encrypted data tlv stream when used for onion
    * messages.
    */
  sealed trait MessageData extends Data

  /** Data contained in the encrypted data tlv stream when used for payments. */
  sealed trait PaymentData extends Data {
    val paymentConstraints: PaymentConstraints =
      records.get[PaymentConstraints].get
    val allowedFeatures: Features[Feature] =
      records.get[AllowedFeatures].map(_.features).getOrElse(Features.empty)
  }

  case class MessageRelayData(records: TlvStream[RouteBlindingEncryptedDataTlv])
      extends MessageData {
    val nextNodeId: PublicKey = records.get[OutgoingNodeId].get.nodeId
    val nextBlindingOpt: Option[PublicKey] =
      records.get[NextBlinding].map(_.blinding)
  }

  case class MessageRecipientData(
      records: TlvStream[RouteBlindingEncryptedDataTlv]
  ) extends MessageData {
    val pathIdOpt: Option[ByteVector] = records.get[PathId].map(_.data)
  }

  case class PaymentRelayData(records: TlvStream[RouteBlindingEncryptedDataTlv])
      extends PaymentData {
    private val paymentRelay: PaymentRelay = records.get[PaymentRelay].get
    val outgoingChannelId: ShortChannelId =
      records.get[OutgoingChannelId].get.shortChannelId

    def amountToForward(amountReceived: MilliSatoshi): MilliSatoshi =
      MilliSatoshi(
        (amountReceived - paymentRelay.feeBase).toLong * 1_000_000 +
          1_000_000 +
          paymentRelay.feeProportionalMillionths -
          1
      ) / (1_000_000 + paymentRelay.feeProportionalMillionths)

    def outgoingCltv(incomingCltv: CltvExpiry): CltvExpiry =
      incomingCltv - paymentRelay.cltvExpiryDelta
  }

  case class PaymentRecipientData(
      records: TlvStream[RouteBlindingEncryptedDataTlv]
  ) extends PaymentData {
    val pathIdOpt: Option[ByteVector] = records.get[PathId].map(_.data)
  }

}

object RouteBlindingEncryptedDataCodecs {
  import BlindedRouteData._
  import RouteBlindingEncryptedDataTlv._
  import scoin.CommonCodecs.{publickey, shortchannelid, varint, varintoverflow}
  import scodec.Codec
  import scodec.codecs._

  private val padding: Codec[Padding] =
    variableSizeBytesLong(varintoverflow, "padding" | bytes).as[Padding]
  private val outgoingChannelId: Codec[OutgoingChannelId] =
    variableSizeBytesLong(varintoverflow, "short_channel_id" | shortchannelid)
      .as[OutgoingChannelId]
  private val outgoingNodeId: Codec[OutgoingNodeId] =
    (("length" | constant(
      ByteVector.fromValidHex("21")
    )) :: ("node_id" | publickey))
      .as[OutgoingNodeId]
  private val pathId: Codec[PathId] =
    variableSizeBytesLong(varintoverflow, "path_id" | bytes).as[PathId]
  private val nextBlinding: Codec[NextBlinding] =
    (("length" | constant(
      ByteVector.fromValidHex("21")
    )) :: ("blinding" | publickey))
      .as[NextBlinding]
  private val paymentRelay: Codec[PaymentRelay] = variableSizeBytesLong(
    varintoverflow,
    ("cltv_expiry_delta" | cltvExpiryDelta) ::
      ("fee_proportional_millionths" | uint32) ::
      ("fee_base_msat" | tmillisatoshi32)
  ).as[PaymentRelay]
  private val paymentConstraints: Codec[PaymentConstraints] =
    variableSizeBytesLong(
      varintoverflow,
      ("max_cltv_expiry" | cltvExpiry) ::
        ("htlc_minimum_msat" | tmillisatoshi)
    ).as[PaymentConstraints]
  private val allowedFeatures: Codec[AllowedFeatures] =
    variableSizeBytesLong(varintoverflow, featuresCodec).as[AllowedFeatures]

  private val encryptedDataTlvCodec =
    discriminated[RouteBlindingEncryptedDataTlv]
      .by(varint)
      .typecase(UInt64(1), padding)
      .typecase(UInt64(2), outgoingChannelId)
      .typecase(UInt64(4), outgoingNodeId)
      .typecase(UInt64(6), pathId)
      .typecase(UInt64(8), nextBlinding)
      .typecase(UInt64(10), paymentRelay)
      .typecase(UInt64(12), paymentConstraints)
      .typecase(UInt64(14), allowedFeatures)

  private val blindedRouteDataCodec = TlvCodecs
    .tlvStream[RouteBlindingEncryptedDataTlv](encryptedDataTlvCodec)
    .complete

  val messageRelayDataCodec: Codec[MessageRelayData] =
    blindedRouteDataCodec.narrow(
      {
        case tlvs if tlvs.get[OutgoingNodeId].isEmpty =>
          Attempt.failure(MissingRequiredTlv(UInt64(4)))
        case tlvs if tlvs.get[PathId].isDefined =>
          Attempt.failure(ForbiddenTlv(UInt64(6)))
        case tlvs if tlvs.get[PaymentRelay].isDefined =>
          Attempt.failure(ForbiddenTlv(UInt64(10)))
        case tlvs if tlvs.get[PaymentConstraints].isDefined =>
          Attempt.failure(ForbiddenTlv(UInt64(12)))
        case tlvs => Attempt.successful(MessageRelayData(tlvs))
      },
      { case MessageRelayData(tlvs) =>
        tlvs
      }
    )

  val messageRecipientDataCodec: Codec[MessageRecipientData] =
    blindedRouteDataCodec.narrow(
      {
        case tlvs if tlvs.get[PaymentRelay].isDefined =>
          Attempt.failure(ForbiddenTlv(UInt64(10)))
        case tlvs if tlvs.get[PaymentConstraints].isDefined =>
          Attempt.failure(ForbiddenTlv(UInt64(12)))
        case tlvs => Attempt.successful(MessageRecipientData(tlvs))
      },
      { case MessageRecipientData(tlvs) =>
        tlvs
      }
    )

  val paymentRelayDataCodec: Codec[PaymentRelayData] =
    blindedRouteDataCodec.narrow(
      {
        case tlvs if tlvs.get[OutgoingChannelId].isEmpty =>
          Attempt.failure(MissingRequiredTlv(UInt64(2)))
        case tlvs if tlvs.get[PaymentRelay].isEmpty =>
          Attempt.failure(MissingRequiredTlv(UInt64(10)))
        case tlvs if tlvs.get[PaymentConstraints].isEmpty =>
          Attempt.failure(MissingRequiredTlv(UInt64(12)))
        case tlvs if tlvs.get[PathId].isDefined =>
          Attempt.failure(ForbiddenTlv(UInt64(6)))
        case tlvs => Attempt.successful(PaymentRelayData(tlvs))
      },
      { case PaymentRelayData(tlvs) =>
        tlvs
      }
    )

  val paymentRecipientDataCodec: Codec[PaymentRecipientData] =
    blindedRouteDataCodec.narrow(
      {
        case tlvs if tlvs.get[PaymentConstraints].isEmpty =>
          Attempt.failure(MissingRequiredTlv(UInt64(12)))
        case tlvs => Attempt.successful(PaymentRecipientData(tlvs))
      },
      { case PaymentRecipientData(tlvs) =>
        tlvs
      }
    )

  /** Decrypt and decode the contents of an encrypted_recipient_data TLV field.
    *
    * @param nodePrivKey
    *   this node's private key.
    * @param blindingKey
    *   blinding point (usually provided in the lightning message).
    * @param encryptedData
    *   encrypted route blinding data (usually provided inside an onion).
    * @param encryptedDataCodec
    *   codec to parse the decrypted data.
    * @return
    *   decrypted contents of the encrypted recipient data, which usually
    *   contain information about the next node, and the blinding point that
    *   should be sent to the next node.
    */
  def decode[T <: BlindedRouteData.Data](
      nodePrivKey: PrivateKey,
      blindingKey: PublicKey,
      encryptedData: ByteVector,
      encryptedDataCodec: Codec[T]
  ): Try[(T, PublicKey)] = {
    Sphinx.RouteBlinding
      .decryptPayload(nodePrivKey, blindingKey, encryptedData)
      .flatMap { case (payload, nextBlindingKey) =>
        encryptedDataCodec
          .decode(payload.bits)
          .map(r => (r.value, nextBlindingKey))
          .toTry
      }
  }

}
