package scoin.ln

import scala.util.{Failure, Success, Try}
import scodec.bits.ByteVector
import scodec.{Attempt, Codec, DecodeResult}

import scoin._
import scoin.Crypto.{PrivateKey, PublicKey}
import scoin.ln._

sealed trait IncomingPaymentPacket

/** Helpers to handle incoming payment packets. */
object IncomingPaymentPacket {

  /** We are the final recipient. */
  case class FinalPacket(
      add: UpdateAddHtlc,
      payload: PaymentOnion.FinalTlvPayload
  ) extends IncomingPaymentPacket

  /** We are an intermediate node. */
  sealed trait RelayPacket extends IncomingPaymentPacket

  /** We must relay the payment to a direct peer. */
  case class ChannelRelayPacket(
      add: UpdateAddHtlc,
      payload: PaymentOnion.ChannelRelayData,
      nextPacket: OnionRoutingPacket,
      nextBlindingKeyOpt: Option[PublicKey]
  ) extends RelayPacket {
    val relayFeeMsat: MilliSatoshi = add.amountMsat - payload.amountToForward
    val expiryDelta: CltvExpiryDelta = add.cltvExpiry - payload.outgoingCltv
  }

  /** We must relay the payment to a remote node. */
  case class NodeRelayPacket(
      add: UpdateAddHtlc,
      outerPayload: PaymentOnion.FinalTlvPayload,
      innerPayload: PaymentOnion.NodeRelayPayload,
      nextPacket: OnionRoutingPacket
  ) extends RelayPacket

  case class DecodedOnionPacket[T <: PaymentOnion.PacketType](
      payload: T,
      next: OnionRoutingPacket
  )

  private def decryptOnion[T <: PaymentOnion.PacketType](
      paymentHash: ByteVector32,
      privateKey: PrivateKey,
      packet: OnionRoutingPacket,
      perHopPayloadCodec: Boolean => Codec[T]
  ): Either[FailureMessage, DecodedOnionPacket[T]] =
    Sphinx.peel(privateKey, Some(paymentHash), packet) match {
      case Right(p @ Sphinx.DecryptedPacket(payload, nextPacket, _)) =>
        perHopPayloadCodec(p.isLastPacket).decode(payload.bits) match {
          case Attempt.Successful(DecodeResult(perHopPayload, _)) =>
            Right(DecodedOnionPacket(perHopPayload, nextPacket))
          case Attempt.Failure(e: OnionRoutingCodecs.MissingRequiredTlv) =>
            Left(e.failureMessage)
          case Attempt.Failure(e: OnionRoutingCodecs.ForbiddenTlv) =>
            Left(e.failureMessage)
          // Onion is correctly encrypted but the content of the per-hop payload couldn't be parsed.
          // It's hard to provide tag and offset information from scodec failures, so we currently don't do it.
          case Attempt.Failure(_) => Left(InvalidOnionPayload(UInt64(0), 0))
        }
      case Left(badOnion) => Left(badOnion)
    }

  /** Decrypt the onion packet of a received htlc. If we are the final
    * recipient, we validate that the HTLC fields match the onion fields (this
    * prevents intermediate nodes from sending an invalid amount or expiry).
    *
    * NB: we can't fully validate RelayPackets because it requires knowing the
    * channel/route we'll be using, which we don't know yet. Such validation is
    * the responsibility of downstream components.
    *
    * @param add
    *   incoming htlc
    * @param privateKey
    *   this node's private key
    * @return
    *   whether the payment is to be relayed or if our node is the final
    *   recipient (or an error).
    */
  def decrypt(
      add: UpdateAddHtlc,
      privateKey: PrivateKey
  ): Either[FailureMessage, IncomingPaymentPacket] = {
    // We first derive the decryption key used to peel the onion.
    val outerOnionDecryptionKey = add.blindingOpt match {
      case Some(blinding) =>
        Sphinx.RouteBlinding.derivePrivateKey(privateKey, blinding)
      case None => privateKey
    }
    decryptOnion(
      add.paymentHash,
      outerOnionDecryptionKey,
      add.onionRoutingPacket,
      PaymentOnionCodecs.paymentOnionPerHopPayloadCodec
    ) match {
      case Left(failure) => Left(failure)
      case Right(
            DecodedOnionPacket(payload: PaymentOnion.ChannelRelayPayload, next)
          ) =>
        payload match {
          case payload: PaymentOnion.BlindedChannelRelayPayload =>
            if (add.blindingOpt.isDefined && payload.blindingOpt.isDefined) {
              Left(InvalidOnionPayload(UInt64(12), 0))
            } else {
              add.blindingOpt.orElse(payload.blindingOpt) match {
                case Some(blinding) =>
                  RouteBlindingEncryptedDataCodecs.decode(
                    privateKey,
                    blinding,
                    payload.encryptedRecipientData,
                    RouteBlindingEncryptedDataCodecs.paymentRelayDataCodec
                  ) match {
                    case Failure(_) =>
                      // There are two possibilities in this case:
                      //  - the blinding point is invalid: the sender or the previous node is buggy or malicious
                      //  - the encrypted data is invalid: the recipient is buggy or malicious
                      // TODO: return an unparseable error
                      Left(InvalidOnionPayload(UInt64(12), 0))
                    case Success((relayData, nextBlinding)) =>
                      if (
                        isValidBlindedPayment(
                          relayData,
                          add.amountMsat,
                          add.cltvExpiry,
                          Features.empty
                        )
                      ) {
                        // TODO: If we build routes with several copies of our node at the end to hide the true length of the
                        // route, then we should add some code here to continue decrypting onions until we reach the final packet.
                        Right(
                          ChannelRelayPacket(
                            add,
                            PaymentOnion.BlindedChannelRelayData(
                              relayData,
                              add.amountMsat,
                              add.cltvExpiry
                            ),
                            next,
                            Some(nextBlinding)
                          )
                        )
                      } else {
                        // The sender is buggy or malicious, probably trying to probe the blinded route.
                        // TODO: return an unparseable error
                        Left(InvalidOnionPayload(UInt64(12), 0))
                      }
                  }
                case None =>
                  // The sender is trying to use route blinding, but we didn't receive the blinding point used to derive
                  // the decryption key. The sender or the previous peer is buggy or malicious.
                  // TODO: return an unparseable error
                  Left(InvalidOnionPayload(UInt64(12), 0))
              }
            }
          case _ if add.blindingOpt.isDefined =>
            Left(InvalidOnionPayload(UInt64(12), 0))
          // NB: we don't validate the ChannelRelayPacket here because its fees and cltv depend on what channel we'll choose to use.
          case payload: PaymentOnion.ChannelRelayTlvPayload =>
            Right(ChannelRelayPacket(add, payload, next, None))
        }
      case Right(DecodedOnionPacket(payload: PaymentOnion.FinalPayload, _)) =>
        payload match {
          case payload: PaymentOnion.FinalTlvPayload =>
            // We check if the payment is using trampoline: if it is, we may not be the final recipient.
            payload.records.get[OnionPaymentPayloadTlv.TrampolineOnion] match {
              case Some(
                    OnionPaymentPayloadTlv.TrampolineOnion(trampolinePacket)
                  ) =>
                // NB: when we enable blinded trampoline routes, we will need to check if the outer onion contains a blinding
                // point and use it to derive the decryption key for the blinded trampoline onion.
                decryptOnion(
                  add.paymentHash,
                  privateKey,
                  trampolinePacket,
                  PaymentOnionCodecs.trampolineOnionPerHopPayloadCodec
                ) match {
                  case Left(failure) => Left(failure)
                  case Right(
                        DecodedOnionPacket(
                          innerPayload: PaymentOnion.NodeRelayPayload,
                          next
                        )
                      ) =>
                    validateNodeRelay(add, payload, innerPayload, next)
                  case Right(
                        DecodedOnionPacket(
                          innerPayload: PaymentOnion.FinalTlvPayload,
                          _
                        )
                      ) =>
                    validateFinal(add, payload, innerPayload)
                  case Right(
                        DecodedOnionPacket(
                          _: PaymentOnion.BlindedFinalPayload,
                          _
                        )
                      ) =>
                    Left(
                      InvalidOnionPayload(UInt64(12), 0)
                    ) // trampoline blinded routes are not supported yet
                }
              case None => validateFinal(add, payload)
            }
          case _: PaymentOnion.BlindedFinalPayload =>
            // TODO: receiving through blinded routes is not supported yet.
            Left(InvalidOnionPayload(UInt64(12), 0))
        }
    }
  }

  private def isValidBlindedPayment(
      data: BlindedRouteData.PaymentData,
      amount: MilliSatoshi,
      cltvExpiry: CltvExpiry,
      features: Features[Feature]
  ): Boolean = {
    val amountOk = amount >= data.paymentConstraints.minAmount
    val expiryOk = cltvExpiry <= data.paymentConstraints.maxCltvExpiry
    val featuresOk = Features.areCompatible(features, data.allowedFeatures)
    amountOk && expiryOk && featuresOk
  }

  private def validateFinal(
      add: UpdateAddHtlc,
      payload: PaymentOnion.FinalTlvPayload
  ): Either[FailureMessage, IncomingPaymentPacket] = {
    if (add.amountMsat != payload.amount) {
      Left(FinalIncorrectHtlcAmount(add.amountMsat))
    } else if (add.cltvExpiry != payload.expiry) {
      Left(FinalIncorrectCltvExpiry(add.cltvExpiry))
    } else {
      Right(FinalPacket(add, payload))
    }
  }

  private def validateFinal(
      add: UpdateAddHtlc,
      outerPayload: PaymentOnion.FinalTlvPayload,
      innerPayload: PaymentOnion.FinalTlvPayload
  ): Either[FailureMessage, IncomingPaymentPacket] = {
    if (add.amountMsat != outerPayload.amount) {
      Left(FinalIncorrectHtlcAmount(add.amountMsat))
    } else if (add.cltvExpiry != outerPayload.expiry) {
      Left(FinalIncorrectCltvExpiry(add.cltvExpiry))
    } else if (outerPayload.expiry != innerPayload.expiry) {
      Left(
        FinalIncorrectCltvExpiry(add.cltvExpiry)
      ) // previous trampoline didn't forward the right expiry
    } else if (outerPayload.totalAmount != innerPayload.amount) {
      Left(
        FinalIncorrectHtlcAmount(outerPayload.totalAmount)
      ) // previous trampoline didn't forward the right amount
    } else {
      // We merge contents from the outer and inner payloads.
      // We must use the inner payload's total amount and payment secret because the payment may be split between multiple trampoline payments (#reckless).
      Right(
        FinalPacket(
          add,
          PaymentOnion.createMultiPartPayload(
            outerPayload.amount,
            innerPayload.totalAmount,
            outerPayload.expiry,
            innerPayload.paymentSecret,
            innerPayload.paymentMetadata
          )
        )
      )
    }
  }

  private def validateNodeRelay(
      add: UpdateAddHtlc,
      outerPayload: PaymentOnion.FinalTlvPayload,
      innerPayload: PaymentOnion.NodeRelayPayload,
      next: OnionRoutingPacket
  ): Either[FailureMessage, IncomingPaymentPacket] = {
    if (add.amountMsat < outerPayload.amount) {
      Left(FinalIncorrectHtlcAmount(add.amountMsat))
    } else if (add.cltvExpiry != outerPayload.expiry) {
      Left(FinalIncorrectCltvExpiry(add.cltvExpiry))
    } else {
      Right(NodeRelayPacket(add, outerPayload, innerPayload, next))
    }
  }
}
