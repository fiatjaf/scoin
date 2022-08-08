package scoin.ln

import scodec.Codec
import scodec.codecs._
import scodec.bits.{BitVector, ByteVector}

import scoin.ln.CommonCodecs._

private[scoin] trait LightningMessageCodecsVersionCompat {
  import LightningMessageCodecs._

  val channelUpdateChecksumCodec =
    ("chainHash" | bytes32) ::
      ("shortChannelId" | shortchannelid) ::
      (messageFlagsCodec
        .consume { messageFlags =>
          channelFlagsCodec ::
            ("cltvExpiryDelta" | cltvExpiryDelta) ::
            ("htlcMinimumMsat" | millisatoshi) ::
            ("feeBaseMsat" | millisatoshi32) ::
            ("feeProportionalMillionths" | uint32) ::
            ("htlcMaximumMsat" | conditional(
              messageFlags.optionChannelHtlcMax,
              millisatoshi
            ))
        } {
          // The purpose of this is to tell scodec how to derive the message flags from the data, so we can remove that field
          // from the codec definition and the case class, making it purely a serialization detail.
          case (_, _, _, _, _, htlcMaximumMsatOpt) =>
            MessageFlags(optionChannelHtlcMax = htlcMaximumMsatOpt.isDefined)
        })

  val channelUpdateWitnessCodec =
    ("chainHash" | bytes32) ::
      ("shortChannelId" | shortchannelid) ::
      ("timestamp" | timestampSecond) ::
      (messageFlagsCodec
        .consume { messageFlags =>
          channelFlagsCodec ::
            ("cltvExpiryDelta" | cltvExpiryDelta) ::
            ("htlcMinimumMsat" | millisatoshi) ::
            ("feeBaseMsat" | millisatoshi32) ::
            ("feeProportionalMillionths" | uint32) ::
            ("htlcMaximumMsat" | conditional(
              messageFlags.optionChannelHtlcMax,
              millisatoshi
            )) ::
            ("tlvStream" | ChannelUpdateTlv.channelUpdateTlvCodec)
        } {
          // same comment above
          case (_, _, _, _, _, htlcMaximumMsatOpt, _) =>
            MessageFlags(optionChannelHtlcMax = htlcMaximumMsatOpt.isDefined)
        })
}

private[scoin] trait Bolt11CodecsVersionCompat {
  def alignedBytesCodec[A](valueCodec: Codec[A]): Codec[A] = Codec[A](
    (value: A) => valueCodec.encode(value),
    (wire: BitVector) =>
      (limitedSizeBits(
        wire.size - wire.size % 8,
        valueCodec
      ) :: constant(
        BitVector.fill(wire.size % 8)(high = false)
      ))
        .map(_._1)
        .decode(wire) // the 'constant' codec ensures that padding is zero
  )
}

private[scoin] trait ChannelTypesVersionCompat {
  import ChannelTypes._

  protected val features2ChannelType
      : Map[Features[InitFeature], SupportedChannelType] =
    Set(
      Standard,
      StaticRemoteKey,
      AnchorOutputs,
      AnchorOutputsZeroFeeHtlcTx(scidAlias = false, zeroConf = false),
      AnchorOutputsZeroFeeHtlcTx(scidAlias = false, zeroConf = true),
      AnchorOutputsZeroFeeHtlcTx(scidAlias = true, zeroConf = false),
      AnchorOutputsZeroFeeHtlcTx(scidAlias = true, zeroConf = true)
    )
      .map(channelType =>
        Features(
          channelType.features.map(_ -> FeatureSupport.Mandatory).toMap
        ) -> channelType
      )
      .toMap
}
