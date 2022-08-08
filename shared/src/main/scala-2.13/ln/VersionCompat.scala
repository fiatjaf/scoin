package scoin.ln

import scodec.Codec
import scodec.codecs._
import scodec.bits.{BitVector, ByteVector}
import shapeless._

import scoin.ln.CommonCodecs._

private[scoin] trait LightningMessageCodecsVersionCompat {
  import LightningMessageCodecs._

  val channelUpdateChecksumCodec =
    ("chainHash" | bytes32) ::
      ("shortChannelId" | shortchannelid) ::
      (messageFlagsCodec >>:~ { messageFlags =>
        channelFlagsCodec ::
          ("cltvExpiryDelta" | cltvExpiryDelta) ::
          ("htlcMinimumMsat" | millisatoshi) ::
          ("feeBaseMsat" | millisatoshi32) ::
          ("feeProportionalMillionths" | uint32) ::
          ("htlcMaximumMsat" | conditional(
            messageFlags.optionChannelHtlcMax,
            millisatoshi
          ))
      }).derive[MessageFlags].from {
        // The purpose of this is to tell scodec how to derive the message flags from the data, so we can remove that field
        // from the codec definition and the case class, making it purely a serialization detail.
        // see: https://github.com/scodec/scodec/blob/series/1.11.x/unitTests/src/test/scala/scodec/examples/ProductsExample.scala#L108-L127
        case _ :: _ :: _ :: _ :: _ :: htlcMaximumMsat_opt :: HNil =>
          MessageFlags(optionChannelHtlcMax = htlcMaximumMsat_opt.isDefined)
      }

  val channelUpdateWitnessCodec =
    (("chainHash" | bytes32) ::
      ("shortChannelId" | shortchannelid) ::
      ("timestamp" | timestampSecond) ::
      (messageFlagsCodec >>:~ { messageFlags =>
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
      })).derive[MessageFlags].from {
      // same comment above
      case _ :: _ :: _ :: _ :: _ :: _ :: _ :: _ :: htlcMaximumMsat_opt :: _ :: HNil =>
        MessageFlags(optionChannelHtlcMax = htlcMaximumMsat_opt.isDefined)
    }
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
        .map { case v :: _ :: shapeless.HNil => v }
        .decode(wire) // the 'constant' codec ensures that padding is zero
  )
}

private[scoin] trait ChannelTypesVersionCompat {
  import ChannelTypes._

  protected val features2ChannelType
      : Map[Features[_ <: InitFeature], SupportedChannelType] = Set(
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
