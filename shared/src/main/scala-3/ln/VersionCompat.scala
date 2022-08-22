package scoin.ln

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
