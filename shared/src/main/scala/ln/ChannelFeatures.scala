package scoin.ln

import scoin.ln.transactions.Transactions.{
  CommitmentFormat,
  DefaultCommitmentFormat,
  UnsafeLegacyAnchorOutputsCommitmentFormat,
  ZeroFeeHtlcTxAnchorOutputsCommitmentFormat
}
import scoin.ln.{
  ChannelTypeFeature,
  FeatureSupport,
  Features,
  InitFeature,
  PermanentChannelFeature
}

/** Subset of Bolt 9 features used to configure a channel and applicable over
  * the lifetime of that channel. Even if one of these features is later
  * disabled at the connection level, it will still apply to the channel until
  * the channel is upgraded or closed.
  */
case class ChannelFeatures(features: Set[PermanentChannelFeature]) {
  val channelType: SupportedChannelType = {
    if (hasFeature(Features.AnchorOutputsZeroFeeHtlcTx)) {
      ChannelTypes.AnchorOutputsZeroFeeHtlcTx(
        scidAlias = features.contains(Features.ScidAlias),
        zeroConf = features.contains(Features.ZeroConf)
      )
    } else if (hasFeature(Features.AnchorOutputs)) {
      ChannelTypes.AnchorOutputs
    } else if (hasFeature(Features.StaticRemoteKey)) {
      ChannelTypes.StaticRemoteKey
    } else {
      ChannelTypes.Standard
    }
  }

  val paysDirectlyToWallet: Boolean = channelType.paysDirectlyToWallet
  val commitmentFormat: CommitmentFormat = channelType.commitmentFormat

  def hasFeature(feature: PermanentChannelFeature): Boolean =
    features.contains(feature)

  override def toString: String = features.mkString(",")

}

object ChannelFeatures {
  def apply(features: PermanentChannelFeature*): ChannelFeatures =
    ChannelFeatures(Set.from(features))

  /** Enrich the channel type with other permanent features that will be applied
    * to the channel.
    */
  def apply(
      channelType: SupportedChannelType,
      localFeatures: Features[InitFeature],
      remoteFeatures: Features[InitFeature],
      announceChannel: Boolean
  ): ChannelFeatures = {
    val additionalPermanentFeatures = Features.knownFeatures.collect {
      // If we both support 0-conf or scid_alias, we use it even if it wasn't in the channel-type.
      case Features.ScidAlias
          if Features.canUseFeature(
            localFeatures,
            remoteFeatures,
            Features.ScidAlias
          ) && !announceChannel =>
        Some(Features.ScidAlias)
      case Features.ZeroConf
          if Features.canUseFeature(
            localFeatures,
            remoteFeatures,
            Features.ZeroConf
          ) =>
        Some(Features.ZeroConf)
      // Other channel-type features are negotiated in the channel-type, we ignore their value from the init message.
      case _: ChannelTypeFeature => None
      // We add all other permanent channel features that aren't negotiated as part of the channel-type.
      case f: PermanentChannelFeature
          if Features.canUseFeature(localFeatures, remoteFeatures, f) =>
        Some(f)
    }.flatten
    val allPermanentFeatures =
      channelType.features.toSeq ++ additionalPermanentFeatures
    ChannelFeatures(allPermanentFeatures: _*)
  }

}

/** A channel type is a specific set of even feature bits that represent
  * persistent channel features as defined in Bolt 2.
  */
sealed trait ChannelType {
  /* Features representing that channel type. */
  def features: Set[ChannelTypeFeature]
}

sealed trait SupportedChannelType extends ChannelType {
  /* Known channel-type features */
  override def features: Set[ChannelTypeFeature]

  /** True if our main output in the remote commitment is directly sent (without
    * any delay) to one of our wallet addresses.
    */
  def paysDirectlyToWallet: Boolean

  /** Format of the channel transactions. */
  def commitmentFormat: CommitmentFormat
}

object ChannelTypes extends ChannelTypesVersionCompat {
  case object Standard extends SupportedChannelType {
    override def features: Set[ChannelTypeFeature] = Set.empty
    override def paysDirectlyToWallet: Boolean = false
    override def commitmentFormat: CommitmentFormat = DefaultCommitmentFormat
    override def toString: String = "standard"
  }
  case object StaticRemoteKey extends SupportedChannelType {
    override def features: Set[ChannelTypeFeature] = Set(
      Features.StaticRemoteKey
    )
    override def paysDirectlyToWallet: Boolean = true
    override def commitmentFormat: CommitmentFormat = DefaultCommitmentFormat
    override def toString: String = "static_remotekey"
  }
  case object AnchorOutputs extends SupportedChannelType {
    override def features: Set[ChannelTypeFeature] =
      Set(Features.StaticRemoteKey, Features.AnchorOutputs)
    override def paysDirectlyToWallet: Boolean = false
    override def commitmentFormat: CommitmentFormat =
      UnsafeLegacyAnchorOutputsCommitmentFormat
    override def toString: String = "anchor_outputs"
  }
  case class AnchorOutputsZeroFeeHtlcTx(scidAlias: Boolean, zeroConf: Boolean)
      extends SupportedChannelType {
    override def features: Set[ChannelTypeFeature] = Set(
      if (scidAlias) Some(Features.ScidAlias) else None,
      if (zeroConf) Some(Features.ZeroConf) else None,
      Some(Features.StaticRemoteKey),
      Some(Features.AnchorOutputsZeroFeeHtlcTx)
    ).flatten
    override def paysDirectlyToWallet: Boolean = false
    override def commitmentFormat: CommitmentFormat =
      ZeroFeeHtlcTxAnchorOutputsCommitmentFormat
    override def toString: String =
      s"anchor_outputs_zero_fee_htlc_tx${if (scidAlias) "+scid_alias" else ""}${if (zeroConf) "+zeroconf" else ""}"
  }
  case class UnsupportedChannelType(featureBits: Features[InitFeature])
      extends ChannelType {
    override def features: Set[ChannelTypeFeature] =
      featureBits.activated.keySet
        .filter(_.isInstanceOf[ChannelTypeFeature])
        .map(_.asInstanceOf[ChannelTypeFeature])
    override def toString: String = s"0x${featureBits.toByteVector.toHex}"
  }

  // protected val features2ChannelType : Map[Features[InitFeature], SupportedChannelType] defined in ChannelFeaturesVersionCompat

  // NB: Bolt 2: features must exactly match in order to identify a channel type.
  def fromFeatures(features: Features[InitFeature]): ChannelType =
    features2ChannelType.getOrElse(features, UnsupportedChannelType(features))

  /** Pick the channel type based on local and remote feature bits, as defined
    * by the spec.
    */
  def defaultFromFeatures(
      localFeatures: Features[InitFeature],
      remoteFeatures: Features[InitFeature],
      announceChannel: Boolean
  ): SupportedChannelType = {
    def canUse(feature: InitFeature): Boolean =
      Features.canUseFeature(localFeatures, remoteFeatures, feature)

    if (canUse(Features.AnchorOutputsZeroFeeHtlcTx)) {
      AnchorOutputsZeroFeeHtlcTx(
        scidAlias = canUse(Features.ScidAlias) && !announceChannel,
        zeroConf = canUse(Features.ZeroConf)
      ) // alias feature is incompatible with public channel
    } else if (canUse(Features.AnchorOutputs)) {
      AnchorOutputs
    } else if (canUse(Features.StaticRemoteKey)) {
      StaticRemoteKey
    } else {
      Standard
    }
  }

  /** Check if a given channel type is compatible with our features. */
  def areCompatible(
      localFeatures: Features[InitFeature],
      remoteChannelType: ChannelType
  ): Option[SupportedChannelType] = remoteChannelType match {
    case _: UnsupportedChannelType => None
    // We ensure that we support the features necessary for this channel type.
    case proposedChannelType: SupportedChannelType =>
      if (
        proposedChannelType.features.forall(f => localFeatures.hasFeature(f))
      ) {
        Some(proposedChannelType)
      } else {
        None
      }
  }
}