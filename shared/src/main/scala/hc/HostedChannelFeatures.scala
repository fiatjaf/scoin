package scoin.hc

import scoin.ln.{Feature, InitFeature, NodeFeature}

case object HostedChannelsLegacy
    extends Feature
    with InitFeature
    with NodeFeature {
  val rfcName = "Hosted channels legacy"
  val mandatory = 32972
}

case object HostedChannels extends Feature with InitFeature with NodeFeature {
  val rfcName = "Hosted channels"
  val mandatory = 256
}
