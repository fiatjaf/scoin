package scoin.ln

import scala.util.Success
import scodec.bits._
import scoin._
import scoin.ln._
import scoin.ln.Sphinx.RouteBlinding.BlindedRoute
import utest._

object SphinxTest extends TestSuite {
  import Sphinx._
  import SphinxSpec._

  /*
  hop_shared_secret[0] = 0x53eb63ea8a3fec3b3cd433b85cd62a4b145e1dda09391b348c4e1cd36a03ea66
  hop_blinding_factor[0] = 0x2ec2e5da605776054187180343287683aa6a51b4b1c04d6dd49c45d8cffb3c36
  hop_ephemeral_pubkey[0] = 0x02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619

  hop_shared_secret[1] = 0xa6519e98832a0b179f62123b3567c106db99ee37bef036e783263602f3488fae
  hop_blinding_factor[1] = 0xbf66c28bc22e598cfd574a1931a2bafbca09163df2261e6d0056b2610dab938f
  hop_ephemeral_pubkey[1] = 0x028f9438bfbf7feac2e108d677e3a82da596be706cc1cf342b75c7b7e22bf4e6e2

  hop_shared_secret[2] = 0x3a6b412548762f0dbccce5c7ae7bb8147d1caf9b5471c34120b30bc9c04891cc
  hop_blinding_factor[2] = 0xa1f2dadd184eb1627049673f18c6325814384facdee5bfd935d9cb031a1698a5
  hop_ephemeral_pubkey[2] = 0x03bfd8225241ea71cd0843db7709f4c222f62ff2d4516fd38b39914ab6b83e0da0

  hop_shared_secret[3] = 0x21e13c2d7cfe7e18836df50872466117a295783ab8aab0e7ecc8c725503ad02d
  hop_blinding_factor[3] = 0x7cfe0b699f35525029ae0fa437c69d0f20f7ed4e3916133f9cacbb13c82ff262
  hop_ephemeral_pubkey[3] = 0x031dde6926381289671300239ea8e57ffaf9bebd05b9a5b95beaf07af05cd43595

  hop_shared_secret[4] = 0xb5756b9b542727dbafc6765a49488b023a725d631af688fc031217e90770c328
  hop_blinding_factor[4] = 0xc96e00dddaf57e7edcd4fb5954be5b65b09f17cb6d20651b4e90315be5779205
  hop_ephemeral_pubkey[4] = 0x03a214ebd875aab6ddfd77f22c5e7311d7f77f17a169e599f157bbcdae8bf071f4
   */

  val tests = Tests {
    test("generate ephemeral keys and secrets (reference test vector)") {
      val (ephkeys, sharedsecrets) =
        computeEphemeralPublicKeysAndSharedSecrets(sessionKey, publicKeys)
      assert(
        ephkeys(0) == PublicKey(
          hex"02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"
        )
      )
      assert(
        sharedsecrets(0) == ByteVector32(
          hex"53eb63ea8a3fec3b3cd433b85cd62a4b145e1dda09391b348c4e1cd36a03ea66"
        )
      )
      assert(
        ephkeys(1) == PublicKey(
          hex"028f9438bfbf7feac2e108d677e3a82da596be706cc1cf342b75c7b7e22bf4e6e2"
        )
      )
      assert(
        sharedsecrets(1) == ByteVector32(
          hex"a6519e98832a0b179f62123b3567c106db99ee37bef036e783263602f3488fae"
        )
      )
      assert(
        ephkeys(2) == PublicKey(
          hex"03bfd8225241ea71cd0843db7709f4c222f62ff2d4516fd38b39914ab6b83e0da0"
        )
      )
      assert(
        sharedsecrets(2) == ByteVector32(
          hex"3a6b412548762f0dbccce5c7ae7bb8147d1caf9b5471c34120b30bc9c04891cc"
        )
      )
      assert(
        ephkeys(3) == PublicKey(
          hex"031dde6926381289671300239ea8e57ffaf9bebd05b9a5b95beaf07af05cd43595"
        )
      )
      assert(
        sharedsecrets(3) == ByteVector32(
          hex"21e13c2d7cfe7e18836df50872466117a295783ab8aab0e7ecc8c725503ad02d"
        )
      )
      assert(
        ephkeys(4) == PublicKey(
          hex"03a214ebd875aab6ddfd77f22c5e7311d7f77f17a169e599f157bbcdae8bf071f4"
        )
      )
      assert(
        sharedsecrets(4) == ByteVector32(
          hex"b5756b9b542727dbafc6765a49488b023a725d631af688fc031217e90770c328"
        )
      )
    }

    test("generate filler") {
      val (_, sharedsecrets) =
        computeEphemeralPublicKeysAndSharedSecrets(sessionKey, publicKeys)
      val filler = generateFiller(
        "rho",
        1300,
        sharedsecrets.dropRight(1),
        referencePaymentPayloads.dropRight(1)
      )
      assert(
        filler == hex"51c30cc8f20da0153ca3839b850bcbc8fefc7fd84802f3e78cb35a660e747b57aa5b0de555cbcf1e6f044a718cc34219b96597f3684eee7a0232e1754f638006cb15a14788217abdf1bdd67910dc1ca74a05dcce8b5ad841b0f939fca8935f6a3ff660e0efb409f1a24ce4aa16fc7dc074cd84422c10cc4dd4fc150dd6d1e4f50b36ce10fef29248dd0cec85c72eb3e4b2f4a7c03b5c9e0c9dd12976553ede3d0e295f842187b33ff743e6d685075e98e1bcab8a46bff0102ca8b2098ae91798d370b01ca7076d3d626952a03663fe8dc700d1358263b73ba30e36731a0b72092f8d5bc8cd346762e93b2bf203d00264e4bc136fc142de8f7b69154deb05854ea88e2d7506222c95ba1aab06"
      )
    }

    test("is last packet") {
      val testCases = Seq(
        // Bolt 1.0 payloads use the next packet's hmac to signal termination.
        (
          true,
          DecryptedPacket(
            hex"00",
            OnionRoutingPacket(
              0,
              publicKeys.head.value,
              ByteVector.empty,
              ByteVector32.Zeroes
            ),
            ByteVector32.One
          )
        ),
        (
          false,
          DecryptedPacket(
            hex"00",
            OnionRoutingPacket(
              0,
              publicKeys.head.value,
              ByteVector.empty,
              ByteVector32.One
            ),
            ByteVector32.One
          )
        ),
        // Bolt 1.1 payloads currently also use the next packet's hmac to signal termination.
        (
          true,
          DecryptedPacket(
            hex"0101",
            OnionRoutingPacket(
              0,
              publicKeys.head.value,
              ByteVector.empty,
              ByteVector32.Zeroes
            ),
            ByteVector32.One
          )
        ),
        (
          false,
          DecryptedPacket(
            hex"0101",
            OnionRoutingPacket(
              0,
              publicKeys.head.value,
              ByteVector.empty,
              ByteVector32.One
            ),
            ByteVector32.One
          )
        ),
        (
          false,
          DecryptedPacket(
            hex"0100",
            OnionRoutingPacket(
              0,
              publicKeys.head.value,
              ByteVector.empty,
              ByteVector32.One
            ),
            ByteVector32.One
          )
        ),
        (
          false,
          DecryptedPacket(
            hex"0101",
            OnionRoutingPacket(
              0,
              publicKeys.head.value,
              ByteVector.empty,
              ByteVector32.One
            ),
            ByteVector32.One
          )
        )
      )

      for ((expected, packet) <- testCases) {
        assert(packet.isLastPacket == expected)
      }
    }

    test("bad onion") {
      val badOnions = Seq[OnionRoutingPacket](
        OnionRoutingPacket(
          1,
          ByteVector.fill(33)(0),
          ByteVector.fill(65)(1),
          ByteVector32.Zeroes
        ),
        OnionRoutingPacket(
          0,
          ByteVector.fill(33)(0),
          ByteVector.fill(65)(1),
          ByteVector32.Zeroes
        ),
        OnionRoutingPacket(
          0,
          publicKeys.head.value,
          ByteVector.fill(42)(1),
          ByteVector32(
            hex"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
          )
        )
      )

      val expected = Seq[BadOnion](
        InvalidOnionVersion(
          ByteVector32(
            hex"2f89b15c6cb0bb256d7a71b66de0d50cd3dd806f77d1cc1a3b0d86a0becd28ce"
          )
        ),
        InvalidOnionKey(
          ByteVector32(
            hex"d2602c65fc331d6ae728331ae50e602f35929312ca7a951dc5ce250031b6b999"
          )
        ),
        InvalidOnionHmac(
          ByteVector32(
            hex"3c01a86e6bc51b44a2718745fbbbc71a5c5dde5f46a489da17046c9d097bb303"
          )
        )
      )

      for ((packet, expected) <- badOnions zip expected) {
        val res = peel(privKeys.head, associatedData, packet)
        assert(res == Left(expected))
      }
    }

    test("create payment packet (reference test vector)") {
      val PacketAndSecrets(onion, sharedSecrets) = create(
        sessionKey,
        1300,
        publicKeys,
        referencePaymentPayloads,
        associatedData
      ).get
      assert(
        serializePaymentOnion(
          onion
        ) == hex"0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619f7f3416a5aa36dc7eeb3ec6d421e9615471ab870a33ac07fa5d5a51df0a8823aabe3fea3f90d387529d4f72837f9e687230371ccd8d263072206dbed0234f6505e21e282abd8c0e4f5b9ff8042800bbab065036eadd0149b37f27dde664725a49866e052e809d2b0198ab9610faa656bbf4ec516763a59f8f42c171b179166ba38958d4f51b39b3e98706e2d14a2dafd6a5df808093abfca5aeaaca16eded5db7d21fb0294dd1a163edf0fb445d5c8d7d688d6dd9c541762bf5a5123bf9939d957fe648416e88f1b0928bfa034982b22548e1a4d922690eecf546275afb233acf4323974680779f1a964cfe687456035cc0fba8a5428430b390f0057b6d1fe9a8875bfa89693eeb838ce59f09d207a503ee6f6299c92d6361bc335fcbf9b5cd44747aadce2ce6069cfdc3d671daef9f8ae590cf93d957c9e873e9a1bc62d9640dc8fc39c14902d49a1c80239b6c5b7fd91d05878cbf5ffc7db2569f47c43d6c0d27c438abff276e87364deb8858a37e5a62c446af95d8b786eaf0b5fcf78d98b41496794f8dcaac4eef34b2acfb94c7e8c32a9e9866a8fa0b6f2a06f00a1ccde569f97eec05c803ba7500acc96691d8898d73d8e6a47b8f43c3d5de74458d20eda61474c426359677001fbd75a74d7d5db6cb4feb83122f133206203e4e2d293f838bf8c8b3a29acb321315100b87e80e0edb272ee80fda944e3fb6084ed4d7f7c7d21c69d9da43d31a90b70693f9b0cc3eac74c11ab8ff655905688916cfa4ef0bd04135f2e50b7c689a21d04e8e981e74c6058188b9b1f9dfc3eec6838e9ffbcf22ce738d8a177c19318dffef090cee67e12de1a3e2a39f61247547ba5257489cbc11d7d91ed34617fcc42f7a9da2e3cf31a94a210a1018143173913c38f60e62b24bf0d7518f38b5bab3e6a1f8aeb35e31d6442c8abb5178efc892d2e787d79c6ad9e2fc271792983fa9955ac4d1d84a36c024071bc6e431b625519d556af38185601f70e29035ea6a09c8b676c9d88cf7e05e0f17098b584c4168735940263f940033a220f40be4c85344128b14beb9e75696db37014107801a59b13e89cd9d2258c169d523be6d31552c44c82ff4bb18ec9f099f3bf0e5b1bb2ba9a87d7e26f98d294927b600b5529c47e04d98956677cbcee8fa2b60f49776d8b8c367465b7c626da53700684fb6c918ead0eab8360e4f60edd25b4f43816a75ecf70f909301825b512469f8389d79402311d8aecb7b3ef8599e79485a4388d87744d899f7c47ee644361e17040a7958c8911be6f463ab6a9b2afacd688ec55ef517b38f1339efc54487232798bb25522ff4572ff68567fe830f92f7b8113efce3e98c3fffbaedce4fd8b50e41da97c0c08e423a72689cc68e68f752a5e3a9003e64e35c957ca2e1c48bb6f64b05f56b70b575ad2f278d57850a7ad568c24a4d32a3d74b29f03dc125488bc7c637da582357f40b0a52d16b3b40bb2c2315d03360bc24209e20972c200566bcf3bbe5c5b0aedd83132a8a4d5b4242ba370b6d67d9b67eb01052d132c7866b9cb502e44796d9d356e4e3cb47cc527322cd24976fe7c9257a2864151a38e568ef7a79f10d6ef27cc04ce382347a2488b1f404fdbf407fe1ca1c9d0d5649e34800e25e18951c98cae9f43555eef65fee1ea8f15828807366c3b612cd5753bf9fb8fced08855f742cddd6f765f74254f03186683d646e6f09ac2805586c7cf11998357cafc5df3f285329366f475130c928b2dceba4aa383758e7a9d20705c4bb9db619e2992f608a1ba65db254bb389468741d0502e2588aeb54390ac600c19af5c8e61383fc1bebe0029e4474051e4ef908828db9cca13277ef65db3fd47ccc2179126aaefb627719f421e20"
      )

      val DecryptedPacket(payload0, nextPacket0, sharedSecret0) =
        peel(privKeys(0), associatedData, onion).toOption.get
      val DecryptedPacket(payload1, nextPacket1, sharedSecret1) =
        peel(privKeys(1), associatedData, nextPacket0).toOption.get
      val DecryptedPacket(payload2, nextPacket2, sharedSecret2) =
        peel(privKeys(2), associatedData, nextPacket1).toOption.get
      val DecryptedPacket(payload3, nextPacket3, sharedSecret3) =
        peel(privKeys(3), associatedData, nextPacket2).toOption.get
      val DecryptedPacket(payload4, nextPacket4, sharedSecret4) =
        peel(privKeys(4), associatedData, nextPacket3).toOption.get
      assert(
        Seq(
          payload0,
          payload1,
          payload2,
          payload3,
          payload4
        ) == referencePaymentPayloads
      )
      assert(
        Seq(
          sharedSecret0,
          sharedSecret1,
          sharedSecret2,
          sharedSecret3,
          sharedSecret4
        ) == sharedSecrets.map(_._1)
      )

      val packets =
        Seq(nextPacket0, nextPacket1, nextPacket2, nextPacket3, nextPacket4)
      assert(
        packets(0).hmac == ByteVector32(
          hex"901fb2bb905d1cfac67727f900daa2bb9da6801ac31ccce78663e5021e83983b"
        )
      )
      assert(
        packets(1).hmac == ByteVector32(
          hex"2c4763d8ef214ced399c9e9ef52ca1b59abdfeb95f9035825fa3b750dfebdfd6"
        )
      )
      assert(
        packets(2).hmac == ByteVector32(
          hex"e9a00fc5e742ca4b512e0a69f7eea60163b1f1aaaaf743aa8639766a6a2e6428"
        )
      )
      assert(
        packets(3).hmac == ByteVector32(
          hex"c0a88e11af86d0ad229e02960e4ae3f7c9d708e0bbd06f49397a6fecb842c0f8"
        )
      )
      assert(
        packets(4).hmac == ByteVector32(
          hex"0000000000000000000000000000000000000000000000000000000000000000"
        )
      )
    }

    test("create payment packet with payloads filling the onion") {
      val PacketAndSecrets(onion, sharedSecrets) =
        create(
          sessionKey,
          1300,
          publicKeys,
          paymentPayloadsFull,
          associatedData
        ).get
      assert(
        serializePaymentOnion(
          onion
        ) == hex"0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f2836866196ef84350c2a76fc232b5d46d421e9615471ab9e0bc887beff8c95fdb878f7b3a7141453e5f8d22b6101810ae541ce499a09b4a9d9f80d1845c8960c85fc6d1a87bf74b2ce49922898e9353fa268086c00ae8b7f718405b72ad3829dbb38c85e02a00427eb4bdbda8fcd42b44708a9efde49cf776b75ebb389bf84d0bfbf58590e510e034572a01e409c309396778760423a8d8754c52e9a01a8f0e271cba5068bab5ee5bd0b5cd98276b0e04d60ba6a0f6bafd75ff41903ab352a1f47586eae3c6c8e437d4308766f71052b46ba2efbd87c0a781e8b3f456300fc7efbefc78ab515338666aed2070e674143c30b520b9cc1782ba8b46454db0d4ce72589cfc2eafb2db452ec98573ad08496483741de5376bfc7357fc6ea629e31236ba6ba7703014959129141a1719788ec83884f2e9151a680e2a96d2bcc67a8a2935aa11acee1f9d04812045b4ae5491220313756b5b9a0a6f867f2a95be1fab14870f04eeab694d9594620632b14ec4b424b495914f3dc587f75cd4582c113bb61e34a0fa7f79f97463be4e3c6fb99516889ed020acee419bb173d38e5ba18a00065e11fd733cf9ae46505dbb4ef70ef2f502601f4f6ee1fdb9d17435e15080e962f24760843f35bac1ac079b694ff7c347c1ed6a87f02b0758fbf00917764716c68ed7d6e6c0e75ccdb6dc7fa59554784b3ad906127ea77a6cdd814662ee7d57a939e28d77b3da47efc072436a3fd7f9c40515af8c4903764301e62b57153a5ca03ff5bb49c7dc8d3b2858100fb4aa5df7a94a271b73a76129445a3ea180d84d19029c003c164db926ed6983e5219028721a294f145e3fcc20915b8a2147efc8b5d508339f64970feee3e2da9b9c9348c1a0a4df7527d0ae3f8ae507a5beb5c73c2016ecf387a3cd8b79df80a8e9412e707cb9c761a0809a84c606a779567f9f0edf685b38c98877e90d02aedd096ed841e50abf2114ce01efbff04788fb280f870eca20c7ec353d5c381903e7d08fc57695fd79c27d43e7bd603a876068d3f1c7f45af99003e5eec7e8d8c91e395320f1fc421ef3552ea033129429383304b760c8f93de342417c3223c2112a623c3514480cdfae8ec15a99abfca71b03a8396f19edc3d5000bcfb77b5544813476b1b521345f4da396db09e783870b97bc2034bd11611db30ed2514438b046f1eb7093eceddfb1e73880786cd7b540a3896eaadd0a0692e4b19439815b5f2ec855ec8ececce889442a64037e956452a3f7b86cb3780b3e316c8dde464bc74a60a85b613f849eb0b29daf81892877bd4be9ba5997fc35544d3c2a00e5e1f45dc925607d952c6a89721bd0b6f6aec03314d667166a5b8b18471403be7018b2479aaef6c7c6c554a50a98b717dff06d50be39fb36dc03e678e0a52fc615be46b223e3bee83fa0c7c47a1f29fb94f1e9eebf6c9ecf8fc79ae847df2effb60d07aba301fc536546ec4899eedb4fec9a9bed79e3a83c4b32757745778e977e485c67c0f12bbc82c0b3bb0f4df0bd13d046fed4446f54cd85bfce55ef781a80e5f63d289d08de001237928c2a4e0c8694d0c1e68cc23f2409f30009019085e831a928e7bc5b00a1f29d25482f7fd0b6dad30e6ef8edc68ddf7db404ea7d11540fc2cee74863d64af4c945457e04b7bea0a5fb8636edadb1e1d6f2630d61062b781c1821f46eddadf269ea1fada829547590081b16bc116e074cae0224a375f2d9ce16e836687c89cd285e3b40f1e59ce2caa3d1d8cf37ee4d5e3abe7ef0afd6ffeb4fd6905677b950894863c828ab8d93519566f69fa3c2129da763bf58d9c4d2837d4d9e13821258f7e7098b34f695a589bd9eb568ba51ee3014b2d3ba1d4cf9ebaed0231ed57ecea7bd918216"
      )

      val DecryptedPacket(payload0, nextPacket0, sharedSecret0) =
        peel(privKeys(0), associatedData, onion).toOption.get
      val DecryptedPacket(payload1, nextPacket1, sharedSecret1) =
        peel(privKeys(1), associatedData, nextPacket0).toOption.get
      val DecryptedPacket(payload2, nextPacket2, sharedSecret2) =
        peel(privKeys(2), associatedData, nextPacket1).toOption.get
      val DecryptedPacket(payload3, nextPacket3, sharedSecret3) =
        peel(privKeys(3), associatedData, nextPacket2).toOption.get
      val DecryptedPacket(payload4, nextPacket4, sharedSecret4) =
        peel(privKeys(4), associatedData, nextPacket3).toOption.get
      assert(
        Seq(
          payload0,
          payload1,
          payload2,
          payload3,
          payload4
        ) == paymentPayloadsFull
      )
      assert(
        Seq(
          sharedSecret0,
          sharedSecret1,
          sharedSecret2,
          sharedSecret3,
          sharedSecret4
        ) == sharedSecrets.map(_._1)
      )

      val packets =
        Seq(nextPacket0, nextPacket1, nextPacket2, nextPacket3, nextPacket4)
      assert(
        packets(0).hmac == ByteVector32(
          hex"859cd694cf604442547246f4fae144f255e71e30cb366b9775f488cac713f0db"
        )
      )
      assert(
        packets(1).hmac == ByteVector32(
          hex"259982a8af80bd3b8018443997fa5f74c48b488fff62e531be54b887d53fe0ac"
        )
      )
      assert(
        packets(2).hmac == ByteVector32(
          hex"58110c95368305b73ae15d22b884fda0482c60993d3ba4e506e37ff5021efb13"
        )
      )
      assert(
        packets(3).hmac == ByteVector32(
          hex"f45e7099e32b8973f54cbfd1f6c48e7e0b90718ad7b00a88e1e98cebeb6d3916"
        )
      )
      assert(
        packets(4).hmac == ByteVector32(
          hex"0000000000000000000000000000000000000000000000000000000000000000"
        )
      )
    }

    test("create payment packet with single payload filling the onion") {
      val PacketAndSecrets(onion, _) = create(
        sessionKey,
        1300,
        publicKeys.take(1),
        oneHopPaymentPayload,
        associatedData
      ).get
      assert(
        serializePaymentOnion(
          onion
        ) == hex"0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f28368661918f5b235c2a76fc232b5e46d421e9615471ab9e0bc887beff8c95fdb878f7b3a7141453e5f8d22b6351810ae541ce499a09b4a9d9f80d1845c8960c85fc6d1a87bd24b2cc49922898e9353fa268086c00ae8b7f718405b72ad380cdbb38c85e02a00427eb4bdbda8fcd42b44708a9efde49cf753b75ebb389bf84d0bfbf58590e510e034572a01e409c30939e2e4a090ecc89c371820af54e06e4ad5495d4e58718385cca5414552e078fedf284fdc2cc5c070cba21a6a8d4b77525ddbc9a9fca9b2f29aac5783ee8badd709f81c73ff60556cf2ee623af073b5a84799acc1ca46b764f74b97068c7826cc0579794a540d7a55e49eac26a6930340132e946a983240b0cd1b732e305c1042f580c4b26f140fc1cab3ee6f620958e0979f85eddf586c410ce42e93a4d7c803ead45fc47cf4396d284632314d789e73cf3f534126c63fe244069d9e8a7c4f98e7e530fc588e648ef4e641364981b5377542d5e7a4aaab6d35f6df7d3a9d7ca715213599ee02c4dbea4dc78860febe1d29259c64b59b3333ffdaebbaff4e7b31c27a3791f6bf848a58df7c69bb2b1852d2ad357b9919ffdae570b27dc709fba087273d3a4de9e6a6be66db647fb6a8d1a503b3f481befb96745abf5cc4a6bba0f780d5c7759b9e303a2a6b17eb05b6e660f4c474959db183e1cae060e1639227ee0bca03978a238dc4352ed764da7d4f3ed5337f6d0376dff72615beeeeaaeef79ab93e4bcbf18cd8424eb2b6ad7f33d2b4ffd5ea08372e6ed1d984152df17e04c6f73540988d7dd979e020424a163c271151a255966be7edef42167b8facca633649739bab97572b485658cde409e5d4a0f653f1a5911141634e3d2b6079b19347df66f9820755fd517092dae62fb278b0bafcc7ad682f7921b3a455e0c6369988779e26f0458b31bffd7e4e5bfb31944e80f100b2553c3b616e75be18328dc430f6618d55cd7d0962bb916d26ed4b117c46fa29e0a112c02c36020b34a96762db628fa3490828ec2079962ad816ef20ea0bca78fb2b7f7aedd4c47e375e64294d151ff03083730336dea64934003a27730cc1c7dec5049ddba8188123dd191aa71390d43a49fb792a3da7082efa6cced73f00eccea18145fbc84925349f7b552314ab8ed4c491e392aed3b1f03eb79474c294b42e2eba1528da26450aa592cba7ea22e965c54dff0fd6fdfd6b52b9a0f5f762e27fb0e6c3cd326a1ca1c5973de9be881439f702830affeb0c034c18ac8d5c2f135c964bf69de50d6e99bde88e90321ba843d9753c8f83666105d25fafb1a11ea22d62ef6f1fc34ca4e60c35d69773a104d9a44728c08c20b6314327301a2c400a71e1424c12628cf9f4a67990ade8a2203b0edb96c6082d4673b7309cd52c4b32b02951db2f66c6c72bd6c7eac2b50b83830c75cdfc3d6e9c2b592c45ed5fa5f6ec0da85710b7e1562aea363e28665835791dc574d9a70b2e5e2b9973ab590d45b94d244fc4256926c5a55b01cd0aca21fe5f9c907691fb026d0c56788b03ca3f08db0abb9f901098dde2ec4003568bc3ca27475ff86a7cb0aabd9e5136c5de064d16774584b252024109bb02004dba1fabf9e8277de097a0ab0dc8f6e26fcd4a28fb9d27cd4a2f6b13e276ed259a39e1c7e60f3c32c5cc4c4f96bd981edcb5e2c76a517cdc285aa2ca571d1e3d463ecd7614ae227df17af7445305bd7c661cf7dba658b0adcf36b0084b74a5fa408e272f703770ac5351334709112c5d4e4fe987e0c27b670412696f52b33245c229775da550729938268ee4e7a282e4a60b25dbb28ea8877a5069f819e5d1d31d9140bbc627ff3df267d22e5f0e151db066577845d71b7cd4484089f3f59194963c8f02bd7a637"
      )

      val DecryptedPacket(payload, nextPacket, _) =
        peel(privKeys(0), associatedData, onion).toOption.get
      assert(payload == oneHopPaymentPayload.head)
      assert(
        nextPacket.hmac == ByteVector32(
          hex"0000000000000000000000000000000000000000000000000000000000000000"
        )
      )
    }

    test(
      "reject payment packet with fixed-size payloads (legacy reference test vector)"
    ) {
      val pubkey =
        hex"02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"
      val payload =
        hex"e5f14350c2a76fc232b5e46d421e9615471ab9e0bc887beff8c95fdb878f7b3a71e87f9aab8f6378c6ff744c1f34b393ad28d065b535c1a8668d85d3b34a1b3befd10f7d61ab590531cf08000178a333a347f8b4072e216400406bdf3bf038659793a1f9e7abc789266cc861cabd95818c0fc8efbdfdc14e3f7c2bc7eb8d6a79ef75ce721caad69320c3a469a202f3e468c67eaf7a7cda226d0fd32f7b48084dca885d014698cf05d742557763d9cb743faeae65dcc79dddaecf27fe5942be5380d15e9a1ec866abe044a9ad635778ba61fc0776dc832b39451bd5d35072d2269cf9b040a2a2fba158a0d8085926dc2e44f0c88bf487da56e13ef2d5e676a8589881b4869ed4c7f0218ff8c6c7dd7221d189c65b3b9aaa71a01484b122846c7c7b57e02e679ea8469b70e14fe4f70fee4d87b910cf144be6fe48eef24da475c0b0bcc6565a9f99728426ce2380a9580e2a9442481ceae7679906c30b1a0e21a10f26150e0645ab6edfdab1ce8f8bea7b1dee511c5fd38ac0e702c1c15bb86b52bca1b71e15b96982d262a442024c33ceb7dd8f949063c2e5e613e873250e2f8708bd4e1924abd45f65c2fa5617bfb10ee9e4a42d6b5811acc8029c16274f937dac9e8817c7e579fdb767ffe277f26d413ced06b620ede8362081da21cf67c2ca9d6f15fe5bc05f82f5bb93f8916bad3d63338ca824f3bbc11b57ce94a5fa1bc239533679903d6fec92a8c792fd86e2960188c14f21e399cfd72a50c620e10aefc6249360b463df9a89bf6836f4f26359207b765578e5ed76ae9f31b1cc48324be576e3d8e44d217445dba466f9b6293fdf05448584eb64f61e02903f834518622b7d4732471c6e0e22e22d1f45e31f0509eab39cdea5980a492a1da2aaac55a98a01216cd4bfe7abaa682af0fbff2dfed030ba28f1285df750e4d3477190dd193f8643b61d8ac1c427d590badb1f61a05d480908fbdc7c6f0502dd0c4abb51d725e92f95da2a8facb79881a844e2026911adcc659d1fb20a2fce63787c8bb0d9f6789c4b231c76da81c3f0718eb7156565a081d2be6b4170c0e0bcebddd459f53db2590c974bca0d705c055dee8c629bf854a5d58edc85228499ec6dde80cce4c8910b81b1e9e8b0f43bd39c8d69c3a80672729b7dc952dd9448688b6bd06afc2d2819cda80b66c57b52ccf7ac1a86601410d18d0c732f69de792e0894a9541684ef174de766fd4ce55efea8f53812867be6a391ac865802dbc26d93959df327ec2667c7256aa5a1d3c45a69a6158f285d6c97c3b8eedb09527848500517995a9eae4cd911df531544c77f5a9a2f22313e3eb72ca7a07dba243476bc926992e0d1e58b4a2fc8c7b01e0cad726237933ea319bad7537d39f3ed635d1e6c1d29e97b3d2160a09e30ee2b65ac5bce00996a73c008bcf351cecb97b6833b6d121dcf4644260b2946ea204732ac9954b228f0beaa15071930fd9583dfc466d12b5f0eeeba6dcf23d5ce8ae62ee5796359d97a4a15955c778d868d0ef9991d9f2833b5bb66119c5f8b396fd108baed7906cbb3cc376d13551caed97fece6f42a4c908ee279f1127fda1dd3ee77d8de0a6f3c135fa3f1cffe38591b6738dc97b55f0acc52be9753ce53e64d7e497bb00ca6123758df3b68fad99e35c04389f7514a8e36039f541598a417275e77869989782325a15b5342ac5011ff07af698584b476b35d941a4981eac590a07a092bb50342da5d3341f901aa07964a8d02b623c7b106dd0ae50bfa007a22d46c8772fa55558176602946cb1d11ea5460db7586fb89c6d3bcd3ab6dd20df4a4db63d2e7d52380800ad812"
      val hmac = ByteVector32(
        hex"b8640887e027e946df96488b47fbc4a4fadaa8beda4abe446fafea5403fae2ef"
      )
      val onion = OnionRoutingPacket(0, pubkey, payload, hmac)
      assert(peel(privKeys(0), associatedData, onion).isLeft)
    }

    test("create trampoline payment packet") {
      val PacketAndSecrets(onion, sharedSecrets) = create(
        sessionKey,
        400,
        publicKeys,
        trampolinePaymentPayloads,
        associatedData
      ).get
      assert(
        serializeTrampolineOnion(
          onion
        ) == hex"0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619cff34152f3a36e52ca94e74927203a560392b9cc7ce3c45809c6be52166c24a595716880f95f178bf5b30c8ca262744d656e4012980ec037cc7b35c9f43eb265ecc97974a598ff045cee0ecc99e303f3706509aa43ba7c8a88cba175fccf9a8f5016ef06d3b935dbb15196d7ce16dc1a7157845566901d7b2197e52cab4ce48701a2aa5a5249b5aed3b5b40bfefa9c40ab669d55e8a6b1058f02941bf119a7a69129db7c5f7eafaa166578c720619561dd14b3277db557ec7dcdb793771aef0f2f667cfdbe7e5b6eb3bd48bb0fbb30acc853fcdd7218ed9b6189816a7f41c5e0695f0471425951787e2ea8c5391cda7b0fe30c80913ef585234ce442808f7ef9425bcd815c3ba9114a3d48735c6283a24743b94ce93cdc9a27670398d1ee83e68dbdd71c9f39f1d635804a45faa69cfbbcb20a6d82b677ddd5b6cede1f2518dbc20f044f591fb6ea042838e7ff8514af58fc7c201ddbc6ca7c01c480f511870823384ca70e54da6006a8cb254cd68f5ab289b89c6ba512c064515c356ede847c376176339f2c9921ecc29325e613593aa2ba4ad37970adee4b3ef8427cad4cf32a37ab1dbe0e539aef146ad675cdfd96"
      )

      val DecryptedPacket(payload0, nextPacket0, sharedSecret0) =
        peel(privKeys(0), associatedData, onion).toOption.get
      val DecryptedPacket(payload1, nextPacket1, sharedSecret1) =
        peel(privKeys(1), associatedData, nextPacket0).toOption.get
      val DecryptedPacket(payload2, nextPacket2, sharedSecret2) =
        peel(privKeys(2), associatedData, nextPacket1).toOption.get
      val DecryptedPacket(payload3, nextPacket3, sharedSecret3) =
        peel(privKeys(3), associatedData, nextPacket2).toOption.get
      val DecryptedPacket(payload4, _, sharedSecret4) =
        peel(privKeys(4), associatedData, nextPacket3).toOption.get
      assert(
        Seq(
          payload0,
          payload1,
          payload2,
          payload3,
          payload4
        ) == trampolinePaymentPayloads
      )
      assert(
        Seq(
          sharedSecret0,
          sharedSecret1,
          sharedSecret2,
          sharedSecret3,
          sharedSecret4
        ) == sharedSecrets.map(_._1)
      )
    }

    test("create packet with invalid payload") {
      // In this test vector, the payload length (encoded as a varint in the first bytes) isn't equal to the actual
      // payload length.
      val incorrectVarint = Seq(
        hex"fd2a0101234567",
        hex"000000000000000000000000000000000000000000000000000000000000000000"
      )
      assert(
        create(
          sessionKey,
          1300,
          publicKeys.take(2),
          incorrectVarint,
          associatedData
        ).isFailure
      )
    }

    test("create packet with payloads too big") {
      val payloadsTooBig = Seq(
        hex"c0010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101",
        hex"c0020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202"
      )
      assert(
        create(
          sessionKey,
          400,
          publicKeys.take(2),
          payloadsTooBig,
          associatedData
        ).isFailure
      )
    }

    test("decrypt failure message") {
      val sharedSecrets = Seq(
        hex"0101010101010101010101010101010101010101010101010101010101010101",
        hex"0202020202020202020202020202020202020202020202020202020202020202",
        hex"0303030303030303030303030303030303030303030303030303030303030303"
      ).map(ByteVector32(_))

      val expected =
        DecryptedFailurePacket(
          publicKeys.head,
          InvalidOnionKey(ByteVector32.One)
        )

      val packet1 =
        FailurePacket.create(sharedSecrets.head, expected.failureMessage)
      assert(packet1.length == FailurePacket.PacketLength)

      val decrypted1 = FailurePacket
        .decrypt(
          packet1,
          Seq(0).map(i => (sharedSecrets(i), publicKeys(i)))
        )
        .get
      assert(decrypted1 == expected)

      val packet2 = FailurePacket.wrap(packet1, sharedSecrets(1))
      assert(packet2.length == FailurePacket.PacketLength)

      val decrypted2 = FailurePacket
        .decrypt(
          packet2,
          Seq(1, 0).map(i => (sharedSecrets(i), publicKeys(i)))
        )
        .get
      assert(decrypted2 == expected)

      val packet3 = FailurePacket.wrap(packet2, sharedSecrets(2))
      assert(packet3.length == FailurePacket.PacketLength)

      val decrypted3 = FailurePacket
        .decrypt(
          packet3,
          Seq(2, 1, 0).map(i => (sharedSecrets(i), publicKeys(i)))
        )
        .get
      assert(decrypted3 == expected)
    }

    test("decrypt invalid failure message") {
      val sharedSecrets = Seq(
        hex"0101010101010101010101010101010101010101010101010101010101010101",
        hex"0202020202020202020202020202020202020202020202020202020202020202",
        hex"0303030303030303030303030303030303030303030303030303030303030303"
      ).map(ByteVector32(_))

      val packet = FailurePacket.wrap(
        FailurePacket.wrap(
          FailurePacket
            .create(sharedSecrets.head, InvalidOnionPayload(UInt64(0), 0)),
          sharedSecrets(1)
        ),
        sharedSecrets(2)
      )

      assert(
        FailurePacket
          .decrypt(
            packet,
            Seq(0, 2, 1).map(i => (sharedSecrets(i), publicKeys(i)))
          )
          .isFailure
      )
    }

    test("last node replies with a failure message (reference test vector)") {
      for (
        (payloads, packetPayloadLength) <- Seq(
          (referencePaymentPayloads, 1300),
          (paymentPayloadsFull, 1300),
          (trampolinePaymentPayloads, 400)
        )
      ) {
        // route: origin -> node #0 -> node #1 -> node #2 -> node #3 -> node #4

        // origin build the onion packet
        val PacketAndSecrets(packet, sharedSecrets) = create(
          sessionKey,
          packetPayloadLength,
          publicKeys,
          payloads,
          associatedData
        ).get

        // each node parses and forwards the packet
        // node #0
        val DecryptedPacket(_, packet1, sharedSecret0) =
          peel(privKeys(0), associatedData, packet).toOption.get
        // node #1
        val DecryptedPacket(_, packet2, sharedSecret1) =
          peel(privKeys(1), associatedData, packet1).toOption.get
        // node #2
        val DecryptedPacket(_, packet3, sharedSecret2) =
          peel(privKeys(2), associatedData, packet2).toOption.get
        // node #3
        val DecryptedPacket(_, packet4, sharedSecret3) =
          peel(privKeys(3), associatedData, packet3).toOption.get
        // node #4
        val lastPacket @ DecryptedPacket(_, _, sharedSecret4) =
          peel(privKeys(4), associatedData, packet4).toOption.get
        assert(lastPacket.isLastPacket)

        // node #4 want to reply with an error message
        val error = FailurePacket.create(sharedSecret4, TemporaryNodeFailure)
        assert(
          error == hex"a5e6bd0c74cb347f10cce367f949098f2457d14c046fd8a22cb96efb30b0fdcda8cb9168b50f2fd45edd73c1b0c8b33002df376801ff58aaa94000bf8a86f92620f343baef38a580102395ae3abf9128d1047a0736ff9b83d456740ebbb4aeb3aa9737f18fb4afb4aa074fb26c4d702f42968888550a3bded8c05247e045b866baef0499f079fdaeef6538f31d44deafffdfd3afa2fb4ca9082b8f1c465371a9894dd8c243fb4847e004f5256b3e90e2edde4c9fb3082ddfe4d1e734cacd96ef0706bf63c9984e22dc98851bcccd1c3494351feb458c9c6af41c0044bea3c47552b1d992ae542b17a2d0bba1a096c78d169034ecb55b6e3a7263c26017f033031228833c1daefc0dedb8cf7c3e37c9c37ebfe42f3225c326e8bcfd338804c145b16e34e4"
        )
        // error sent back to 3, 2, 1 and 0
        val error1 = FailurePacket.wrap(error, sharedSecret3)
        assert(
          error1 == hex"c49a1ce81680f78f5f2000cda36268de34a3f0a0662f55b4e837c83a8773c22aa081bab1616a0011585323930fa5b9fae0c85770a2279ff59ec427ad1bbff9001c0cd1497004bd2a0f68b50704cf6d6a4bf3c8b6a0833399a24b3456961ba00736785112594f65b6b2d44d9f5ea4e49b5e1ec2af978cbe31c67114440ac51a62081df0ed46d4a3df295da0b0fe25c0115019f03f15ec86fabb4c852f83449e812f141a9395b3f70b766ebbd4ec2fae2b6955bd8f32684c15abfe8fd3a6261e52650e8807a92158d9f1463261a925e4bfba44bd20b166d532f0017185c3a6ac7957adefe45559e3072c8dc35abeba835a8cb01a71a15c736911126f27d46a36168ca5ef7dccd4e2886212602b181463e0dd30185c96348f9743a02aca8ec27c0b90dca270"
        )

        val error2 = FailurePacket.wrap(error1, sharedSecret2)
        assert(
          error2 == hex"a5d3e8634cfe78b2307d87c6d90be6fe7855b4f2cc9b1dfb19e92e4b79103f61ff9ac25f412ddfb7466e74f81b3e545563cdd8f5524dae873de61d7bdfccd496af2584930d2b566b4f8d3881f8c043df92224f38cf094cfc09d92655989531524593ec6d6caec1863bdfaa79229b5020acc034cd6deeea1021c50586947b9b8e6faa83b81fbfa6133c0af5d6b07c017f7158fa94f0d206baf12dda6b68f785b773b360fd0497e16cc402d779c8d48d0fa6315536ef0660f3f4e1865f5b38ea49c7da4fd959de4e83ff3ab686f059a45c65ba2af4a6a79166aa0f496bf04d06987b6d2ea205bdb0d347718b9aeff5b61dfff344993a275b79717cd815b6ad4c0beb568c4ac9c36ff1c315ec1119a1993c4b61e6eaa0375e0aaf738ac691abd3263bf937e3"
        )

        val error3 = FailurePacket.wrap(error2, sharedSecret1)
        assert(
          error3 == hex"aac3200c4968f56b21f53e5e374e3a2383ad2b1b6501bbcc45abc31e59b26881b7dfadbb56ec8dae8857add94e6702fb4c3a4de22e2e669e1ed926b04447fc73034bb730f4932acd62727b75348a648a1128744657ca6a4e713b9b646c3ca66cac02cdab44dd3439890ef3aaf61708714f7375349b8da541b2548d452d84de7084bb95b3ac2345201d624d31f4d52078aa0fa05a88b4e20202bd2b86ac5b52919ea305a8949de95e935eed0319cf3cf19ebea61d76ba92532497fcdc9411d06bcd4275094d0a4a3c5d3a945e43305a5a9256e333e1f64dbca5fcd4e03a39b9012d197506e06f29339dfee3331995b21615337ae060233d39befea925cc262873e0530408e6990f1cbd233a150ef7b004ff6166c70c68d9f8c853c1abca640b8660db2921"
        )

        val error4 = FailurePacket.wrap(error3, sharedSecret0)
        assert(
          error4 == hex"9c5add3963fc7f6ed7f148623c84134b5647e1306419dbe2174e523fa9e2fbed3a06a19f899145610741c83ad40b7712aefaddec8c6baf7325d92ea4ca4d1df8bce517f7e54554608bf2bd8071a4f52a7a2f7ffbb1413edad81eeea5785aa9d990f2865dc23b4bc3c301a94eec4eabebca66be5cf638f693ec256aec514620cc28ee4a94bd9565bc4d4962b9d3641d4278fb319ed2b84de5b665f307a2db0f7fbb757366067d88c50f7e829138fde4f78d39b5b5802f1b92a8a820865af5cc79f9f30bc3f461c66af95d13e5e1f0381c184572a91dee1c849048a647a1158cf884064deddbf1b0b88dfe2f791428d0ba0f6fb2f04e14081f69165ae66d9297c118f0907705c9c4954a199bae0bb96fad763d690e7daa6cfda59ba7f2c8d11448b604d12d"
        )

        // origin parses error packet and can see that it comes from node #4
        val DecryptedFailurePacket(pubkey, failure) =
          FailurePacket.decrypt(error4, sharedSecrets).get
        assert(pubkey == publicKeys(4))
        assert(failure == TemporaryNodeFailure)
      }
    }

    test("intermediate node replies with an invalid onion payload length") {
      // The error will not be recoverable by the sender, but we must still forward it.
      val sharedSecret = ByteVector32(
        hex"4242424242424242424242424242424242424242424242424242424242424242"
      )
      val errors = Seq(
        ByteVector.fill(FailurePacket.PacketLength - MacLength)(13),
        ByteVector.fill(FailurePacket.PacketLength + MacLength)(13)
      )

      for (error <- errors) {
        val wrapped = FailurePacket.wrap(error, sharedSecret)
        assert(wrapped.length == FailurePacket.PacketLength)
      }
    }

    test(
      "intermediate node replies with a failure message (reference test vector)"
    ) {
      for (
        (payloads, packetPayloadLength) <- Seq(
          (referencePaymentPayloads, 1300),
          (paymentPayloadsFull, 1300),
          (trampolinePaymentPayloads, 400)
        )
      ) {
        // route: origin -> node #0 -> node #1 -> node #2 -> node #3 -> node #4

        // origin build the onion packet
        val PacketAndSecrets(packet, sharedSecrets) = create(
          sessionKey,
          packetPayloadLength,
          publicKeys,
          payloads,
          associatedData
        ).get

        // each node parses and forwards the packet
        // node #0
        val DecryptedPacket(_, packet1, sharedSecret0) =
          peel(privKeys(0), associatedData, packet).toOption.get
        // node #1
        val DecryptedPacket(_, packet2, sharedSecret1) =
          peel(privKeys(1), associatedData, packet1).toOption.get
        // node #2
        val DecryptedPacket(_, _, sharedSecret2) =
          peel(privKeys(2), associatedData, packet2).toOption.get

        // node #2 want to reply with an error message
        val error = FailurePacket.create(sharedSecret2, InvalidRealm)

        // error sent back to 1 and 0
        val error1 = FailurePacket.wrap(error, sharedSecret1)
        val error2 = FailurePacket.wrap(error1, sharedSecret0)

        // origin parses error packet and can see that it comes from node #2
        val DecryptedFailurePacket(pubkey, failure) =
          FailurePacket.decrypt(error2, sharedSecrets).get
        assert(pubkey == publicKeys(2))
        assert(failure == InvalidRealm)
      }
    }

    test("decrypt onion like the old immortan does") {
      val packetPayload = ByteVector.fromValidHex(
        "18e0af2783b21a47e365f93b44497ed3d4f1ec5cd126111352bbfbcd2a2685129297ddafd145f0fd99c0cef42ed9f5a07e748a3a233c299a17513939b0320ce781f8771b5044b720956ab4726ad0cb2cafd604df739010a513bbf7c1ca2d4ff6d37d202bd9242be2fe9c1c3d4966753f07278bc7054bff1a7680cfdb2d91d507ddfad73bff37a72f82e28b145d8822292b529480be6dcebb111ec9f7520cbd2426163fbd73fc1510a7ccd73895aeddeee6520a1b29a7f7709643e45b34d3336466100ebab66ed113080a051c8234cdb4eca89ed622cc54eb7cb9fbd5085d659e0b3b6ab47a1b51e6fecdda6fc1f10b80cd250724df7e084ebfaa7c8fc860450d4921b9843b12c5a01eb12cfae5c2a34efb81b9c0429c2e45d48f1ee59ec09d5fa3e438bdc3a8b8717d46e064caea29fefb1d68db16a75a95106a21eba4297d0cdeb728239eae8d6c2637eeaf022fb4207754df21cb2d851cf85b304edbf7e40408b31981119b694b76570a99b4fba49cc4548422d0084a8b56ac13ac9cefbed2a95d4f804c6ebef08134180cbd945ae935c5ff097137af4a1ec02a939d57c12e60b188f22b7f7be9afe491f1660627dd2eeed3f3a649d6d1f2c11b3594912695eb18d99f2dd80dfef8e265bf69faad7f1bafd54d77af89ab30179348f4dead693a8efd2765dd1816868211f6e2f26fd799989d10fe9401b2b774ccd7c1c9555271056a6c8b5973898ade85703615520ed9539fbbdbd8a713cda1263e926f1eb44287fc50aa2b9a9858b536ceb505712d2f6f4f5c46f976efbf99b8d161a1f90977e9cda243609d10e0bf96013eb929361e475fe792b9d18c9800075d53386531e1739ef26ec1c4199b4ad519e7281f66b96d084cdb5c21bc850c6c0e09a5c04b58cec9e6c95a46a513f5fa97a41673a47b0f89d08a0a4201afcce8d6070a93f1ee7205b03db2c8aaa448245fd2691d3ad3a3f77e0560616728512f76a3fd641f4475ed1fc44e58aee20a4f1ca04c4d2ba832a2bbe3a694603ab5ce3dd66a9a01ab2fed866c3f4d8702ed285cfcd89d2737a77b15f6859f15e70f9c574252a0cffaff4f11ec73ad504725c0ee40bff9fcc04ad83ccf8e518f39ce972299c57aa6f81ffe44b8bb71628ba42edc3b4e151564d528003f5da2694ff791a7acc526a52fb56ce4621d02fd86fdb0dcceaec241f33fc9c35bbeff0be7cf3f697d13d0b3b3180f4a1afb3e3ca515b916e2bf6d9130be1a60f8ab6af2fdd3704ee46537b5d558b192d36637d026412c77c1935f49305b113f01024aa882e1a0f89b945a6001c40bcea6b85ab6a82f917df6dfe92ccbd0070849e457f423b6ee05a181c80595f962137ed6889e2348dcbba42e72a52f40704cb85988f12b33834a72e3d93061c7f6bea310331bb5cb4aea5a967400c858997f7a5502cb4cebf458fa6613944863d8cf7a45ef7294be8e6eec7a98d2747898550e289edc19e91c1aeb71dc5565e5be467d75963797722196f096e66496f685c5284ef4f89da5b9d87f71db32209fee9eae74957ff1337add673bd909c64710a76c85cffc3bb0a38550e3e55f885d77f20ddb1e1fbbbb4d9fdf45d0ea7cdb66ed9b627a92c9395c971e79c6461d5dabd8ed85cc177bf96bd37cb4318f345cb79219fa08c28ae638d3203dae2bb2328002df374147cf5ac63e8b632f2055c9e99843d451d8158648e6f5114405a176563203fa5d656628c0dcd709f807fd3aaf6eb3954bf6e635e45a87d19254a974718c836e0c2ff76486073b92098ee5108242d57d13a314e2a9f67bdefdafcfb5a0707fc9ee34fdd0fef9916a5c1b75684c13"
      )
      val associatedData = Some(
        ByteVector32.fromValidHex(
          "374ca90b94556511dfbf9a1ca56b0174b518bb70dd00f2f275babe31c9cac5e3"
        )
      )
      val packetEphKey = PublicKey(
        ByteVector.fromValidHex(
          "02f17cb6fb91a28f08eba06d4630dab121c0b1513329ff4f90bd9c4b9fd92fb5c6"
        )
      )
      val privateKey = PrivateKey(
        ByteVector32.fromValidHex(
          "ce4ab2525cb0dce9bb63ee550a748f43b2a47d25b7bf417c98993a1be50051ec"
        )
      )
      val sharedSecret = computeSharedSecret(packetEphKey, privateKey)
      sharedSecret.toHex ==> "ac95396f65212b936011a3121a4f3e98dd6a62a70782a4ca86e38087ee6acec5"
      val mu = generateKey("mu", sharedSecret)
      mu.toHex ==> "3f33830112874544c62068904ce060cc1b93019f377ad11353cf231020dd4b7b"
      val check = mac(
        mu,
        associatedData.map(packetPayload ++ _).getOrElse(packetPayload)
      )
      check.toHex ==> "b78952ebcddfbde383d54bbc9d85cbf01a5f9715ecb5cad137f99bf34c71f45f"
    }
  }

  object SphinxSpec {
    def serializePaymentOnion(onion: OnionRoutingPacket): ByteVector =
      PaymentOnionCodecs.paymentOnionPacketCodec
        .encode(onion)
        .require
        .toByteVector

    def serializeTrampolineOnion(onion: OnionRoutingPacket): ByteVector =
      PaymentOnionCodecs.trampolineOnionPacketCodec
        .encode(onion)
        .require
        .toByteVector

    val privKeys = Seq(
      PrivateKey(
        hex"4141414141414141414141414141414141414141414141414141414141414141"
      ),
      PrivateKey(
        hex"4242424242424242424242424242424242424242424242424242424242424242"
      ),
      PrivateKey(
        hex"4343434343434343434343434343434343434343434343434343434343434343"
      ),
      PrivateKey(
        hex"4444444444444444444444444444444444444444444444444444444444444444"
      ),
      PrivateKey(
        hex"4545454545454545454545454545454545454545454545454545454545454545"
      )
    )
    val publicKeys = privKeys.map(_.publicKey)
    assert(
      publicKeys == Seq(
        PublicKey(
          hex"02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"
        ),
        PublicKey(
          hex"0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c"
        ),
        PublicKey(
          hex"027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007"
        ),
        PublicKey(
          hex"032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991"
        ),
        PublicKey(
          hex"02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145"
        )
      )
    )

    val sessionKey: PrivateKey = PrivateKey(
      hex"4141414141414141414141414141414141414141414141414141414141414141"
    )

    // origin -> node #0 -> node #1 -> node #2 -> node #3 -> node #4
    val referencePaymentPayloads = Seq(
      hex"12 02023a98 040205dc 06080000000000000001",
      hex"52 020236b0 04020578 06080000000000000002 fd02013c0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f",
      hex"12 020230d4 040204e2 06080000000000000003",
      hex"12 02022710 040203e8 06080000000000000004",
      hex"fd0110 02022710 040203e8 082224a33562c54507a9334e79f0dc4f17d407e6d7c61f0e2f3d0d38599502f617042710 fd012de02a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
    )

    // This test vector uses multiple payloads to fill the whole onion packet.
    // origin -> node #0 -> node #1 -> node #2 -> node #3 -> node #4
    val paymentPayloadsFull = Seq(
      hex"8b09000000000000000030000000000000000000000000000000000000000000000000000000000025000000000000000000000000000000000000000000000000250000000000000000000000000000000000000000000000002500000000000000000000000000000000000000000000000025000000000000000000000000000000000000000000000000",
      hex"fd012a08000000000000009000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000200000000000000000000000000000000000000020000000000000000000000000000000000000002000000000000000000000000000000000000000200000000000000000000000000000000000000020000000000000000000000000000000000000002000000000000000000000000000000000000000200000000000000000000000000000000000000020000000000000000000000000000000000000002000000000000000000000000000000000000000",
      hex"620800000000000000900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      hex"fc120000000000000000000000240000000000000000000000000000000000000000000000240000000000000000000000000000000000000000000000240000000000000000000000000000000000000000000000240000000000000000000000000000000000000000000000240000000000000000000000000000000000000000000000240000000000000000000000000000000000000000000000240000000000000000000000000000000000000000000000240000000000000000000000000000000000000000000000240000000000000000000000000000000000000000000000240000000000000000000000000000000000000000000000",
      hex"fd01582200000000000000000000000000000000000000000022000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000"
    )

    // This test vector uses a single payload filling the whole onion payload.
    // origin -> recipient
    val oneHopPaymentPayload = Seq(
      hex"fd04f16500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    )

    // This test vector uses trampoline variable-size payloads.
    val trampolinePaymentPayloads = Seq(
      hex"2a 02020231 040190 f8210324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c",
      hex"35 fa 33 010000000000000000000000040000000000000000000000000ff0000000000000000000000000000000000000000000000000",
      hex"23 f8 21 032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
      hex"40 0306030303030303 2b06000000000003 2d020003 2f0a00000000000000000000 311e000000000000000000000000000000000000000000000000000000000000",
      hex"23 f8 21 02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"
    )

    // This test vector uses route blinding payloads (encrypted_data).
    val routeBlindingPayloads = Seq(
      hex"0208000000000000002a 0a06009000000000 0c0c000badf80000000000002328 3903123456",
      hex"01020000 02080000000000000231 0a0800900000000103e8 0c0c000badd80000000000001f40 3b00 fdffff0206c1",
      hex"010a00000000000000000000 02080000000000000451 0a08012c0000006403e8 0c0c000bad740000000000001b58",
      hex"010a00000000000000000000 02080000000000000982 0a080062000002a301e9 0c0c000bad420000000000001770",
      hex"06204242424242424242424242424242424242424242424242424242424242424242 0c0c000bac480000000000001388"
    )

    val associatedData = Some(
      ByteVector32(
        hex"4242424242424242424242424242424242424242424242424242424242424242"
      )
    )
  }
}
