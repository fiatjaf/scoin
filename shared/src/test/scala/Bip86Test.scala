package scoin

import scoin._
import utest._
import scodec.bits._
import scoin.DeterministicWallet.KeyPath

object Bip86Test extends TestSuite {
  // https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
  // https://github.com/ACINQ/bitcoin-kmp/pull/40/commits/49bdc91ad284c85f5fe56bf07b4d4d962cd0f79f
  val tests = Tests {
    test("BIP86 reference test") {
      val seed = MnemonicCode.toSeed(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
          .split(" "),
        ""
      )
      val master = DeterministicWallet.generate(seed)
      assertEquals(
        DeterministicWallet.encode(master, DeterministicWallet.xprv),
        "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
      )
      assertEquals(
        DeterministicWallet.encode(
          DeterministicWallet.publicKey(master),
          DeterministicWallet.xpub
        ),
        "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8"
      )
      val accountKey =
        DeterministicWallet.derivePrivateKey(master, KeyPath("m/86'/0'/0'"))
      assertEquals(
        DeterministicWallet.encode(accountKey, DeterministicWallet.xprv),
        "xprv9xgqHN7yz9MwCkxsBPN5qetuNdQSUttZNKw1dcYTV4mkaAFiBVGQziHs3NRSWMkCzvgjEe3n9xV8oYywvM8at9yRqyaZVz6TYYhX98VjsUk"
      )
      assertEquals(
        DeterministicWallet.encode(
          DeterministicWallet.publicKey(accountKey),
          DeterministicWallet.xpub
        ),
        "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ"
      )

      val key = DeterministicWallet.derivePrivateKey(accountKey, List(0L, 0L))
      assertEquals(
        key.secretkeybytes,
        DeterministicWallet
          .derivePrivateKey(master, KeyPath("m/86'/0'/0'/0/0"))
          .secretkeybytes
      )
      val internalKey = key.publicKey.xonly
      assertEquals(
        internalKey.value,
        ByteVector32.fromValidHex(
          "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
        )
      )
      val outputKey = internalKey.tapTweak(merkleRoot = None)._1
      assertEquals(
        outputKey.value,
        ByteVector32.fromValidHex(
          "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
        )
      )
      val script = List(OP_1, OP_PUSHDATA(outputKey.value))
      assertEquals(
        Script.write(script),
        ByteVector.fromValidHex(
          "5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
        )
      )

      val key1 = DeterministicWallet.derivePrivateKey(accountKey, List(0L, 1L))
      assertEquals(
        key1.secretkeybytes,
        DeterministicWallet
          .derivePrivateKey(master, KeyPath("m/86'/0'/0'/0/1"))
          .secretkeybytes
      )
      val internalKey1 = key1.publicKey.xonly
      assertEquals(
        internalKey1.value,
        ByteVector32.fromValidHex(
          "83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145"
        )
      )
      val outputKey1 = internalKey1.tapTweak(merkleRoot = None)._1
      assertEquals(
        outputKey1.value,
        ByteVector32.fromValidHex(
          "a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb"
        )
      )
      val script1 = List(OP_1, OP_PUSHDATA(outputKey1.value))
      assertEquals(
        Script.write(script1),
        ByteVector.fromValidHex(
          "5120a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb"
        )
      )

      val key2 = DeterministicWallet.derivePrivateKey(accountKey, List(1L, 0L))
      assertEquals(
        key2.secretkeybytes,
        DeterministicWallet
          .derivePrivateKey(master, KeyPath("m/86'/0'/0'/1/0"))
          .secretkeybytes
      )
      val internalKey2 = key2.publicKey.xonly
      assertEquals(
        internalKey2.value,
        ByteVector32.fromValidHex(
          "399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef"
        )
      )
      val outputKey2 = internalKey2.tapTweak(merkleRoot = None)._1
      assertEquals(
        outputKey2.value,
        ByteVector32.fromValidHex(
          "882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc"
        )
      )
      val script2 = List(OP_1, OP_PUSHDATA(outputKey2.value))
      assertEquals(
        Script.write(script2),
        ByteVector.fromValidHex(
          "5120882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc"
        )
      )
    }

    test("compute taproot addresses") {
      val (_, master) = DeterministicWallet.ExtendedPrivateKey.decode(
        "tprv8ZgxMBicQKsPeQQADibg4WF7mEasy3piWZUHyThAzJCPNgMHDVYhTCVfev3jFbDhcYm4GimeFMbbi9z1d9rfY1aL5wfJ9mNebQ4thJ62EJb"
      )
      val key =
        DeterministicWallet.derivePrivateKey(master, KeyPath("86'/1'/0'/0/1"))
      val internalKey = key.publicKey.xonly
      val outputKey = internalKey.tapTweak(None)._1
      assertEquals(
        "tb1phlhs7afhqzkgv0n537xs939s687826vn8l24ldkrckvwsnlj3d7qj6u57c",
        Bech32.encodeWitnessAddress("tb", 1, outputKey.value)
      )
    }
  }

  // helper function so we can copy/paste easier from ACINQ's test code
  def assertEquals[A, B](p1: A, p2: B): Unit = assert(p1 == p2)
}
