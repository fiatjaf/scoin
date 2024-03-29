package scoin

import java.io.{ByteArrayInputStream, ByteArrayOutputStream, ObjectInputStream}
import scala.io.Source
import scala.util.Random
import scoin.Base58.Prefix
import scoin.Crypto._
import scodec.bits._
import utest._

object CryptoTest extends TestSuite {
  val tests = Tests {
    test("import private keys") {
      // exported from the bitcoin client running in testnet mode
      val address = "mhW1BQDyhbTsnHEuB1n7yuj9V81TbeRfTY"
      val privateKey = "cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp"

      val (version, data) = Base58Check.decode(privateKey)
      val priv = PrivateKey(data)
      val publicKey = priv.publicKey
      val computedAddress = Base58Check.encode(
        Prefix.PubkeyAddressTestnet,
        Crypto.hash160(publicKey.value)
      )
      assert(computedAddress == address)
    }

    // see https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses
    test("generate public keys from private keys") {
      val privateKey = PrivateKey(
        hex"18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"
      )
      val publicKey = privateKey.publicKey
      assert(
        publicKey.toUncompressedBin == hex"0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6"
      )

      val address = Base58Check.encode(
        Prefix.PubkeyAddress,
        Crypto.hash160(publicKey.toUncompressedBin)
      )
      assert(address == "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM")
    }

    test("generate public keys from private keys 2") {
      val privateKey = PrivateKey(
        hex"BCF69F7AFF3273B864F9DD76896FACE8E3D3CF69A133585C8177816F14FC9B55"
      )
      val publicKey = privateKey.publicKey
      assert(
        publicKey.toUncompressedBin == hex"04D7E9DD0C618C65DC2E3972E2AA406CCD34E5E77895C96DC48AF0CB16A1D9B8CE0C0A3E2F4CD494FF54FBE4F5A95B410C0BF022EB2B6F23AE39F40DB79FAA6827"
      )

      val address = Base58Check.encode(
        Prefix.PubkeyAddress,
        Crypto.hash160(publicKey.toUncompressedBin)
      )
      assert(address == "19FgFQGZy47NcGTJ4hfNdGMwS8EATqoa1X")
    }

    test("validate public key at instantiation") {
      intercept[Throwable] { // can be IllegalArgumentException or AssertFailException depending on whether bouncycastle or libsecp256k1 is used
        // by default we check
        PublicKey(
          hex"04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          checkValid = true
        )
      }
      // key is invalid but we don't check it
      PublicKey(
        hex"04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        checkValid = false
      )
    }

    test("allow unsafe initialization of public keys") {
      val privateKey = PrivateKey(
        hex"BCF69F7AFF3273B864F9DD76896FACE8E3D3CF69A133585C8177816F14FC9B55"
      )
      val publicKey = privateKey.publicKey
      val rawCompressed = publicKey.value
      val rawUncompressed = publicKey.toUncompressedBin
      assert(rawCompressed.size == 33)
      assert(rawUncompressed.size == 65)
      val publicKeyCompressed1 = PublicKey.fromBin(rawCompressed)
      assert(publicKey == publicKeyCompressed1)
      val publicKeyCompressed2 = PublicKey.fromBin(rawUncompressed)
      assert(publicKey == publicKeyCompressed2)
    }

    test("sign and verify signatures") {
      val privateKey = PrivateKey
        .fromBase58(
          "cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp",
          Base58.Prefix.SecretKeyTestnet
        )
        ._1
      val publicKey = privateKey.publicKey
      val data = Crypto.sha256(ByteVector("this is a test".getBytes("UTF-8")))
      val sig = Crypto.sign(data, privateKey)
      assert(Crypto.verifySignature(data, sig, publicKey))
    }

    test("generate deterministic signatures") {
      // dataset from https://bitcointalk.org/index.php?topic=285142.msg3299061#msg3299061
      val dataset = Seq(
        (
          hex"0000000000000000000000000000000000000000000000000000000000000001",
          "Satoshi Nakamoto",
          hex"3045022100934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d802202442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"
        ),
        (
          hex"0000000000000000000000000000000000000000000000000000000000000001",
          "Everything should be made as simple as possible, but not simpler.",
          hex"3044022033a69cd2065432a30f3d1ce4eb0d59b8ab58c74f27c41a7fdb5696ad4e6108c902206f807982866f785d3f6418d24163ddae117b7db4d5fdf0071de069fa54342262"
        ),
        (
          hex"0000000000000000000000000000000000000000000000000000000000000001",
          "All those moments will be lost in time, like tears in rain. Time to die...",
          hex"30450221008600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b0220547fe64427496db33bf66019dacbf0039c04199abb0122918601db38a72cfc21"
        ),
        (
          hex"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140",
          "Satoshi Nakamoto",
          hex"3045022100fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d002206b39cd0eb1bc8603e159ef5c20a5c8ad685a45b06ce9bebed3f153d10d93bed5"
        ),
        (
          hex"f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181",
          "Alan Turing",
          hex"304402207063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c022058dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea"
        ),
        (
          hex"e91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2",
          "There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!",
          hex"3045022100b552edd27580141f3b2a5463048cb7cd3e047b97c9f98076c32dbdf85a68718b0220279fa72dd19bfae05577e06c7c0c1900c371fcd5893f7e1d56a37d30174671f6"
        )
      )

      dataset.map { case (k, m, s) =>
        val sig: ByteVector = Crypto.compact2der(
          Crypto.sign(
            Crypto.sha256(ByteVector.view(m.getBytes("UTF-8"))),
            PrivateKey(k)
          )
        )
        assert(sig == s)
      }
    }

    /** Schnorr Tests inspiration taken from
      * https://github.com/ACINQ/secp256k1-kmp/blob/master/tests/src/commonTest/kotlin/fr/acinq/secp256k1/Secp256k1Test.kt#L291
      */
    test("schnorr - first schnorr signature test") {
      val seckey = PrivateKey
        .fromBin(
          ByteVector.fromValidHex(
            "0000000000000000000000000000000000000000000000000000000000000003"
          )
        )
        ._1
      val msg = ByteVector32.fromValidHex(
        "0000000000000000000000000000000000000000000000000000000000000000"
      )
      val auxrand32 = ByteVector32.fromValidHex(
        "0000000000000000000000000000000000000000000000000000000000000000"
      )
      val sig = Crypto.signSchnorr(msg, seckey, Some(auxrand32))
      assert(
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0" == sig.toHex
          .toUpperCase()
      )
      val pubkey = seckey.publicKey.xonly
      assert(
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9" == pubkey.toHex
          .toUpperCase()
      )
      assert(Crypto.verifySignatureSchnorr(sig, msg, pubkey))
    }

    test("ecc scalar math") {
      val sk1 = PrivateKey(
        hex"45022100fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447"
      )
      val sk2 = PrivateKey(
        hex"d3f72100fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993555"
      )

      test("add") {
        (sk1 + sk2).value.toHex ==> "18f94201faacfa243b6cdc705322a696fa407093b2c541065345e7afbefc285b"
      }
      test("subtract") {
        (sk1 - sk2).value.toHex ==> "710afffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364033"
      }
      test("multiply") {
        (sk1 * sk2).value.toHex ==> "eef0a8c357919b7c21c0fbd9ec74442bcccb43cf8eee4ff488087332172043bc"
      }
    }

    test("ecc point math") {
      val pk1 = PrivateKey(
        hex"45022100fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447"
      ).publicKey
      val sk2 = PrivateKey(
        hex"d3f72100fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993555"
      )
      val pk2 = sk2.publicKey

      test("add") {
        (pk1 + pk2).value.toHex ==> "0303f24810aafe764cf9573789953af913aaea5b2d92f8ee9a18bba3be16159c6e"
      }
      test("subtract") {
        (pk1 - pk2).value.toHex ==> "03d1f90c3aa425ccf62ddf6edb280ea997a57cffa43abfd028b4ceba7a91a43ecd"
      }
      test("multiply") {
        (pk1 * sk2).value.toHex ==> "02495ddcf039e394422e1733359e81c41207f42f37986953beb370223414e7005c"
      }
    }

    test("key tweaking") {
      val key = PrivateKey(randomBytes32())
      val skTweak = key.tapTweak(None).publicKey.xonly
      val pkTweak = key.publicKey.xonly.tapTweak(None)._1
      assert(skTweak == pkTweak)
    }
  }
}
