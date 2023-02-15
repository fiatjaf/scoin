package scoin

import scoin._
import utest._
import scodec.bits.ByteVector
import Crypto._
import scoin.TaprootTest.assertFails
object Musig2Test extends TestSuite {
  // tests and algorithms mostly from
  // https://github.com/jonasnick/bips/blob/musig2-squashed/bip-musig2.mediawiki
  val tests = Tests {

    test("musig2 - lexographic key sorting") {
      val pubkeys = List(
        "02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
        "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
        "02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8"
      ).map(i => PublicKey(ByteVector.fromValidHex(i)))

      val sorted_pubkeys = List(
        "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
        "02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
        "02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
        "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
      ).map(i => PublicKey(ByteVector.fromValidHex(i)))

      assert((Musig2.keySort(pubkeys)) == sorted_pubkeys)
    }

    test("musig2 - key aggregation") {
      // https://github.com/jonasnick/bips/blob/musig2-squashed/bip-musig2/vectors/key_agg_vectors.json

      // note: some of these pubkeys are invalid
      val pubkeys_bytes = List(
        "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
        "020000000000000000000000000000000000000000000000000000000000000005",
        "02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
        "04F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"
      ).map(i => ByteVector.fromValidHex(i))

      // note: one of these tweaks is out of range
      val tweaks = List(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        "252E4BD67410A76CDF933D30EAA1608214037F1B105A013ECCD3C5C184A6110B"
      ).map(i => BigInt(i,16))
      
      val pubkeys012 = pubkeys_bytes(0) :: pubkeys_bytes(1) :: pubkeys_bytes(2) :: Nil
      assert(
        (Musig2.keyAgg(pubkeys012.map(PublicKey(_))).pointQ.xonly.value.toHex.toUpperCase) 
        == 
        "90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C"
      )

      // same pubkeys as above, different order
      val pubkeys210 = pubkeys_bytes(2) :: pubkeys_bytes(1) :: pubkeys_bytes(0) :: Nil
      assert(
        (Musig2.keyAgg(pubkeys210.map(PublicKey(_))).pointQ.xonly.value.toHex.toUpperCase) 
        == 
        "6204DE8B083426DC6EAF9502D27024D53FC826BF7D2012148A0575435DF54B2B"
      )

      val pubkeys000 = pubkeys_bytes(0) :: pubkeys_bytes(0) :: pubkeys_bytes(0) :: Nil
      assert(
        (Musig2.keyAgg(pubkeys000.map(PublicKey(_))).pointQ.xonly.value.toHex.toUpperCase) 
        == 
        "B436E3BAD62B8CD409969A224731C193D051162D8C5AE8B109306127DA3AA935"
      )

      val pubkeys0011 = pubkeys_bytes(0) :: pubkeys_bytes(0) :: pubkeys_bytes(1) :: pubkeys_bytes(1) :: Nil
      assert(
        (Musig2.keyAgg(pubkeys0011.map(PublicKey(_))).pointQ.xonly.value.toHex.toUpperCase) 
        == 
        "69BC22BFA5D106306E48A20679DE1D7389386124D07571D0D872686028C26A3E"
      )
    }
  }
}