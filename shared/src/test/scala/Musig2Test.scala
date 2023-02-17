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

      // fail when a pubkey is invalid
      // signer(1) pubkey is invalid
      val pubkeys03 = pubkeys_bytes(0) :: pubkeys_bytes(3) :: Nil
      assertFails(
        Musig2.keyAgg(pubkeys03.map(PublicKey(_)))
      )

      // fail when a pubkey is invalid
      // signer(1) public key exceeds field size
      val pubkeys04 = pubkeys_bytes(0) :: pubkeys_bytes(4) :: Nil
      assertFails(
        println(Musig2.keyAgg(pubkeys04.map(PublicKey(_))))
      )

      // fail - invalid pubkey
      // signer(1) first byte of key is not 2 or 3
      val pubkeys50 = pubkeys_bytes(5) :: pubkeys_bytes(0) :: Nil
      assertFails(
        println(Musig2.keyAgg(pubkeys50.map(PublicKey(_))))
      )

      // note: one of these tweaks is out of range
      val tweaks_bytes = List(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        "252E4BD67410A76CDF933D30EAA1608214037F1B105A013ECCD3C5C184A6110B"
      ).map(i => ByteVector32.fromValidHex(i))

      val pubkeys01 = pubkeys_bytes(0) :: pubkeys_bytes(1) :: Nil
      val keygenCtx01 = Musig2.keyAgg(pubkeys01.map(PublicKey(_)))
      assertFails(
        Musig2.applyTweak(
          keygenCtx = keygenCtx01,
          tweak = tweaks_bytes(0),
          isXonlyTweak = true
        )
      )

      val pubkeys6 = pubkeys_bytes(6) :: Nil
      val keygenCtx6 = Musig2.keyAgg(pubkeys6.map(PublicKey(_)))
      assertFails(
        Musig2.applyTweak(
          keygenCtx = keygenCtx6,
          tweak = tweaks_bytes(1),
          isXonlyTweak = false
        )
      )
    }

    test("musig2 - nonce generation 1") {
      /**
        * "rand_": "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
            "sk": "0202020202020202020202020202020202020202020202020202020202020202",
            "pk": "024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766",
            "aggpk": "0707070707070707070707070707070707070707070707070707070707070707",
            "msg": "0101010101010101010101010101010101010101010101010101010101010101",
            "extra_in": "0808080808080808080808080808080808080808080808080808080808080808",
            "expected": "B114E502BEAA4E301DD08A50264172C84E41650E6CB726B410C0694D59EFFB6495B5CAF28D045B973D63E3C99A44B807BDE375FD6CB39E46DC4A511708D0E9D2024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766"
        */
      val (secnonce, pubnonce) = Musig2.nonceGen(
        secretSigningKey = Some(ByteVector32.fromValidHex("0202020202020202020202020202020202020202020202020202020202020202")),
        pubKey = PublicKey(ByteVector.fromValidHex("024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766")),
        aggregateXOnlyPublicKey = Some(XOnlyPublicKey(ByteVector32.fromValidHex("0707070707070707070707070707070707070707070707070707070707070707"))),
        message = Some(ByteVector.fromValidHex("0101010101010101010101010101010101010101010101010101010101010101")),
        extraIn = Some(ByteVector.fromValidHex("0808080808080808080808080808080808080808080808080808080808080808")),
        nextRand32 = ByteVector32.fromValidHex("0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F")
      )
      val expectedSecNonce = ByteVector.fromValidHex("B114E502BEAA4E301DD08A50264172C84E41650E6CB726B410C0694D59EFFB6495B5CAF28D045B973D63E3C99A44B807BDE375FD6CB39E46DC4A511708D0E9D2024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766")
      assert( secnonce == expectedSecNonce)
    }

    test("musig2 - nonce generation 2") {
      val (secnonce, pubnonce) = Musig2.nonceGen(
        secretSigningKey = Some(ByteVector32.fromValidHex("0202020202020202020202020202020202020202020202020202020202020202")),
        pubKey = PublicKey(ByteVector.fromValidHex("024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766")),
        aggregateXOnlyPublicKey = Some(XOnlyPublicKey(ByteVector32.fromValidHex("0707070707070707070707070707070707070707070707070707070707070707"))),
        message = Some(ByteVector.fromValidHex("0101010101010101010101010101010101010101010101010101010101010101")),
        extraIn = Some(ByteVector.fromValidHex("0808080808080808080808080808080808080808080808080808080808080808")),
        nextRand32 = ByteVector32.fromValidHex("0000000000000000000000000000000000000000000000000000000000000000")
      )
      val expectedSecNonce = ByteVector.fromValidHex("227243DCB40EF2A13A981DB188FA433717B506BDFA14B1AE47D5DC027C9C3B9EF2370B2AD206E724243215137C86365699361126991E6FEC816845F837BDDAC3024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766")
      assert( secnonce == expectedSecNonce)
    }

    test("musig2 - nonce generation 3") {
      val (secnonce, pubnonce) = Musig2.nonceGen(
        secretSigningKey = Some(ByteVector32.fromValidHex("0202020202020202020202020202020202020202020202020202020202020202")),
        pubKey = PublicKey(ByteVector.fromValidHex("024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766")),
        aggregateXOnlyPublicKey = Some(XOnlyPublicKey(ByteVector32.fromValidHex("0707070707070707070707070707070707070707070707070707070707070707"))),
        message = Some(ByteVector.fromValidHex("")),
        extraIn = Some(ByteVector.fromValidHex("0808080808080808080808080808080808080808080808080808080808080808")),
        nextRand32 = ByteVector32.fromValidHex("0000000000000000000000000000000000000000000000000000000000000000")
      )
      val expectedSecNonce = ByteVector.fromValidHex("CD0F47FE471D6788FF3243F47345EA0A179AEF69476BE8348322EF39C2723318870C2065AFB52DEDF02BF4FDBF6D2F442E608692F50C2374C08FFFE57042A61C024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766")
      assert( secnonce == expectedSecNonce)
    }

    test("musig2 - nonce generation 4") {
      val (secnonce, pubnonce) = Musig2.nonceGen(
        secretSigningKey = Some(ByteVector32.fromValidHex("0202020202020202020202020202020202020202020202020202020202020202")),
        pubKey = PublicKey(ByteVector.fromValidHex("024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766")),
        aggregateXOnlyPublicKey = Some(XOnlyPublicKey(ByteVector32.fromValidHex("0707070707070707070707070707070707070707070707070707070707070707"))),
        message = Some(ByteVector.fromValidHex("2626262626262626262626262626262626262626262626262626262626262626262626262626")),
        extraIn = Some(ByteVector.fromValidHex("0808080808080808080808080808080808080808080808080808080808080808")),
        nextRand32 = ByteVector32.fromValidHex("0000000000000000000000000000000000000000000000000000000000000000")
      )
      val expectedSecNonce = ByteVector.fromValidHex("011F8BC60EF061DEEF4D72A0A87200D9994B3F0CD9867910085C38D5366E3E6B9FF03BC0124E56B24069E91EC3F162378983F194E8BD0ED89BE3059649EAE262024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766")
      assert( secnonce == expectedSecNonce)
    }

    test("musig2 - nonce generation 5") {
      val (secnonce, pubnonce) = Musig2.nonceGen(
        secretSigningKey = None,
        pubKey = PublicKey(ByteVector.fromValidHex("02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")),
        aggregateXOnlyPublicKey = None,
        message = None,
        extraIn = None,
        nextRand32 = ByteVector32.fromValidHex("0000000000000000000000000000000000000000000000000000000000000000")
      )
      val expectedSecNonce = ByteVector.fromValidHex("890E83616A3BC4640AB9B6374F21C81FF89CDDDBAFAA7475AE2A102A92E3EDB29FD7E874E23342813A60D9646948242646B7951CA046B4B36D7D6078506D3C9402F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
      assert( secnonce == expectedSecNonce)
    }

    test("musig2 - nonce aggregation") {
      val pnonces = List(
        "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E66603BA47FBC1834437B3212E89A84D8425E7BF12E0245D98262268EBDCB385D50641",
        "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833",
        "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E6660279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60379BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        "04FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833",
        "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B831",
        "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A602FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"
      ).map(ByteVector.fromValidHex(_))
      
      val pnonces01 = pnonces(0) :: pnonces(1) :: Nil
      assert(Musig2.nonceAgg(pnonces01) == ByteVector.fromValidHex("035FE1873B4F2967F52FEA4A06AD5A8ECCBE9D0FD73068012C894E2E87CCB5804B024725377345BDE0E9C33AF3C43C0A29A9249F2F2956FA8CFEB55C8573D0262DC8"))
    
      val pnonces23 = pnonces(2) :: pnonces(3) :: Nil
      // "comment": "Sum of second points encoded in the nonces is point at infinity which is serialized as 33 zero bytes"
      assert(Musig2.nonceAgg(pnonces23) == ByteVector.fromValidHex("035FE1873B4F2967F52FEA4A06AD5A8ECCBE9D0FD73068012C894E2E87CCB5804B000000000000000000000000000000000000000000000000000000000000000000"))
    
      val pnonces04 = pnonces(0) :: pnonces(4) :: Nil
      //  "comment": "Public nonce from signer 1 is invalid due wrong tag, 0x04, in the first half"
      assertFails(Musig2.nonceAgg(pnonces04))

      val pnonces51 = pnonces(5) :: pnonces(1) :: Nil
      //  "comment":  "Public nonce from signer 0 is invalid because the second half does not correspond to an X coordinate"
      assertFails(Musig2.nonceAgg(pnonces51))

      val pnonces61 = pnonces(6) :: pnonces(1) :: Nil
      //  "comment":  "Public nonce from signer 0 is invalid because second half exceeds field size"
      assertFails(Musig2.nonceAgg(pnonces61))
    }
  }
}