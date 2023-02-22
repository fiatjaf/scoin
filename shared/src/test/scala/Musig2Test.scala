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

    test("musig2 - partial signature aggregatation") {
      val pubkeys = List(
        "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
        "02D2DC6F5DF7C56ACF38C7FA0AE7A759AE30E19B37359DFDE015872324C7EF6E05",
        "03C7FB101D97FF930ACD0C6760852EF64E69083DE0B06AC6335724754BB4B0522C",
        "02352433B21E7E05D3B452B81CAE566E06D2E003ECE16D1074AABA4289E0E3D581"
      ).map(ByteVector.fromValidHex(_))
      
      val pnonces = List(
        "036E5EE6E28824029FEA3E8A9DDD2C8483F5AF98F7177C3AF3CB6F47CAF8D94AE902DBA67E4A1F3680826172DA15AFB1A8CA85C7C5CC88900905C8DC8C328511B53E",
        "03E4F798DA48A76EEC1C9CC5AB7A880FFBA201A5F064E627EC9CB0031D1D58FC5103E06180315C5A522B7EC7C08B69DCD721C313C940819296D0A7AB8E8795AC1F00",
        "02C0068FD25523A31578B8077F24F78F5BD5F2422AFF47C1FADA0F36B3CEB6C7D202098A55D1736AA5FCC21CF0729CCE852575C06C081125144763C2C4C4A05C09B6",
        "031F5C87DCFBFCF330DEE4311D85E8F1DEA01D87A6F1C14CDFC7E4F1D8C441CFA40277BF176E9F747C34F81B0D9F072B1B404A86F402C2D86CF9EA9E9C69876EA3B9",
        "023F7042046E0397822C4144A17F8B63D78748696A46C3B9F0A901D296EC3406C302022B0B464292CF9751D699F10980AC764E6F671EFCA15069BBE62B0D1C62522A",
        "02D97DDA5988461DF58C5897444F116A7C74E5711BF77A9446E27806563F3B6C47020CBAD9C363A7737F99FA06B6BE093CEAFF5397316C5AC46915C43767AE867C00"
      ).map(ByteVector.fromValidHex(_))

      val tweaks = List(
        "B511DA492182A91B0FFB9A98020D55F260AE86D7ECBD0399C7383D59A5F2AF7C",
        "A815FE049EE3C5AAB66310477FBC8BCCCAC2F3395F59F921C364ACD78A2F48DC",
        "75448A87274B056468B977BE06EB1E9F657577B7320B0A3376EA51FD420D18A8"
      ).map(ByteVector.fromValidHex(_))

      val psigs = List(
        "B15D2CD3C3D22B04DAE438CE653F6B4ECF042F42CFDED7C41B64AAF9B4AF53FB",
        "6193D6AC61B354E9105BBDC8937A3454A6D705B6D57322A5A472A02CE99FCB64",
        "9A87D3B79EC67228CB97878B76049B15DBD05B8158D17B5B9114D3C226887505",
        "66F82EA90923689B855D36C6B7E032FB9970301481B99E01CDB4D6AC7C347A15",
        "4F5AEE41510848A6447DCD1BBC78457EF69024944C87F40250D3EF2C25D33EFE",
        "DDEF427BBB847CC027BEFF4EDB01038148917832253EBC355FC33F4A8E2FCCE4",
        "97B890A26C981DA8102D3BC294159D171D72810FDF7C6A691DEF02F0F7AF3FDC",
        "53FA9E08BA5243CBCB0D797C5EE83BC6728E539EB76C2D0BF0F971EE4E909971",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
      ).map(ByteVector.fromValidHex(_))

      val msg = ByteVector.fromValidHex("599C67EA410D005B9DA90817CF03ED3B1C868E4DA4EDF00A5880B0082C237869")

      { // test 1
        val aggnonce = ByteVector.fromValidHex("0341432722C5CD0268D829C702CF0D1CBCE57033EED201FD335191385227C3210C03D377F2D258B64AADC0E16F26462323D701D286046A2EA93365656AFD9875982B")
        val nonces = pnonces(0) :: pnonces(1) :: Nil
        val keys = pubkeys(0) :: pubkeys(1) :: Nil
        val sigs = psigs(0) :: psigs(1) :: Nil
        val ctx = Musig2.SessionCtx(
          aggNonce = aggnonce,
          numPubKeys = 2,
          pubKeys = keys,
          numTweaks = 0,
          tweaks = List(),
          isXonlyTweak = List(),
          message = msg
        )
        assert(Musig2.partialSigAgg(sigs,ctx) == ByteVector64.fromValidHex("041DA22223CE65C92C9A0D6C2CAC828AAF1EEE56304FEC371DDF91EBB2B9EF0912F1038025857FEDEB3FF696F8B99FA4BB2C5812F6095A2E0004EC99CE18DE1E"))
      }
      { // test 2
        val aggnonce = ByteVector.fromValidHex("0224AFD36C902084058B51B5D36676BBA4DC97C775873768E58822F87FE437D792028CB15929099EEE2F5DAE404CD39357591BA32E9AF4E162B8D3E7CB5EFE31CB20")
        val nonces = pnonces(0) :: pnonces(2) :: Nil
        val keys = pubkeys(0) :: pubkeys(2) :: Nil
        val sigs = psigs(2) :: psigs(3) :: Nil
        val ctx = Musig2.SessionCtx(
          aggNonce = aggnonce,
          numPubKeys = 2,
          pubKeys = keys,
          numTweaks = 0,
          tweaks = List(),
          isXonlyTweak = List(),
          message = msg
        )
        assert(Musig2.partialSigAgg(sigs,ctx) == ByteVector64.fromValidHex("1069B67EC3D2F3C7C08291ACCB17A9C9B8F2819A52EB5DF8726E17E7D6B52E9F01800260A7E9DAC450F4BE522DE4CE12BA91AEAF2B4279219EF74BE1D286ADD9"))
      }
      { // test 3 (now including some tweaks)
        val aggnonce = ByteVector.fromValidHex("0208C5C438C710F4F96A61E9FF3C37758814B8C3AE12BFEA0ED2C87FF6954FF186020B1816EA104B4FCA2D304D733E0E19CEAD51303FF6420BFD222335CAA402916D")
        val nonces = pnonces(0) :: pnonces(3) :: Nil
        val keys = pubkeys(0) :: pubkeys(2) :: Nil
        val sigs = psigs(4) :: psigs(5) :: Nil
        val tw = (tweaks(0) :: Nil).map(ByteVector32(_))
        val ctx = Musig2.SessionCtx(
          aggNonce = aggnonce,
          numPubKeys = keys.size,
          pubKeys = keys,
          numTweaks = tw.size,
          tweaks = tw,
          isXonlyTweak = List(false),
          message = msg
        )
        assert(Musig2.partialSigAgg(sigs,ctx) == ByteVector64.fromValidHex("5C558E1DCADE86DA0B2F02626A512E30A22CF5255CAEA7EE32C38E9A71A0E9148BA6C0E6EC7683B64220F0298696F1B878CD47B107B81F7188812D593971E0CC"))
      }
      { // test 4 (now including some tweaks)
        val nonces = pnonces(0) :: pnonces(4) :: Nil
        val sigs = psigs(6) :: psigs(7) :: Nil
        val ctx = Musig2.SessionCtx(
          aggNonce = ByteVector.fromValidHex("02B5AD07AFCD99B6D92CB433FBD2A28FDEB98EAE2EB09B6014EF0F8197CD58403302E8616910F9293CF692C49F351DB86B25E352901F0E237BAFDA11F1C1CEF29FFD"),
          numPubKeys = 2,
          pubKeys = pubkeys(0) :: pubkeys(3) :: Nil,
          numTweaks = 3,
          tweaks = (tweaks(0) :: tweaks(1) :: tweaks(2) :: Nil).map(ByteVector32(_)),
          isXonlyTweak = List(true,false,true),
          message = msg
        )
        assert(Musig2.partialSigAgg(sigs,ctx) == ByteVector64.fromValidHex("839B08820B681DBA8DAF4CC7B104E8F2638F9388F8D7A555DC17B6E6971D7426CE07BF6AB01F1DB50E4E33719295F4094572B79868E440FB3DEFD3FAC1DB589E"))
      }
      { // test 5 -- error case
        val nonces = pnonces(0) :: pnonces(4) :: Nil
        val sigs = psigs(7) :: psigs(8) :: Nil
        val ctx = Musig2.SessionCtx(
          aggNonce = ByteVector.fromValidHex("02B5AD07AFCD99B6D92CB433FBD2A28FDEB98EAE2EB09B6014EF0F8197CD58403302E8616910F9293CF692C49F351DB86B25E352901F0E237BAFDA11F1C1CEF29FFD"),
          numPubKeys = 2,
          pubKeys = pubkeys(0) :: pubkeys(3) :: Nil,
          numTweaks = 3,
          tweaks = (tweaks(0) :: tweaks(1) :: tweaks(2) :: Nil).map(ByteVector32(_)),
          isXonlyTweak = List(true,false,true),
          message = msg
        )
        //  "comment": "Partial signature is invalid (signer index 1) because it exceeds group size"
        assertFails(Musig2.partialSigAgg(sigs,ctx))
      }
    }

    test("musig2 - partial signature verification") {
      val sk = PrivateKey(ByteVector32.fromValidHex("7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671"))
      val pubkeys = List(
        "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
        "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA661",
        "020000000000000000000000000000000000000000000000000000000000000007"
      ).map(ByteVector.fromValidHex(_))
      val secnonces = List(
        "508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"
      ).map(ByteVector.fromValidHex(_))
      val pnonces = List(
        "0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
        "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        "032DE2662628C90B03F5E720284EB52FF7D71F4284F627B68A853D78C78E1FFE9303E4C5524E83FFE1493B9077CF1CA6BEB2090C93D930321071AD40B2F44E599046",
        "0237C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0387BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
        "020000000000000000000000000000000000000000000000000000000000000009"
      ).map(ByteVector.fromValidHex(_))
      val aggnonces = List(
        "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "048465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9",
        "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61020000000000000000000000000000000000000000000000000000000000000009",
        "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD6102FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"
      ).map(ByteVector.fromValidHex(_))
      val msgs = List(
        "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF",
        "",
        "2626262626262626262626262626262626262626262626262626262626262626262626262626"
      ).map(ByteVector.fromValidHex(_))

      def innerTestAssertValid(key_indices: List[Int], nonce_indices: List[Int], aggnonce_index: Int, msg_index: Int, signer_index: Int, expected: String, comment:String = ""): Unit = {
        val pubkeys_ = key_indices.map(i => pubkeys(i))
        val pubnonces_ = nonce_indices.map(i => pnonces(i))
        val aggnonce_ = aggnonces(aggnonce_index)
        assert(Musig2.nonceAgg(pubnonces_) == aggnonce_)
        val msg_ = msgs(msg_index)
        val ctx = Musig2.SessionCtx(aggnonce_, pubkeys_.size, pubkeys_, 0,List.empty, List.empty,message = msg_)
        /**
          * # WARNING: An actual implementation should _not_ copy the secnonce.
          * Reusing the secnonce, as we do here for testing purposes, can leak the
          * secret key.
          */
        val secnonce_tmp = secnonces(0) // index 0 for valid tests
        val psig = Musig2.sign(secnonce_tmp,sk,ctx)
        assert(psig == ByteVector32.fromValidHex(expected))
        assert(Musig2.partialSigVerify(psig.bytes,pubnonces_,pubkeys_,List.empty,List.empty,msg_,signer_index))
      }

      innerTestAssertValid(
        key_indices = List(0,1,2),
        nonce_indices = List(0,1,2),
        aggnonce_index = 0,
        msg_index = 0,
        signer_index = 0,
        expected = "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB",
        comment = ""
      )

      innerTestAssertValid(
        key_indices = List(1,0,2),
        nonce_indices = List(1,0,2),
        aggnonce_index = 0,
        msg_index = 0,
        signer_index = 1,
        expected = "9FF2F7AAA856150CC8819254218D3ADEEB0535269051897724F9DB3789513A52",
        comment = ""
      )

      innerTestAssertValid(
        key_indices = List(1,2,0),
        nonce_indices = List(1,2,0),
        aggnonce_index = 0,
        msg_index = 0,
        signer_index = 2,
        expected = "FA23C359F6FAC4E7796BB93BC9F0532A95468C539BA20FF86D7C76ED92227900",
        comment = ""
      )
      innerTestAssertValid(
        key_indices = List(0,1),
        nonce_indices = List(0,3),
        aggnonce_index = 1,
        msg_index = 0,
        signer_index = 0,
        expected = "AE386064B26105404798F75DE2EB9AF5EDA5387B064B83D049CB7C5E08879531",
        comment = "Both halves of aggregate nonce correspond to point at infinity"
      )
      innerTestAssertValid(
        key_indices = List(0,1,2),
        nonce_indices = List(0,1,2),
        aggnonce_index = 0,
        msg_index = 1,
        signer_index = 0,
        expected = "D7D63FFD644CCDA4E62BC2BC0B1D02DD32A1DC3030E155195810231D1037D82D",
        comment = "Empty message"
      )
      innerTestAssertValid(
        key_indices = List(0,1,2),
        nonce_indices = List(0,1,2),
        aggnonce_index = 0,
        msg_index = 2,
        signer_index = 0,
        expected = "E184351828DA5094A97C79CABDAAA0BFB87608C32E8829A4DF5340A6F243B78C",
        comment = "38-byte message"
      )       
    }
  }
}