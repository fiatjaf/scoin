package scoin

import scoin._
import utest._
import scodec.bits._
import scoin.DeterministicWallet
import scoin.DeterministicWallet.KeyPath
import scoin.Crypto.XOnlyPublicKey
import scoin.Crypto.PrivateKey
import scoin.Crypto.PublicKey
import scala.util.Failure
import scala.util.Success
import scoin.ScriptElt.elt2code

object AnyprevoutTest extends TestSuite {
  val tests = Tests {
    test("build spacechain bmm of length 1") {
      /*
       * tx1[_: [ANYPREVOUT <sig> <G> CHECKSIG]] -> tx2[_: OP_RETURN the end]
       *                     this sig signs tx2 which spends tx1
       * https://gist.githubusercontent.com/RubenSomsen/5e4be6d18e5fa526b17d8b34906b16a5/raw/eb7779f0ce48f84956d1be25a94f63371ff6090a/BMM.svg
       * https://youtu.be/N2ow4Q34Jeg?t=2214
       */
      // now we the sig we can do the magic described at

      val priv = Crypto.PrivateKey(1)
      val pub = priv.publicKey

      assert(pub == Crypto.G)

      val (tx2, sig2) = {
        val tx = Transaction(
          version = 2,
          txIn = List(TxIn.placeholder(1)),
          txOut = List(
            TxOut(
              Satoshi(0),
              Script.write(
                List(
                  OP_RETURN,
                  OP_PUSHDATA(ByteVector.view("the end".getBytes()))
                )
              )
            )
          ),
          lockTime = 0
        )

        // compute the tx hash. since we're using anyprevoutanyscript we don't care about the inputs
        val hash = Transaction.hashForSigningSchnorr(
          tx,
          0,
          List(tx.txOut(0)),
          SIGHASH_ANYPREVOUTANYSCRIPT | SIGHASH_SINGLE,
          SigVersion.SIGVERSION_TAPSCRIPT,
          annex = None,
          tapleafHash = None // because of anyprevoutanyscript this can be None
        )

        val sig = Crypto.signSchnorr(hash, priv, None)

        (tx, sig)
      }

      val script1 = List(
        OP_PUSHDATA(
          sig2 ++ ByteVector
            .fromInt((SIGHASH_ANYPREVOUTANYSCRIPT | SIGHASH_SINGLE), 1)
        ),
        OP_1,
        OP_CHECKSIG
      )

      val (tweakedKey2, controlBlock2) = {
        // simple script tree with a single element
        val scriptTree = ScriptTree.Leaf(
          ScriptLeaf(0, Script.write(script1), Script.TAPROOT_LEAF_TAPSCRIPT)
        )
        val merkleRoot = ScriptTree.hash(scriptTree)

        val internalPubkey = pub.xonly
        val (tweakedKey, parity) = internalPubkey.tapTweak(Some(merkleRoot))

        val controlBlock = ByteVector(
          (Script.TAPROOT_LEAF_TAPSCRIPT + (if (parity) 1 else 0)).toByte
        ) ++ internalPubkey.value

        (tweakedKey, controlBlock)
      }

      val tx1 = Transaction(
        version = 2,
        txIn = List.empty, // irrelevant for this test
        txOut =
          List(TxOut(Satoshi(1000000), List(OP_1, OP_PUSHDATA(tweakedKey2)))),
        lockTime = 0
      )

      assert(
        Transaction
          .correctlySpends(
            tx2.copy(txIn =
              Seq(
                TxIn(
                  outPoint = OutPoint(tx1, 0),
                  sequence = 0,
                  signatureScript = ByteVector.empty,
                  witness = ScriptWitness(
                    List(
                      Script.write(script1),
                      controlBlock2
                    )
                  )
                )
              )
            ),
            List(tx1),
            ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS | ScriptFlags.SCRIPT_VERIFY_ANYPREVOUT
          )
          .isFailure
      )

      assert(
        Transaction
          .correctlySpends(
            tx2.copy(txIn =
              List(
                TxIn(
                  outPoint = OutPoint(tx1, 0),
                  sequence = 1,
                  signatureScript = ByteVector.empty,
                  witness = ScriptWitness(
                    List(
                      Script.write(script1),
                      controlBlock2
                    )
                  )
                )
              )
            ),
            List(tx1),
            ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS | ScriptFlags.SCRIPT_VERIFY_ANYPREVOUT
          )
          .isSuccess
      )
    }

    test("test eltoo transactions from instagibbs") {
      val update = Transaction.read(
        "02000000000101a3c416668a0b114bb7fc594fd52608b77d44d72259d505bbb04c161d5e99d2750100000000fdffffff0140420f0000000000225120d1102755f5d0700003ff4a486b02f390f8b6bd9ce2dbc12429cceafde44289cb0441a5f0c640b307803cffc0ce0f205c8acef84ec4a4bb0267b224d2b42baca18737a40b65b549a3c44b6038cf713acf273a08fb63b8a80c4e33acbdc97de730dd02c30251ac21c14c2ef50ba924c2d69bdb070db119ed4fa8be451a39f272579215820ee55eb518215004ad094f7fcde24d22e1b773bd665c134378449bc0d34212eb8e2fbc242c23cc0065cd1d"
      )

      val settlement = Transaction.read(
        "020000000001011b669edfbcb703e6c52fe315b6b532bb1fd5a0ed4232b5bd3d1d1e0e550565b8000000000005000000020000000000000000015140420f00000000002251202dbc0053dd6f3310d84e55eebaacfad53fe3e3ec3c2cecb1cffebdd95fa8063f026541cc5a574bbbc57400177c6e97d8447dd35c150c9d2b91d03361e11e23baf6ecd6527e04ecfee8b0f741489713c12e757ca46f28f4c38e869e7cf2f458ad175234c1210179be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac41c04c2ef50ba924c2d69bdb070db119ed4fa8be451a39f272579215820ee55eb518b4d868d7231ff3d15775dbd01acf0051b86eccd1f1139772222152b32986c4df0065cd1d"
      )

      assert(
        Transaction
          .correctlySpends(
            settlement,
            List(update),
            ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS | ScriptFlags.SCRIPT_VERIFY_ANYPREVOUT
          )
          .isSuccess
      )

      assert(
        Transaction
          .correctlySpends(
            settlement.updateWitness(0, ScriptWitness(Seq.empty)),
            List(update),
            ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS | ScriptFlags.SCRIPT_VERIFY_ANYPREVOUT
          )
          .isFailure
      )
    }

    test("test signet transaction from aj towns") {
      // taken from https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2022-December/021275.html

      assert(
        Transaction
          .correctlySpends(
            Transaction.read(
              "020000000001018ad015211d2468d779573d499c402d0957fff52a944f2b7b1f3b09d1955a33fb0100000000ffffffff0200046bf41400000016001481113cad52683679a83e76f76f84a4cfe36f750100e40b54020000001600141b94e6a88e7bfb3a552d6888b102c4f615dc2f56034189d888393f0c46872fbd002b3523cf58dd474ab86014096bdf69e5248cc06cd6f4b5a223053eb97a708b47ed1d25ad26be7f197536af86ad3389cb1d53a0e643c10251ac21c0624aa2e3277b1f5d667c5acc0ec58eccad8c8be7c7815e122d2b65127f8b0e2800000000"
            ),
            List(
              Transaction.read(
                "02000000000115cd3bba8f058252537f95c99b911a46127f959c2269766c7e6ccc4e3c6337c4b10000000000fefffffff820556c38da6fe524211d702a8e61482090d0bbeecd2d572cf911f2d742edcd0000000000feffffff9c80ed85770ff3dc7e985c998ba832f880a3d6dbdaa22f96610a7556d3a17f0d0000000000feffffff336f352e9bd08b673d3fa7700d6f069fecb27f0160b256d5b3751fc9889be0fd0000000000feffffff7b19fda0924a6c08d1c209d6046f3dac5e86a8f01f78e0604cde50ae6d8140730000000000feffffff2325485cf07ec1f25003fc81469ad954459d24d2a8c2df3f0b3fa07f722272fe0000000000feffffffec2a101b7608f618f9dbbe7826910f152c5f12b905fa1120ee3d9fea5246632b0000000000feffffff580d2175ddf1703c803dfbf5bf325abbabccbe5c410a339eaf25287d827968780000000000feffffff5b0d9c7ad2b8ac10f93a236adeb7529da6191f8fc84dff6d062f0ef4679ccf7a0000000000feffffff7702ea82ddb786c6e902933a4adfd9b50d0f4f8eae64967a9452d178fa7a9f160000000000feffffff4533a36a9124d41637e70a5a1301042917fba52ec083fe2fa1a68cfc18f38d030000000000feffffffca889b8999f1b72e23bab6fc7c1ec6cf0ef290183fc59eb7522eb738b51f8e790000000000feffffff0aa190dec20cd498bd998420b6f43fa3490fe5ff7988c48a8473c5673952cf180000000000feffffffdb1d048d79559d8fae1ea61813b239b3b860f10f74563c79a3c2d00126b1831d0000000000feffffff48006c44ae38c28e4e880d56cbedc3422252dd9b3e1578433ef206d0b1acd3c60000000000feffffff6211db0e287482f056663232666d813da25fcf11357d689a0e413a57a0192fbb0000000000feffffffe3ff30fcbf5a121979d18347acefdf35c1d0d103384943308b7d73076fb5bd090000000000feffffffe2d33cc41a7fc8552c5d23eed47571d106d4ae805e8e2a9dc80b7500b16d1b2a0000000000feffffff7d43b3944e054cd9357b09fe54364342ea8f37173f1f481502c3b0f5a0d251f40000000000feffffff44ee2e453102cc6259610653b9cdb0f9b57660e2a9cfc734c0cdbd276db0fa4e0000000000feffffff4e3d9caecef3e8ee84c48e7b59b1058d35e493a2ee19281f883ce5603d96f9c10000000000feffffff02f38e042a01000000160014208047f4c70ef2a956df50dce824dc24118d20a6a06e7848170000002251207099e4b23427fc40ba4777bbf52cfd0b7444d69a3e21ef281270723f54c0c14b014021a254c9770a4f5ea3023dbd64f475e4a8fce8bc22d94af6623459e19904bd1958c18ed4afffb858589c4d449f32d75b30b1ec0f95e6df7415ea92bbd51470ad01404e723f07580d5b2e133533101d7fd29ddee2822876dd5a7b1a2293868a316819af1b03e2bd3144aed24a8d7ebd6a25d1146c1e2efcaacb085b3d19d12d3efe8901405340d88d281fa1c95ba64934e9f6d16341a157425bb34846411fea4e09888acbfa06d961e737cdf6534df9b9032b3cb8346c74098dbdb6e8ac50db61674ed4e001402b7a879b19ac6133a4c97a4a161f17a7bf9407f61da0aed17037a4f45670b15a836a63042fd1411b18b41f622a66fea220e0a751ba0fbec89c4ec482637d8d1901405f38882dc9b0dbaedb6d12b81029dd3ddd3ada180ff85b4c6883e7317a8baf8cba9cf753ead2da0049b704933139bd6db233a8865791670f2ed0689fc89d58a001400bbf133dc951205ad8a312a79305d8f7ced9150a76deefd5dbab0d0d616cf2e964f5ba5dc4797adad6c6fe3aa8b06c324bd551626eb7bb6d9565371fdb7a262a014039aad3c70fd4375468013f8c347fe8a0bf572618c0774b2fc5f15d3b5439648431b7bf5c26ed17f3a174c33e4e29985e01ee6b792ac185b2e3242b688e36a5eb01409197740f4ae9d50336d499fc91ec404a0b240cfedcf2f314076e4ada267c7f2503bee097916e9b03f7768b93881baa4e535352410e674814cfe2bb0859b73b830140e9e8e82bf3a04e51f8a1256c12340eb00cf8517adaf40f01cd9050f0b1cb928886f3d1699b0504b72a0494d640ae40a5eaeab8f869b90cc4a1087c0193d4d66501402c0e0171b57d3b19e158a003991652be5e7cd5a9134e506006acf93c34d6327e37d4d765e39b51300b9187062c551fcbfce9ec3af89e66f4308530d532ce13b101409b8e2b3569bcfbb103c50b8981b8bd6a3116c8010285b234fae99383ceb03df005abed4957744050c04a9add127d39e5c29681e02e7822e07dfcfe23f00756d20140b5b3d905644ae443248243b214734a590b3e9342ce58f39b6db1a73c0d75e1fefc71452ac950bd3032e7f5c9283fe2c856c4791851e91a1b9cc6a6cdab2a47b7014079a16c56c8b29a631f2531744f4edf7d75ad6f495f97f10a2b10886fb4e78f258e9e8975928bfcea90bb744472fa99b4be2ff1efd25de29ef515a76c4c51eb590140cbd7876708c8b606c6c7a6e7e28e02ad4ac5535be5f7a46a63176ed8075c85540e94629a2a70b777563efcc5b8b129d497125558ba6d5c98277752774e7f5c7601407e9489ffbbf41d5142552d7b2296227c8a762eb4eddb9fcdefb623a0270d2642a835d4c8ca13dd7f85f2fecad8f57ad427b138f2781de71fa40fffa3a440ee1801409f4fe21e3bf769ec2bea54abb2f89a411a71bfa2e8c85544089e511a8a1e1736252f5c31b7a70ac5be47dd63e7ff84e4cd5782fc344bb4ed695aa908d5ab19cf01402952dde231feb4b5a963a4733034f38b431a32bd9370a9ddb3cdec38cf72b620f8ca234a1b3f459ce2eb5a1cd73527acae200c877696760fab5deeac5be8c3d00140ea6582eddbac103b5747ae53bc41293b7ec6c8c600c494435e84392a504f9eeae41f2688bb32a3a3a24752072f2fcd52afc1c8065578b71a83b20b080adcbf8e014085818bf1341457e4d816972e2dc87f5b5c1965e2496ec527f1ceb33dda140d911e1d0231b5a795433e656f876c4170dae71539be76bdcedee978377a85f9fd620140a920a0a7275216b0c7609e9553f2afe8db95b3febd993389c8b66785420c68001578f295f05c80dac55faa9d110c2f5bdca671d46fa11ca6fa938dd7a6cc0a82014007e79487b1f584d2caaae706c95672fed92a25e478337d1089ba3695fcf7a57b95c85bb8512554dc8f730004a4a0ec259dfe32080a0ee7525f1d8ce2ad437bc100000000"
              )
            ),
            ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS | ScriptFlags.SCRIPT_VERIFY_ANYPREVOUT
          )
          .isSuccess
      )
    }
  }
}
