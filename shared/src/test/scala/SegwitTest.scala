package scoin

import scoin._
import scodec.bits._
import Crypto._
import utest._

object SegwitTest extends TestSuite {
  val tests = Tests {
    test("pay2wpkh - create and spend - acinq") {
      // https://github.com/ACINQ/bitcoin-lib/blob/master/src/test/scala/fr/acinq/bitcoin/scalacompat/SegwitSpec.scala#L66
      val priv1 = PrivateKey.fromBase58("cV7LGVeY2VPuCyCSarqEqFCUNig2NzwiAEBTTA89vNRQ4Vqjfurs", Base58.Prefix.SecretKeyTestnet)._1
      val pub1 = priv1.publicKey
      val address1 = Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, Crypto.hash160(pub1.value))

      assert(address1 == "mp4eLFx7CpifAJxnvCZ3FmqKsh9dQmi5dA")

      // this is a standard tx that sends 0.04 BTC to mp4eLFx7CpifAJxnvCZ3FmqKsh9dQmi5dA
      val tx1 = Transaction.read("02000000000101516508384a3e006340f1ea700eb3635330beed5d94c7b460b6b495eb1593d55c0100000023220020a5fdf5b5f2c592362b78a50997821964b39dd90476c6e1f3e97e79acb134ca3bfdffffff0200093d00000000001976a9145dbf52b8d7af4fb5f9b75b808f0a8284493531b388aca005071d0000000017a914d77e5f7ca4d9f05dc4f25dc0aa1391f0e901bdfc87040047304402207bfb18327be173512f38bd4120b8f02545321ecc6105a852cbc25b1de687ba570220705a1225d8a8e0fbd4b35f3bc38a2840706f8524e8dc6f0151746aeff14033ce014730440220486925fb0495442e4ccb1b711692af7057d4db24f8775b5dfa3f8c74992081f102203beae7d96423e0c66b7b5f8919a5f3ad89a42dc4303f37201e4e596909478357014752210245119449d07c16992c148e3b33f1395ee05c936fc510d9fae83417f8e1901f922103eb03f67b56c88bccff90b76182c08556eac9ebc5a0efee8669bef69ae6d4ea5752ae75bb2300")

      // now let's create a simple tx that spends tx1 and send 0.039 BTC to P2WPK output
      val tx2 = {
        val tmp = Transaction(version = 1,
          txIn = TxIn(OutPoint(tx1.hash, 0), sequence = 0xffffffffL, signatureScript = ByteVector.empty, witness = ScriptWitness.empty) :: Nil,
          txOut = TxOut(0.039.btc, Script.pay2wpkh(pub1)) :: Nil,
          lockTime = 0
        )
        val sig = Transaction.signInput(tmp, 0, tx1.txOut(0).publicKeyScript, SIGHASH_ALL, 0.sat, SigVersion.SIGVERSION_BASE, priv1)
        tmp.updateSigScript(0, OP_PUSHDATA(sig) :: OP_PUSHDATA(priv1.publicKey) :: Nil)
      }
      Transaction.correctlySpends(tx2, Seq(tx1), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
      assert(tx2.txid == ByteVector32(hex"f25b3fecc9652466926237d96e4bc7ee2c984051fe48e61417aba218af5570c3"))
      // this tx was published on testnet as f25b3fecc9652466926237d96e4bc7ee2c984051fe48e61417aba218af5570c3

      // and now we create a testnet tx that spends the P2WPK output
      val tx3 = {
        val tmp: Transaction = Transaction(version = 1,
          txIn = TxIn(OutPoint(tx2.hash, 0), sequence = 0xffffffffL, signatureScript = ByteVector.empty, witness = ScriptWitness.empty) :: Nil,
          txOut = TxOut(0.038.btc, Script.pay2wpkh(pub1)) :: Nil, // we reuse the same output script but if could be anything else
          lockTime = 0
        )
        // mind this: the pubkey script used for signing is not the prevout pubscript (which is just a push
        // of the pubkey hash), but the actual script that is evaluated by the script engine, in this case a PAY2PKH script
        val pubKeyScript = Script.pay2pkh(pub1)
        val sig = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL, tx2.txOut(0).amount, SigVersion.SIGVERSION_WITNESS_V0, priv1)
        val witness = ScriptWitness(Seq(sig, pub1.value))
        tmp.updateWitness(0, witness)
      }

      assert(Transaction.correctlySpends(tx3, Seq(tx2), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS) match {
        case util.Failure(exception) => throw exception
        case util.Success(value) => true
      })
      assert(tx3.txid == ByteVector32(hex"739e7cba97af259d2c089690adea00aa78b1c8d7995aa9377be58fe5332378aa"))
      // this tx was published on testnet as 739e7cba97af259d2c089690adea00aa78b1c8d7995aa9377be58fe5332378aa
    }

    test("pay2wpkh - create and spend - 2") {
      val priv = PrivateKey(ByteVector32.fromValidHex("01"*32))

      val fundingTx = Transaction(
        version = 1L,
        txIn = TxIn.coinbase(OP_1 :: OP_1 :: Nil) :: Nil,
        txOut = TxOut(Satoshi(1000000L),Script.pay2wpkh(priv.publicKey)) :: Nil,
        lockTime = 0L
      )

      val tx = {
        val tmp = Transaction(
          version = 1L,
          txIn = TxIn(
            outPoint = OutPoint(fundingTx,0),
            signatureScript = ByteVector.empty,
            sequence = TxIn.SEQUENCE_FINAL,
            witness = ScriptWitness.empty
          ) :: Nil,
          txOut = TxOut(
            amount = Satoshi(1000000L),
            publicKeyScript = OP_1 :: OP_CHECKSEQUENCEVERIFY :: Nil
          ) :: Nil,
          lockTime = 0L
        )
        val pubkeyScript = Script.pay2pkh(priv.publicKey) // <-- pay2pkh not p2wpkh
        // IMPORTANT: notice how `pubkeyScript` above which is used for signing
        // below is *not* the prevout pubscript (which is just a push
        // of the pubkey hash), but the actual script that is evaluated by the 
        // script engine, in this case a PAY2PKH script
        val sig = Transaction.signInput(tmp,0,pubkeyScript,SIGHASH_ALL, Satoshi(1000000L),SigVersion.SIGVERSION_WITNESS_V0,priv)
        val witness = ScriptWitness(Seq(sig,priv.publicKey.value))
        tmp.updateWitness(0,witness)
      }

      assert(
        Transaction.correctlySpends(tx,List(fundingTx),ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS) match {
          case util.Failure(exception) => throw exception
          case util.Success(value) => true
        }
      )
    }

    test("pay2wsh - acinq - create and spend") {
      // this test copied from: https://github.com/ACINQ/bitcoin-lib/blob/bba17601f8e892d83c1c74c953aa42fd08d44c0e/src/test/scala/fr/acinq/bitcoin/scalacompat/SegwitSpec.scala#L110
      val priv1 = PrivateKey
        .fromBase58(
          "cV5oyXUgySSMcUvKNdKtuYg4t4NTaxkwYrrocgsJZuYac2ogEdZX",
          Base58.Prefix.SecretKeyTestnet
        )
        ._1
      val pub1 = priv1.publicKey
      val address1 = Base58Check.encode(
        Base58.Prefix.PubkeyAddressTestnet,
        Crypto.hash160(pub1.value)
      )

      assert(address1 == "mkNdbutRYE3me7wvbwvvJ8XQwbzi56sneZ")

      val priv2 = PrivateKey
        .fromBase58(
          "cV7LGVeY2VPuCyCSarqEqFCUNig2NzwiAEBTTA89vNRQ4Vqjfurs",
          Base58.Prefix.SecretKeyTestnet
        )
        ._1
      val pub2 = priv2.publicKey

      val priv3 = PrivateKey
        .fromBase58(
          "cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp",
          Base58.Prefix.SecretKeyTestnet
        )
        ._1
      val pub3 = priv3.publicKey

      // this is a standard tx that sends 0.05 BTC to mkNdbutRYE3me7wvbwvvJ8XQwbzi56sneZ
      val tx1 = Transaction.read(
        "020000000001016ecc08b535a0c774234419dee508867ace1535a0d256d6b2aa19942441777336000000002322002073bb471aa121fbdd95942eabb5e665d66e71542e6e075c8392cd0df72a075b72fdffffff02803823030000000017a914d3c15be7951c9de644bdf9e22dcbcb77550c4ae487404b4c00000000001976a9143545b2a6659dbe5bdf841d1158135be184d81d3688ac0400473044022041cac92405e4e3215c2f9c27a67ff0792c8fb76e4182023fed081f541f4563e002203bd04d4d810ef8074aeb26a19e01e1ee1a40ad83e4d0ac2c614b8cb22825d2ae0147304402204c947b46ea480419c04098a56a5219bb1f491b07e12926fb6f304132a1f1e29e022078cc9f004c74d6c3c2b2dfcca6385d2fabe44d4eadb027a0d764e1ab9d7f09190147522102be608bf8904326b4d0ec9346aa348773fe51ee70338849acd2dd710b73bf611a2103627c19e40f67c5ee8b44df85ee911b7e978869fa5a3de1d972a461f47ea349e452ae90bb2300"
      )

      // now let's create a simple tx that spends tx1 and send 0.5 BTC to a P2WSH output
      val tx2 = {
        // our script is a 2-of-2 multisig script
        val redeemScript = Script.createMultiSigMofN(2, Seq(pub2, pub3))
        val tmp = Transaction(
          version = 1,
          txIn = TxIn(
            OutPoint(tx1.hash, 1),
            sequence = 0xffffffffL,
            signatureScript = ByteVector.empty
          ) :: Nil,
          txOut = TxOut(0.049.btc, Script.pay2wsh(redeemScript)) :: Nil,
          lockTime = 0
        )
        val sig = Transaction.signInput(
          tmp,
          0,
          tx1.txOut(1).publicKeyScript,
          SIGHASH_ALL,
          0.sat,
          SigVersion.SIGVERSION_BASE,
          priv1
        )
        tmp.updateSigScript(
          0,
          OP_PUSHDATA(sig) :: OP_PUSHDATA(priv1.publicKey) :: Nil
        )
        // Transaction.sign(tmp, Seq(SignData(tx1.txOut(1).publicKeyScript, priv1)))
      }
      assert(
        Transaction
          .correctlySpends(
            tx2,
            Seq(tx1),
            ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS
          )
          .isSuccess
      )
      assert(
        tx2.txid == ByteVector32(
          hex"2f8360a06a31ca642d717b1857aa86b3306fc554fa9c437d88b4bc61b7f2b3e9"
        )
      )
      // this tx was published on testnet as 2f8360a06a31ca642d717b1857aa86b3306fc554fa9c437d88b4bc61b7f2b3e9

      // and now we create a testnet tx that spends the P2WSH output
      val tx3 = {
        val tmp: Transaction = Transaction(
          version = 1,
          txIn = TxIn(
            OutPoint(tx2.hash, 0),
            sequence = 0xffffffffL,
            signatureScript = ByteVector.empty
          ) :: Nil,
          txOut = TxOut(0.048.btc, Script.pay2wpkh(pub1)) :: Nil,
          lockTime = 0
        )
        val pubKeyScript =
          Script.write(Script.createMultiSigMofN(2, Seq(pub2, pub3)))
        val sig2 = Transaction.signInput(
          tmp,
          0,
          pubKeyScript,
          SIGHASH_ALL,
          tx2.txOut(0).amount,
          SigVersion.SIGVERSION_WITNESS_V0,
          priv2
        )
        val sig3 = Transaction.signInput(
          tmp,
          0,
          pubKeyScript,
          SIGHASH_ALL,
          tx2.txOut(0).amount,
          SigVersion.SIGVERSION_WITNESS_V0,
          priv3
        )
        val witness =
          ScriptWitness(Seq(ByteVector.empty, sig2, sig3, pubKeyScript))
        tmp.updateWitness(0, witness)
      }

      assert(
        Transaction
          .correctlySpends(
            tx3,
            Seq(tx2),
            ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS
          )
          .isSuccess
      )
      assert(
        tx3.txid == ByteVector32(
          hex"4817f79def9d9f559ddaa636f0c196e79f31bc959feead77b4151733114c652a"
        )
      )
      // this tx was published on testnet as 4817f79def9d9f559ddaa636f0c196e79f31bc959feead77b4151733114c652a
    }

    test("segwit - input and output weights") {
      // this test taken from: https://github.com/ACINQ/bitcoin-kmp/pull/84/files
      val publicKey1 = PublicKey(
        ByteVector.fromValidHex(
          "03949633a194a43a310c5a593aada2f2d4a4e3c181880e2b396facfb2130a7f0b5"
        )
      )
      val publicKey2 = PublicKey(
        ByteVector.fromValidHex(
          "02cf5642ac302c004f429b1d9334ac3f93f65ae4df2fb6bf23af3a848166afc662"
        )
      )
      val sig = ByteVector.fromValidHex(
        "f55bcf4c0650024f421bef9f47f9967fe3015b8ceeda8328185d0f2e73e8c30980e95282b1a73c8d30ceae3c40a9d6df952fd93ea027f6d2a41f6b21dcb1afbef37e81988e8f770cca"
      )
      val txId = ByteVector32.fromValidHex(
        "2f8dbf25b36aef3ab1c14c302e3d07fddd8a9d860126bc6a03e8533bb6a31cbe"
      )

      val p2wpkhInputNoWitness = TxIn(OutPoint(txId, 3), ByteVector.empty, 0)
      val p2wpkhInputWithWitness = TxIn(
        OutPoint(txId, 3),
        ByteVector.empty,
        0,
        Script.witnessPay2wpkh(publicKey1, sig)
      )
      // See https://bitcoin.stackexchange.com/questions/100159/what-is-the-size-and-weight-of-a-p2wpkh-input
      assert(p2wpkhInputNoWitness.weight == 164)
      assert(p2wpkhInputWithWitness.weight == 273)

      // This is similar to a lightning channel funding input.
      val p2wshInputWithWitness = TxIn(
        OutPoint(txId, 3),
        ByteVector.empty,
        0,
        Script.witnessMultiSigMofN(List(publicKey1, publicKey2), List(sig, sig))
      )
      assert(p2wshInputWithWitness.weight == 386)

      val p2wpkhOutput = TxOut(Satoshi(150_000), Script.pay2wpkh(publicKey1))
      val p2wshOutput = TxOut(
        Satoshi(150_000),
        Script.pay2wsh(
          Script.createMultiSigMofN(1, List(publicKey1, publicKey2))
        )
      )
      val p2trOutput = TxOut(Satoshi(150_000), Script.pay2tr(publicKey1.xonly))
      // See https://bitcoin.stackexchange.com/questions/66428/what-is-the-size-of-different-bitcoin-transaction-types
      assert(p2wpkhOutput.weight == 124)
      assert(p2wshOutput.weight == 172)
      assert(p2trOutput.weight == 172)

    }
  }
}
