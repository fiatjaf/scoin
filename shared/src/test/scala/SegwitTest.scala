package scoin

import scoin._
import scodec.bits._
import Crypto._
import utest._

object SegwitTest extends TestSuite {
  val tests = Tests {
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
        Transaction.correctlySpends(
          tx2,
          Seq(tx1),
          ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS
        )
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
        Transaction.correctlySpends(
          tx3,
          Seq(tx2),
          ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS
        )
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
