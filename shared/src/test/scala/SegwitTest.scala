package scoin

import scoin._
import scodec.bits._
import Crypto._
import utest._

object SegwitTest extends TestSuite {
  val tests = Tests {
    test("pay2wsh - acinq - create and spend"){
      // this test copied from: https://github.com/ACINQ/bitcoin-lib/blob/bba17601f8e892d83c1c74c953aa42fd08d44c0e/src/test/scala/fr/acinq/bitcoin/scalacompat/SegwitSpec.scala#L110
      val priv1 = PrivateKey.fromBase58("cV5oyXUgySSMcUvKNdKtuYg4t4NTaxkwYrrocgsJZuYac2ogEdZX", Base58.Prefix.SecretKeyTestnet)._1
      val pub1 = priv1.publicKey
      val address1 = Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, Crypto.hash160(pub1.value))

      assert(address1 == "mkNdbutRYE3me7wvbwvvJ8XQwbzi56sneZ")

      val priv2 = PrivateKey.fromBase58("cV7LGVeY2VPuCyCSarqEqFCUNig2NzwiAEBTTA89vNRQ4Vqjfurs", Base58.Prefix.SecretKeyTestnet)._1
      val pub2 = priv2.publicKey

      val priv3 = PrivateKey.fromBase58("cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp", Base58.Prefix.SecretKeyTestnet)._1
      val pub3 = priv3.publicKey

      // this is a standard tx that sends 0.05 BTC to mkNdbutRYE3me7wvbwvvJ8XQwbzi56sneZ
      val tx1 = Transaction.read("020000000001016ecc08b535a0c774234419dee508867ace1535a0d256d6b2aa19942441777336000000002322002073bb471aa121fbdd95942eabb5e665d66e71542e6e075c8392cd0df72a075b72fdffffff02803823030000000017a914d3c15be7951c9de644bdf9e22dcbcb77550c4ae487404b4c00000000001976a9143545b2a6659dbe5bdf841d1158135be184d81d3688ac0400473044022041cac92405e4e3215c2f9c27a67ff0792c8fb76e4182023fed081f541f4563e002203bd04d4d810ef8074aeb26a19e01e1ee1a40ad83e4d0ac2c614b8cb22825d2ae0147304402204c947b46ea480419c04098a56a5219bb1f491b07e12926fb6f304132a1f1e29e022078cc9f004c74d6c3c2b2dfcca6385d2fabe44d4eadb027a0d764e1ab9d7f09190147522102be608bf8904326b4d0ec9346aa348773fe51ee70338849acd2dd710b73bf611a2103627c19e40f67c5ee8b44df85ee911b7e978869fa5a3de1d972a461f47ea349e452ae90bb2300")

      // now let's create a simple tx that spends tx1 and send 0.5 BTC to a P2WSH output
      val tx2 = {
        // our script is a 2-of-2 multisig script
        val redeemScript = Script.createMultiSigMofN(2, Seq(pub2, pub3))
        val tmp = Transaction(version = 1,
          txIn = TxIn(OutPoint(tx1.hash, 1), sequence = 0xffffffffL, signatureScript = ByteVector.empty) :: Nil,
          txOut = TxOut(0.049.btc, Script.pay2wsh(redeemScript)) :: Nil,
          lockTime = 0
        )
        val sig = Transaction.signInput(tmp, 0, tx1.txOut(1).publicKeyScript, SIGHASH_ALL, 0.sat, SigVersion.SIGVERSION_BASE, priv1)
        tmp.updateSigScript(0, OP_PUSHDATA(sig) :: OP_PUSHDATA(priv1.publicKey) :: Nil)
        //Transaction.sign(tmp, Seq(SignData(tx1.txOut(1).publicKeyScript, priv1)))
      }
      Transaction.correctlySpends(tx2, Seq(tx1), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
      assert(tx2.txid == ByteVector32(hex"2f8360a06a31ca642d717b1857aa86b3306fc554fa9c437d88b4bc61b7f2b3e9"))
      // this tx was published on testnet as 2f8360a06a31ca642d717b1857aa86b3306fc554fa9c437d88b4bc61b7f2b3e9

      // and now we create a testnet tx that spends the P2WSH output
      val tx3 = {
        val tmp: Transaction = Transaction(version = 1,
          txIn = TxIn(OutPoint(tx2.hash, 0), sequence = 0xffffffffL, signatureScript = ByteVector.empty) :: Nil,
          txOut = TxOut(0.048.btc, Script.pay2wpkh(pub1)) :: Nil,
          lockTime = 0
        )
        val pubKeyScript = Script.write(Script.createMultiSigMofN(2, Seq(pub2, pub3)))
        val sig2 = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL, tx2.txOut(0).amount, SigVersion.SIGVERSION_WITNESS_V0, priv2)
        val sig3 = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL, tx2.txOut(0).amount, SigVersion.SIGVERSION_WITNESS_V0, priv3)
        val witness = ScriptWitness(Seq(ByteVector.empty, sig2, sig3, pubKeyScript))
        tmp.updateWitness(0, witness)
      }

      Transaction.correctlySpends(tx3, Seq(tx2), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
      assert(tx3.txid == ByteVector32(hex"4817f79def9d9f559ddaa636f0c196e79f31bc959feead77b4151733114c652a"))
      // this tx was published on testnet as 4817f79def9d9f559ddaa636f0c196e79f31bc959feead77b4151733114c652a
    }

    /*test("pay2wsh - scoin - create and spend") {
      val priv1 = PrivateKey.fromBase58("cV5oyXUgySSMcUvKNdKtuYg4t4NTaxkwYrrocgsJZuYac2ogEdZX", Base58.Prefix.SecretKeyTestnet)._1
      val pub1 = priv1.publicKey
      val address1 = Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, Crypto.hash160(pub1.value))

      assert(address1 == "mkNdbutRYE3me7wvbwvvJ8XQwbzi56sneZ")

      val priv2 = PrivateKey.fromBase58("cV7LGVeY2VPuCyCSarqEqFCUNig2NzwiAEBTTA89vNRQ4Vqjfurs", Base58.Prefix.SecretKeyTestnet)._1
      val pub2 = priv2.publicKey

      val priv3 = PrivateKey.fromBase58("cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp", Base58.Prefix.SecretKeyTestnet)._1
      val pub3 = priv3.publicKey

      // this is a standard tx that sends 0.05 BTC to mkNdbutRYE3me7wvbwvvJ8XQwbzi56sneZ
      val tx1 = Transaction(
        version = 1,
        txIn = TxIn.coinbase(OP_1 :: OP_1 :: Nil) :: Nil,
        txOut = TxOut(0.5.btc, Script.pay2pkh(pub1)) :: Nil,
        lockTime = 0L
      )
      // now let's create a simple tx that spends tx1 and sends 0.049 BTC to a P2WSH output
      val tx2 = {
        // our script is a 2-of-2 multisig script
        val redeemScript = Script.createMultiSigMofN(2, Seq(pub2, pub3))
        val tmp = Transaction(version = 1,
          txIn = TxIn(OutPoint(tx1.hash, 0), sequence = 0xffffffffL, signatureScript = ByteVector.empty) :: Nil,
          txOut = TxOut(0.049.btc, Script.pay2wsh(redeemScript)) :: Nil,
          lockTime = 0
        )
        val sig = Transaction.signInput(tmp, 0, tx1.txOut(0).publicKeyScript, SIGHASH_ALL, 0.5.btc, SigVersion.SIGVERSION_BASE, priv1)
        tmp.updateSigScript(0, OP_PUSHDATA(sig) :: OP_PUSHDATA(priv1.publicKey) :: Nil)
        //Transaction.sign(tmp, Seq(SignData(tx1.txOut(0).publicKeyScript, priv1)))
      }
      Transaction.correctlySpends(tx2, Seq(tx1), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
      // and now we create a segwit tx that spends the P2WSH output
      val tx3 = {
        val tmp: Transaction = Transaction(version = 1,
          txIn = TxIn(OutPoint(tx2.hash, 0), sequence = 0xffffffffL, signatureScript = ByteVector.empty) :: Nil,
          txOut = TxOut(0.048.btc, Script.pay2wpkh(pub1)) :: Nil,
          lockTime = 0
        )
        val pubKeyScript = Script.write(Script.createMultiSigMofN(2, Seq(pub2, pub3)))
        val sig2 = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL, tx2.txOut(0).amount, SigVersion.SIGVERSION_WITNESS_V0, priv2)
        val sig3 = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL, tx2.txOut(0).amount, SigVersion.SIGVERSION_WITNESS_V0, priv3)
        val witness = ScriptWitness(Seq(ByteVector.empty, sig2, sig3, pubKeyScript))
        tmp.updateWitness(0, witness)
      }

      Transaction.correctlySpends(tx3, Seq(tx2), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    }*/
  }
}