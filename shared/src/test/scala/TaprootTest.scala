package scoin

import scoin._
import utest._
import scodec.bits._
import scoin.DeterministicWallet
import scoin.DeterministicWallet.KeyPath
import scoin.Crypto.XOnlyPublicKey
import scoin.Crypto.PrivateKey

object TaprootTest extends TestSuite {
    // https://github.com/ACINQ/bitcoin-kmp/pull/40/commits/fecb238fcc41aea9be48a12e3cfaa87c35bf960b#diff-ff1783827538d549c00a3f880a3aadba3523737a3c110fbe6634ccad4b6d2354
    val tests = Tests {
        test("check taproot signatures") {
            // derive BIP86 wallet key
            val (_, master) = DeterministicWallet.ExtendedPrivateKey.decode("tprv8ZgxMBicQKsPeQQADibg4WF7mEasy3piWZUHyThAzJCPNgMHDVYhTCVfev3jFbDhcYm4GimeFMbbi9z1d9rfY1aL5wfJ9mNebQ4thJ62EJb")
            val key = DeterministicWallet.derivePrivateKey(master, KeyPath("86'/1'/0'/0/1"))
            val internalKey = XOnlyPublicKey(key.publicKey)
            val outputKey = internalKey.outputKey(merkleRoot = None)
            assertEquals("tb1phlhs7afhqzkgv0n537xs939s687826vn8l24ldkrckvwsnlj3d7qj6u57c", Bech32.encodeWitnessAddress("tb", 1, outputKey.value))

            // tx sends to tb1phlhs7afhqzkgv0n537xs939s687826vn8l24ldkrckvwsnlj3d7qj6u57c
            val tx = Transaction.read("02000000000101590c995983abb86d8196f57357f2aac0e6cc6144d8239fd8a171810b476269d50000000000feffffff02a086010000000000225120bfef0f753700ac863e748f8d02c4b0d1fc7569933fd55fb6c3c598e84ff28b7c13d3abe65a060000160014353b5487959c58f5feafe63800057899f9ece4280247304402200b20c43175358c970850a583fd60d36c06588f1103b82b0968dc21e20e7d7958022027c64923623205c4985541d4a9fc6b5df4111d918fe63803337538b029c17ea20121022f685476d299e7b49d3a6b380e10aec1f93d96819fd7697669fabb533cc052624ff50000")
            assertEquals(Script.pay2tr(outputKey), Script.parse(tx.txOut(0).publicKeyScript))

             // tx1 spends tx using key path spending i.e its witness just includes a single signature that is valid for outputKey
            val tx1 = Transaction.read("020000000001018cd229daf76b9733dad3f4d183809f6594abb788a1bf07f04d6e889d2040dbc00000000000fdffffff011086010000000000225120bfef0f753700ac863e748f8d02c4b0d1fc7569933fd55fb6c3c598e84ff28b7c01407f330922263a3f281e111bf8583964644ef7f694494d028de546b162cbd68591ab38f9626a8922dc20a84776dc9bd8a21dc5c64ffc5fa6f28f0d42ed2e5ffb7dcef50000")
            val sig = ByteVector64(tx1.txIn(0).witness.stack.head)
            val sighashType: Int = if(sig.size == 65) sig(64).toInt else 0

            // check that tx1's signature is valid
            val hash = Transaction.hashForSigningSchnorr(tx1, 0, List(tx.txOut.head), sighashType)
            assertTrue(Crypto.verifySignatureSchnorr(sig, hash, outputKey))

            // re-create signature
            val priv = key.privateKey.tweak(internalKey.tweak(None))
            // here auxiliary random data is set to null, which does not the same result as using all-zero random data
            // this is being changed in bitcoin core, so that null == all zeros
            val ourSig = Crypto.signSchnorr(hash, priv, None)
            assertTrue(Crypto.verifySignatureSchnorr(ourSig, hash, outputKey))

            // generate another sig with all zero random data, and check that it is valid too
            val ourSig1 = Crypto.signSchnorr(hash, priv, Some(ByteVector32.fromValidHex("0000000000000000000000000000000000000000000000000000000000000000")))
            assertTrue(Crypto.verifySignatureSchnorr(ourSig1, hash, outputKey))
        }
    }

    // helper function so we can copy/paste easier from ACINQ's test code
    def assertEquals[A,B](p1: A, p2: B): Unit = assert(p1 == p2)
    def assertTrue(p1: Boolean) = assert(p1)
}