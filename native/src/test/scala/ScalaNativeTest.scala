package scoin

import scoin._
import utest._
import scodec.bits._
import inefficient.Curve._

object ScalaNativeTest extends TestSuite {
    val tests = Tests {
        test("compressed point G") {
            require(secp256k1.G.compressed.toHex.toUpperCase == "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
        }

        test("uncompressed point G") {
            require(secp256k1.G.uncompressed.toHex.toUpperCase == "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
        }

        test("point mul") {
            val curve = inefficient.Curve.secp256k1
            val priv = BigInt(27)
            // from https://asecuritysite.com/encryption/ecc_real for secp256k1
            // 27*G= (99023490166718961467148584643029653267652245207820783364668071358307234645801, 75362751621984629832705305750958516370071248757681753180287377123479199292501)
            //      = (0xdaed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729, 0xa69dce4a7d6c98e8d4a1aca87ef8d7003f83c230f3afa726ab40e52290be1c55)
            // 
            val point = curve.CurvePoint.fromUnCompressed(Crypto.PrivateKey(priv).publicKey.toUncompressedBin)
            require(point.x.toString(16) == BigInt("99023490166718961467148584643029653267652245207820783364668071358307234645801").toString(16))
            require(point.y.toString(16) == BigInt("75362751621984629832705305750958516370071248757681753180287377123479199292501").toString(16))
            require(point.compressed.toHex == "03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729")            
        }
    }
}