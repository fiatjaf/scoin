package scoin

import utest._

import scodec.bits._

object RecklessTest extends TestSuite {
    val tests = Tests {
        test("reckless hello"){
            assert(true)
        }
        
        test("reckless sha256"){
            scoin.Crypto.sha256(ByteVector("abcd".getBytes))
        }
    }
}