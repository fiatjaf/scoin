import java.math.BigInteger
import scala.language.implicitConversions
import scodec.bits.ByteVector

import scoin.Crypto.{PublicKey, PrivateKey, randomBytes}
import scala.util.Try
import scala.util.Failure
import scala.util.Success

/** Types and utils related to Bitcoin blockchain objects: blocks, scripts,
  * transactions, addresses, PSBTs, keys, signatures, hashes.
  */
package object scoin {
  val MaxScriptElementSize = 520
  val MaxBlockSize = 1000000
  val LockTimeThreshold = 500000000L

  /** signature hash flags
    */
  val SIGHASH_ALL = 1
  val SIGHASH_NONE = 2
  val SIGHASH_SINGLE = 3
  val SIGHASH_ANYONECANPAY = 0x80

  object SigVersion {
    val SIGVERSION_BASE = 0
    val SIGVERSION_WITNESS_V0 = 1
  }

  implicit object NumericSatoshi extends Numeric[Satoshi] {
    // @formatter:off
    override def compare(x: Satoshi, y: Satoshi): Int = x.compare(y)
    override def minus(x: Satoshi, y: Satoshi): Satoshi = x - y
    override def negate(x: Satoshi): Satoshi = -x
    override def plus(x: Satoshi, y: Satoshi): Satoshi = x + y
    override def times(x: Satoshi, y: Satoshi): Satoshi = x * y.toLong
    override def toDouble(x: Satoshi): Double = x.toLong.toDouble
    override def toFloat(x: Satoshi): Float = x.toLong.toFloat
    override def toInt(x: Satoshi): Int = x.toLong.toInt
    override def toLong(x: Satoshi): Long = x.toLong
    override def fromInt(x: Int): Satoshi = Satoshi(x)
    override def parseString(str: String): Option[Satoshi] = None
    // @formatter:on
  }

  implicit final class SatoshiLong(private val n: Long) extends AnyVal {
    def sat = Satoshi(n)
  }

  implicit final class BtcDouble(private val n: Double) extends AnyVal {
    def btc = Btc(n)
  }

  // @formatter:off
  implicit def satoshi2btc(input: Satoshi): Btc = input.toBtc
  implicit def btc2satoshi(input: Btc): Satoshi = input.toSatoshi
  implicit def satoshi2millisatoshi(input: Satoshi): MilliSatoshi = input.toMilliSatoshi
  implicit def millisatoshi2satoshi(input: MilliSatoshi): Satoshi = input.toSatoshi
  implicit def btc2millisatoshi(input: Btc): MilliSatoshi = input.toMilliSatoshi
  implicit def millisatoshi2btc(input: MilliSatoshi): Btc = input.toBtc
  // @formatter:on

  /** @param input
    *   compact size encoded integer as used to encode proof-of-work difficulty
    *   target
    * @return
    *   a (result, isNegative, overflow) tuple were result is the decoded
    *   integer
    */
  def decodeCompact(input: Long): (BigInteger, Boolean, Boolean) = {
    val nSize = (input >> 24).toInt
    val (nWord, result) = if (nSize <= 3) {
      val nWord1 = (input & 0x007fffffL) >> 8 * (3 - nSize)
      (nWord1, BigInteger.valueOf(nWord1))
    } else {
      val nWord1 = input & 0x007fffffL
      (nWord1, BigInteger.valueOf(nWord1).shiftLeft(8 * (nSize - 3)))
    }
    val isNegative = nWord != 0 && (input & 0x00800000) != 0
    val overflow =
      nWord != 0 && ((nSize > 34) || (nWord > 0xff && nSize > 33) || (nWord > 0xffff && nSize > 32))
    (result, isNegative, overflow)
  }

  /** @param value
    *   input value
    * @return
    *   the compact encoding of the input value. this is used to encode
    *   proof-of-work target into the `bits` block header field
    */
  def encodeCompact(value: BigInteger): Long = {
    var size = value.toByteArray.length
    var compact =
      if (size <= 3) value.longValue << 8 * (3 - size)
      else value.shiftRight(8 * (size - 3)).longValue
    // The 0x00800000 bit denotes the sign.
    // Thus, if it is already set, divide the mantissa by 256 and increase the exponent.
    if ((compact & 0x00800000L) != 0) {
      compact >>= 8
      size += 1
    }
    compact |= size << 24
    compact |= (if (value.signum() == -1) 0x00800000 else 0)
    compact
  }

  def isAnyoneCanPay(sighashType: Int): Boolean =
    (sighashType & SIGHASH_ANYONECANPAY) != 0

  def isHashSingle(sighashType: Int): Boolean =
    (sighashType & 0x1f) == SIGHASH_SINGLE

  def isHashNone(sighashType: Int): Boolean =
    (sighashType & 0x1f) == SIGHASH_NONE

  def computeP2PkhAddress(pub: PublicKey, chainHash: ByteVector32): String = {
    val hash = pub.hash160
    chainHash match {
      case Block.SignetGenesisBlock.hash | Block.RegtestGenesisBlock.hash |
          Block.TestnetGenesisBlock.hash =>
        Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, hash)
      case Block.LivenetGenesisBlock.hash =>
        Base58Check.encode(Base58.Prefix.PubkeyAddress, hash)
      case _ =>
        throw new IllegalArgumentException("Unknown chain hash: " + chainHash)
    }
  }

  def computeBIP44Address(pub: PublicKey, chainHash: ByteVector32): String =
    computeP2PkhAddress(pub, chainHash)

  /** @param pub
    *   public key
    * @param chainHash
    *   chain hash (i.e. hash of the genesis block of the chain we're on)
    * @return
    *   the p2swh-of-p2pkh address for this key). It is a Base58 address that is
    *   compatible with most bitcoin wallets
    */
  def computeP2ShOfP2WpkhAddress(
      pub: PublicKey,
      chainHash: ByteVector32
  ): String = {
    val script = Script.pay2wpkh(pub)
    val hash = Crypto.hash160(Script.write(script))
    chainHash match {
      case Block.SignetGenesisBlock.hash | Block.RegtestGenesisBlock.hash |
          Block.TestnetGenesisBlock.hash =>
        Base58Check.encode(Base58.Prefix.ScriptAddressTestnet, hash)
      case Block.LivenetGenesisBlock.hash =>
        Base58Check.encode(Base58.Prefix.ScriptAddress, hash)
      case _ =>
        throw new IllegalArgumentException("Unknown chain hash: " + chainHash)
    }
  }

  def computeBIP49Address(pub: PublicKey, chainHash: ByteVector32): String =
    computeP2ShOfP2WpkhAddress(pub, chainHash)

  /** @param pub
    *   public key
    * @param chainHash
    *   chain hash (i.e. hash of the genesis block of the chain we're on)
    * @return
    *   the BIP84 address for this key (i.e. the p2wpkh address for this key).
    *   It is a Bech32 address that will be understood only by native sewgit
    *   wallets
    */
  def computeP2WpkhAddress(pub: PublicKey, chainHash: ByteVector32): String = {
    val hash = pub.hash160
    val hrp = chainHash match {
      case Block.LivenetGenesisBlock.hash => "bc"
      case Block.TestnetGenesisBlock.hash => "tb"
      case Block.RegtestGenesisBlock.hash => "bcrt"
      case Block.SignetGenesisBlock.hash  => "tb"
      case _ =>
        throw new IllegalArgumentException("Unknown chain hash: " + chainHash)
    }
    Bech32.encodeWitnessAddress(hrp, 0, hash)
  }

  def computeBIP84Address(pub: PublicKey, chainHash: ByteVector32): String =
    computeP2WpkhAddress(pub, chainHash)

  /** @param chainHash
    *   hash of the chain (i.e. hash of the genesis block of the chain we're on)
    * @param script
    *   public key script
    * @return
    *   the address of this public key script on this chain
    */
  def computeScriptAddress(
      chainHash: ByteVector32,
      script: Seq[ScriptElt]
  ): String = {
    val base58PubkeyPrefix = chainHash match {
      case Block.LivenetGenesisBlock.hash => Base58.Prefix.PubkeyAddress
      case Block.TestnetGenesisBlock.hash | Block.RegtestGenesisBlock.hash =>
        Base58.Prefix.PubkeyAddressTestnet
      case _ =>
        throw new IllegalArgumentException(s"invalid chain hash $chainHash")
    }
    val base58ScriptPrefix = chainHash match {
      case Block.LivenetGenesisBlock.hash => Base58.Prefix.ScriptAddress
      case Block.TestnetGenesisBlock.hash | Block.RegtestGenesisBlock.hash =>
        Base58.Prefix.ScriptAddressTestnet
      case _ =>
        throw new IllegalArgumentException(s"invalid chain hash $chainHash")
    }
    val hrp = chainHash match {
      case Block.LivenetGenesisBlock.hash => "bc"
      case Block.TestnetGenesisBlock.hash => "tb"
      case Block.RegtestGenesisBlock.hash => "bcrt"
      case _ =>
        throw new IllegalArgumentException(s"invalid chain hash $chainHash")
    }
    script match {
      case OP_DUP :: OP_HASH160 :: OP_PUSHDATA(
            pubKeyHash,
            _
          ) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil =>
        Base58Check.encode(base58PubkeyPrefix, pubKeyHash)
      case OP_HASH160 :: OP_PUSHDATA(scriptHash, _) :: OP_EQUAL :: Nil =>
        Base58Check.encode(base58ScriptPrefix, scriptHash)
      case OP_0 :: OP_PUSHDATA(pubKeyHash, _) :: Nil
          if pubKeyHash.length == 20 =>
        Bech32.encodeWitnessAddress(hrp, 0, pubKeyHash)
      case OP_0 :: OP_PUSHDATA(scriptHash, _) :: Nil
          if scriptHash.length == 32 =>
        Bech32.encodeWitnessAddress(hrp, 0, scriptHash)
      case OP_1 :: OP_PUSHDATA(program, _) :: Nil
          if 2 <= program.length && program.length <= 40 =>
        Bech32.encodeWitnessAddress(hrp, 1, program)
      case OP_2 :: OP_PUSHDATA(program, _) :: Nil
          if 2 <= program.length && program.length <= 40 =>
        Bech32.encodeWitnessAddress(hrp, 2, program)
      case OP_3 :: OP_PUSHDATA(program, _) :: Nil
          if 2 <= program.length && program.length <= 40 =>
        Bech32.encodeWitnessAddress(hrp, 3, program)
      case OP_4 :: OP_PUSHDATA(program, _) :: Nil
          if 2 <= program.length && program.length <= 40 =>
        Bech32.encodeWitnessAddress(hrp, 4, program)
      case OP_5 :: OP_PUSHDATA(program, _) :: Nil
          if 2 <= program.length && program.length <= 40 =>
        Bech32.encodeWitnessAddress(hrp, 5, program)
      case OP_6 :: OP_PUSHDATA(program, _) :: Nil
          if 2 <= program.length && program.length <= 40 =>
        Bech32.encodeWitnessAddress(hrp, 6, program)
      case OP_7 :: OP_PUSHDATA(program, _) :: Nil
          if 2 <= program.length && program.length <= 40 =>
        Bech32.encodeWitnessAddress(hrp, 7, program)
      case OP_8 :: OP_PUSHDATA(program, _) :: Nil
          if 2 <= program.length && program.length <= 40 =>
        Bech32.encodeWitnessAddress(hrp, 8, program)
      case OP_9 :: OP_PUSHDATA(program, _) :: Nil
          if 2 <= program.length && program.length <= 40 =>
        Bech32.encodeWitnessAddress(hrp, 9, program)
      case OP_10 :: OP_PUSHDATA(program, _) :: Nil
          if 2 <= program.length && program.length <= 40 =>
        Bech32.encodeWitnessAddress(hrp, 10, program)
      case OP_11 :: OP_PUSHDATA(program, _) :: Nil
          if 2 <= program.length && program.length <= 40 =>
        Bech32.encodeWitnessAddress(hrp, 11, program)
      case OP_12 :: OP_PUSHDATA(program, _) :: Nil
          if 2 <= program.length && program.length <= 40 =>
        Bech32.encodeWitnessAddress(hrp, 12, program)
      case OP_13 :: OP_PUSHDATA(program, _) :: Nil
          if 2 <= program.length && program.length <= 40 =>
        Bech32.encodeWitnessAddress(hrp, 13, program)
      case OP_14 :: OP_PUSHDATA(program, _) :: Nil
          if 2 <= program.length && program.length <= 40 =>
        Bech32.encodeWitnessAddress(hrp, 14, program)
      case OP_15 :: OP_PUSHDATA(program, _) :: Nil
          if 2 <= program.length && program.length <= 40 =>
        Bech32.encodeWitnessAddress(hrp, 15, program)
      case OP_16 :: OP_PUSHDATA(program, _) :: Nil
          if 2 <= program.length && program.length <= 40 =>
        Bech32.encodeWitnessAddress(hrp, 16, program)
      case _ =>
        throw new IllegalArgumentException(
          s"invalid pubkey script ${Script.write(script)}"
        )
    }
  }

  /** @param chainHash
    *   hash of the chain (i.e. hash of the genesis block of the chain we're on)
    * @param script
    *   public key script
    * @return
    *   the address of this public key script on this chain
    */
  def computeScriptAddress(
      chainHash: ByteVector32,
      script: ByteVector
  ): String = computeScriptAddress(chainHash, Script.parse(script))

  /* miscellaneous */
  def randomBytes32(): ByteVector32 = ByteVector32(randomBytes(32))
  def randomBytes64(): ByteVector64 = ByteVector64(randomBytes(64))
  def randomKey(): PrivateKey = PrivateKey(randomBytes32())

  val invalidPubKey: PublicKey =
    PublicKey.fromBin(ByteVector.fromValidHex("02" * 33), checkValid = false)

  def isPay2PubkeyHash(address: String): Boolean =
    address.startsWith("1") || address.startsWith("m") || address.startsWith(
      "n"
    )

  /**
    * Given an address and chain code, find public key script (if exists).
    * Will try Base58 encoding first, then Bech32.
    *
    * @param chainHash
    * @param address
    * @return
    */
  def addressToPublicKeyScript(chainHash: ByteVector32, address:String): Seq[ScriptElt] = {
    val witnessVersions = Map(
                  0.toByte -> OP_0,
            1.toByte -> OP_1,
            2.toByte -> OP_2,
            3.toByte -> OP_3,
            4.toByte -> OP_4,
            5.toByte -> OP_5,
            6.toByte -> OP_6,
            7.toByte -> OP_7,
            8.toByte -> OP_8,
            9.toByte -> OP_9,
            10.toByte -> OP_10,
            11.toByte -> OP_11,
            12.toByte -> OP_12,
            13.toByte -> OP_13,
            14.toByte -> OP_14,
            15.toByte -> OP_15,
            16.toByte -> OP_16
    )
    Try(Base58Check.decode(address)) match {
      case Success((prefix,data)) => prefix match {
        case Base58.Prefix.PubkeyAddressTestnet if( chainHash == Block.TestnetGenesisBlock.hash || chainHash == Block.RegtestGenesisBlock.hash || chainHash == Block.SignetGenesisBlock.hash ) => Script.pay2pkh(data)
        case Base58.Prefix.PubkeyAddress if( chainHash == Block.LivenetGenesisBlock.hash) => Script.pay2pkh(data)
        case Base58.Prefix.ScriptAddressTestnet if( chainHash == Block.TestnetGenesisBlock.hash || chainHash == Block.RegtestGenesisBlock.hash || chainHash == Block.SignetGenesisBlock.hash ) => List(OP_HASH160, OP_PUSHDATA(data), OP_EQUAL)
        case Base58.Prefix.ScriptAddress if ( chainHash == Block.LivenetGenesisBlock.hash) => List(OP_HASH160, OP_PUSHDATA(data), OP_EQUAL)
        case _ => throw new IllegalArgumentException("base58 address does not match our blockchain")
      }
      case Failure(base58error) => Try(Bech32.decodeWitnessAddress(address)) match {
        case Success((prefix,version,program)) => {
          witnessVersions.get(version) match {
            case None => throw new IllegalArgumentException(s"invalid version $version in bech32 address")
            case Some(wv) if(program.size != 20 && program.size != 32) => throw new IllegalArgumentException("hash length in bech32 address must be either 20 or 32 bytes")
            case Some(wv) if(prefix == "bc" && chainHash == Block.LivenetGenesisBlock.hash) => List(wv, OP_PUSHDATA(program))
            case Some(wv) if(prefix == "tb" && chainHash == Block.TestnetGenesisBlock.hash) => List(wv, OP_PUSHDATA(program))
            case Some(wv) if(prefix == "tb" && chainHash == Block.SignetGenesisBlock.hash) => List(wv, OP_PUSHDATA(program))
            case Some(wv) if(prefix == "bcrt" && chainHash == Block.RegtestGenesisBlock.hash) => List(wv, OP_PUSHDATA(program))
            case _ => throw new IllegalArgumentException("bech32 address does not match our blockchain")
          }
        }
        case Failure(exception) => throw new IllegalArgumentException(s"$address is neither a valid Base58 address ($base58error) nor a valid Bech32 address")
      }
    }
  }
}
