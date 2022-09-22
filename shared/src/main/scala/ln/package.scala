package scoin

import scala.util.{Try, Success, Failure}
import scodec.bits.{ByteVector, BitVector}
import scodec.Attempt

/** Types, utils and wire codecs related to the BOLT specification (the
  * Lightning Network).
  */
package object ln {
  def toLongId(
      fundingTxHash: ByteVector32,
      fundingOutputIndex: Int
  ): ByteVector32 = {
    require(
      fundingOutputIndex < 65536,
      "fundingOutputIndex must not be greater than FFFF"
    )
    val channelId = ByteVector32(
      fundingTxHash.take(30) :+ (fundingTxHash(
        30
      ) ^ (fundingOutputIndex >> 8)).toByte :+ (fundingTxHash(
        31
      ) ^ fundingOutputIndex).toByte
    )
    channelId
  }

  def serializationResult(attempt: Attempt[BitVector]): ByteVector =
    attempt match {
      case Attempt.Successful(bin) => bin.toByteVector
      case Attempt.Failure(cause) =>
        throw new RuntimeException(s"serialization error: $cause")
    }

  /** Tests whether the binary data is composed solely of printable ASCII
    * characters (see BOLT 1)
    *
    * @param data
    *   to check
    */
  def isAsciiPrintable(data: ByteVector): Boolean =
    data.toArray.forall(ch => ch >= 32 && ch < 127)

  /** @param baseFee
    *   fixed fee
    * @param proportionalFee
    *   proportional fee (millionths)
    * @param paymentAmount
    *   payment amount in millisatoshi
    * @return
    *   the fee that a node should be paid to forward an HTLC of 'paymentAmount'
    *   millisatoshis
    */
  def nodeFee(
      baseFee: MilliSatoshi,
      proportionalFee: Long,
      paymentAmount: MilliSatoshi
  ): MilliSatoshi = baseFee + (paymentAmount * proportionalFee) / 1000000

  /** @param address
    *   base58 of bech32 address
    * @param chainHash
    *   hash of the chain we're on, which will be checked against the input
    *   address
    * @return
    *   the public key script that matches the input address.
    */
  def addressToPublicKeyScript(
      address: String,
      chainHash: ByteVector32
  ): Seq[ScriptElt] = {

    def decodeBase58(input: String): (Byte, ByteVector) = {
      val decoded = Base58Check.decode(input)
      (decoded._1.byteValue(), decoded._2)
    }

    def decodeBech32(input: String): (String, Byte, ByteVector) = {
      val decoded = Bech32.decodeWitnessAddress(input)
      (
        decoded._1,
        decoded._2.byteValue(),
        decoded._3
      )
    }

    Try(decodeBase58(address)) match {
      case Success((Base58.Prefix.PubkeyAddressTestnet, pubKeyHash))
          if chainHash == Block.TestnetGenesisBlock.hash || chainHash == Block.RegtestGenesisBlock.hash || chainHash == Block.SignetGenesisBlock.hash =>
        Script.pay2pkh(pubKeyHash)
      case Success((Base58.Prefix.PubkeyAddress, pubKeyHash))
          if chainHash == Block.LivenetGenesisBlock.hash =>
        Script.pay2pkh(pubKeyHash)
      case Success((Base58.Prefix.ScriptAddressTestnet, scriptHash))
          if chainHash == Block.TestnetGenesisBlock.hash || chainHash == Block.RegtestGenesisBlock.hash || chainHash == Block.SignetGenesisBlock.hash =>
        OP_HASH160 :: OP_PUSHDATA(scriptHash) :: OP_EQUAL :: Nil
      case Success((Base58.Prefix.ScriptAddress, scriptHash))
          if chainHash == Block.LivenetGenesisBlock.hash =>
        OP_HASH160 :: OP_PUSHDATA(scriptHash) :: OP_EQUAL :: Nil
      case Success(_) =>
        throw new IllegalArgumentException(
          "base58 address does not match our blockchain"
        )
      case Failure(base58error) =>
        Try(decodeBech32(address)) match {
          case Success((_, version, _)) if version != 0.toByte =>
            throw new IllegalArgumentException(
              s"invalid version $version in bech32 address"
            )
          case Success((_, _, bin)) if bin.length != 20 && bin.length != 32 =>
            throw new IllegalArgumentException(
              "hash length in bech32 address must be either 20 or 32 bytes"
            )
          case Success(("bc", _, bin))
              if chainHash == Block.LivenetGenesisBlock.hash =>
            OP_0 :: OP_PUSHDATA(bin) :: Nil
          case Success(("tb", _, bin))
              if chainHash == Block.TestnetGenesisBlock.hash || chainHash == Block.SignetGenesisBlock.hash =>
            OP_0 :: OP_PUSHDATA(bin) :: Nil
          case Success(("bcrt", _, bin))
              if chainHash == Block.RegtestGenesisBlock.hash =>
            OP_0 :: OP_PUSHDATA(bin) :: Nil
          case Success(_) =>
            throw new IllegalArgumentException(
              "bech32 address does not match our blockchain"
            )
          case Failure(bech32error) =>
            throw new IllegalArgumentException(
              s"$address is neither a valid Base58 address ($base58error) nor a valid Bech32 address ($bech32error)"
            )
        }
    }
  }
}
