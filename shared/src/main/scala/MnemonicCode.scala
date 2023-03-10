package scoin

import java.nio.{ByteBuffer, IntBuffer}
import scala.annotation.tailrec

import scodec.bits.ByteVector
import scala.util.{Try,Failure,Success}

/** see https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
  */
object MnemonicCode {

  // requiring the `Id` implementation of Resources here so as to not break
  // other code (e.g. this entire file is essentially using the `Id` monad).
  // 
  lazy val englishWordlist = Resources[cats.Id].bip39_english_wordlist

  private def toBinary(x: Byte): List[Boolean] = {
    @tailrec
    def loop(x: Int, acc: List[Boolean] = List.empty[Boolean]): List[Boolean] =
      if (x == 0) acc else loop(x / 2, ((x % 2) != 0) :: acc)

    val digits = loop(x & 0xff)
    val zeroes = List.fill(8 - digits.length)(false)
    zeroes ++ digits
  }

  private def toBinary(x: ByteVector): List[Boolean] =
    x.toSeq.flatMap(toBinary).toList

  private def fromBinary(bin: Seq[Boolean]): Int = bin.foldLeft(0) {
    case (acc, flag) => if (flag) 2 * acc + 1 else 2 * acc
  }

  /** BIP39 entropy encoding
    *
    * @param entropy
    *   input entropy
    * @param wordlist
    *   word list (must be 2048 words long)
    * @return
    *   a list of mnemonic words that encodes the input entropy
    */
  def toMnemonics(
      entropy: ByteVector,
      wordlist: Seq[String] = englishWordlist
  ): List[String] = {
    require(wordlist.length == 2048, "invalid word list (size should be 2048)")
    val digits = toBinary(entropy) ++ toBinary(Crypto.sha256(entropy))
      .take(entropy.length.toInt / 4)
    digits.grouped(11).map(fromBinary).map(index => wordlist(index)).toList
  }

  /** validate that a mnemonic seed is valid
    *
    * @param mnemonics
    *   list of mnemomic words
    */
  def validate(
      mnemonics: Seq[String],
      wordlist: Seq[String] = englishWordlist
  ): Unit = {
    require(wordlist.length == 2048, "invalid word list (size should be 2048)")
    require(mnemonics.nonEmpty, "mnemonic code cannot be empty")
    require(
      mnemonics.length % 3 == 0,
      s"invalid mnemonic word count ${mnemonics.length}, it must be a multiple of 3"
    )
    val wordMap = wordlist.zipWithIndex.toMap
    mnemonics.foreach(word =>
      require(wordMap.contains(word), s"invalid mnemonic word $word")
    )
    val indexes = mnemonics.map(word => wordMap(word))

    @tailrec
    def toBits(
        index: Int,
        acc: Seq[Boolean] = Seq.empty[Boolean]
    ): Seq[Boolean] =
      if (acc.length == 11) acc else toBits(index / 2, (index % 2 != 0) +: acc)

    val bits = indexes.flatMap(i => toBits(i))
    val bitlength = (bits.length * 32) / 33
    val (databits, checksumbits) = bits.splitAt(bitlength)
    val data = ByteVector(databits.grouped(8).map(fromBinary).map(_.toByte))
    val check = toBinary(Crypto.sha256(data)).take(data.length.toInt / 4)
    require(check == checksumbits, "invalid checksum")
  }

  def validate(mnemonics: String): Unit = validate(mnemonics.split(" ").toSeq)

  /** BIP39 seed derivation
    *
    * @param mnemonics
    *   mnemonic words
    * @param passphrase
    *   passphrase
    * @return
    *   a seed derived from the mnemonic words and passphrase
    */
  def toSeed(mnemonics: Seq[String], passphrase: String): ByteVector =
    pbkdf2Sha512(
      ByteVector.view(mnemonics.mkString(" ").getBytes("UTF-8")),
      ByteVector.view(("mnemonic" + passphrase).getBytes("UTF-8")),
      2048,
      64
    )

  def toSeed(mnemonics: String, passphrase: String): ByteVector =
    toSeed(mnemonics.split(" ").toSeq, passphrase)

  private def pbkdf2Sha512(
      password: ByteVector,
      salt: ByteVector,
      iterations: Int,
      keyLen: Int
  ): ByteVector = {
    val hashLen = 64
    val numBlocks = (keyLen + hashLen - 1) / hashLen

    // pseudo-random function defined in the spec
    @inline def prf(buf: ByteVector) = Crypto.hmac512(password, buf)

    // this is a translation of the helper function "F" defined in the spec
    def calculateBlock(blockNum: Int): Array[Byte] = {
      // u_1
      val u_1 = prf(
        ByteVector.concat(List(salt ++ ByteVector.fromInt(blockNum)))
      )

      val buf = IntBuffer
        .allocate(u_1.size.toInt / 4)
        .put(ByteBuffer.wrap(u_1.toArray).asIntBuffer)
        .array
        .clone
      var u = u_1
      var iter = 1
      while (iter < iterations) {
        // u_2 through u_c : calculate u_n and xor it with the previous value
        u = prf(u)
        xorInPlace(buf, u.toArray)
        iter += 1
      }

      val ret = ByteBuffer.allocate(u_1.size.toInt)
      ret.asIntBuffer.put(buf)
      ret.array
    }

    // how many blocks we'll need to calculate (the last may be truncated)
    val blocksNeeded = (keyLen.toFloat / 20).ceil.toInt

    ByteVector.view(
      (1 to blocksNeeded).iterator
        .map(calculateBlock)
        .flatten
        .take(keyLen)
        .toArray
    )
  }

  private def xorInPlace(buff: Array[Int], a2: Array[Byte]): Unit = {
    val b2 = ByteBuffer.wrap(a2).asIntBuffer

    val len = buff.array.size
    var i = 0
    while (i < len) {
      buff(i) ^= b2.get(i)
      i += 1
    }
  }

    /** recover the entropy encoded in the mnemonic words
    *
    * @param mnemonics
    *   list of mnemomic words
    */
  def recoverEntropy(
      mnemonics: Seq[String],
      wordlist: Seq[String] = englishWordlist
  ): Try[ByteVector] = Try {
    require(wordlist.length == 2048, "invalid word list (size should be 2048)")
    require(mnemonics.nonEmpty, "mnemonic code cannot be empty")
    require(
      mnemonics.length % 3 == 0,
      s"invalid mnemonic word count ${mnemonics.length}, it must be a multiple of 3"
    )
    val wordMap = wordlist.zipWithIndex.toMap
    mnemonics.foreach(word =>
      require(wordMap.contains(word), s"invalid mnemonic word $word")
    )
    val indexes = mnemonics.map(word => wordMap(word))

    @tailrec
    def toBits(
        index: Int,
        acc: Seq[Boolean] = Seq.empty[Boolean]
    ): Seq[Boolean] =
      if (acc.length == 11) acc else toBits(index / 2, (index % 2 != 0) +: acc)

    val bits = indexes.flatMap(i => toBits(i))
    val bitlength = (bits.length * 32) / 33
    val (databits, checksumbits) = bits.splitAt(bitlength)
    val data = ByteVector(databits.grouped(8).map(fromBinary).map(_.toByte))
    val check = toBinary(Crypto.sha256(data)).take(data.length.toInt / 4)
    require(check == checksumbits, "invalid checksum")
    scodec.bits.BitVector.bits(databits).bytes
  }
}
