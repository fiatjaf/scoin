package scoin

import java.nio.ByteOrder
import org.bouncycastle.crypto.engines.ChaCha7539Engine
import org.bouncycastle.crypto.params.{KeyParameter, ParametersWithIV}
import scodec.bits.ByteVector
import scoin._
import scoin.ChaCha20Poly1305.{DecryptionError, EncryptionError, InvalidCounter}

/** Poly1305 authenticator see https://tools.ietf.org/html/rfc7539#section-2.5
  */
private[scoin] object Poly1305 {

  /** @param key
    *   input key
    * @param datas
    *   input data
    * @return
    *   a 16 byte authentication tag
    */
  def mac(key: ByteVector, datas: ByteVector*): ByteVector = {
    val out = new Array[Byte](16)
    val poly = new org.bouncycastle.crypto.macs.Poly1305()
    poly.init(new KeyParameter(key.toArray))
    datas.foreach(data => poly.update(data.toArray, 0, data.length.toInt))
    poly.doFinal(out, 0)
    ByteVector.view(out)
  }
}

/** ChaCha20 block cipher see https://tools.ietf.org/html/rfc7539#section-2.5
  */
private[scoin] object ChaCha20 {
  def xor(
      input: ByteVector,
      key: ByteVector,
      nonce: ByteVector,
      counter: Int = 0
  ): ByteVector = {
    val engine = new ChaCha7539Engine()
    engine.init(
      true,
      new ParametersWithIV(new KeyParameter(key.toArray), nonce.toArray)
    )
    val output: Array[Byte] = new Array[Byte](input.length.toInt)
    counter match {
      case 0 => ()
      case 1 =>
        // skip 1 block == set counter to 1 instead of 0
        val dummy = new Array[Byte](64)
        engine.processBytes(new Array[Byte](64), 0, 64, dummy, 0)
      case _ => throw InvalidCounter()
    }
    val len = engine.processBytes(
      input.toArray,
      0,
      input.length.toInt,
      output,
      0
    )
    if (len != input.length) throw EncryptionError()
    ByteVector.view(output)
  }
}

/** ChaCha20Poly1305 AEAD (Authenticated Encryption with Additional Data)
  * algorithm see https://tools.ietf.org/html/rfc7539#section-2.5
  *
  * This what we should be using (see BOLT #8)
  */
private[scoin] object ChaCha20Poly1305 {
  // @formatter:off
  abstract class ChaCha20Poly1305Error(msg: String) extends RuntimeException(msg)
  case class InvalidMac() extends ChaCha20Poly1305Error("invalid mac")
  case class DecryptionError() extends ChaCha20Poly1305Error("decryption error")
  case class EncryptionError() extends ChaCha20Poly1305Error("encryption error")
  case class InvalidCounter() extends ChaCha20Poly1305Error("chacha20 counter must be 0 or 1")
  // @formatter:on

  /** @param key
    *   32 bytes encryption key
    * @param nonce
    *   12 bytes nonce
    * @param plaintext
    *   plain text
    * @param aad
    *   additional authentication data. can be empty
    * @return
    *   a (ciphertext, mac) tuple
    */
  def encrypt(
      plaintext: ByteVector,
      key: ByteVector,
      nonce: ByteVector,
      aad: ByteVector
  ): (ByteVector, ByteVector) = {
    val polykey = ChaCha20.xor(ByteVector32.Zeroes, key, nonce)
    val ciphertext = ChaCha20.xor(plaintext, key, nonce, 1)
    val tag = Poly1305.mac(
      polykey,
      aad,
      pad16(aad),
      ciphertext,
      pad16(ciphertext),
      Protocol.writeUInt64(aad.length, ByteOrder.LITTLE_ENDIAN),
      Protocol.writeUInt64(ciphertext.length, ByteOrder.LITTLE_ENDIAN)
    )
    (ciphertext, tag)
  }

  /** @param key
    *   32 bytes decryption key
    * @param nonce
    *   12 bytes nonce
    * @param ciphertext
    *   ciphertext
    * @param aad
    *   additional authentication data. can be empty
    * @param mac
    *   authentication mac
    * @return
    *   the decrypted plaintext if the mac is valid.
    */
  def decrypt(
      ciphertext: ByteVector,
      key: ByteVector,
      nonce: ByteVector,
      aad: ByteVector,
      mac: ByteVector
  ): ByteVector = {
    val polykey = ChaCha20.xor(ByteVector32.Zeroes, key, nonce)
    val tag = Poly1305.mac(
      polykey,
      aad,
      pad16(aad),
      ciphertext,
      pad16(ciphertext),
      Protocol.writeUInt64(aad.length, ByteOrder.LITTLE_ENDIAN),
      Protocol.writeUInt64(ciphertext.length, ByteOrder.LITTLE_ENDIAN)
    )
    if (tag != mac) throw InvalidMac()
    val plaintext = ChaCha20.xor(ciphertext, key, nonce, 1)
    plaintext
  }

  def pad16(data: ByteVector): ByteVector =
    if (data.size % 16 == 0)
      ByteVector.empty
    else
      ByteVector.fill(16 - (data.size % 16))(0)
}
