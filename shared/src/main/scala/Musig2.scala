package scoin

import Crypto._
import scodec.bits.ByteVector
import scala.util.{Try, Success, Failure}

object Musig2 {

  /**
   *  Musig2 draft specification
    * https://github.com/jonasnick/bips/blob/musig2-squashed/bip-musig2.mediawiki
    */

  /**
    * KeyGen Context for Musig2 signing session.
    *
    * @param pointQ 
    *   The point Q representing the aggregate and potentially tweaked public 
    *   key: an elliptic curve point
    * @param gacc
    *   `1 or -1 mod n` where `n` is the group order.
    * @param accumulatedTweak
    *   The accumulated tweak tacc: an integer with `0 ≤ accumuatedTweak < n` 
    *   where `n` is the group order.
    */
  final case class KeyGenCtx ( 
    pointQ: PublicKey, 
    gacc: BigInt,
    accumulatedTweak: BigInt
  )

  /**
    * Sort a list of public keys in lexographical order
    *
    * @param pubkeys
    */
  def keySort(pubkeys: List[PublicKey]): List[PublicKey] = pubkeys.sortBy(_.value)

  /**
    * Aggregate pubkeys according to Musig2 specification of `KeyAgg(..)`
    * https://github.com/jonasnick/bips/blob/musig2-squashed/bip-musig2.mediawiki#user-content-Algorithms
    *
    * @param pubkeys
    * @return
    */
  def keyAgg(pubkeys: List[PublicKey]): KeyGenCtx = {
    // note: max list size is 2^32 - 1
    val pk2 = getSecondKey(pubkeys.map(_.value))
    // if this function is being called, then we assume all PublicKeys in the
    // list are valid public keys
    val coefficients = pubkeys.map(i => keyAggCoeffInternal(pubkeys,i.value,pk2))
    val pointQ = pubkeys.zip(coefficients).map{
      case (pubkey_i, coeff_i) => pubkey_i.multiply(PrivateKey(coeff_i))
    }.reduce{
      case (lhs, rhs) => lhs + rhs
    }

    // ensure that the aggregate point is not the point at infinity
    require(pointQ.isValid, "invalid aggregate public key")
    KeyGenCtx(pointQ, gacc = BigInt(1), accumulatedTweak = BigInt(0))
  }

  private[scoin] def hashKeys(pubkeys: List[PublicKey]): ByteVector32 =
    taggedHash(
      pubkeys.foldLeft(ByteVector.empty){
        case (accum, i) => accum ++ i.value
      },
      "KeyAgg list"
    )

  private[scoin] def getSecondKey(pubkeys: List[ByteVector]): ByteVector =
    pubkeys.headOption match {
      case None => throw new IllegalArgumentException("list of public keys cannot be empty")
      case Some(pk0) => pubkeys.dropWhile(_ == pk0).headOption match {
        case None => ByteVector.fill(33)(0.toByte)
        case Some(pkj) => pkj
      }
    }

  private[scoin] def keyAggCoeff(pubkeys: List[ByteVector], pubkey: ByteVector): BigInt 
    = keyAggCoeffInternal(pubkeys.map(PublicKey(_)),pubkey, getSecondKey(pubkeys))

  private[scoin] def keyAggCoeffInternal(
                        pubkeys: List[PublicKey], 
                        pubkey: ByteVector, 
                        pubkey2: ByteVector
                      ): BigInt = {
                        val L = hashKeys(pubkeys)
                        if( pubkey == pubkey2 ) 
                          BigInt(1)
                        else
                          BigInt(
                            taggedHash(L ++ pubkey,"KeyAgg coefficient").toHex,
                            radix = 16
                          ).mod(N)
                      }
  /**
    * Tweak a `KeyGenCtx` with a tweak value so as to obtain a new
    * (tweaked) `KeyGenCtx`.
    *
    * @param keygenCtx
    * @param tweak
    * @param isXonlyTweak
    * @return
    */
  def applyTweak(
        keygenCtx: KeyGenCtx,  
        tweak: ByteVector32, 
        isXonlyTweak: Boolean
        ): KeyGenCtx = {

          val KeyGenCtx(pointQ,gacc,tacc) = keygenCtx
          val g = if(isXonlyTweak && pointQ.isOdd) 
                    BigInt(-1).mod(N)
                  else BigInt(1)
          val t = BigInt(tweak.toHex,16)
          require(t >= 0)
          require(t < N, "tweak value cannot exceed the group order")
          val pointQ1 = (pointQ*PrivateKey(g)) + (G*PrivateKey(t))
          require(pointQ1.isValid, "tweaked combined pub key Q is not valid (infinte?)")
          val gacc1 = (g*gacc).mod(N)
          val tacc1 = (t + g*tacc).mod(N)
          KeyGenCtx(pointQ1,gacc1,tacc1)
        }

  /**
    * Generate Musig2 nonces. Note, this method requires access to a secure
    * randome number generator. The current implementation is impure. It should
    * probably be rewritten to pass the number generator in as a parameter.
    *
    * @param secretSigningKey
    * @param pubKey
    * @param aggregateXOnlyPublicKey
    * @param message
    * @param extraIn
    * @param nextRand32 the next 32-bytes from cryptographically secure randomness
    * @return (secNonce, pubNonce)
    */
  def nonceGen(
        secretSigningKey: Option[ByteVector32],
        pubKey: PublicKey,
        aggregateXOnlyPublicKey: Option[XOnlyPublicKey],
        message: Option[ByteVector],
        extraIn: Option[ByteVector],
        nextRand32: => ByteVector32 = randomBytes32()
  ): (ByteVector, ByteVector) = {
    val rand: ByteVector32 = secretSigningKey match {
      case None => nextRand32
      case Some(sk) => ByteVector32(sk.xor(taggedHash(nextRand32.bytes,"MuSig/aux").bytes))
    }
    val aggpk = aggregateXOnlyPublicKey.map(_.value.bytes).getOrElse(ByteVector.empty)
    val m_prefixed = message match {
      case None => ByteVector(0.toByte)
      case Some(m) => ByteVector(1.toByte) ++ ByteVector(m.length).padLeft(8) ++ m
    }
    val extra_in = extraIn.getOrElse(ByteVector.empty)
    
    def k_i(i: Int):ByteVector32 = taggedHash(
      rand.bytes ++ ByteVector(pubKey.value.length.toByte) ++ pubKey.value ++
      ByteVector(aggpk.length.toByte) ++ aggpk ++
      m_prefixed ++ ByteVector(extra_in.length).padLeft(4) ++ extra_in ++
      ByteVector((i - 1).toByte),
      "MuSig/nonce"
    )
    val k1 = BigInt(k_i(1).toHex,16).mod(N)
    val k2 = BigInt(k_i(2).toHex,16).mod(N)
    require(k1 != 0, "k1 cannot be zero")
    require(k2 != 0, "k2 cannot be zero")
    val (pointR1,pointR2) = (G*PrivateKey(k1), G*PrivateKey(k2))
    val pubNonce = pointR1.value ++ pointR2.value
    val secNonce = PrivateKey(k1).value ++ PrivateKey(k2).value ++ pubKey.value
    (secNonce, pubNonce)
  }

  /**
    * The function cpoint(x), where x is a 33-byte array (compressed serialization), sets P = lift_x(int(x[1:33])) and fails if that fails. If x[0] = 2 it returns P and if x[0] = 3 it returns -P. Otherwise, it fails.
    * */
  private[scoin] def cpoint( x: ByteVector ): PublicKey = 
    PublicKey(raw = x, checkValid = false)
  
  /**
    * The function cpoint_ext(x), where x is a 33-byte array (compressed serialization), 
    * returns the point at infinity if x = bytes(33, 0). Otherwise, it returns 
    * cpoint(x) and fails if that fails.
    *
    */
  private[scoin] def cpoint_ext( x: ByteVector ): Option[PublicKey] =
    if( x == ByteVector.fill(33)(0) ) // all zeres is representing point at infinity
      None // using "Nonce" to represent the point at infinity
    else
      Some(cpoint(x))

  /**
    * Take list of public nonces and combine them to create an aggregate public
    * nonce. If this method fails, blame can be assigned to the signer with 
    * the index which caused the failer. 
    *
    * @param publicNonces
    * @return aggregate public nonce
    */
  def nonceAgg( publicNonces: List[ByteVector] ): ByteVector = {
    /**
      * Algorithm NonceAgg(pubnonce1..u):
        Inputs:
          The number u of pubnonces with 0 < u < 2^32
          The public nonces pubnonce1..u: u 66-byte arrays
        For j = 1 .. 2:
          For i = 1 .. u:
            Let Ri,j = cpoint(pubnoncei[(j-1)*33:j*33]); fail if that fails and blame signer i for invalid pubnonce.
          Let Rj = R1,j + R2,j + ... + Ru,j
        Return aggnonce = cbytes_ext(R1) || cbytes_ext(R2)
      */
    val noncepoints = for {
      j <- (1 to 2)
      i <- (0 until publicNonces.size)
      pointR_ij = Try(cpoint(publicNonces(i).drop((j-1)*33).take(j*33))) match {
        case Failure(e) => throw new IllegalArgumentException(s"invalid pubnonce from signer/index $i, $e")
        case Success(v) => v
      }
    } yield (j,pointR_ij)
    noncepoints.filter(_._1 == 1).map(_._2).reduce(_ + _).value  // R_j (j = 1)
    ++ noncepoints.filter(_._1 == 2).map(_._2).reduce(_ + _).value // R_j (j = 2)
  }
}