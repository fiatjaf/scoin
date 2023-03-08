package scoin

import Crypto._
import scodec.bits.ByteVector
import scala.util.{Try, Success, Failure}
import scoin.reckless.Curve.secp256k1

object Musig2 {

  /** Musig2 draft specification
    * https://github.com/jonasnick/bips/blob/musig2-squashed/bip-musig2.mediawiki
    */

  /** KeyGen Context for Musig2 signing session.
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
  final case class KeyGenCtx(
      pointQ: PublicKey,
      gacc: BigInt,
      accumulatedTweak: BigInt
  )

  /** Sort a list of public keys in lexographical order
    *
    * @param pubkeys
    */
  def keySort(pubkeys: List[PublicKey]): List[PublicKey] =
    pubkeys.sortBy(_.value)

  /** Aggregate pubkeys according to Musig2 specification of `KeyAgg(..)`
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
    val coefficients =
      pubkeys.map(i => keyAggCoeffInternal(pubkeys, i.value, pk2))
    val pointQ = pubkeys
      .zip(coefficients)
      .map { case (pubkey_i, coeff_i) =>
        pubkey_i.multiply(PrivateKey(coeff_i))
      }
      .reduce { case (lhs, rhs) =>
        lhs + rhs
      }

    // ensure that the aggregate point is not the point at infinity
    require(pointQ.isValid, "invalid aggregate public key")
    KeyGenCtx(pointQ, gacc = BigInt(1), accumulatedTweak = BigInt(0))
  }

  private[scoin] def hashKeys(pubkeys: List[PublicKey]): ByteVector32 =
    taggedHash(
      pubkeys.foldLeft(ByteVector.empty) { case (accum, i) =>
        accum ++ i.value
      },
      "KeyAgg list"
    )

  private[scoin] def getSecondKey(pubkeys: List[ByteVector]): ByteVector =
    pubkeys.headOption match {
      case None =>
        throw new IllegalArgumentException(
          "list of public keys cannot be empty"
        )
      case Some(pk0) =>
        pubkeys.dropWhile(_ == pk0).headOption match {
          case None      => ByteVector.fill(33)(0.toByte)
          case Some(pkj) => pkj
        }
    }

  private[scoin] def keyAggCoeff(
      pubkeys: List[ByteVector],
      pubkey: ByteVector
  ): BigInt = keyAggCoeffInternal(
    pubkeys.map(PublicKey(_)),
    pubkey,
    getSecondKey(pubkeys)
  )

  private[scoin] def keyAggCoeffInternal(
      pubkeys: List[PublicKey],
      pubkey: ByteVector,
      pubkey2: ByteVector
  ): BigInt = {
    val L = hashKeys(pubkeys)
    if (pubkey == pubkey2)
      BigInt(1)
    else
      BigInt(
        taggedHash(L ++ pubkey, "KeyAgg coefficient").toHex,
        radix = 16
      ).mod(N)
  }

  /** Tweak a `KeyGenCtx` with a tweak value so as to obtain a new (tweaked)
    * `KeyGenCtx`.
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
    val KeyGenCtx(pointQ, gacc, tacc) = keygenCtx
    val g =
      if (isXonlyTweak && pointQ.isOdd)
        BigInt(-1).mod(N)
      else BigInt(1)
    val t = BigInt(tweak.toHex, 16)
    require(t >= 0)
    require(t < N, "tweak value cannot exceed the group order")
    val pointQ1 = (pointQ * PrivateKey(g)) + (G * PrivateKey(t))
    require(
      pointQ1.isValid,
      "tweaked combined pub key Q is not valid (infinite?)"
    )
    val gacc1 = (g * gacc).mod(N)
    val tacc1 = (t + g * tacc).mod(N)
    KeyGenCtx(pointQ1, gacc1, tacc1)
  }

  /** Generate Musig2 nonces. Note, this method requires access to a secure
    * randome number generator. The current implementation is impure. It should
    * probably be rewritten to pass the number generator in as a parameter.
    *
    * @param secretSigningKey
    * @param pubKey
    * @param aggregateXOnlyPublicKey
    * @param message
    * @param extraIn
    * @param nextRand32
    *   the next 32-bytes from cryptographically secure randomness
    * @return
    *   (secNonce, pubNonce)
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
      case Some(sk) =>
        ByteVector32(sk.xor(taggedHash(nextRand32.bytes, "MuSig/aux").bytes))
    }
    val aggpk =
      aggregateXOnlyPublicKey.map(_.value.bytes).getOrElse(ByteVector.empty)
    val m_prefixed = message match {
      case None => ByteVector(0.toByte)
      case Some(m) =>
        ByteVector(1.toByte) ++ ByteVector(m.length).padLeft(8) ++ m
    }
    val extra_in = extraIn.getOrElse(ByteVector.empty)

    def k_i(i: Int): ByteVector32 = taggedHash(
      rand.bytes ++ ByteVector(pubKey.value.length.toByte) ++ pubKey.value ++
        ByteVector(aggpk.length.toByte) ++ aggpk ++
        m_prefixed ++ ByteVector(extra_in.length).padLeft(4) ++ extra_in ++
        ByteVector((i - 1).toByte),
      "MuSig/nonce"
    )
    val k1 = BigInt(k_i(1).toHex, 16).mod(N)
    val k2 = BigInt(k_i(2).toHex, 16).mod(N)
    require(k1 != 0, "k1 cannot be zero")
    require(k2 != 0, "k2 cannot be zero")
    val (pointR1, pointR2) = (G * PrivateKey(k1), G * PrivateKey(k2))
    val pubNonce = pointR1.value ++ pointR2.value
    val secNonce = PrivateKey(k1).value ++ PrivateKey(k2).value ++ pubKey.value
    (secNonce, pubNonce)
  }

  /** The function cpoint(x), where x is a 33-byte array (compressed
    * serialization), sets P = lift_x(int(x[1:33])) and fails if that fails. If
    * x[0] = 2 it returns P and if x[0] = 3 it returns -P. Otherwise, it fails.
    */
  private[scoin] def cpoint(x: ByteVector): PublicKey =
    PublicKey(raw = x, checkValid = true)

  /** The function cpoint_ext(x), where x is a 33-byte array (compressed
    * serialization), returns the point at infinity if x = bytes(33, 0).
    * Otherwise, it returns cpoint(x) and fails if that fails.
    */
  private[scoin] def cpoint_ext(x: ByteVector): Option[PublicKey] =
    if (
      x == ByteVector.fill(33)(0)
    ) // all zeres is representing point at infinity
      None // using "None" to represent the point at infinity
    else
      Some(cpoint(x))

  private[scoin] def cbytes_ext(pk: Option[PublicKey]): ByteVector = pk match {
    case None => ByteVector.fill(33)(0.toByte) // serialized point at infinity
    case Some(pubkey) => pubkey.value
  }

  private[scoin] val infinity: Option[PublicKey] = None

  /** Insecure hack!! Here we assume that if point addition "fails" in the sense
    * that the underlying library implementing point addition throws an
    * exception, then the point returned is to be the point at infinity which is
    * represented as `None`.
    *
    * @param lhs
    * @param rhs
    * @return
    */
  private[scoin] def point_add_ext(
      lhs: Option[PublicKey],
      rhs: Option[PublicKey]
  ): Option[PublicKey] =
    lhs.flatMap(x => rhs.map(y => (x, y))) match {
      case None => None
      case Some((x, y)) =>
        Try(x + y) match {
          case Failure(exception) => None // this is the hacky/insecure part
          case Success(pk)        => Some(pk)
        }
    }

  /** Take list of public nonces and combine them to create an aggregate public
    * nonce. If this method fails, blame can be assigned to the signer with the
    * index which caused the failer.
    *
    * @param publicNonces
    * @return
    *   aggregate public nonce
    */
  def nonceAgg(publicNonces: List[ByteVector]): ByteVector = {

    /** Algorithm NonceAgg(pubnonce1..u): Inputs: The number u of pubnonces with
      * 0 < u < 2^32 The public nonces pubnonce1..u: u 66-byte arrays For j = 1
      * .. 2: For i = 1 .. u: Let Ri,j = cpoint(pubnoncei[(j-1)*33:j*33]); fail
      * if that fails and blame signer i for invalid pubnonce. Let Rj = R1,j +
      * R2,j + ... + Ru,j Return aggnonce = cbytes_ext(R1) || cbytes_ext(R2)
      */
    val noncepoints = for {
      j <- (1 to 2)
      i <- (0 until publicNonces.size)
      pointR_ij = Try(
        cpoint(publicNonces(i).drop((j - 1) * 33).take(j * 33))
      ) match {
        case Failure(e) =>
          throw new IllegalArgumentException(
            s"invalid pubnonce from signer/index $i, $e"
          )
        case Success(v) => v
      }
    } yield (j, Option(pointR_ij))
    cbytes_ext(noncepoints.filter(_._1 == 1).map(_._2).reduce { case (x, y) =>
      point_add_ext(x, y)
    }) // R_j (j = 1)
      ++ cbytes_ext(noncepoints.filter(_._1 == 2).map(_._2).reduce {
        case (x, y) => point_add_ext(x, y)
      }) // R_j (j = 2)
  }

  /** The Session Context is a data structure consisting of the following
    * elements:
    *
    * @param aggNonce
    *   The aggregate public nonce aggnonce: a 66-byte array
    * @param numPubKeys
    *   The number u of public keys with 0 < u < 2^32
    * @param pubKeys
    *   The plain public keys pk1..u: u 33-byte arrays
    * @param numTweaks
    *   The number v of tweaks with 0 ≤ v < 2^32
    * @param tweaks
    *   The tweaks tweak1..v: v 32-byte arrays
    * @param isXonlyTweak
    *   The tweak modes is_xonly_t1..v : v booleans
    * @param message
    *   The message m: a byte array
    */
  final case class SessionCtx(
      aggNonce: ByteVector,
      numPubKeys: Int,
      pubKeys: List[ByteVector],
      numTweaks: Int,
      tweaks: List[ByteVector32],
      isXonlyTweak: List[Boolean],
      message: ByteVector
  )

  // names taken from spec...unfortunately quite confusing
  final case class SessionValues(
      pointQ: PublicKey,
      gacc: BigInt,
      tacc: BigInt,
      b: BigInt,
      pointR: PublicKey,
      e: BigInt
  )

  /** return integer mod n representation of bytes where n is the group order
    *
    * @param bytes
    * @return
    */
  private[scoin] def intModN(bytes: ByteVector): BigInt =
    BigInt(bytes.toHex, 16).mod(N)
  private[scoin] def intModN(bytes: ByteVector32): BigInt =
    BigInt(bytes.toHex, 16).mod(N)

  private[scoin] def int(bytes: ByteVector): BigInt = BigInt(bytes.toHex, 16)
  private[scoin] def int(bytes: ByteVector32): BigInt = BigInt(bytes.toHex, 16)

  def getSessionValues(ctx: SessionCtx): SessionValues = {
    // the following will throw if any pubkeys are invalid
    def keygen_ctx_i(i: Int): KeyGenCtx = i match {
      case 0 => keyAgg(ctx.pubKeys.map(PublicKey(_)))
      case i =>
        applyTweak(
          keygen_ctx_i(i - 1),
          ctx.tweaks(i - 1),
          ctx.isXonlyTweak(i - 1)
        )
    }
    val KeyGenCtx(pointQ, gacc, tacc) = keygen_ctx_i(ctx.numTweaks)
    val b = intModN(
      taggedHash(
        ctx.aggNonce ++ pointQ.xonly.value.bytes ++ ctx.message,
        "MuSig/noncecoef"
      )
    )
    val (pointR1, pointR2) = (
      cpoint_ext(ctx.aggNonce.slice(0, 33)),
      cpoint_ext(ctx.aggNonce.slice(33, 66))
    )
    // if above fails, we should throw error and blame nonce aggregator for invalid aggNonce

    val pointRfinal =
      point_add_ext(pointR1, pointR2.map(_ * PrivateKey(b))) match {
        case None     => G // if inifite, use point G instead
        case Some(pt) => pt
      }
    require(
      pointRfinal.isValid,
      "final nonce invalid (point at infinity maybe?)"
    )
    val e = intModN(
      Crypto.calculateBip340challenge(
        data = ctx.message,
        noncePointR = pointRfinal.xonly,
        publicKey = pointQ.xonly
      )
    )
    SessionValues(pointQ, gacc, tacc, b, pointRfinal, e)
  }

  def getSessionKeyAggCoeff(ctx: SessionCtx, pubkey: PublicKey): BigInt = {
    require(
      ctx.pubKeys.contains(pubkey.value),
      "pubkey not part of this session context"
    )
    keyAggCoeff(ctx.pubKeys, pubkey.value)
  }

  def partialSigAgg(psigs: List[ByteVector], ctx: SessionCtx): ByteVector64 = {
    val SessionValues(pointQ, _, tacc, _, pointR, e) = getSessionValues(ctx)
    val s = psigs.map(int(_))
    s.zipWithIndex.foreach { case (s_i, i) =>
      require(s_i < N, s"signer $i submitted invalid signature")
    }
    val g = if (pointQ.isEven) BigInt(1) else BigInt(-1).mod(N)
    ByteVector64(
      pointR.xonly.value ++ PrivateKey(
        (s.reduce(_ + _).mod(N) + (e * g * tacc).mod(N))
      ).value
    )
  }

  def pointNegate(point: PublicKey): PublicKey = {
    import reckless._
    val p = secp256k1.CurvePoint.fromUnCompressed(point.toUncompressedBin)
    PublicKey(Curve.pointNegate(secp256k1)(p).compressed)
  }

  private[scoin] def partialSigVerifyInternal(
      psig: ByteVector,
      pubnonce: ByteVector,
      pubkey: PublicKey,
      ctx: SessionCtx
  ): Boolean = {
    val SessionValues(pointQ, gacc, _, b, pointR, e) = getSessionValues(ctx)
    val s = int(psig)
    require(s < N, "partial signature exceeds group order")
    val (pointR1, pointR2) =
      (cpoint(pubnonce.slice(0, 33)), cpoint(pubnonce.slice(33, 66)))
    val pointReffective =
      if (pointR.isEven)
        pointR1 + (pointR2 * PrivateKey(b))
      else
        pointNegate((pointR1 + (pointR2 * PrivateKey(b))))
    val pointP = pubkey
    val a = getSessionKeyAggCoeff(ctx, pointP)
    val g = if (pointQ.isEven) BigInt(1) else BigInt(-1).mod(N)
    val gPrime = (g * gacc).mod(N)
    require(
      (G * PrivateKey(s)) == (pointReffective + pointP * PrivateKey(
        (e * a * gPrime).mod(N)
      )),
      "invalid partial signature"
    )
    true
  }

  def partialSigVerify(
      psig: ByteVector,
      pubnonces: List[ByteVector],
      pubkeys: List[ByteVector],
      tweaks: List[ByteVector32],
      isXonlyTweak: List[Boolean],
      message: ByteVector,
      index: Int
  ): Boolean = {
    val aggnonce = nonceAgg(pubnonces)
    require(aggnonce.nonEmpty, "invalid aggregate nonce")
    partialSigVerifyInternal(
      psig,
      pubnonces(index),
      PublicKey(pubkeys(index)),
      SessionCtx(
        aggNonce = aggnonce,
        numPubKeys = pubkeys.size,
        pubKeys = pubkeys,
        numTweaks = tweaks.size,
        tweaks = tweaks,
        isXonlyTweak = isXonlyTweak,
        message = message
      )
    )
  }

  /** Sign according to Musig2 specification.
    * @see
    *   https://github.com/jonasnick/bips/blob/musig2-squashed/bip-musig2.mediawiki
    *
    * @param secnonce
    *   The secret nonce secnonce that has never been used as input to Sign
    *   before: a 97-byte array
    * @param privateKey
    *   the secret signing key
    * @param ctx
    *   the SessionCtx
    * @return
    *   a partial signature which can be aggregated according to Musig2
    */
  def sign(
      secnonce: ByteVector,
      privateKey: PrivateKey,
      ctx: SessionCtx
  ): ByteVector32 = {
    val SessionValues(pointQ, gacc, _, b, pointR, e) = getSessionValues(ctx)
    val (k1p, k2p) = (int(secnonce.slice(0, 32)), int(secnonce.slice(32, 64)))
    require(k1p != 0 && k2p != 0, "secnonce k1, k2 cannot be zero")
    require(k1p < N && k2p < N, "secnonces k1,k2 cannot exceed group order")
    val n = BigInt(N)
    val (k1, k2) = if (pointR.isEven) (k1p, k2p) else (n - k1p, n - k2p)
    val pointP = privateKey.publicKey
    require(
      pointP.value == secnonce.slice(64, 97),
      "secnonce does not match signing public key"
    )
    val a = getSessionKeyAggCoeff(ctx, pointP)
    val g = if (pointQ.isEven) BigInt(1) else BigInt(-1).mod(n)
    val d = (g * gacc * BigInt(privateKey.value.toHex, 16))
      .mod(n) // see: negation of secret key when signing
    val s = (k1 + b * k2 + e * a * d).mod(n)
    val psig = PrivateKey(s).value
    val pubnonce = (G * PrivateKey(k1p)).value ++ (G * PrivateKey(k2p)).value
    require(
      partialSigVerifyInternal(psig, pubnonce, pointP, ctx),
      "invalid partial signature, your parameters"
    )
    psig
  }
}
