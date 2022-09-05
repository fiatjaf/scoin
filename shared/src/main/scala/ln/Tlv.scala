package scoin.ln

import scala.reflect.ClassTag
import scodec.{Attempt, Codec, Err}
import scodec.bits.ByteVector
import scodec.codecs._

import scoin._
import scoin.Crypto.PublicKey
import scoin.ln._
import scoin.ln.Features._
import scoin.ln.TlvCodecs._
import scoin.ln.CommonCodecs._

trait Tlv

/** Generic tlv type we fallback to if we don't understand the incoming tlv.
  *
  * @param tag
  *   tlv tag.
  * @param value
  *   tlv value (length is implicit, and encoded as a varint).
  */
case class GenericTlv(tag: UInt64, value: ByteVector) extends Tlv

/** A tlv stream is a collection of tlv records. A tlv stream is constrained to
  * a specific tlv namespace that dictates how to parse the tlv records. That
  * namespace is provided by a trait extending the top-level tlv trait.
  *
  * @param records
  *   known tlv records.
  * @param unknown
  *   unknown tlv records.
  * @tparam T
  *   the stream namespace is a trait extending the top-level tlv trait.
  */
case class TlvStream[T <: Tlv](
    records: Iterable[T],
    unknown: Iterable[GenericTlv] = Nil
) {

  /** @tparam R
    *   input type parameter, must be a subtype of the main TLV type
    * @return
    *   the TLV record of type that matches the input type parameter if any
    *   (there can be at most one, since BOLTs specify that TLV records are
    *   supposed to be unique)
    */
  def get[R <: T: ClassTag]: Option[R] = records.collectFirst { case r: R => r }
}

object TlvStream {
  def empty[T <: Tlv]: TlvStream[T] = TlvStream[T](Nil, Nil)
  def apply[T <: Tlv](records: T*): TlvStream[T] = TlvStream(records, Nil)
}

object TlvCodecs {
  // high range types are greater than or equal 2^16, see https://github.com/lightningnetwork/lightning-rfc/blob/master/01-messaging.md#type-length-value-format
  private val TLV_TYPE_HIGH_RANGE = 65536

  /** Truncated uint64 (0 to 8 bytes unsigned integer). The encoder
    * minimally-encodes every value, and the decoder verifies that values are
    * minimally-encoded. Note that this codec can only be used at the very end
    * of a TLV record.
    */
  val tu64: Codec[UInt64] = Codec(
    (u: UInt64) => {
      val b = (u: @unchecked) match {
        case u if u < 0x01                => ByteVector.empty
        case u if u < 0x0100              => u.toByteVector.takeRight(1)
        case u if u < 0x010000            => u.toByteVector.takeRight(2)
        case u if u < 0x01000000          => u.toByteVector.takeRight(3)
        case u if u < 0x0100000000L       => u.toByteVector.takeRight(4)
        case u if u < 0x010000000000L     => u.toByteVector.takeRight(5)
        case u if u < 0x01000000000000L   => u.toByteVector.takeRight(6)
        case u if u < 0x0100000000000000L => u.toByteVector.takeRight(7)
        case u if u <= UInt64.MaxValue    => u.toByteVector.takeRight(8)
      }
      Attempt.successful(b.bits)
    },
    b =>
      b.length match {
        case l if l <= 0 =>
          minimalvalue(uint64, UInt64(0x00)).decode(b.padLeft(64))
        case l if l <= 8 =>
          minimalvalue(uint64, UInt64(0x01)).decode(b.padLeft(64))
        case l if l <= 16 =>
          minimalvalue(uint64, UInt64(0x0100)).decode(b.padLeft(64))
        case l if l <= 24 =>
          minimalvalue(uint64, UInt64(0x010000)).decode(b.padLeft(64))
        case l if l <= 32 =>
          minimalvalue(uint64, UInt64(0x01000000)).decode(b.padLeft(64))
        case l if l <= 40 =>
          minimalvalue(uint64, UInt64(0x0100000000L)).decode(b.padLeft(64))
        case l if l <= 48 =>
          minimalvalue(uint64, UInt64(0x010000000000L)).decode(b.padLeft(64))
        case l if l <= 56 =>
          minimalvalue(uint64, UInt64(0x01000000000000L)).decode(b.padLeft(64))
        case l if l <= 64 =>
          minimalvalue(uint64, UInt64(0x0100000000000000L)).decode(
            b.padLeft(64)
          )
        case _ =>
          Attempt.failure(
            Err(s"too many bytes to decode for truncated uint64 (${b.toHex})")
          )
      }
  )

  /** Truncated long (0 to 8 bytes unsigned integer). This codec can be safely
    * used for values < `2^63` and will fail otherwise.
    */
  val tu64overflow: Codec[Long] = tu64.exmap(
    u =>
      if (u <= Long.MaxValue) Attempt.Successful(u.toBigInt.toLong)
      else Attempt.Failure(Err(s"overflow for value $u")),
    l =>
      if (l >= 0) Attempt.Successful(UInt64(l))
      else Attempt.Failure(Err(s"uint64 must be positive (actual=$l)"))
  )

  /** Truncated millisatoshi (0 to 8 bytes unsigned). This codec can be safely
    * used for values < `2^63` and will fail otherwise.
    */
  val tmillisatoshi: Codec[MilliSatoshi] =
    tu64overflow.xmap(l => MilliSatoshi(l), m => m.toLong)

  /** Truncated millisatoshi (0 to 4 bytes unsigned).
    */
  val tmillisatoshi32: Codec[MilliSatoshi] =
    tu32.xmap(l => MilliSatoshi(l), m => m.toLong)

  /** Truncated uint32 (0 to 4 bytes unsigned integer). */
  val tu32: Codec[Long] = tu64.exmap(
    {
      case i if i > 0xffffffffL => Attempt.Failure(Err("tu32 overflow"))
      case i                    => Attempt.Successful(i.toBigInt.toLong)
    },
    l => Attempt.Successful(UInt64(l))
  )

  /** Truncated uint16 (0 to 2 bytes unsigned integer). */
  val tu16: Codec[Int] = tu32.exmap(
    {
      case i if i > 0xffff => Attempt.Failure(Err("tu16 overflow"))
      case i               => Attempt.Successful(i.toInt)
    },
    l => Attempt.Successful(l)
  )

  /** Length-prefixed truncated uint64 (1 to 9 bytes unsigned integer). */
  val ltu64: Codec[UInt64] = variableSizeBytes(uint8, tu64)

  /** Length-prefixed truncated long (1 to 9 bytes unsigned integer). */
  val ltu64overflow: Codec[Long] = variableSizeBytes(uint8, tu64overflow)

  /** Length-prefixed truncated millisatoshi (1 to 9 bytes unsigned). */
  val ltmillisatoshi: Codec[MilliSatoshi] =
    variableSizeBytes(uint8, tmillisatoshi)

  /** Length-prefixed truncated uint32 (1 to 5 bytes unsigned integer). */
  val ltu32: Codec[Long] = variableSizeBytes(uint8, tu32)

  /** Length-prefixed truncated uint16 (1 to 3 bytes unsigned integer). */
  val ltu16: Codec[Int] = variableSizeBytes(uint8, tu16)

  private def validateGenericTlv(g: GenericTlv): Attempt[GenericTlv] = {
    if (g.tag < TLV_TYPE_HIGH_RANGE && g.tag.toBigInt % 2 == 0) {
      Attempt.Failure(Err("unknown even tlv type"))
    } else {
      Attempt.Successful(g)
    }
  }

  val genericTlv: Codec[GenericTlv] =
    (("tag" | varint) :: variableSizeBytesLong(varintoverflow, bytes))
      .as[GenericTlv]
      .exmap(validateGenericTlv, validateGenericTlv)

  private def tag[T <: Tlv](
      codec: DiscriminatorCodec[T, UInt64],
      record: Either[GenericTlv, T]
  ): UInt64 = record match {
    case Left(generic) => generic.tag
    case Right(tlv)    => tag(codec, tlv)
  }

  private def tag[T <: Tlv](
      codec: DiscriminatorCodec[T, UInt64],
      record: T
  ): UInt64 =
    codec.encode(record).flatMap(bits => varint.decode(bits)).require.value

  private def validateStream[T <: Tlv](
      codec: DiscriminatorCodec[T, UInt64],
      records: List[Either[GenericTlv, T]]
  ): Attempt[TlvStream[T]] = {
    val tags = records.map(r => tag(codec, r))
    if (tags.length != tags.distinct.length) {
      Attempt.Failure(Err("tlv streams must not contain duplicate records"))
    } else if (tags != tags.sorted) {
      Attempt.Failure(
        Err("tlv records must be ordered by monotonically-increasing types")
      )
    } else {
      Attempt.Successful(
        TlvStream(
          records.collect { case Right(tlv) => tlv },
          records.collect { case Left(generic) => generic }
        )
      )
    }
  }

  /** A tlv stream codec relies on an underlying tlv codec. This allows tlv
    * streams to have different namespaces, increasing the total number of tlv
    * types available.
    *
    * @param codec
    *   codec used for the tlv records contained in the stream.
    * @tparam T
    *   stream namespace.
    */
  def tlvStream[T <: Tlv](
      codec: DiscriminatorCodec[T, UInt64]
  ): Codec[TlvStream[T]] = list(discriminatorFallback(genericTlv, codec)).exmap(
    records => validateStream(codec, records),
    (stream: TlvStream[T]) => {
      val records =
        (stream.records.map(Right(_)) ++ stream.unknown.map(Left(_))).toList
      val tags = records.map(r => tag(codec, r))
      if (tags.length != tags.distinct.length) {
        Attempt.Failure(Err("tlv streams must not contain duplicate records"))
      } else {
        Attempt.Successful(tags.zip(records).sortBy(_._1).map(_._2))
      }
    }
  )

  /** When used inside a message, most of the time a tlv stream needs to specify
    * its length. Note that some messages will have an independent length field
    * and won't need this codec.
    *
    * @param codec
    *   codec used for the tlv records contained in the stream.
    * @tparam T
    *   stream namespace.
    */
  def lengthPrefixedTlvStream[T <: Tlv](
      codec: DiscriminatorCodec[T, UInt64]
  ): Codec[TlvStream[T]] =
    variableSizeBytesLong(CommonCodecs.varintoverflow, tlvStream(codec))
}

sealed trait OpenChannelTlv extends Tlv
sealed trait AcceptChannelTlv extends Tlv

object ChannelTlv {

  /** Commitment to where the funds will go in case of a mutual close, which
    * remote node will enforce in case we're compromised.
    */
  case class UpfrontShutdownScriptTlv(script: ByteVector)
      extends OpenChannelTlv
      with AcceptChannelTlv {
    val isEmpty: Boolean = script.isEmpty
  }

  val upfrontShutdownScriptCodec: Codec[UpfrontShutdownScriptTlv] =
    variableSizeBytesLong(varintoverflow, bytes).as[UpfrontShutdownScriptTlv]

  /** A channel type is a set of even feature bits that represent persistent
    * features which affect channel operations.
    */
  // case class ChannelTypeTlv(channelType: ChannelType)
  //     extends OpenChannelTlv
  //     with AcceptChannelTlv
  //
  // val channelTypeCodec: Codec[ChannelTypeTlv] =
  //   variableSizeBytesLong(varintoverflow, bytes).xmap(
  //     b =>
  //       ChannelTypeTlv(ChannelTypes.fromFeatures(Features(b).initFeatures())),
  //     tlv =>
  //       Features(
  //         tlv.channelType.features.map(f => f -> FeatureSupport.Mandatory).toMap
  //       ).toByteVector
  //   )
}

object OpenChannelTlv {
  import ChannelTlv._

  val openTlvCodec: Codec[TlvStream[OpenChannelTlv]] = tlvStream(
    discriminated[OpenChannelTlv]
      .by(varint)
      .typecase(UInt64(0), upfrontShutdownScriptCodec)
    // .typecase(UInt64(1), channelTypeCodec)
  )
}

object AcceptChannelTlv {
  import ChannelTlv._

  val acceptTlvCodec: Codec[TlvStream[AcceptChannelTlv]] = tlvStream(
    discriminated[AcceptChannelTlv]
      .by(varint)
      .typecase(UInt64(0), upfrontShutdownScriptCodec)
    // .typecase(UInt64(1), channelTypeCodec)
  )
}

sealed trait FundingCreatedTlv extends Tlv

object FundingCreatedTlv {
  val fundingCreatedTlvCodec: Codec[TlvStream[FundingCreatedTlv]] = tlvStream(
    discriminated[FundingCreatedTlv].by(varint)
  )
}

sealed trait FundingSignedTlv extends Tlv

object FundingSignedTlv {
  val fundingSignedTlvCodec: Codec[TlvStream[FundingSignedTlv]] = tlvStream(
    discriminated[FundingSignedTlv].by(varint)
  )
}

sealed trait FundingLockedTlv extends Tlv

object FundingLockedTlv {
  val fundingLockedTlvCodec: Codec[TlvStream[FundingLockedTlv]] = tlvStream(
    discriminated[FundingLockedTlv].by(varint)
  )
}

sealed trait ChannelReestablishTlv extends Tlv

object ChannelReestablishTlv {
  val channelReestablishTlvCodec: Codec[TlvStream[ChannelReestablishTlv]] =
    tlvStream(discriminated[ChannelReestablishTlv].by(varint))
}

sealed trait UpdateFeeTlv extends Tlv

object UpdateFeeTlv {
  val updateFeeTlvCodec: Codec[TlvStream[UpdateFeeTlv]] = tlvStream(
    discriminated[UpdateFeeTlv].by(varint)
  )
}

sealed trait ShutdownTlv extends Tlv

object ShutdownTlv {
  val shutdownTlvCodec: Codec[TlvStream[ShutdownTlv]] = tlvStream(
    discriminated[ShutdownTlv].by(varint)
  )
}

sealed trait ClosingSignedTlv extends Tlv

object ClosingSignedTlv {
  case class FeeRange(min: Satoshi, max: Satoshi) extends ClosingSignedTlv
  private val feeRange: Codec[FeeRange] =
    (("min_fee_satoshis" | satoshi) :: ("max_fee_satoshis" | satoshi))
      .as[FeeRange]
  val closingSignedTlvCodec: Codec[TlvStream[ClosingSignedTlv]] = tlvStream(
    discriminated[ClosingSignedTlv]
      .by(varint)
      .typecase(UInt64(1), variableSizeBytesLong(varintoverflow, feeRange))
  )
}

sealed trait UpdateAddHtlcTlv extends Tlv

object UpdateAddHtlcTlv {

  /** Blinding ephemeral public key that should be used to derive shared secrets
    * when using route blinding.
    */
  case class BlindingPoint(publicKey: PublicKey) extends UpdateAddHtlcTlv

  private val blindingPoint: Codec[BlindingPoint] =
    (("length" | constant(
      ByteVector.fromValidHex("21")
    )) :: ("blinding" | publicKey))
      .as[BlindingPoint]

  val addHtlcTlvCodec: Codec[TlvStream[UpdateAddHtlcTlv]] = tlvStream(
    discriminated[UpdateAddHtlcTlv]
      .by(varint)
      .typecase(UInt64(0), blindingPoint)
  )
}

sealed trait UpdateFulfillHtlcTlv extends Tlv

object UpdateFulfillHtlcTlv {
  val updateFulfillHtlcTlvCodec: Codec[TlvStream[UpdateFulfillHtlcTlv]] =
    tlvStream(discriminated[UpdateFulfillHtlcTlv].by(varint))
}

sealed trait UpdateFailHtlcTlv extends Tlv

object UpdateFailHtlcTlv {
  val updateFailHtlcTlvCodec: Codec[TlvStream[UpdateFailHtlcTlv]] = tlvStream(
    discriminated[UpdateFailHtlcTlv].by(varint)
  )
}

sealed trait UpdateFailMalformedHtlcTlv extends Tlv

object UpdateFailMalformedHtlcTlv {
  val updateFailMalformedHtlcTlvCodec
      : Codec[TlvStream[UpdateFailMalformedHtlcTlv]] = tlvStream(
    discriminated[UpdateFailMalformedHtlcTlv].by(varint)
  )
}

sealed trait CommitSigTlv extends Tlv

object CommitSigTlv {
  val commitSigTlvCodec: Codec[TlvStream[CommitSigTlv]] = tlvStream(
    discriminated[CommitSigTlv].by(varint)
  )
}

sealed trait RevokeAndAckTlv extends Tlv

object RevokeAndAckTlv {
  val revokeAndAckTlvCodec: Codec[TlvStream[RevokeAndAckTlv]] = tlvStream(
    discriminated[RevokeAndAckTlv].by(varint)
  )
}

sealed trait AnnouncementSignaturesTlv extends Tlv

object AnnouncementSignaturesTlv {
  val announcementSignaturesTlvCodec
      : Codec[TlvStream[AnnouncementSignaturesTlv]] = tlvStream(
    discriminated[AnnouncementSignaturesTlv].by(varint)
  )
}

sealed trait NodeAnnouncementTlv extends Tlv

object NodeAnnouncementTlv {
  val nodeAnnouncementTlvCodec: Codec[TlvStream[NodeAnnouncementTlv]] =
    tlvStream(discriminated[NodeAnnouncementTlv].by(varint))
}

sealed trait ChannelAnnouncementTlv extends Tlv

object ChannelAnnouncementTlv {
  val channelAnnouncementTlvCodec: Codec[TlvStream[ChannelAnnouncementTlv]] =
    tlvStream(discriminated[ChannelAnnouncementTlv].by(varint))
}

sealed trait ChannelUpdateTlv extends Tlv

object ChannelUpdateTlv {
  val channelUpdateTlvCodec: Codec[TlvStream[ChannelUpdateTlv]] = tlvStream(
    discriminated[ChannelUpdateTlv].by(varint)
  )
}

sealed trait GossipTimestampFilterTlv extends Tlv

object GossipTimestampFilterTlv {
  val gossipTimestampFilterTlvCodec
      : Codec[TlvStream[GossipTimestampFilterTlv]] = tlvStream(
    discriminated[GossipTimestampFilterTlv].by(varint)
  )
}

sealed trait QueryChannelRangeTlv extends Tlv

object QueryChannelRangeTlv {

  /** Optional query flag that is appended to QueryChannelRange
    *
    * @param flag
    *   bit 1 set means I want timestamps, bit 2 set means I want checksums
    */
  case class QueryFlags(flag: Long) extends QueryChannelRangeTlv {
    val wantTimestamps = QueryFlags.wantTimestamps(flag)

    val wantChecksums = QueryFlags.wantChecksums(flag)
  }

  case object QueryFlags {
    val WANT_TIMESTAMPS: Long = 1
    val WANT_CHECKSUMS: Long = 2
    val WANT_ALL: Long = WANT_TIMESTAMPS | WANT_CHECKSUMS

    def wantTimestamps(flag: Long): Boolean = (flag & WANT_TIMESTAMPS) != 0

    def wantChecksums(flag: Long): Boolean = (flag & WANT_CHECKSUMS) != 0
  }

  val queryFlagsCodec: Codec[QueryFlags] =
    ("flag" | varintoverflow).as[QueryFlags]

  val codec: Codec[TlvStream[QueryChannelRangeTlv]] = TlvCodecs.tlvStream(
    discriminated
      .by(varint)
      .typecase(
        UInt64(1),
        variableSizeBytesLong(varintoverflow, queryFlagsCodec)
      )
  )

}

sealed trait ReplyChannelRangeTlv extends Tlv

object ReplyChannelRangeTlv {

  /** @param timestamp1
    *   timestamp for node 1, or 0
    * @param timestamp2
    *   timestamp for node 2, or 0
    */
  case class Timestamps(
      timestamp1: TimestampSecond,
      timestamp2: TimestampSecond
  )

  /** Optional timestamps TLV that can be appended to ReplyChannelRange
    *
    * @param encoding
    *   same convention as for short channel ids
    */
  case class EncodedTimestamps(
      encoding: EncodingType,
      timestamps: List[Timestamps]
  ) extends ReplyChannelRangeTlv {
    /* custom toString because it can get huge in logs */
    override def toString: String =
      s"EncodedTimestamps($encoding, size=${timestamps.size})"
  }

  /** @param checksum1
    *   checksum for node 1, or 0
    * @param checksum2
    *   checksum for node 2, or 0
    */
  case class Checksums(checksum1: Long, checksum2: Long)

  /** Optional checksums TLV that can be appended to ReplyChannelRange
    */
  case class EncodedChecksums(checksums: List[Checksums])
      extends ReplyChannelRangeTlv {

    /** custom toString because it can get huge in logs */
    override def toString: String = s"EncodedChecksums(size=${checksums.size})"
  }

  val timestampsCodec: Codec[Timestamps] = (
    ("timestamp1" | timestampSecond) ::
      ("timestamp2" | timestampSecond)
  ).as[Timestamps]

  val encodedTimestampsCodec: Codec[EncodedTimestamps] = variableSizeBytesLong(
    varintoverflow,
    discriminated[EncodedTimestamps]
      .by(byte)
      .subcaseP(0) { case a @ EncodedTimestamps(EncodingType.UNCOMPRESSED, _) =>
        a
      }(
        (provide[EncodingType](EncodingType.UNCOMPRESSED) :: list(
          timestampsCodec
        )).as[EncodedTimestamps]
      )
  )

  val checksumsCodec: Codec[Checksums] = (
    ("checksum1" | uint32) ::
      ("checksum2" | uint32)
  ).as[Checksums]

  val encodedChecksumsCodec: Codec[EncodedChecksums] =
    variableSizeBytesLong(varintoverflow, list(checksumsCodec))
      .as[EncodedChecksums]

  val innerCodec = discriminated[ReplyChannelRangeTlv]
    .by(varint)
    .typecase(UInt64(1), encodedTimestampsCodec)
    .typecase(UInt64(3), encodedChecksumsCodec)

  val codec: Codec[TlvStream[ReplyChannelRangeTlv]] =
    TlvCodecs.tlvStream(innerCodec)
}

sealed trait QueryShortChannelIdsTlv extends Tlv

object QueryShortChannelIdsTlv {

  /** Optional TLV-based query message that can be appended to
    * QueryShortChannelIds
    *
    * @param encoding
    *   0 means uncompressed, 1 means compressed with zlib
    * @param array
    *   array of query flags, each flags specifies the info we want for a given
    *   channel
    */
  case class EncodedQueryFlags(encoding: EncodingType, array: List[Long])
      extends QueryShortChannelIdsTlv {

    /** custom toString because it can get huge in logs */
    override def toString: String =
      s"EncodedQueryFlags($encoding, size=${array.size})"
  }

  case object QueryFlagType {
    val INCLUDE_CHANNEL_ANNOUNCEMENT: Long = 1
    val INCLUDE_CHANNEL_UPDATE_1: Long = 2
    val INCLUDE_CHANNEL_UPDATE_2: Long = 4
    val INCLUDE_NODE_ANNOUNCEMENT_1: Long = 8
    val INCLUDE_NODE_ANNOUNCEMENT_2: Long = 16

    def includeChannelAnnouncement(flag: Long): Boolean =
      (flag & INCLUDE_CHANNEL_ANNOUNCEMENT) != 0

    def includeUpdate1(flag: Long): Boolean =
      (flag & INCLUDE_CHANNEL_UPDATE_1) != 0

    def includeUpdate2(flag: Long): Boolean =
      (flag & INCLUDE_CHANNEL_UPDATE_2) != 0

    def includeNodeAnnouncement1(flag: Long): Boolean =
      (flag & INCLUDE_NODE_ANNOUNCEMENT_1) != 0

    def includeNodeAnnouncement2(flag: Long): Boolean =
      (flag & INCLUDE_NODE_ANNOUNCEMENT_2) != 0
  }

  val encodedQueryFlagsCodec: Codec[EncodedQueryFlags] =
    discriminated[EncodedQueryFlags]
      .by(byte)
      .subcaseP(0) { case a @ EncodedQueryFlags(EncodingType.UNCOMPRESSED, _) =>
        a
      }(
        (provide[EncodingType](EncodingType.UNCOMPRESSED) :: list(
          varintoverflow
        )).as[EncodedQueryFlags]
      )

  val codec: Codec[TlvStream[QueryShortChannelIdsTlv]] = TlvCodecs.tlvStream(
    discriminated
      .by(varint)
      .typecase(
        UInt64(1),
        variableSizeBytesLong(varintoverflow, encodedQueryFlagsCodec)
      )
  )
}

sealed trait ReplyShortChannelIdsEndTlv extends Tlv

object ReplyShortChannelIdsEndTlv {
  val replyShortChannelIdsEndTlvCodec
      : Codec[TlvStream[ReplyShortChannelIdsEndTlv]] = tlvStream(
    discriminated[ReplyShortChannelIdsEndTlv].by(varint)
  )
}

/** Tlv types used inside Init messages. */
sealed trait InitTlv extends Tlv

object InitTlv {

  /** The chains the node is interested in. */
  case class Networks(chainHashes: List[ByteVector32]) extends InitTlv

  /** When receiving an incoming connection, we can send back the public address
    * our peer is connecting from. This lets our peer discover if its public IP
    * has changed from within its local network.
    */
  case class RemoteAddress(address: NodeAddress) extends InitTlv
}

object InitTlvCodecs {
  import InitTlv._

  private val networks: Codec[Networks] =
    variableSizeBytesLong(varintoverflow, list(bytes32)).as[Networks]
  private val remoteAddress: Codec[RemoteAddress] =
    variableSizeBytesLong(varintoverflow, nodeaddress).as[RemoteAddress]

  val initTlvCodec = tlvStream(
    discriminated[InitTlv]
      .by(varint)
      .typecase(UInt64(1), networks)
      .typecase(UInt64(3), remoteAddress)
  )
}

sealed trait WarningTlv extends Tlv

object WarningTlv {
  val warningTlvCodec: Codec[TlvStream[WarningTlv]] = tlvStream(
    discriminated[WarningTlv].by(varint)
  )
}

sealed trait ErrorTlv extends Tlv

object ErrorTlv {
  val errorTlvCodec: Codec[TlvStream[ErrorTlv]] = tlvStream(
    discriminated[ErrorTlv].by(varint)
  )
}

sealed trait PingTlv extends Tlv

object PingTlv {
  val pingTlvCodec: Codec[TlvStream[PingTlv]] = tlvStream(
    discriminated[PingTlv].by(varint)
  )
}

sealed trait PongTlv extends Tlv

object PongTlv {
  val pongTlvCodec: Codec[TlvStream[PongTlv]] = tlvStream(
    discriminated[PongTlv].by(varint)
  )
}
