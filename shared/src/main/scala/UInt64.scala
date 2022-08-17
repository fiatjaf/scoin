package scoin

import scala.language.implicitConversions
import scodec.bits.ByteVector

case class UInt64(private val underlying: Long) extends Ordered[UInt64] {
  override def compare(o: UInt64): Int =
    java.lang.Long.compareUnsigned(underlying, o.underlying)
  private def compare(other: MilliSatoshi): Int = other.toLong match {
    case l if l < 0 =>
      1 // if @param 'other' is negative then is always smaller than 'this'
    case _ =>
      compare(
        UInt64(other.toLong)
      ) // we must do an unsigned comparison here because the uint64 can exceed the capacity of MilliSatoshi class
  }

  def <(other: MilliSatoshi): Boolean = compare(other) < 0
  def >(other: MilliSatoshi): Boolean = compare(other) > 0
  def <=(other: MilliSatoshi): Boolean = compare(other) <= 0
  def >=(other: MilliSatoshi): Boolean = compare(other) >= 0

  def toByteVector: ByteVector = ByteVector.fromLong(underlying)
  def toBigInt: BigInt = (BigInt(underlying >>> 1) << 1) + (underlying & 1)

  override def toString: String =
    java.lang.Long.toUnsignedString(underlying, 10)
}

object UInt64 {
  val MaxValue = UInt64(ByteVector.fromValidHex("0xffffffffffffffff"))
  def apply(bin: ByteVector): UInt64 = UInt64(bin.toLong(signed = false))

  object Conversions {
    implicit def intToUint64(l: Int): UInt64 = UInt64(l)
    implicit def longToUint64(l: Long): UInt64 = UInt64(l)
  }
}
