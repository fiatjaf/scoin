package scoin

sealed trait BtcAmount

case class MilliSatoshi(private val underlying: Long)
    extends BtcAmount
    with Ordered[MilliSatoshi] {
  def +(other: MilliSatoshi) = MilliSatoshi(underlying + other.underlying)
  def -(other: MilliSatoshi) = MilliSatoshi(underlying - other.underlying)
  def *(m: Long) = MilliSatoshi(underlying * m)
  def *(m: Double) = MilliSatoshi((underlying * m).toLong)
  def /(d: Long) = MilliSatoshi(underlying / d)
  def unary_- = MilliSatoshi(-underlying)

  override def compare(other: MilliSatoshi): Int =
    underlying.compareTo(other.underlying)
  def max(other: MilliSatoshi): MilliSatoshi = if (this > other) this else other
  def min(other: MilliSatoshi): MilliSatoshi = if (this < other) this else other

  def truncateToSatoshi: Satoshi = Satoshi(underlying / 1000)
  def toBtc: Btc = truncateToSatoshi.toBtc
  def toLong: Long = underlying
  override def toString = s"${underlying}msat"
}

case class Satoshi(private val underlying: Long)
    extends BtcAmount
    with Ordered[Satoshi] {
  // @formatter:off
  def +(other: Satoshi) = Satoshi(underlying + other.underlying)
  def -(other: Satoshi) = Satoshi(underlying - other.underlying)
  def unary_- = Satoshi(-underlying)
  def *(m: Long) = Satoshi(underlying * m)
  def *(m: Double) = Satoshi((underlying * m).toLong)
  def /(d: Long) = Satoshi(underlying / d)
  def compare(other: Satoshi): Int = underlying.compare(other.underlying)
  def max(other: BtcAmount): Satoshi = other match {
    case other: MilliSatoshi => if (this.toMilliSatoshi.toLong > other.toLong) this else other.toSatoshi
    case other: Satoshi => if (underlying > other.underlying) this else other
    case other: Btc => if (underlying > other.toSatoshi.underlying) this else other.toSatoshi
  }
  def min(other: BtcAmount): Satoshi = other match {
    case other:  MilliSatoshi => if (this.toMilliSatoshi.toLong < other.toLong) this else other
    case other: Satoshi => if (underlying < other.underlying) this else other
    case other: Btc => if (underlying < other.toSatoshi.underlying) this else other.toSatoshi
  }
  def toBtc: Btc = Btc(BigDecimal(underlying) / BtcAmount.Coin)
  def toMilliSatoshi:  MilliSatoshi = MilliSatoshi(underlying * 1000)
  def toLong = underlying
  override def toString = s"${underlying}sat"
  // @formatter:on
}

case class Btc(private val underlying: BigDecimal)
    extends BtcAmount
    with Ordered[Btc] {
  require(underlying.abs <= 21e6, "amount must not be greater than 21 millions")

  // @formatter:off
  def +(other: Btc) = Btc(underlying + other.underlying)
  def -(other: Btc) = Btc(underlying - other.underlying)
  def unary_- = Btc(-underlying)
  def *(m: Long) = Btc(underlying * m)
  def *(m: Double) = Btc(underlying * m)
  def /(d: Long) = Btc(underlying / d)
  def compare(other: Btc): Int = underlying.compare(other.underlying)
  def max(other: BtcAmount): Btc = other match {
    case other: MilliSatoshi => if (this.toMilliSatoshi.toLong > other.toLong) this else other.toBtc
    case other: Satoshi => if (underlying > other.toBtc.underlying) this else other.toBtc
    case other: Btc => if (underlying > other.underlying) this else other
  }
  def min(other: BtcAmount): Btc = other match {
    case other: MilliSatoshi => if (this.toMilliSatoshi.toLong < other.toLong) this else other.toBtc
    case other: Satoshi => if (underlying < other.toBtc.underlying) this else other.toBtc
    case other: Btc => if (underlying < other.underlying) this else other
  }
  def toMilliSatoshi: MilliSatoshi = toSatoshi.toMilliSatoshi
  def toSatoshi: Satoshi = Satoshi((underlying * BtcAmount.Coin).toLong)
  def toBigDecimal = underlying
  def toDouble: Double = underlying.toDouble
  def toLong: Long = underlying.toLong
  override def toString = s"$underlying BTC"
  // @formatter:on
}

object BtcAmount {
  val Coin = 100000000L
  val MaxMoney = 21e6 * Coin
}
