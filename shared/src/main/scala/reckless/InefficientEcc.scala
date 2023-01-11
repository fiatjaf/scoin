package scoin.reckless
import scodec.bits._


/**
 * The elliptic curve domain parameters over F_p associated with 
 * a Koblitz curve E of the form y^2 = x^3 + a*x + b  mod p
 * */
trait Curve[A] {
    type F_p = BigInt

    val _p: BigInt // the modulus of the finite field
    val _a: F_p // the a coefficient
    val _b: F_p // the b coefficient
    val _n: BigInt // the order of the group of curve points

    sealed trait Point {
        def compressed: ByteVector = {
            require(this.isInstanceOf[CurvePoint])
            val x = this.asInstanceOf[CurvePoint].x
            val y = this.asInstanceOf[CurvePoint].y
            val firstByte = y % 2 == 0 match {
                case true  => ByteVector(0x02)
                case false => ByteVector(0x03)
            }
            firstByte 
            ++ ByteVector.fromValidHex(x.toString(16).reverse.padTo(32,'0').reverse) 
            //++ ByteVector.fromValidHex(y.toString(16).reverse.padTo(32,'0').reverse)
        }
        def uncompressed: ByteVector = {
            require(this.isInstanceOf[CurvePoint])
            val x = this.asInstanceOf[CurvePoint].x
            val y = this.asInstanceOf[CurvePoint].y
            ByteVector(0x04) 
            ++ ByteVector.fromValidHex(x.toString(16).reverse.padTo(32,'0').reverse) 
            ++ ByteVector.fromValidHex(y.toString(16).reverse.padTo(32,'0').reverse)
        }
    }
    case class CurvePoint(x: F_p, y: F_p) extends Point
    object CurvePoint {
        def fromUnCompressed(uncompressed: ByteVector):CurvePoint = {
            require(uncompressed.size == 65)
            CurvePoint(BigInt(uncompressed.drop(1).take(32).toHex,16),BigInt(uncompressed.drop(33).toHex,16))
        }
    }
    case object PointAtInfinity extends Point
    val G: CurvePoint // generator point G
}

object Curve {
    def apply[A : Curve]: Curve[A] = implicitly

    def isPointOnCurve[A](curve: Curve[A])(pt: curve.CurvePoint): Boolean = {
        pt.y.pow(2).mod(curve._p) == (pt.x.pow(3).mod(curve._p) + (pt.x*curve._a).mod(curve._p) + curve._b).mod(curve._p)
    }

    def pointNegate[A](curve: Curve[A])(pt: curve.CurvePoint): curve.CurvePoint = curve.CurvePoint(pt.x, curve._p - pt.y)

    def pointDouble[A](curve: Curve[A])(pt: curve.Point): curve.Point = pt match {
        case curve.PointAtInfinity => curve.PointAtInfinity
        case curve.CurvePoint(x,y) => {
                val three = BigInt(3)
                val two = BigInt(2)
                val L = (((three * x.pow(2)).mod(curve._p) + curve._a).mod(curve._p) * (two * y).modInverse(curve._p)).mod(curve._p) 
                val xR = (L.pow(2).mod(curve._p) - x - x).mod(curve._p)
                val yR = (L*(x - xR).mod(curve._p) - y).mod(curve._p)
                curve.CurvePoint(xR,yR)
        }
    }

    def pointAdd[A](curve: Curve[A])(lhs: curve.Point, rhs: curve.Point): curve.Point = (lhs,rhs) match {
        case (curve.PointAtInfinity,curve.PointAtInfinity) => curve.PointAtInfinity
        case (curve.PointAtInfinity,b) => b 
        case (a, curve.PointAtInfinity) => a
        case (a,b) if (a == b) => pointDouble(curve)(a) 
        case (a:curve.CurvePoint,b:curve.CurvePoint) => {
                val L = ((b.y - a.y).mod(curve._p) * (b.x - a.x).modInverse(curve._p)).mod(curve._p)
                val xR = (L.pow(2).mod(curve._p) - a.x - b.x).mod(curve._p)
                val yR = (L*(a.x - xR).mod(curve._p) - a.y).mod(curve._p)
                curve.CurvePoint(xR,yR)
        }
    }

    def multByScalar[A](curve: Curve[A])(point: curve.Point, scalar: BigInt): curve.Point = {
        //recursive formula here: https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Double-and-add
        def inner(pt: curve.Point, k: BigInt) = {
            if( k == 0 )
                curve.PointAtInfinity
            else if(k == 1)
                pt
            else if(k % 2 == 1)
                pointAdd(curve)(pt,multByScalar(curve)(pt, k-1)) //add when odd
            else 
                multByScalar(curve)(pointDouble(curve)(pt),(k / 2)) //double when even
        }
        // now start the recursion
        // note the modulus; we cannot have k > _n (which is order(G))
        inner(point, scalar)
    }

    object secp256k1 extends Secp256k1
}

trait Secp256k1 extends Curve[Secp256k1] {

    /** 
     * The elliptic curve domain parameters over F_p associated with a Koblitz curve secp256k1 are specified by 
        the sextuple T = (p,a,b,G,n,h) where the finite field Fp is defined by:

        p = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
        = 2256 - 232 - 29 - 28 - 27 - 26 - 24 - 1
        The curve E: y2 = x3+ax+b over Fp is defined by:

        a = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        b = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000007
        The base point G in compressed form is:

        G = 02 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
        and in uncompressed form is:

        G = 04 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8
        
        Finally the order n of G and the cofactor are:
        n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        h = 01

        Helpful description of the difference between the prime modulus p, and 
        _n, the order of G: https://crypto.stackexchange.com/questions/86328/secp256k1-prime-modulus-vs-order
    */

    val _p = BigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",16)
    val _a = BigInt(0)
    val _b = BigInt(7)
    val _n = BigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16)

    //val scalarFiniteField = FiniteField.Z_n(_n)
    val G_x = BigInt("79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798".split(' ').mkString ,16)
    val G_y = BigInt("483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8".split(' ').mkString, 16)

    val G: CurvePoint = CurvePoint(G_x,G_y)

}
