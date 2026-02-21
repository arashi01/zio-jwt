package zio.jwt.crypto

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint

import zio.jwt.Algorithm
import zio.jwt.EcCurve
import zio.jwt.JwtError

/** EC curve JCA mapping, curve orders, ECDSA sanity checks, and point-on-curve validation. */
object EcParams:

  // -- Curve orders (NIST FIPS 186-4) --

  private val p256Order: BigInteger =
    BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

  private val p384Order: BigInteger =
    BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16)

  private val p521Order: BigInteger =
    BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16)

  // -- Lazy-loaded ECParameterSpec per curve (cached) --

  private lazy val p256Spec: ECParameterSpec = loadSpec("secp256r1")
  private lazy val p384Spec: ECParameterSpec = loadSpec("secp384r1")
  private lazy val p521Spec: ECParameterSpec = loadSpec("secp521r1")

  private def loadSpec(name: String): ECParameterSpec =
    import scala.language.unsafeNulls
    val params = AlgorithmParameters.getInstance("EC")
    params.init(ECGenParameterSpec(name))
    params.getParameterSpec(classOf[ECParameterSpec])

  // -- Extension methods on EcCurve --

  extension (crv: EcCurve)

    /** JCA named curve identifier (e.g. "secp256r1"). */
    def jcaName: String = crv match
      case EcCurve.P256 => "secp256r1"
      case EcCurve.P384 => "secp384r1"
      case EcCurve.P521 => "secp521r1"

    /** JCA EC parameter specification for key construction. */
    def spec: ECParameterSpec = crv match
      case EcCurve.P256 => p256Spec
      case EcCurve.P384 => p384Spec
      case EcCurve.P521 => p521Spec

    /** Curve group order N. */
    def order: BigInteger = crv match
      case EcCurve.P256 => p256Order
      case EcCurve.P384 => p384Order
      case EcCurve.P521 => p521Order

    /** Byte length of a single field element (coordinate or private key). */
    def componentLength: Int = crv match
      case EcCurve.P256 => 32
      case EcCurve.P384 => 48
      case EcCurve.P521 => 66

  // -- Algorithm-to-curve mapping --

  /** Maps an ECDSA algorithm to its corresponding curve. */
  def curveForAlgorithm(alg: Algorithm): Option[EcCurve] = alg match
    case Algorithm.ES256 => Some(EcCurve.P256)
    case Algorithm.ES384 => Some(EcCurve.P384)
    case Algorithm.ES512 => Some(EcCurve.P521)
    case _               => None

  // -- ECDSA signature sanity checks (ss7.2) --

  /**
   * Validates an ECDSA signature per ss7.2 (CVE-2022-21449 mitigations).
   * Must be called before passing the signature to JCA `verify()`.
   */
  def validateSignature(alg: Algorithm, signature: Array[Byte]): Either[JwtError, Unit] =
    import scala.language.unsafeNulls

    for
      sigLen <- EcdsaCodec.signatureLength(alg).toRight(JwtError.InvalidSignature)
      crv    <- curveForAlgorithm(alg).toRight(JwtError.InvalidSignature)

      // Step 1: reject all-zero signatures
      _ <- Either.cond(!signature.forall(_ == 0.toByte), (), JwtError.InvalidSignature)

      // Step 2: reject wrong length
      _ <- Either.cond(signature.length == sigLen, (), JwtError.InvalidSignature)

      // Steps 3-6: validate R and S components
      mid = sigLen / 2
      r   = BigInteger(1, signature.slice(0, mid))
      s   = BigInteger(1, signature.slice(mid, sigLen))
      n   = crv.order

      // Step 4: reject R = 0 or S = 0
      _ <- Either.cond(r.signum() > 0 && s.signum() > 0, (), JwtError.InvalidSignature)

      // Step 5: reject R >= N or S >= N
      _ <- Either.cond(r.compareTo(n) < 0 && s.compareTo(n) < 0, (), JwtError.InvalidSignature)

      // Step 6: reject R mod N = 0 or S mod N = 0 (redundant given steps 4+5, but spec-mandated)
      _ <- Either.cond(r.mod(n).signum() > 0 && s.mod(n).signum() > 0, (), JwtError.InvalidSignature)
    yield ()

  // -- EC point-on-curve validation (ss7.3) --

  /** Validates that the point (x, y) lies on the specified curve: y^2 mod p = (x^3 + ax + b) mod p. */
  def validatePointOnCurve(crv: EcCurve, point: ECPoint): Either[JwtError, Unit] =
    import scala.language.unsafeNulls

    val ecSpec = crv.spec
    val curve  = ecSpec.getCurve
    curve.getField match
      case fp: ECFieldFp =>
        val p = fp.getP
        val a = curve.getA
        val b = curve.getB
        val x = point.getAffineX
        val y = point.getAffineY

        // y^2 mod p
        val lhs = y.modPow(BigInteger.valueOf(2), p)

        // x^3 + ax + b mod p
        val x3  = x.modPow(BigInteger.valueOf(3), p)
        val ax  = a.multiply(x).mod(p)
        val rhs = x3.add(ax).add(b).mod(p)

        Either.cond(lhs.compareTo(rhs) == 0, (), JwtError.MalformedToken(
          IllegalArgumentException("EC point is not on the curve")
        ))

      case _ =>
        Left(JwtError.MalformedToken(
          IllegalArgumentException("Unsupported EC field type")
        ))
