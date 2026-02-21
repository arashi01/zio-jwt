package zio.jwt.crypto

import java.math.BigInteger
import java.security.spec.ECFieldFp
import java.security.spec.ECPoint

import zio.jwt.*

/** ECDSA sanity checks (ss7.2), point-on-curve validation (ss7.3), and algorithm-to-curve mapping. */
object EcParams:

  // -- ECDSA signature sanity checks (ss7.2) --

  /**
   * Validates an ECDSA signature per ss7.2 (CVE-2022-21449 mitigations).
   * Must be called before passing the signature to JCA `verify()`.
   */
  def validateSignature(alg: Algorithm, signature: Array[Byte]): Either[JwtError, Unit] =
    for
      sigLen <- EcdsaCodec.signatureLength(alg).toRight(JwtError.InvalidSignature)
      crv    <- alg.curve.toRight(JwtError.InvalidSignature)

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
