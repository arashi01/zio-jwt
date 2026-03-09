/*
 * Copyright (c) 2026 Ali Rashid.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package zio.jwt.crypto

import java.math.BigInteger
import java.security.spec.ECFieldFp
import java.security.spec.ECPoint

import boilerplate.nullable.*

import zio.jwt.*

/** ECDSA sanity checks, point-on-curve validation, and algorithm-to-curve mapping. */
object EcParams:

  // -- ECDSA signature sanity checks --

  /** Validates an ECDSA signature (CVE-2022-21449 mitigations). Must be called before passing the
    * signature to JCA `verify()`.
    */
  def validateSignature(alg: Algorithm, signature: Array[Byte]): Either[JwtError, Unit] =
    for
      sigLen <- EcdsaCodec.signatureLength(alg).toRight(JwtError.InvalidSignature)
      crv <- alg.curve.toRight(JwtError.InvalidSignature)

      // Step 1: reject all-zero signatures
      _ <- Either.cond(!signature.forall(_ == 0.toByte), (), JwtError.InvalidSignature)

      // Step 2: reject wrong length
      _ <- Either.cond(signature.length == sigLen, (), JwtError.InvalidSignature)

      // Steps 3-6: validate R and S components
      mid = sigLen / 2
      r = BigInteger(1, signature.slice(0, mid))
      s = BigInteger(1, signature.slice(mid, sigLen))
      n = crv.order

      // Step 4: reject R = 0 or S = 0
      _ <- Either.cond(r.signum() > 0 && s.signum() > 0, (), JwtError.InvalidSignature)

      // Step 5: reject R >= N or S >= N
      _ <- Either.cond(r.compareTo(n) < 0 && s.compareTo(n) < 0, (), JwtError.InvalidSignature)

      // Step 6: reject R mod N = 0 or S mod N = 0 (redundant given steps 4+5, but spec-mandated)
      _ <- Either.cond(r.mod(n).signum() > 0 && s.mod(n).signum() > 0, (), JwtError.InvalidSignature)
    yield ()

  // -- EC point-on-curve validation --

  /** Validates that the point (x, y) lies on the specified curve: y^2 mod p = (x^3 + ax + b) mod p. */
  def validatePointOnCurve(crv: EcCurve, point: ECPoint): Either[JwtError, Unit] =
    val ecSpec = crv.spec
    val curve = ecSpec.getCurve.unsafe("EC spec has null curve")
    curve.getField match
      case fp: ECFieldFp =>
        val p = fp.getP.unsafe("ECFieldFp has null p")
        val a = curve.getA.unsafe("EC curve has null a")
        val b = curve.getB.unsafe("EC curve has null b")
        val x = point.getAffineX.unsafe("EC point has null x")
        val y = point.getAffineY.unsafe("EC point has null y")

        // y^2 mod p
        val lhs = y.modPow(BigInteger.valueOf(2), p)

        // x^3 + ax + b mod p
        val x3 = x.modPow(BigInteger.valueOf(3), p)
        val ax = a.multiply(x).mod(p)
        val rhs = x3.add(ax).add(b).mod(p)

        Either.cond(lhs.compareTo(rhs) == 0,
                    (),
                    JwtError.InvalidKey(
                      "EC point is not on the curve"
                    )
        )

      case _ =>
        Left(
          JwtError.InvalidKey(
            "Unsupported EC field type"
          )
        )
    end match
  end validatePointOnCurve
end EcParams
