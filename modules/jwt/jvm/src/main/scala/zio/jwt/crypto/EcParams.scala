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

// JVM-specific EC point-on-curve validation requiring JCA types.
// Augments the shared EcParams companion with a JVM-only method.

extension (companion: EcParams.type)

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

        Either.cond(
          lhs.compareTo(rhs) == 0,
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
end extension
