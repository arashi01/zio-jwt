package zio.jwt.crypto

import java.security.spec.ECPoint

import scala.annotation.targetName

import zio.jwt.EcCurve
import zio.jwt.JwtError

// Extension methods on EcCurve delegating to EcParams utility functions.
// Discoverable via `import zio.jwt.crypto.*`.
// EcParams.validatePointOnCurve(crv, point) serves as the non-curried alias (ss1.4).

extension (crv: EcCurve)

  /** Validates that the given point lies on this curve (ss7.3). */
  @targetName("ecCurveValidatePoint")
  def validatePoint(point: ECPoint): Either[JwtError, Unit] =
    EcParams.validatePointOnCurve(crv, point)
