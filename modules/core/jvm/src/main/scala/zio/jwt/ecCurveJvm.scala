package zio.jwt

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec

import scala.annotation.targetName

// JVM-specific extensions on EcCurve requiring JCA types.
// Discoverable via `import zio.jwt.*` (ss13).

private lazy val p256Spec: ECParameterSpec = loadEcSpec("secp256r1")
private lazy val p384Spec: ECParameterSpec = loadEcSpec("secp384r1")
private lazy val p521Spec: ECParameterSpec = loadEcSpec("secp521r1")

private def loadEcSpec(name: String): ECParameterSpec =
  import scala.language.unsafeNulls
  val params = AlgorithmParameters.getInstance("EC")
  params.init(ECGenParameterSpec(name))
  params.getParameterSpec(classOf[ECParameterSpec])

// Curve orders (NIST FIPS 186-4)
private val p256Order: BigInteger =
  BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

private val p384Order: BigInteger =
  BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16)

private val p521Order: BigInteger =
  BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16)

extension (crv: EcCurve)

  /** JCA EC parameter specification for key construction. */
  @targetName("ecCurveSpec")
  def spec: ECParameterSpec = crv match
    case EcCurve.P256 => p256Spec
    case EcCurve.P384 => p384Spec
    case EcCurve.P521 => p521Spec

  /** Curve group order N. */
  @targetName("ecCurveOrder")
  def order: BigInteger = crv match
    case EcCurve.P256 => p256Order
    case EcCurve.P384 => p384Order
    case EcCurve.P521 => p521Order
