package zio.jwt

import scala.annotation.targetName

/** JOSE elliptic curve identifiers (RFC 7518 ss6.2.1.1). */
enum EcCurve derives CanEqual:
  case P256, P384, P521

/** Companion for [[EcCurve]]. Provides JCA naming and sizing extensions. */
object EcCurve:
  extension (crv: EcCurve)

    /** JCA named curve identifier (e.g. "secp256r1"). */
    @targetName("ecCurveJcaName")
    def jcaName: String = crv match
      case P256 => "secp256r1"
      case P384 => "secp384r1"
      case P521 => "secp521r1"

    /** Byte length of a single field element (coordinate or private key). */
    @targetName("ecCurveComponentLength")
    def componentLength: Int = crv match
      case P256 => 32
      case P384 => 48
      case P521 => 66
