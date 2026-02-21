package zio.jwt

import scala.annotation.targetName

/** Algorithm family grouping for key-type dispatch. */
enum AlgorithmFamily derives CanEqual:
  case HMAC, RSA, EC, RSAPSS

/** JWS digital signature and MAC algorithm identifiers (RFC 7518 ss3.1). */
enum Algorithm derives CanEqual:
  // HMAC
  case HS256, HS384, HS512
  // RSA PKCS#1 v1.5
  case RS256, RS384, RS512
  // ECDSA
  case ES256, ES384, ES512
  // RSA-PSS
  case PS256, PS384, PS512

/** Companion for [[Algorithm]]. Provides JCA mapping and family classification. */
object Algorithm:
  extension (alg: Algorithm)

    /** JCA algorithm name for [[java.security.Signature]] or [[javax.crypto.Mac]]. */
    @targetName("algorithmJcaName")
    def jcaName: String = alg match
      case Algorithm.HS256 => "HmacSHA256"
      case Algorithm.HS384 => "HmacSHA384"
      case Algorithm.HS512 => "HmacSHA512"
      case Algorithm.RS256 => "SHA256withRSA"
      case Algorithm.RS384 => "SHA384withRSA"
      case Algorithm.RS512 => "SHA512withRSA"
      case Algorithm.ES256 => "SHA256withECDSA"
      case Algorithm.ES384 => "SHA384withECDSA"
      case Algorithm.ES512 => "SHA512withECDSA"
      case Algorithm.PS256 => "RSASSA-PSS"
      case Algorithm.PS384 => "RSASSA-PSS"
      case Algorithm.PS512 => "RSASSA-PSS"

    /** Algorithm family for key-type dispatch. */
    @targetName("algorithmFamily")
    def family: AlgorithmFamily = alg match
      case Algorithm.HS256 | Algorithm.HS384 | Algorithm.HS512 => AlgorithmFamily.HMAC
      case Algorithm.RS256 | Algorithm.RS384 | Algorithm.RS512 => AlgorithmFamily.RSA
      case Algorithm.ES256 | Algorithm.ES384 | Algorithm.ES512 => AlgorithmFamily.EC
      case Algorithm.PS256 | Algorithm.PS384 | Algorithm.PS512 => AlgorithmFamily.RSAPSS

    /** ECDSA curve for this algorithm, if applicable. */
    @targetName("algorithmCurve")
    def curve: Option[EcCurve] = alg match
      case Algorithm.ES256 => Some(EcCurve.P256)
      case Algorithm.ES384 => Some(EcCurve.P384)
      case Algorithm.ES512 => Some(EcCurve.P521)
      case _               => None
