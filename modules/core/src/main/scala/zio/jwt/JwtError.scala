package zio.jwt

import java.time.Instant

import scala.util.control.NoStackTrace

import boilerplate.unwrap

/**
 * Validation and structural errors produced during JWT processing.
 * Extends [[NoStackTrace]] -- these are expected domain errors, not exceptional conditions.
 */
enum JwtError extends Throwable with NoStackTrace derives CanEqual:

  case Expired(exp: NumericDate, now: Instant)

  case NotYetValid(nbf: NumericDate, now: Instant)

  case InvalidAudience(expected: String, actual: Option[Audience])

  case InvalidIssuer(expected: String, actual: Option[String])

  case InvalidSignature

  case MalformedToken(cause: Throwable)

  case UnsupportedAlgorithm(alg: String)

  case KeyNotFound(kid: Option[Kid])

  // Overriding upstream Throwable member -- permitted by core_requirements.md ss1.1.
  override def getMessage: String = this match
    case Expired(exp, now) =>
      s"Token expired at ${exp.unwrap}, current time $now"
    case NotYetValid(nbf, now) =>
      s"Token not yet valid until ${nbf.unwrap}, current time $now"
    case InvalidAudience(expected, actual) =>
      s"Expected audience '$expected', got ${actual.fold("none")(_.toString)}"
    case InvalidIssuer(expected, actual) =>
      s"Expected issuer '$expected', got ${actual.getOrElse("none")}"
    case InvalidSignature =>
      "Invalid signature"
    case MalformedToken(cause) =>
      s"Malformed token: ${cause.getMessage}"
    case UnsupportedAlgorithm(alg) =>
      s"Unsupported algorithm: $alg"
    case KeyNotFound(kid) =>
      s"Key not found${kid.fold("")(k => s" for kid '${k.unwrap}'")}"

  override def getCause: Throwable | Null = this match
    case MalformedToken(cause) => cause
    case _                     => null
