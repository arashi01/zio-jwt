package zio.jwt

import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.Instant

import scala.util.Try

import zio.IO
import zio.ZIO
import zio.ZLayer

import boilerplate.unwrap

import zio.jwt.crypto.SignatureEngine

/**
 * Service for validating JWT tokens.
 * Instances live in the ZIO environment; construct via [[JwtValidator$ JwtValidator]].live.
 */
trait JwtValidator:
  def validate[A: JwtCodec](token: TokenString): IO[JwtError, Jwt[A]]

/**
 * Companion for [[JwtValidator]]. Provides the live layer and validation utilities.
 */
object JwtValidator:

  /**
   * Constructs a [[JwtValidator]] layer from [[ValidationConfig]] and [[KeySource]].
   * Codec instances are injected via `using` parameters.
   */
  def live(using
      headerCodec: JwtCodec[JoseHeader],
      claimsCodec: JwtCodec[RegisteredClaims]
  ): ZLayer[ValidationConfig & KeySource, Nothing, JwtValidator] =
    ZLayer.fromZIO {
      for
        config    <- ZIO.service[ValidationConfig]
        keySource <- ZIO.service[KeySource]
      yield LiveValidator(config, keySource, headerCodec, claimsCodec)
    }

  // -- Token parsing --

  private final case class TokenSegments(
      headerBytes: Array[Byte],
      payloadBytes: Array[Byte],
      signatureBytes: Array[Byte],
      signingInput: Array[Byte]
  )

  private def parseSegments(token: TokenString): Either[JwtError, TokenSegments] =
    Try {
      import scala.language.unsafeNulls
      val raw = token.unwrap
      val dot1 = raw.indexOf('.')
      val dot2 = raw.indexOf('.', dot1 + 1)
      val decoder = java.util.Base64.getUrlDecoder
      TokenSegments(
        headerBytes = decoder.decode(raw.substring(0, dot1)),
        payloadBytes = decoder.decode(raw.substring(dot1 + 1, dot2)),
        signatureBytes = decoder.decode(raw.substring(dot2 + 1)),
        signingInput = raw.substring(0, dot2).getBytes(StandardCharsets.US_ASCII)
      )
    }.toEither.left.map(JwtError.MalformedToken(_))

  // -- Temporal validation (ss10.1) --

  private def validateExp(exp: NumericDate, now: Instant, clockSkew: Duration): Either[JwtError, Unit] =
    // RFC 7519 ss4.1.4: reject when now >= exp + clockSkew
    Either.cond(now.isBefore(exp.unwrap.plus(clockSkew)), (), JwtError.Expired(exp, now))

  private def validateNbf(nbf: NumericDate, now: Instant, clockSkew: Duration): Either[JwtError, Unit] =
    // RFC 7519 ss4.1.5: reject when now < nbf - clockSkew
    Either.cond(!now.isBefore(nbf.unwrap.minus(clockSkew)), (), JwtError.NotYetValid(nbf, now))

  // -- Claim validation --

  private def validateIss(expected: String, actual: Option[String]): Either[JwtError, Unit] =
    Either.cond(actual.contains(expected), (), JwtError.InvalidIssuer(expected, actual))

  private def validateAud(expected: String, actual: Option[Audience]): Either[JwtError, Unit] =
    Either.cond(actual.exists(_.contains(expected)), (), JwtError.InvalidAudience(expected, actual))

  private def validateTyp(expected: String, actual: Option[String]): Either[JwtError, Unit] =
    Either.cond(
      actual.contains(expected),
      (),
      JwtError.MalformedToken(
        IllegalArgumentException(s"Expected typ '$expected', got ${actual.getOrElse("none")}")
      )
    )

  // -- Live implementation --

  private final class LiveValidator(
      config: ValidationConfig,
      keySource: KeySource,
      headerCodec: JwtCodec[JoseHeader],
      claimsCodec: JwtCodec[RegisteredClaims]
  ) extends JwtValidator:

    def validate[A: JwtCodec](token: TokenString): IO[JwtError, Jwt[A]] =
      for
        // Step 1: Parse token segments
        segments         <- ZIO.fromEither(parseSegments(token))
        // Step 2: Decode header and validate algorithm
        header           <- ZIO.fromEither(headerCodec.decode(segments.headerBytes).left.map(JwtError.MalformedToken(_)))
        _                <- ZIO.fromEither(checkAlgorithmAllowed(header.alg))
        // Step 3 + 4: Resolve key and verify signature
        _                <- verifySignature(header, segments)
        // Step 5: Decode claims
        customClaims     <- ZIO.fromEither(summon[JwtCodec[A]].decode(segments.payloadBytes).left.map(JwtError.MalformedToken(_)))
        registeredClaims <- ZIO.fromEither(claimsCodec.decode(segments.payloadBytes).left.map(JwtError.MalformedToken(_)))
        // Step 6: Validate claims
        now              <- zio.Clock.instant
        _                <- ZIO.fromEither(validateAllClaims(header, registeredClaims, now))
      yield Jwt(header, customClaims, registeredClaims)

    private def checkAlgorithmAllowed(alg: Algorithm): Either[JwtError, Unit] =
      Either.cond(config.allowedAlgorithms.contains(alg), (), JwtError.UnsupportedAlgorithm(alg.toString))

    private def verifySignature(header: JoseHeader, segments: TokenSegments): IO[JwtError, Unit] =
      header.alg.family match
        case AlgorithmFamily.HMAC =>
          keySource.resolveSecretKey(header).flatMap { key =>
            ZIO.fromEither(SignatureEngine.verify(segments.signingInput, segments.signatureBytes, key, header.alg))
          }
        case _ =>
          keySource.resolvePublicKey(header).flatMap { key =>
            ZIO.fromEither(SignatureEngine.verify(segments.signingInput, segments.signatureBytes, key, header.alg))
          }

    private def validateAllClaims(
        header: JoseHeader,
        claims: RegisteredClaims,
        now: Instant
    ): Either[JwtError, Unit] =
      for
        _ <- claims.exp.fold[Either[JwtError, Unit]](Right(()))(e => validateExp(e, now, config.clockSkew))
        _ <- claims.nbf.fold[Either[JwtError, Unit]](Right(()))(n => validateNbf(n, now, config.clockSkew))
        _ <- config.requiredIssuer.fold[Either[JwtError, Unit]](Right(()))(iss => validateIss(iss, claims.iss))
        _ <- config.requiredAudience.fold[Either[JwtError, Unit]](Right(()))(aud => validateAud(aud, claims.aud))
        _ <- config.requiredTyp.fold[Either[JwtError, Unit]](Right(()))(typ => validateTyp(typ, header.typ))
      yield ()
