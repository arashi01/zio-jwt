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
package zio.jwt

import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.Instant

import scala.util.Try

import zio.IO
import zio.ZIO
import zio.ZLayer

import zio.jwt.crypto.SignatureEngine

/** Service for validating JWT tokens. Instances live in the ZIO environment; construct via
  * [[JwtValidator$ JwtValidator]].live.
  */
trait JwtValidator:
  def validate[A: JwtCodec](token: TokenString): IO[JwtError, Jwt[A]]

/** Companion for [[JwtValidator]]. Provides the live layer and validation utilities. */
object JwtValidator:

  /** Constructs a [[JwtValidator]] layer from [[ValidationConfig]] and [[KeySource]]. Codec
    * instances are injected via `using` parameters.
    */
  def live(using
    headerCodec: JwtCodec[JoseHeader],
    claimsCodec: JwtCodec[RegisteredClaims]
  ): ZLayer[ValidationConfig & KeySource, Nothing, JwtValidator] =
    ZLayer.fromZIO {
      for
        config <- ZIO.service[ValidationConfig]
        keySource <- ZIO.service[KeySource]
      yield LiveValidator(config, keySource, headerCodec, claimsCodec)
    }

  // -- Token parsing --

  final private case class TokenSegments(
    headerBytes: Array[Byte],
    payloadBytes: Array[Byte],
    signatureBytes: Array[Byte],
    signingInput: Array[Byte]
  )

  // scalafix:off DisableSyntax.asInstanceOf; bypasses opaque type allowing deferred inline methods on JwtCodec
  private inline def parseSegments(token: TokenString): Either[JwtError, TokenSegments] =
    Try {
      import scala.language.unsafeNulls
      val raw = token.asInstanceOf[String]
      val dot1 = raw.indexOf('.')
      val dot2 = raw.indexOf('.', dot1 + 1)
      val decoder = java.util.Base64.getUrlDecoder
      TokenSegments(
        headerBytes = decoder.decode(raw.substring(0, dot1)),
        payloadBytes = decoder.decode(raw.substring(dot1 + 1, dot2)),
        signatureBytes = decoder.decode(raw.substring(dot2 + 1)),
        signingInput = raw.substring(0, dot2).getBytes(StandardCharsets.US_ASCII)
      )
    }.toEither.left.map(JwtError.MalformedToken.apply)

  // -- Temporal validation (ss10.1) --

  private inline def validateExp(exp: NumericDate, now: Instant, clockSkew: Duration): Either[JwtError, Unit] =
    // RFC 7519 ss4.1.4: reject when now >= exp + clockSkew
    Either.cond(now.isBefore(exp.asInstanceOf[Instant].plus(clockSkew)), (), JwtError.Expired(exp, now))

  private inline def validateNbf(nbf: NumericDate, now: Instant, clockSkew: Duration): Either[JwtError, Unit] =
    // RFC 7519 ss4.1.5: reject when now < nbf - clockSkew
    Either.cond(!now.isBefore(nbf.asInstanceOf[Instant].minus(clockSkew)), (), JwtError.NotYetValid(nbf, now))
  // scalafix:on

  // -- Claim validation --

  private inline def validateIss(expected: String, actual: Option[String]): Either[JwtError, Unit] =
    Either.cond(actual.contains(expected), (), JwtError.InvalidIssuer(expected, actual))

  private inline def validateAud(expected: String, actual: Option[Audience]): Either[JwtError, Unit] =
    Either.cond(actual.exists(_.contains(expected)), (), JwtError.InvalidAudience(expected, actual))

  private inline def validateTyp(expected: String, actual: Option[String]): Either[JwtError, Unit] =
    Either.cond(
      actual.contains(expected),
      (),
      JwtError.MalformedToken(
        IllegalArgumentException(s"Expected typ '$expected', got ${actual.getOrElse("none")}")
      )
    )

  // -- Live implementation --

  final private class LiveValidator(
    config: ValidationConfig,
    keySource: KeySource,
    headerCodec: JwtCodec[JoseHeader],
    claimsCodec: JwtCodec[RegisteredClaims]
  ) extends JwtValidator:

    inline def validate[A: JwtCodec](token: TokenString): IO[JwtError, Jwt[A]] =
      for
        // Step 1: Parse token segments
        segments <- ZIO.fromEither(parseSegments(token))
        // Step 2: Decode header and validate algorithm
        header <- ZIO.fromEither(headerCodec.decode(segments.headerBytes).left.map(JwtError.MalformedToken(_)))
        _ <- ZIO.fromEither(checkAlgorithmAllowed(header.alg))
        // Step 3 + 4: Resolve key and verify signature
        _ <- verifySignature(header, segments)
        // Step 5: Decode claims
        customClaims <- ZIO.fromEither(summon[JwtCodec[A]].decode(segments.payloadBytes).left.map(JwtError.MalformedToken(_)))
        registeredClaims <- ZIO.fromEither(claimsCodec.decode(segments.payloadBytes).left.map(JwtError.MalformedToken(_)))
        // Step 6: Validate claims
        now <- zio.Clock.instant
        _ <- ZIO.fromEither(validateAllClaims(header, registeredClaims, now))
      yield Jwt(header, customClaims, registeredClaims)

    private inline def checkAlgorithmAllowed(alg: Algorithm): Either[JwtError, Unit] =
      Either.cond(config.allowedAlgorithms.contains(alg), (), JwtError.UnsupportedAlgorithm(alg.toString))

    private inline def verifySignature(header: JoseHeader, segments: TokenSegments): IO[JwtError, Unit] =
      header.alg.family match
        case AlgorithmFamily.HMAC =>
          keySource.resolveSecretKey(header).flatMap { key =>
            ZIO.fromEither(SignatureEngine.verify(segments.signingInput, segments.signatureBytes, key, header.alg))
          }
        case _ =>
          keySource.resolvePublicKey(header).flatMap { key =>
            ZIO.fromEither(SignatureEngine.verify(segments.signingInput, segments.signatureBytes, key, header.alg))
          }

    private inline def validateAllClaims(
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
  end LiveValidator
end JwtValidator
