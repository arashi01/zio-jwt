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
import scala.util.boundary
import scala.util.boundary.break

import zio.Chunk
import zio.IO
import zio.NonEmptyChunk
import zio.ZIO
import zio.ZLayer

import zio.jwt.crypto.SignatureEngine

/** Service for validating JWT tokens. Instances live in the ZIO environment; construct via
  * [[JwtValidator$ JwtValidator]].live.
  */
trait JwtValidator:
  /** Validates the token fully: parses, verifies the signature, and checks all claims. */
  def validate[A: JwtCodec](token: TokenString): IO[JwtError, Jwt[A]]

  /** Decodes a token without signature verification or claim validation. Useful for debugging, log
    * enrichment, or routing based on unverified claims (e.g. selecting key source by `iss`).
    *
    * Algorithm allowlist checking is also skipped - the header may contain any algorithm string,
    * including ones not in [[ValidationConfig.allowedAlgorithms]].
    *
    * '''Security warning''': the returned [[UnverifiedJwt]] has not been verified - do not trust
    * its contents for authorisation decisions.
    */
  def decode[A: JwtCodec](token: TokenString): IO[JwtError, UnverifiedJwt[A]]

  /** Validates the token and accumulates all claim validation errors rather than failing on the
    * first one. Signature verification still fails fast. Returns a
    * [[zio.NonEmptyChunk NonEmptyChunk]] of errors if any claim validation fails.
    */
  def validateAll[A: JwtCodec](token: TokenString): IO[NonEmptyChunk[JwtError], Jwt[A]]
end JwtValidator

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
    }.toEither.left.map(e => JwtError.MalformedToken(e.getMessage.nn))

  // -- Temporal validation --

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
      JwtError.InvalidTyp(expected, actual)
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
        header <- ZIO.fromEither(headerCodec.decode(segments.headerBytes).left.map(e => JwtError.DecodeError(e.getMessage.nn)))
        _ <- ZIO.fromEither(checkAlgorithmAllowed(header.alg))
        // Step 3 + 4: Resolve key and verify signature
        _ <- verifySignature(header, segments)
        // Step 5: Decode claims
        customClaims <- ZIO.fromEither(summon[JwtCodec[A]].decode(segments.payloadBytes).left.map(e => JwtError.DecodeError(e.getMessage.nn)))
        registeredClaims <- ZIO.fromEither(claimsCodec.decode(segments.payloadBytes).left.map(e => JwtError.DecodeError(e.getMessage.nn)))
        // Step 6: Validate claims
        now <- zio.Clock.instant
        _ <- ZIO.fromEither(validateAllClaims(header, registeredClaims, now))
      yield Jwt(header, customClaims, registeredClaims)

    inline def decode[A: JwtCodec](token: TokenString): IO[JwtError, UnverifiedJwt[A]] =
      for
        segments <- ZIO.fromEither(parseSegments(token))
        header <- ZIO.fromEither(headerCodec.decode(segments.headerBytes).left.map(e => JwtError.DecodeError(e.getMessage.nn)))
        customClaims <- ZIO.fromEither(summon[JwtCodec[A]].decode(segments.payloadBytes).left.map(e => JwtError.DecodeError(e.getMessage.nn)))
        registeredClaims <- ZIO.fromEither(claimsCodec.decode(segments.payloadBytes).left.map(e => JwtError.DecodeError(e.getMessage.nn)))
      yield UnverifiedJwt(header, customClaims, registeredClaims)

    inline def validateAll[A: JwtCodec](token: TokenString): IO[NonEmptyChunk[JwtError], Jwt[A]] =
      val structural: IO[JwtError, (JoseHeader, A, RegisteredClaims)] =
        for
          segments <- ZIO.fromEither(parseSegments(token))
          header <- ZIO.fromEither(headerCodec.decode(segments.headerBytes).left.map(e => JwtError.DecodeError(e.getMessage.nn)))
          _ <- ZIO.fromEither(checkAlgorithmAllowed(header.alg))
          _ <- verifySignature(header, segments)
          customClaims <-
            ZIO.fromEither(summon[JwtCodec[A]].decode(segments.payloadBytes).left.map(e => JwtError.DecodeError(e.getMessage.nn)))
          registeredClaims <- ZIO.fromEither(claimsCodec.decode(segments.payloadBytes).left.map(e => JwtError.DecodeError(e.getMessage.nn)))
        yield (header, customClaims, registeredClaims)
      structural
        .mapError(e => NonEmptyChunk(e))
        .flatMap { case (header, customClaims, registeredClaims) =>
          zio.Clock.instant.flatMap { now =>
            ZIO
              .fromEither(accumulateClaimErrors(header, registeredClaims, now))
              .as(Jwt(header, customClaims, registeredClaims))
          }
        }
    end validateAll

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
      boundary:
        claims.exp.foreach(e =>
          validateExp(e, now, config.clockSkew) match
            case Left(err) => break(Left(err))
            case _         => ()
        )
        claims.nbf.foreach(n =>
          validateNbf(n, now, config.clockSkew) match
            case Left(err) => break(Left(err))
            case _         => ()
        )
        config.requiredIssuer.foreach(iss =>
          validateIss(iss, claims.iss) match
            case Left(err) => break(Left(err))
            case _         => ()
        )
        config.requiredAudience.foreach(aud =>
          validateAud(aud, claims.aud) match
            case Left(err) => break(Left(err))
            case _         => ()
        )
        config.requiredTyp.foreach(typ =>
          validateTyp(typ, header.typ) match
            case Left(err) => break(Left(err))
            case _         => ()
        )
        Right(())

    /** Collects all claim validation errors. Returns [[Left]] with the accumulated errors when at
      * least one claim check fails, or [[Right]] if all pass.
      */
    private inline def accumulateClaimErrors(
      header: JoseHeader,
      claims: RegisteredClaims,
      now: Instant
    ): Either[NonEmptyChunk[JwtError], Unit] =
      val builder = Chunk.newBuilder[JwtError]
      claims.exp.foreach(e => validateExp(e, now, config.clockSkew).left.foreach(builder += _))
      claims.nbf.foreach(n => validateNbf(n, now, config.clockSkew).left.foreach(builder += _))
      config.requiredIssuer.foreach(iss => validateIss(iss, claims.iss).left.foreach(builder += _))
      config.requiredAudience.foreach(aud => validateAud(aud, claims.aud).left.foreach(builder += _))
      config.requiredTyp.foreach(typ => validateTyp(typ, header.typ).left.foreach(builder += _))
      NonEmptyChunk.fromChunk(builder.result()) match
        case Some(nec) => Left(nec)
        case None      => Right(())
    end accumulateClaimErrors
  end LiveValidator
end JwtValidator
