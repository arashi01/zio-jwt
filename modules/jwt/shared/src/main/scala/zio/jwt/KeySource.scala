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

import scala.annotation.targetName

import zio.Chunk
import zio.IO
import zio.UIO
import zio.ZIO

/** Source of [[Jwk]] keys for signature verification and signing. Implementations provide keys as
  * an infallible effect; structural validity is checked lazily during key resolution.
  *
  * @see [[KeySource$ KeySource]] for static factory methods and key resolution.
  */
trait KeySource:
  def keys: UIO[Chunk[Jwk]]

/** Companion for [[KeySource]]. Provides static factories and Jwk-centric key resolution. */
object KeySource:

  /** Creates a [[KeySource]] backed by a fixed set of keys. */
  def static(jwks: Chunk[Jwk]): KeySource =
    new KeySource:
      def keys: UIO[Chunk[Jwk]] = ZIO.succeed(jwks)

  /** Creates a [[KeySource]] backed by a single key. */
  def static(jwk: Jwk): KeySource = static(Chunk(jwk))

  /** Resolves a [[Jwk]] suitable for signature verification matching the given header. */
  def resolveVerificationKey(source: KeySource, header: JoseHeader): IO[JwtError, Jwk] =
    resolveJwk(source, header, _.suitableForVerification(header.alg))

  /** Resolves a [[Jwk]] suitable for signing matching the given header. */
  def resolveSigningKey(source: KeySource, header: JoseHeader): IO[JwtError, Jwk] =
    resolveJwk(source, header, _.suitableForSigning(header.alg))

  extension (source: KeySource)

    /** Resolves a [[Jwk]] suitable for signature verification. */
    @targetName("keySourceResolveVerificationKey")
    def resolveVerificationKey(header: JoseHeader): IO[JwtError, Jwk] =
      KeySource.resolveVerificationKey(source, header)

    /** Resolves a [[Jwk]] suitable for signing. */
    @targetName("keySourceResolveSigningKey")
    def resolveSigningKey(header: JoseHeader): IO[JwtError, Jwk] =
      KeySource.resolveSigningKey(source, header)

  end extension

  // -- Internal resolution logic --

  private def resolveJwk(source: KeySource, header: JoseHeader, suitability: Jwk => Boolean): IO[JwtError, Jwk] =
    source.keys.flatMap { allKeys =>
      val filtered = allKeys.filter(suitability)

      val selected = header.kid match
        case Some(headerKid) =>
          filtered.filter(_.kid.contains(headerKid)) match
            case chunk if chunk.size == 1 => Right(chunk(0))
            case chunk if chunk.isEmpty   => Left(JwtError.KeyNotFound(Some(headerKid)))
            case chunk                    => Left(JwtError.AmbiguousKey(Some(headerKid), chunk.size))
        case None =>
          filtered match
            case chunk if chunk.size == 1 => Right(chunk(0))
            case chunk if chunk.isEmpty   => Left(JwtError.KeyNotFound(None))
            case chunk                    => Left(JwtError.AmbiguousKey(None, chunk.size))

      ZIO.fromEither(selected)
    }
end KeySource
