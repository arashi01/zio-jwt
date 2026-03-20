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

import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.SecretKey

import scala.annotation.targetName

import zio.IO
import zio.ZIO

/** JVM-only convenience extensions on [[KeySource]] that resolve [[Jwk]] keys to JCA key objects.
  * These delegate to the cross-platform [[KeySource.resolveVerificationKey]] and
  * [[KeySource.resolveSigningKey]], then convert via JVM-specific `toPublicKey` / `toPrivateKey` /
  * `toSecretKey` extensions on [[Jwk]].
  */
extension (source: KeySource)

  /** Resolves a JCA [[PublicKey]] suitable for signature verification. */
  @targetName("keySourceResolvePublicKey")
  def resolvePublicKey(header: JoseHeader): IO[JwtError, PublicKey] =
    source.resolveVerificationKey(header).flatMap(jwk => ZIO.fromEither(jwk.toPublicKey))

  /** Resolves a JCA [[SecretKey]] suitable for HMAC verification. */
  @targetName("keySourceResolveSecretKey")
  def resolveSecretKey(header: JoseHeader): IO[JwtError, SecretKey] =
    source.resolveVerificationKey(header).flatMap(jwk => ZIO.fromEither(jwk.toSecretKey))

  /** Resolves a JCA [[PrivateKey]] suitable for signing. */
  @targetName("keySourceResolveSigningPrivateKey")
  def resolveSigningPrivateKey(header: JoseHeader): IO[JwtError, PrivateKey] =
    source.resolveSigningKey(header).flatMap(jwk => ZIO.fromEither(jwk.toPrivateKey))

  /** Resolves a JCA [[SecretKey]] suitable for HMAC signing. */
  @targetName("keySourceResolveSigningSecretKey")
  def resolveSigningSecretKey(header: JoseHeader): IO[JwtError, SecretKey] =
    source.resolveSigningKey(header).flatMap(jwk => ZIO.fromEither(jwk.toSecretKey))
end extension
