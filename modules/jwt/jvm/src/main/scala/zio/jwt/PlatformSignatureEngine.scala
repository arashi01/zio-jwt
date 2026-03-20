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

import zio.IO
import zio.ZIO

import zio.jwt.crypto.SignatureEngine

/** JVM signature engine backed by JCA. Converts [[Jwk]] to JCA key objects and delegates to
  * [[SignatureEngine]].
  */
private[jwt] object PlatformSignatureEngine:

  /** Signs `data` using the given [[Jwk]] and [[Algorithm]]. */
  def sign(data: Array[Byte], jwk: Jwk, alg: Algorithm): IO[JwtError, Array[Byte]] =
    alg.family match
      case AlgorithmFamily.HMAC =>
        ZIO.fromEither(jwk.toSecretKey.flatMap(key => SignatureEngine.sign(data, key, alg)))
      case _ =>
        ZIO.fromEither(jwk.toPrivateKey.flatMap(key => SignatureEngine.sign(data, key, alg)))

  /** Verifies `signature` against `data` using the given [[Jwk]] and [[Algorithm]]. */
  def verify(data: Array[Byte], signature: Array[Byte], jwk: Jwk, alg: Algorithm): IO[JwtError, Unit] =
    alg.family match
      case AlgorithmFamily.HMAC =>
        ZIO.fromEither(jwk.toSecretKey.flatMap(key => SignatureEngine.verify(data, signature, key, alg)))
      case _ =>
        ZIO.fromEither(jwk.toPublicKey.flatMap(key => SignatureEngine.verify(data, signature, key, alg)))
end PlatformSignatureEngine
