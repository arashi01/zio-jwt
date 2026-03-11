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

/** JS signature engine stub. Web Crypto API integration is planned for a future release.
  *
  * Not `private[jwt]` due to Scala.js backend limitation with package-qualified access across
  * sub-packages (assertion failure: "Cannot use package as value").
  */
object PlatformSignatureEngine:

  /** Signs `data` using the given [[Jwk]] and [[Algorithm]]. Not yet implemented on JS. */
  def sign(data: Array[Byte], jwk: Jwk, alg: Algorithm): IO[JwtError, Array[Byte]] =
    val _ = (data, jwk) // stub — parameters unused until Web Crypto integration
    ZIO.fail(JwtError.UnsupportedAlgorithm(s"Signing not yet supported on JS: ${alg.name}"))

  /** Verifies `signature` against `data`. Not yet implemented on JS. */
  def verify(data: Array[Byte], signature: Array[Byte], jwk: Jwk, alg: Algorithm): IO[JwtError, Unit] =
    val _ = (data, signature, jwk) // stub — parameters unused until Web Crypto integration
    ZIO.fail(JwtError.UnsupportedAlgorithm(s"Verification not yet supported on JS: ${alg.name}"))
end PlatformSignatureEngine
