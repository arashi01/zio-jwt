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
package zio.jwt.crypto

import java.security.cert.X509Certificate

import boilerplate.nullable.*

import zio.jwt.Base64UrlString
import zio.jwt.JwtError
import zio.jwt.PlatformBase64

// X.509 certificate thumbprint extensions (RFC 7515 §4.1.7-8).
// Discoverable via `import zio.jwt.crypto.*`.

extension (cert: X509Certificate)

  /** SHA-1 thumbprint for the JOSE `x5t` header parameter (RFC 7515 ss4.1.7). */
  def x5t: Either[JwtError, Base64UrlString] =
    PlatformDigest
      .digest("SHA-1", cert.getEncoded.unsafe)
      .map(hash => Base64UrlString.wrap(PlatformBase64.urlEncode(hash)))

  /** SHA-256 thumbprint for the JOSE `x5t#S256` header parameter (RFC 7515 ss4.1.8). */
  def x5tS256: Either[JwtError, Base64UrlString] =
    PlatformDigest
      .digest("SHA-256", cert.getEncoded.unsafe)
      .map(hash => Base64UrlString.wrap(PlatformBase64.urlEncode(hash)))
end extension
