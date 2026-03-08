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

/** Configuration for JWT token issuance. The issuer constructs the JOSE header from these settings.
  * The `x5t` and `x5tS256` fields carry base64url-encoded X.509 certificate thumbprints (SHA-1 and
  * SHA-256 respectively) for certificate-based key identification (RFC 7515 ss4.1.7, ss4.1.8).
  * Instances may be constructed via [[JwtIssuerConfig$ JwtIssuerConfig]].
  */
final case class JwtIssuerConfig(
  algorithm: Algorithm,
  kid: Option[Kid],
  typ: Option[String],
  cty: Option[String],
  x5t: Option[Base64UrlString],
  x5tS256: Option[Base64UrlString]
) derives CanEqual

/** Companion for [[JwtIssuerConfig]]. */
object JwtIssuerConfig
