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

import boilerplate.nullable.*
import boilerplate.unwrap

/** Decodes JWT tokens without signature verification or claim validation. Cross-platform (JVM, JS,
  * Native). Useful for debugging, log enrichment, routing by unverified claims (e.g. selecting key
  * source by `iss`), or client-side token inspection.
  *
  * '''Security warning''': the returned [[UnverifiedJwt]] has not been cryptographically verified.
  * Do not use its contents for authorisation decisions. Algorithm allowlist and `crit` header
  * checks are also skipped.
  */
object JwtDecoder:

  /** Decodes a token's header, custom claims, and registered claims without any verification. */
  def decode[A: JwtCodec](token: TokenString)(using
    headerCodec: JwtCodec[JoseHeader],
    claimsCodec: JwtCodec[RegisteredClaims]
  ): Either[JwtError, UnverifiedJwt[A]] =
    val raw = token.unwrap
    val dot1 = raw.indexOf('.')
    val dot2 = if dot1 >= 0 then raw.indexOf('.', dot1 + 1) else -1
    if dot1 < 0 || dot2 < 0 then Left(JwtError.MalformedToken("Token must contain exactly three segments"))
    else
      for
        headerBytes <- Base64Url.decode(raw.substring(0, dot1))
        payloadBytes <- Base64Url.decode(raw.substring(dot1 + 1, dot2))
        header <- headerCodec.decode(headerBytes).left.map(e => JwtError.DecodeError(e.getMessage.getOrElse("header decode failed")))
        customClaims <-
          summon[JwtCodec[A]].decode(payloadBytes).left.map(e => JwtError.DecodeError(e.getMessage.getOrElse("claims decode failed")))
        registeredClaims <-
          claimsCodec.decode(payloadBytes).left.map(e => JwtError.DecodeError(e.getMessage.getOrElse("claims decode failed")))
      yield UnverifiedJwt(header, customClaims, registeredClaims)
  end decode

end JwtDecoder
