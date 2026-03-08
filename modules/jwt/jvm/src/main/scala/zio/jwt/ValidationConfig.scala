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

import java.time.Duration

import zio.NonEmptyChunk

/** Configuration for JWT token validation (RFC 7519 ss4.1). `clockSkew` is the tolerance applied to
  * `exp` and `nbf` checks. `requiredIssuer` and `requiredAudience` reject tokens that do not match
  * the expected values. `requiredTyp` enforces the JOSE `typ` header. `allowedAlgorithms` restricts
  * which signing algorithms are accepted; at least one algorithm is required.
  */
final case class ValidationConfig(
  clockSkew: Duration,
  requiredIssuer: Option[String],
  requiredAudience: Option[String],
  requiredTyp: Option[String],
  allowedAlgorithms: NonEmptyChunk[Algorithm]
) derives CanEqual
