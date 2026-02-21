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

import java.time.Instant

import scala.util.control.NoStackTrace

import boilerplate.unwrap

/** Validation and structural errors produced during JWT processing. Extends [[NoStackTrace]] --
  * these are expected domain errors, not exceptional conditions.
  */
enum JwtError extends Throwable with NoStackTrace derives CanEqual:

  case Expired(exp: NumericDate, now: Instant)

  case NotYetValid(nbf: NumericDate, now: Instant)

  case InvalidAudience(expected: String, actual: Option[Audience])

  case InvalidIssuer(expected: String, actual: Option[String])

  case InvalidSignature

  case MalformedToken(cause: Throwable)

  case UnsupportedAlgorithm(alg: String)

  case KeyNotFound(kid: Option[Kid])

  override def getMessage: String = this match
    case Expired(exp, now) =>
      s"Token expired at ${exp.unwrap}, current time $now"
    case NotYetValid(nbf, now) =>
      s"Token not yet valid until ${nbf.unwrap}, current time $now"
    case InvalidAudience(expected, actual) =>
      s"Expected audience '$expected', got ${actual.fold("none")(_.toString)}"
    case InvalidIssuer(expected, actual) =>
      s"Expected issuer '$expected', got ${actual.getOrElse("none")}"
    case InvalidSignature =>
      "Invalid signature"
    case MalformedToken(cause) =>
      s"Malformed token: ${cause.getMessage}"
    case UnsupportedAlgorithm(alg) =>
      s"Unsupported algorithm: $alg"
    case KeyNotFound(kid) =>
      s"Key not found${kid.fold("")(k => s" for kid '${k.unwrap}'")}"

  override def getCause: Throwable | Null = this match
    case MalformedToken(cause) => cause
    case _                     => null // scalafix:ok DisableSyntax.null; JDK Throwable.getCause contract
end JwtError
