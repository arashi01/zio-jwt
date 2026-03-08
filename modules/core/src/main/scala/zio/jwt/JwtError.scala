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

  /** Token has expired per RFC 7519 ss4.1.4. */
  case Expired(exp: NumericDate, now: Instant)

  /** Token is not yet valid per RFC 7519 ss4.1.5. */
  case NotYetValid(nbf: NumericDate, now: Instant)

  /** The `aud` claim does not contain the required audience. */
  case InvalidAudience(expected: String, actual: Option[Audience])

  /** The `iss` claim does not match the required issuer. */
  case InvalidIssuer(expected: String, actual: Option[String])

  /** Cryptographic signature verification failed. */
  case InvalidSignature

  /** Token structure is malformed (bad base64url, wrong segment count, etc.). */
  case MalformedToken(message: String)

  /** Header or claims JSON could not be decoded. */
  case DecodeError(message: String)

  /** A key is structurally invalid (wrong type, too small, off-curve point, etc.). */
  case InvalidKey(message: String)

  /** The `typ` header parameter does not match the required value. */
  case InvalidTyp(expected: String, actual: Option[String])

  /** The algorithm in the JOSE header is not in the allowed set. */
  case UnsupportedAlgorithm(alg: String)

  /** No key with the requested `kid` was found. */
  case KeyNotFound(kid: Option[Kid])

  /** Multiple keys matched the requested `kid`; resolution is ambiguous. */
  case AmbiguousKey(kid: Option[Kid], count: Int)

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
    case MalformedToken(message) =>
      s"Malformed token: $message"
    case DecodeError(message) =>
      s"Decode error: $message"
    case InvalidKey(message) =>
      s"Invalid key: $message"
    case InvalidTyp(expected, actual) =>
      s"Expected typ '$expected', got ${actual.getOrElse("none")}"
    case UnsupportedAlgorithm(alg) =>
      s"Unsupported algorithm: $alg"
    case KeyNotFound(kid) =>
      s"Key not found${kid.fold("")(k => s" for kid '${k.unwrap}'")}"
    case AmbiguousKey(kid, count) =>
      s"Ambiguous key${kid.fold("")(k => s" for kid '${k.unwrap}'")}: $count keys match"
end JwtError
