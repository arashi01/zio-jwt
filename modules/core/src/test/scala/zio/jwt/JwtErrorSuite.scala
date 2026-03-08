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

import boilerplate.unwrap

class JwtErrorSuite extends munit.FunSuite:

  test("Expired getMessage includes expiry and current time") {
    val exp = NumericDate.fromEpochSecond(1700000000L)
    val now = Instant.ofEpochSecond(1700000060L)
    val err = JwtError.Expired(exp, now)
    assert(err.getMessage.contains("expired"))
    assert(err.getMessage.contains(exp.unwrap.toString))
    assert(err.getMessage.contains(now.toString))
  }

  test("NotYetValid getMessage includes nbf and current time") {
    val nbf = NumericDate.fromEpochSecond(1700000000L)
    val now = Instant.ofEpochSecond(1699999990L)
    val err = JwtError.NotYetValid(nbf, now)
    assert(err.getMessage.contains("not yet valid"))
  }

  test("InvalidAudience getMessage includes expected and actual") {
    val err = JwtError.InvalidAudience("api", Some(Audience("other")))
    assert(err.getMessage.contains("api"))
  }

  test("InvalidAudience getMessage handles missing audience") {
    val err = JwtError.InvalidAudience("api", None)
    assert(err.getMessage.contains("none"))
  }

  test("InvalidIssuer getMessage includes expected and actual") {
    val err = JwtError.InvalidIssuer("auth.example.com", Some("wrong.com"))
    assert(err.getMessage.contains("auth.example.com"))
    assert(err.getMessage.contains("wrong.com"))
  }

  test("InvalidSignature getMessage is descriptive") {
    assertEquals(JwtError.InvalidSignature.getMessage, "Invalid signature")
  }

  test("MalformedToken getMessage wraps message") {
    val err = JwtError.MalformedToken("unexpected EOF")
    assert(err.getMessage.contains("unexpected EOF"))
  }

  test("DecodeError getMessage wraps message") {
    val err = JwtError.DecodeError("invalid JSON")
    assert(err.getMessage.contains("invalid JSON"))
  }

  test("InvalidKey getMessage wraps message") {
    val err = JwtError.InvalidKey("RSA key too small")
    assert(err.getMessage.contains("RSA key too small"))
  }

  test("InvalidTyp getMessage includes expected and actual") {
    val err = JwtError.InvalidTyp("JWT", Some("at+jwt"))
    assert(err.getMessage.contains("JWT"))
    assert(err.getMessage.contains("at+jwt"))
  }

  test("InvalidTyp getMessage handles missing typ") {
    val err = JwtError.InvalidTyp("JWT", None)
    assert(err.getMessage.contains("none"))
  }

  test("getCause returns null for all variants") {
    assertEquals(JwtError.InvalidSignature.getCause, null) // scalafix:ok DisableSyntax.null; testing JDK getCause contract
    assertEquals(JwtError.MalformedToken("test").getCause, null) // scalafix:ok DisableSyntax.null; testing JDK getCause contract
  }

  test("UnsupportedAlgorithm getMessage includes algorithm name") {
    val err = JwtError.UnsupportedAlgorithm("none")
    assert(err.getMessage.contains("none"))
  }

  test("KeyNotFound getMessage includes kid when present") {
    val err = JwtError.KeyNotFound(Some(Kid.fromUnsafe("rsa-1")))
    assert(err.getMessage.contains("rsa-1"))
  }

  test("KeyNotFound getMessage handles absent kid") {
    val err = JwtError.KeyNotFound(None)
    assert(err.getMessage.contains("Key not found"))
  }

  test("AmbiguousKey getMessage includes kid when present") {
    val err = JwtError.AmbiguousKey(Some(Kid.fromUnsafe("rsa-1")), 3)
    assert(err.getMessage.contains("rsa-1"))
    assert(err.getMessage.contains("3"))
  }

  test("AmbiguousKey getMessage handles absent kid") {
    val err = JwtError.AmbiguousKey(None, 5)
    assert(err.getMessage.contains("Ambiguous key"))
    assert(err.getMessage.contains("5"))
  }

  test("FetchError getMessage wraps message") {
    val err = JwtError.FetchError("connection refused")
    assert(err.getMessage.contains("connection refused"))
  }

  test("extends NoStackTrace (no stack trace captured)") {
    val err = JwtError.InvalidSignature
    assertEquals(err.getStackTrace.length, 0)
  }
end JwtErrorSuite
