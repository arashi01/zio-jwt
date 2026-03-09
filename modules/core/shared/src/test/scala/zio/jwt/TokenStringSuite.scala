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

import boilerplate.unwrap

class TokenStringSuite extends munit.FunSuite:

  private val validToken =
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

  test("accepts well-formed three-segment token") {
    val result = TokenString.from(validToken)
    assert(result.isRight)
    assertEquals(result.map(_.unwrap), Right(validToken))
  }

  test("accepts minimal three-segment token") {
    assert(TokenString.from("a.b.c").isRight)
  }

  test("rejects empty string") {
    assert(TokenString.from("").isLeft)
  }

  test("rejects single segment") {
    assert(TokenString.from("onlyone").isLeft)
  }

  test("rejects two segments") {
    assert(TokenString.from("header.payload").isLeft)
  }

  test("rejects four segments") {
    assert(TokenString.from("a.b.c.d").isLeft)
  }

  test("rejects empty first segment (leading dot)") {
    assert(TokenString.from(".payload.signature").isLeft)
  }

  test("rejects empty middle segment (consecutive dots)") {
    assert(TokenString.from("header..signature").isLeft)
  }

  test("rejects empty last segment (trailing dot)") {
    assert(TokenString.from("header.payload.").isLeft)
  }

  test("rejects invalid characters in segment") {
    assert(TokenString.from("hea der.payload.sig").isLeft)
  }

  test("rejects base64 padding characters") {
    assert(TokenString.from("header=.payload.sig").isLeft)
  }

  test("rejects standard base64 characters (+ and /)") {
    assert(TokenString.from("hea+der.pay/load.sig").isLeft)
  }

  test("accepts base64url special characters (- and _)") {
    assert(TokenString.from("he-ad.pay_load.si-g").isRight)
  }

  test("round-trips through unwrap") {
    val ts = TokenString.fromUnsafe(validToken)
    assertEquals(ts.unwrap, validToken)
  }
end TokenStringSuite
