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

class Base64UrlStringSuite extends munit.FunSuite:

  test("accepts valid base64url string") {
    val result = Base64UrlString.from("SGVsbG8")
    assert(result.isRight)
    assertEquals(result.map(_.unwrap), Right("SGVsbG8"))
  }

  test("accepts base64url with hyphen and underscore") {
    assert(Base64UrlString.from("abc-def_ghi").isRight)
  }

  test("rejects empty string") {
    val result = Base64UrlString.from("")
    assert(result.isLeft)
    assert(result.left.exists(_.getMessage.contains("must not be empty")))
  }

  test("rejects string with padding character") {
    assert(Base64UrlString.from("SGVsbG8=").isLeft)
  }

  test("rejects string with plus (standard base64, not base64url)") {
    assert(Base64UrlString.from("abc+def").isLeft)
  }

  test("rejects string with slash (standard base64, not base64url)") {
    assert(Base64UrlString.from("abc/def").isLeft)
  }

  test("rejects string with space") {
    assert(Base64UrlString.from("abc def").isLeft)
  }

  test("fromUnsafe succeeds for valid input") {
    val value = Base64UrlString.fromUnsafe("dGVzdA")
    assertEquals(value.unwrap, "dGVzdA")
  }

  test("fromUnsafe throws for invalid input") {
    intercept[IllegalArgumentException] {
      Base64UrlString.fromUnsafe("")
    }
  }

  test("round-trips through unwrap") {
    val raw = "eyJhbGciOiJIUzI1NiJ9"
    val b64 = Base64UrlString.fromUnsafe(raw)
    assertEquals(b64.unwrap, raw)
  }
end Base64UrlStringSuite
