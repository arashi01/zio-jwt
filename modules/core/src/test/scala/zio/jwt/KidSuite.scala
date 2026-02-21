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

class KidSuite extends munit.FunSuite:

  test("accepts non-empty string") {
    val result = Kid.from("my-key-id")
    assert(result.isRight)
    assertEquals(result.map(_.unwrap), Right("my-key-id"))
  }

  test("rejects empty string") {
    val result = Kid.from("")
    assert(result.isLeft)
    assert(result.left.exists(_.getMessage.contains("must not be empty")))
  }

  test("fromUnsafe succeeds for valid input") {
    assertEquals(Kid.fromUnsafe("key-1").unwrap, "key-1")
  }

  test("fromUnsafe throws for empty input") {
    intercept[IllegalArgumentException] {
      Kid.fromUnsafe("")
    }
  }

  test("preserves arbitrary non-empty content") {
    val raw = "rsa-key-2024-01-15T12:00:00Z"
    assertEquals(Kid.fromUnsafe(raw).unwrap, raw)
  }
end KidSuite
