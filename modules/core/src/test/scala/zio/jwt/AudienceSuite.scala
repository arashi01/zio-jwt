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

import zio.NonEmptyChunk

class AudienceSuite extends munit.FunSuite:

  test("apply(String) creates Single") {
    Audience("https://api.example.com") match
      case _: Audience.Single => ()
      case other              => fail(s"Expected Audience.Single, got $other")
  }

  test("apply(NonEmptyChunk) with one element creates Single") {
    Audience(NonEmptyChunk("only")) match
      case _: Audience.Single => ()
      case other              => fail(s"Expected Audience.Single, got $other")
  }

  test("apply(NonEmptyChunk) with multiple elements creates Many") {
    Audience(NonEmptyChunk("a", "b")) match
      case _: Audience.Many => ()
      case other            => fail(s"Expected Audience.Many, got $other")
  }

  test("values returns NonEmptyChunk for Single") {
    val aud = Audience("one")
    assertEquals(aud.values, NonEmptyChunk("one"))
  }

  test("values returns original chunk for Many") {
    val expected = NonEmptyChunk("x", "y", "z")
    val aud = Audience(expected)
    assertEquals(aud.values, expected)
  }

  test("contains finds matching audience in Single") {
    val aud = Audience("target")
    assert(aud.contains("target"))
    assert(!aud.contains("other"))
  }

  test("contains finds matching audience in Many") {
    val aud = Audience(NonEmptyChunk("a", "b", "c"))
    assert(aud.contains("b"))
    assert(!aud.contains("d"))
  }
end AudienceSuite
"apply(NonEmptyChunk) with one element creates Single") {
    Audience(NonEmptyChunk("only")) match
      case _: Audience.Single => ()
      case other              => fail(s"Expected Audience.Single, got $other")
  }

  test("apply(NonEmptyChunk) with multiple elements creates Many") {
    Audience(NonEmptyChunk("a", "b")) match
      case _: Audience.Many => ()
      case other            => fail(s"Expected Audience.Many, got $other")
  }

  test("values returns NonEmptyChunk for Single") {
    val aud = Audience("one")
    assertEquals(aud.values, NonEmptyChunk("one"))
  }

  test("values returns original chunk for Many") {
    val expected = NonEmptyChunk("x", "y", "z")
    val aud = Audience(expected)
    assertEquals(aud.values, expected)
  }

  test("contains finds matching audience in Single") {
    val aud = Audience("target")
    assert(aud.contains("target"))
    assert(!aud.contains("other"))
  }

  test("contains finds matching audience in Many") {
    val aud = Audience(NonEmptyChunk("a", "b", "c"))
    assert(aud.contains("b"))
    assert(!aud.contains("d"))
  }
end AudienceSuite
