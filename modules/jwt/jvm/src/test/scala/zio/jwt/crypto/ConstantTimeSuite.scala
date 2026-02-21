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
package zio.jwt.crypto

class ConstantTimeSuite extends munit.FunSuite:

  test("equal arrays return true") {
    val a = Array[Byte](1, 2, 3, 4)
    val b = Array[Byte](1, 2, 3, 4)
    assert(ConstantTime.areEqual(a, b))
  }

  test("differing arrays return false") {
    val a = Array[Byte](1, 2, 3, 4)
    val b = Array[Byte](1, 2, 3, 5)
    assert(!ConstantTime.areEqual(a, b))
  }

  test("different lengths return false") {
    val a = Array[Byte](1, 2, 3)
    val b = Array[Byte](1, 2, 3, 4)
    assert(!ConstantTime.areEqual(a, b))
  }

  test("empty arrays return true") {
    assert(ConstantTime.areEqual(Array.emptyByteArray, Array.emptyByteArray))
  }

  test("one empty one non-empty returns false") {
    assert(!ConstantTime.areEqual(Array.emptyByteArray, Array[Byte](1)))
  }

  test("all-zero arrays return true") {
    val a = new Array[Byte](32)
    val b = new Array[Byte](32)
    assert(ConstantTime.areEqual(a, b))
  }

  test("single byte difference detected") {
    val a = new Array[Byte](256)
    val b = new Array[Byte](256)
    b(200) = 1
    assert(!ConstantTime.areEqual(a, b))
  }
end ConstantTimeSuite
