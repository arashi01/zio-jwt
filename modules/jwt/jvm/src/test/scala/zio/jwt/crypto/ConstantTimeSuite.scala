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
