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
