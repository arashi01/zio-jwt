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
