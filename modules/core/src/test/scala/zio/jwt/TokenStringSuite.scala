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
