package zio.jwt

import zio.NonEmptyChunk

class AudienceSuite extends munit.FunSuite:

  test("apply(String) creates Single") {
    val aud = Audience("https://api.example.com")
    assert(aud.isInstanceOf[Audience.Single])
  }

  test("apply(NonEmptyChunk) with one element creates Single") {
    val aud = Audience(NonEmptyChunk("only"))
    assert(aud.isInstanceOf[Audience.Single])
  }

  test("apply(NonEmptyChunk) with multiple elements creates Many") {
    val aud = Audience(NonEmptyChunk("a", "b"))
    assert(aud.isInstanceOf[Audience.Many])
  }

  test("values returns NonEmptyChunk for Single") {
    val aud = Audience("one")
    assertEquals(aud.values, NonEmptyChunk("one"))
  }

  test("values returns original chunk for Many") {
    val expected = NonEmptyChunk("x", "y", "z")
    val aud      = Audience(expected)
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
