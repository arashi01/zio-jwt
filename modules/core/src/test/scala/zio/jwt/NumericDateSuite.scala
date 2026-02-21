package zio.jwt

import java.time.Instant

import boilerplate.unwrap

class NumericDateSuite extends munit.FunSuite:

  test("wraps Instant without validation") {
    val instant = Instant.ofEpochSecond(1700000000L)
    val result  = NumericDate.from(instant)
    assert(result.isRight)
    assertEquals(result.map(_.unwrap), Right(instant))
  }

  test("fromEpochSecond creates from epoch seconds") {
    val nd = NumericDate.fromEpochSecond(1700000000L)
    assertEquals(nd.unwrap, Instant.ofEpochSecond(1700000000L))
  }

  test("toEpochSecond extracts epoch seconds") {
    val nd = NumericDate.fromEpochSecond(1700000000L)
    assertEquals(nd.toEpochSecond, 1700000000L)
  }

  test("round-trips through epoch seconds") {
    val epoch = 1609459200L
    assertEquals(NumericDate.fromEpochSecond(epoch).toEpochSecond, epoch)
  }

  test("handles epoch zero") {
    val nd = NumericDate.fromEpochSecond(0L)
    assertEquals(nd.unwrap, Instant.EPOCH)
    assertEquals(nd.toEpochSecond, 0L)
  }

  test("handles negative epoch (pre-1970)") {
    val nd = NumericDate.fromEpochSecond(-86400L)
    assertEquals(nd.toEpochSecond, -86400L)
  }
