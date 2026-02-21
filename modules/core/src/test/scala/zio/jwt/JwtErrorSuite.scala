package zio.jwt

import java.time.Instant

import boilerplate.unwrap

class JwtErrorSuite extends munit.FunSuite:

  test("Expired getMessage includes expiry and current time") {
    val exp = NumericDate.fromEpochSecond(1700000000L)
    val now = Instant.ofEpochSecond(1700000060L)
    val err = JwtError.Expired(exp, now)
    assert(err.getMessage.contains("expired"))
    assert(err.getMessage.contains(exp.unwrap.toString))
    assert(err.getMessage.contains(now.toString))
  }

  test("NotYetValid getMessage includes nbf and current time") {
    val nbf = NumericDate.fromEpochSecond(1700000000L)
    val now = Instant.ofEpochSecond(1699999990L)
    val err = JwtError.NotYetValid(nbf, now)
    assert(err.getMessage.contains("not yet valid"))
  }

  test("InvalidAudience getMessage includes expected and actual") {
    val err = JwtError.InvalidAudience("api", Some(Audience("other")))
    assert(err.getMessage.contains("api"))
  }

  test("InvalidAudience getMessage handles missing audience") {
    val err = JwtError.InvalidAudience("api", None)
    assert(err.getMessage.contains("none"))
  }

  test("InvalidIssuer getMessage includes expected and actual") {
    val err = JwtError.InvalidIssuer("auth.example.com", Some("wrong.com"))
    assert(err.getMessage.contains("auth.example.com"))
    assert(err.getMessage.contains("wrong.com"))
  }

  test("InvalidSignature getMessage is descriptive") {
    assertEquals(JwtError.InvalidSignature.getMessage, "Invalid signature")
  }

  test("MalformedToken getMessage wraps cause message") {
    val cause = RuntimeException("unexpected EOF")
    val err   = JwtError.MalformedToken(cause)
    assert(err.getMessage.contains("unexpected EOF"))
  }

  test("MalformedToken getCause returns wrapped throwable") {
    val cause = RuntimeException("parse failure")
    val err   = JwtError.MalformedToken(cause)
    assertEquals(err.getCause, cause)
  }

  test("non-MalformedToken getCause returns null") {
    assertEquals(JwtError.InvalidSignature.getCause, null)
  }

  test("UnsupportedAlgorithm getMessage includes algorithm name") {
    val err = JwtError.UnsupportedAlgorithm("none")
    assert(err.getMessage.contains("none"))
  }

  test("KeyNotFound getMessage includes kid when present") {
    val err = JwtError.KeyNotFound(Some(Kid.fromUnsafe("rsa-1")))
    assert(err.getMessage.contains("rsa-1"))
  }

  test("KeyNotFound getMessage handles absent kid") {
    val err = JwtError.KeyNotFound(None)
    assert(err.getMessage.contains("Key not found"))
  }

  test("extends NoStackTrace (no stack trace captured)") {
    val err = JwtError.InvalidSignature
    assertEquals(err.getStackTrace.length, 0)
  }
