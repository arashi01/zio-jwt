package zio.jwt.jsoniter

import com.github.plokhotnyuk.jsoniter_scala.core.*

import zio.NonEmptyChunk
import zio.jwt.*

class NumericDateCodecSuite extends munit.FunSuite:

  test("round-trips epoch seconds") {
    val nd    = NumericDate.fromEpochSecond(1700000000L)
    val bytes = writeToArray(nd)
    assertEquals(new String(bytes, "UTF-8"), "1700000000")
    assertEquals(readFromArray[NumericDate](bytes), nd)
  }

  test("encodes as plain integer, not ISO-8601") {
    val nd = NumericDate.fromEpochSecond(0L)
    assertEquals(new String(writeToArray(nd), "UTF-8"), "0")
  }

  test("decodes negative epoch (pre-1970)") {
    val bytes = "-86400".getBytes("UTF-8")
    assertEquals(readFromArray[NumericDate](bytes).toEpochSecond, -86400L)
  }

class AlgorithmCodecSuite extends munit.FunSuite:

  test("round-trips all 12 algorithms") {
    Algorithm.values.foreach { alg =>
      val bytes   = writeToArray(alg)
      val decoded = readFromArray[Algorithm](bytes)
      assertEquals(decoded, alg)
    }
  }

  test("encodes as quoted string") {
    val bytes = writeToArray(Algorithm.HS256)
    assertEquals(new String(bytes, "UTF-8"), "\"HS256\"")
  }

  test("rejects 'none' algorithm") {
    val bytes = "\"none\"".getBytes("UTF-8")
    intercept[JsonReaderException] {
      readFromArray[Algorithm](bytes)
    }
  }

  test("rejects unknown algorithm string") {
    val bytes = "\"XYZ999\"".getBytes("UTF-8")
    intercept[JsonReaderException] {
      readFromArray[Algorithm](bytes)
    }
  }

class KidCodecSuite extends munit.FunSuite:

  test("round-trips valid kid") {
    val kid   = Kid.fromUnsafe("rsa-key-1")
    val bytes = writeToArray(kid)
    assertEquals(readFromArray[Kid](bytes), kid)
  }

  test("rejects empty kid string") {
    val bytes = "\"\"".getBytes("UTF-8")
    intercept[JsonReaderException] {
      readFromArray[Kid](bytes)
    }
  }

class AudienceCodecSuite extends munit.FunSuite:

  test("encodes Single as JSON string") {
    val aud = Audience("https://api.example.com")
    assertEquals(new String(writeToArray(aud), "UTF-8"), "\"https://api.example.com\"")
  }

  test("encodes Many as JSON array") {
    val aud = Audience(NonEmptyChunk("a", "b"))
    assertEquals(new String(writeToArray(aud), "UTF-8"), """["a","b"]""")
  }

  test("decodes JSON string as Single") {
    val bytes = "\"one\"".getBytes("UTF-8")
    assertEquals(readFromArray[Audience](bytes), Audience.Single("one"))
  }

  test("decodes JSON array as Many") {
    val bytes = """["x","y","z"]""".getBytes("UTF-8")
    val aud   = readFromArray[Audience](bytes)
    assertEquals(aud, Audience.Many(NonEmptyChunk("x", "y", "z")))
  }

  test("decodes single-element array as Single") {
    val bytes = """["only"]""".getBytes("UTF-8")
    assertEquals(readFromArray[Audience](bytes), Audience.Single("only"))
  }

  test("rejects empty array") {
    val bytes = "[]".getBytes("UTF-8")
    intercept[JsonReaderException] {
      readFromArray[Audience](bytes)
    }
  }

class JoseHeaderCodecSuite extends munit.FunSuite:

  test("round-trips minimal header") {
    val header = JoseHeader(Algorithm.RS256, None, None, None)
    val bytes  = writeToArray(header)
    assertEquals(readFromArray[JoseHeader](bytes), header)
  }

  test("round-trips full header") {
    val header = JoseHeader(Algorithm.ES256, Some("JWT"), Some("jwt"), Some(Kid.fromUnsafe("k1")))
    val bytes  = writeToArray(header)
    assertEquals(readFromArray[JoseHeader](bytes), header)
  }

  test("encodes alg as string") {
    val bytes = writeToArray(JoseHeader(Algorithm.HS256, None, None, None))
    val json  = new String(bytes, "UTF-8")
    assert(json.contains("\"alg\":\"HS256\""))
  }

  test("omits None fields") {
    val bytes = writeToArray(JoseHeader(Algorithm.HS256, None, None, None))
    val json  = new String(bytes, "UTF-8")
    assert(!json.contains("typ"))
    assert(!json.contains("cty"))
    assert(!json.contains("kid"))
  }

  test("rejects missing alg field") {
    val bytes = """{"typ":"JWT"}""".getBytes("UTF-8")
    intercept[JsonReaderException] {
      readFromArray[JoseHeader](bytes)
    }
  }

  test("rejects alg:none") {
    val bytes = """{"alg":"none"}""".getBytes("UTF-8")
    intercept[JsonReaderException] {
      readFromArray[JoseHeader](bytes)
    }
  }

  test("rejects unsupported algorithm") {
    val bytes = """{"alg":"A128KW"}""".getBytes("UTF-8")
    intercept[JsonReaderException] {
      readFromArray[JoseHeader](bytes)
    }
  }

  test("ignores unknown fields") {
    val bytes = """{"alg":"HS256","x5t":"abc","custom":42}""".getBytes("UTF-8")
    val h     = readFromArray[JoseHeader](bytes)
    assertEquals(h.alg, Algorithm.HS256)
    assertEquals(h.typ, None)
  }

class RegisteredClaimsCodecSuite extends munit.FunSuite:

  test("round-trips empty claims") {
    val claims = RegisteredClaims(None, None, None, None, None, None, None)
    val bytes  = writeToArray(claims)
    assertEquals(readFromArray[RegisteredClaims](bytes), claims)
  }

  test("round-trips full claims") {
    val claims = RegisteredClaims(
      iss = Some("auth.example.com"),
      sub = Some("user-123"),
      aud = Some(Audience("api")),
      exp = Some(NumericDate.fromEpochSecond(1700000000L)),
      nbf = Some(NumericDate.fromEpochSecond(1699999900L)),
      iat = Some(NumericDate.fromEpochSecond(1699999800L)),
      jti = Some("unique-id-1")
    )
    val bytes = writeToArray(claims)
    assertEquals(readFromArray[RegisteredClaims](bytes), claims)
  }

  test("encodes NumericDate fields as epoch seconds") {
    val claims = RegisteredClaims(None, None, None, Some(NumericDate.fromEpochSecond(1700000000L)), None, None, None)
    val json   = new String(writeToArray(claims), "UTF-8")
    assert(json.contains("\"exp\":1700000000"))
    assert(!json.contains("T"))
  }

  test("decodes with audience as string") {
    val bytes = """{"aud":"api"}""".getBytes("UTF-8")
    val c     = readFromArray[RegisteredClaims](bytes)
    assertEquals(c.aud, Some(Audience.Single("api")))
  }

  test("decodes with audience as array") {
    val bytes = """{"aud":["a","b"]}""".getBytes("UTF-8")
    val c     = readFromArray[RegisteredClaims](bytes)
    assertEquals(c.aud, Some(Audience.Many(NonEmptyChunk("a", "b"))))
  }

  test("decodes null audience as None") {
    val bytes = """{"aud":null}""".getBytes("UTF-8")
    val c     = readFromArray[RegisteredClaims](bytes)
    assertEquals(c.aud, None)
  }

  test("ignores unknown fields") {
    val bytes = """{"iss":"x","custom_claim":true,"nested":{"a":1}}""".getBytes("UTF-8")
    val c     = readFromArray[RegisteredClaims](bytes)
    assertEquals(c.iss, Some("x"))
  }

  test("encodes audience Single as string") {
    val claims = RegisteredClaims(None, None, Some(Audience("one")), None, None, None, None)
    val json   = new String(writeToArray(claims), "UTF-8")
    assert(json.contains("\"aud\":\"one\""))
  }

  test("encodes audience Many as array") {
    val claims = RegisteredClaims(None, None, Some(Audience(NonEmptyChunk("a", "b"))), None, None, None, None)
    val json   = new String(writeToArray(claims), "UTF-8")
    assert(json.contains("\"aud\":[\"a\",\"b\"]"))
  }

class JwtCodecBridgeSuite extends munit.FunSuite:

  test("JwtCodec bridge decodes JoseHeader") {
    val codec = summon[JwtCodec[JoseHeader]]
    val bytes = """{"alg":"HS256","typ":"JWT"}""".getBytes("UTF-8")
    val result = codec.decode(bytes)
    assert(result.isRight)
    assertEquals(result.toOption.get.alg, Algorithm.HS256)
    assertEquals(result.toOption.get.typ, Some("JWT"))
  }

  test("JwtCodec bridge decode returns Left on invalid input") {
    val codec  = summon[JwtCodec[JoseHeader]]
    val bytes  = "not json".getBytes("UTF-8")
    val result = codec.decode(bytes)
    assert(result.isLeft)
  }

  test("JwtCodec bridge encode then decode round-trips") {
    val codec  = summon[JwtCodec[RegisteredClaims]]
    val claims = RegisteredClaims(Some("iss"), None, None, Some(NumericDate.fromEpochSecond(100L)), None, None, None)
    val bytes  = codec.encode(claims)
    assertEquals(codec.decode(bytes), Right(claims))
  }
