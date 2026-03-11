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

import java.nio.charset.StandardCharsets

class JwtDecoderSuite extends munit.FunSuite:

  // -- Minimal stub codecs for cross-platform testing (no jsoniter dependency) --

  // Header JSON: {"alg":"HS256","typ":"JWT"}
  private given JwtCodec[JoseHeader] = new JwtCodec[JoseHeader]:
    def decode(bytes: Array[Byte]): Either[Throwable, JoseHeader] =
      val json = new String(bytes, StandardCharsets.UTF_8)
      if json.contains("\"alg\"") then
        val alg =
          if json.contains("HS256") then Algorithm.HS256
          else if json.contains("RS256") then Algorithm.RS256
          else return Left(Exception("Unsupported algorithm in stub codec")) // scalafix:ok
        val typ = if json.contains("\"typ\"") then Some("JWT") else None
        Right(JoseHeader(alg, typ, None, None, None, None, None))
      else Left(Exception("Missing alg in header"))
    def encode(value: JoseHeader): Either[Throwable, Array[Byte]] =
      Right(s"""{"alg":"${value.alg.name}","typ":"JWT"}""".getBytes(StandardCharsets.UTF_8))

  // Claims JSON: {"iss":"test","sub":"user1"}
  private given JwtCodec[RegisteredClaims] = new JwtCodec[RegisteredClaims]:
    def decode(bytes: Array[Byte]): Either[Throwable, RegisteredClaims] =
      val json = new String(bytes, StandardCharsets.UTF_8)
      val iss = extractField(json, "iss")
      val sub = extractField(json, "sub")
      Right(RegisteredClaims(iss, sub, None, None, None, None, None))
    def encode(value: RegisteredClaims): Either[Throwable, Array[Byte]] =
      val parts = List(
        value.iss.map(v => s""""iss":"$v""""),
        value.sub.map(v => s""""sub":"$v"""")
      ).flatten
      Right(s"{${parts.mkString(",")}}".getBytes(StandardCharsets.UTF_8))

  // Custom claims type
  private case class TestClaims(role: String) derives CanEqual

  private given JwtCodec[TestClaims] = new JwtCodec[TestClaims]:
    def decode(bytes: Array[Byte]): Either[Throwable, TestClaims] =
      val json = new String(bytes, StandardCharsets.UTF_8)
      extractField(json, "role") match
        case Some(r) => Right(TestClaims(r))
        case None    => Right(TestClaims("none"))
    def encode(value: TestClaims): Either[Throwable, Array[Byte]] =
      Right(s"""{"role":"${value.role}"}""".getBytes(StandardCharsets.UTF_8))

  // Trivial JSON field extractor (no dependency on jsoniter)
  private def extractField(json: String, field: String): Option[String] =
    val key = s""""$field":""""
    val idx = json.indexOf(key)
    if idx < 0 then None
    else
      val start = idx + key.length
      val end = json.indexOf('"', start)
      if end < 0 then None
      else Some(json.substring(start, end))

  // -- Test token: header.payload.signature --
  // Header:  {"alg":"HS256","typ":"JWT"}
  // Payload: {"iss":"test","sub":"user1","role":"admin"}
  // Signature: dummy (not verified by JwtDecoder)
  private val testHeaderB64 = Base64Url.encode(
    """{"alg":"HS256","typ":"JWT"}""".getBytes(StandardCharsets.UTF_8)
  )

  private val testPayloadB64 = Base64Url.encode(
    """{"iss":"test","sub":"user1","role":"admin"}""".getBytes(StandardCharsets.UTF_8)
  )

  private val testSigB64 = Base64Url.encode(Array[Byte](1, 2, 3, 4))

  // TokenString requires exactly three base64url segments
  private val testToken: TokenString =
    TokenString.from(s"$testHeaderB64.$testPayloadB64.$testSigB64") match
      case Right(t) => t
      case Left(e)  => throw e // scalafix:ok

  test("decode returns UnverifiedJwt with correct header") {
    val result = JwtDecoder.decode[TestClaims](testToken)
    assert(result.isRight, s"decode failed: ${result.left.toOption}")
    val jwt = result.toOption.get
    assertEquals(jwt.header.alg, Algorithm.HS256)
    assertEquals(jwt.header.typ, Some("JWT"))
  }

  test("decode returns UnverifiedJwt with correct registered claims") {
    val result = JwtDecoder.decode[TestClaims](testToken)
    val jwt = result.toOption.get
    assertEquals(jwt.registeredClaims.iss, Some("test"))
    assertEquals(jwt.registeredClaims.sub, Some("user1"))
  }

  test("decode returns UnverifiedJwt with correct custom claims") {
    val result = JwtDecoder.decode[TestClaims](testToken)
    val jwt = result.toOption.get
    assertEquals(jwt.claims.role, "admin")
  }

  test("decode fails with MalformedToken on invalid base64url") {
    val badToken = TokenString.from("!!!.payload.sig")
    // TokenString.from should reject this, but if it doesn't, JwtDecoder should
    badToken match
      case Left(_)  => () // expected: invalid base64url chars rejected by TokenString
      case Right(t) =>
        val result = JwtDecoder.decode[TestClaims](t)
        assert(result.isLeft)
        assert(result.left.toOption.get.isInstanceOf[JwtError.MalformedToken]) // scalafix:ok
  }

  test("decode fails with DecodeError when header codec fails") {
    // Build a token where the header is valid base64url but not valid JSON for our codec
    val badHeaderB64 = Base64Url.encode("""{"noalg":true}""".getBytes(StandardCharsets.UTF_8))
    TokenString.from(s"$badHeaderB64.$testPayloadB64.$testSigB64") match
      case Left(_)  => () // shouldn't happen
      case Right(t) =>
        val result = JwtDecoder.decode[TestClaims](t)
        assert(result.isLeft)
        assert(result.left.toOption.get.isInstanceOf[JwtError.DecodeError]) // scalafix:ok
  }

  test("Base64Url decode round-trips with encode") {
    val original = Array[Byte](0, 1, 2, 127, -128, -1, 42, 99)
    val encoded = Base64Url.encode(original)
    val decoded = Base64Url.decode(encoded)
    assert(decoded.isRight)
    assert(decoded.toOption.get.sameElements(original), "round-trip mismatch")
  }

  test("Base64Url encode produces no padding") {
    val data = Array[Byte](1, 2, 3)
    val encoded = Base64Url.encode(data)
    assert(!encoded.contains('='), s"encoded string contains padding: $encoded")
    assert(!encoded.contains('+'), s"encoded string contains '+': $encoded")
    assert(!encoded.contains('/'), s"encoded string contains '/': $encoded")
  }

  test("Base64Url decode rejects invalid input") {
    val result = Base64Url.decode("not valid base64 $$$")
    assert(result.isLeft)
  }

end JwtDecoderSuite
