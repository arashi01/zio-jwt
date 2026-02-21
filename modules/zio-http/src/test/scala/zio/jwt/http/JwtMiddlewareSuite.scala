package zio.jwt.http

import java.nio.charset.StandardCharsets

import javax.crypto.KeyGenerator

import munit.ZSuite

import zio.NonEmptyChunk
import zio.Scope
import zio.ZLayer

import zio.http.*

import boilerplate.unwrap

import zio.jwt.*
import zio.jwt.crypto.SignatureEngine
import zio.jwt.jsoniter.given

class JwtMiddlewareSuite extends ZSuite:

  // -- Codec for empty custom claims --

  private given JwtCodec[Unit] = new JwtCodec[Unit]:
    def decode(bytes: Array[Byte]): Either[Throwable, Unit] = Right(())
    def encode(value: Unit): Array[Byte] =
      "{}".getBytes(StandardCharsets.UTF_8)

  // -- Key generation --

  private lazy val hmac256Key =
    val kg = KeyGenerator.getInstance("HmacSHA256")
    kg.init(256)
    kg.generateKey()

  private lazy val hmacJwk =
    Jwk.from(hmac256Key, Some(Kid.fromUnsafe("k1"))).toOption.get

  private lazy val keySource = KeySource.static(hmacJwk)

  // -- Token construction --

  private def createToken(
      header: JoseHeader,
      claims: RegisteredClaims
  ): TokenString =
    import scala.language.unsafeNulls
    val encoder = java.util.Base64.getUrlEncoder.withoutPadding()
    val headerCodec = summon[JwtCodec[JoseHeader]]
    val claimsCodec = summon[JwtCodec[RegisteredClaims]]
    val headerB64 = encoder.encodeToString(headerCodec.encode(header))
    val payloadB64 = encoder.encodeToString(claimsCodec.encode(claims))
    val signingInput = s"$headerB64.$payloadB64".getBytes(StandardCharsets.US_ASCII)
    val sig = SignatureEngine.sign(signingInput, hmac256Key, Algorithm.HS256).toOption.get
    val sigB64 = encoder.encodeToString(sig)
    TokenString.from(s"$headerB64.$payloadB64.$sigB64").toOption.get

  // -- Layers --

  private def validatorLayer: ZLayer[Any, Nothing, JwtValidator] =
    val config = ValidationConfig(
      clockSkew = java.time.Duration.ZERO,
      requiredIssuer = None,
      requiredAudience = None,
      requiredTyp = None,
      allowedAlgorithms = NonEmptyChunk(Algorithm.HS256)
    )
    ZLayer.succeed(config) ++ ZLayer.succeed(keySource: KeySource) >>> JwtValidator.live

  // -- Test routes --

  private val routes: Routes[JwtValidator, Response] =
    Routes(
      Method.GET / "protected" -> handler((_: Request) =>
        withContext((jwt: Jwt[Unit]) =>
          Response.text(jwt.registeredClaims.sub.getOrElse("anonymous"))
        )
      )
    ) @@ JwtMiddleware.bearer[Unit]

  // -- Tests --

  testZ("returns 200 with valid bearer token") {
    val header = JoseHeader(Algorithm.HS256, None, None, Some(Kid.fromUnsafe("k1")))
    val claims = RegisteredClaims(None, Some("test-user"), None, None, None, None, None)
    val token = createToken(header, claims)
    val request = Request.get(URL.root / "protected")
      .copy(headers = Headers(Header.Authorization.Bearer(token.unwrap)))
    for
      response <- routes.runZIO(request).provide(Scope.default, validatorLayer)
      body     <- response.body.asString
    yield
      assertEquals(response.status, Status.Ok)
      assertEquals(body, "test-user")
  }

  testZ("returns 401 when no Authorization header") {
    val request = Request.get(URL.root / "protected")
    for
      response <- routes.runZIO(request).provide(Scope.default, validatorLayer)
    yield
      assertEquals(response.status, Status.Unauthorized)
      assert(response.headers.get(Header.WWWAuthenticate).isDefined)
  }

  testZ("returns 401 with invalid token") {
    val request = Request.get(URL.root / "protected")
      .copy(headers = Headers(Header.Authorization.Bearer("not.a.valid-token")))
    for
      response <- routes.runZIO(request).provide(Scope.default, validatorLayer)
    yield
      assertEquals(response.status, Status.Unauthorized)
  }

  testZ("returns 401 with expired token") {
    val header = JoseHeader(Algorithm.HS256, None, None, Some(Kid.fromUnsafe("k1")))
    val claims = RegisteredClaims(None, None, None, Some(NumericDate.fromEpochSecond(0L)), None, None, None)
    val token = createToken(header, claims)
    val request = Request.get(URL.root / "protected")
      .copy(headers = Headers(Header.Authorization.Bearer(token.unwrap)))
    for
      response <- routes.runZIO(request).provide(Scope.default, validatorLayer)
    yield
      assertEquals(response.status, Status.Unauthorized)
  }

  testZ("WWW-Authenticate header includes Bearer realm") {
    val request = Request.get(URL.root / "protected")
    for
      response <- routes.runZIO(request).provide(Scope.default, validatorLayer)
    yield
      val wwwAuth = response.rawHeader("WWW-Authenticate")
      assert(wwwAuth.isDefined, "Expected WWW-Authenticate header")
      assert(wwwAuth.get.contains("Bearer"), s"Expected Bearer in WWW-Authenticate, got ${wwwAuth.get}")
  }
