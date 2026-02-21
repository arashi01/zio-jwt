package zio.jwt

import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey as JcaEcPrivateKey
import java.security.interfaces.ECPublicKey as JcaEcPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator

import munit.ZSuite

import zio.NonEmptyChunk
import zio.ZIO
import zio.ZLayer

import boilerplate.unwrap

import zio.jwt.jsoniter.JwtCodecInstances.given
import zio.jwt.jsoniter.codecs.given

class JwtIssuerSuite extends ZSuite:

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

  private lazy val rsaKeyPair =
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(2048)
    kpg.generateKeyPair()

  private lazy val ec256KeyPair =
    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(ECGenParameterSpec("secp256r1"))
    kpg.generateKeyPair()

  // -- Issuer + Validator layer helper --

  private def issuerLayer(config: JwtIssuerConfig, keySource: KeySource): ZLayer[Any, Nothing, JwtIssuer] =
    ZLayer.succeed(config) ++ ZLayer.succeed(keySource) >>> JwtIssuer.live

  private def validatorLayer(config: ValidationConfig, keySource: KeySource): ZLayer[Any, Nothing, JwtValidator] =
    ZLayer.succeed(config) ++ ZLayer.succeed(keySource) >>> JwtValidator.live

  private def validConfig(alg: Algorithm): ValidationConfig =
    ValidationConfig(
      clockSkew = java.time.Duration.ZERO,
      requiredIssuer = None,
      requiredAudience = None,
      requiredTyp = None,
      allowedAlgorithms = NonEmptyChunk(alg)
    )

  // -- HMAC issue and round-trip --

  testZ("issues a valid HMAC HS256 token") {
    val jwk = Jwk.from(hmac256Key, Some(Kid.fromUnsafe("k1"))).toOption.get
    val keySource = KeySource.static(jwk)
    val issuerConfig = JwtIssuerConfig(Algorithm.HS256, Some(Kid.fromUnsafe("k1")), None, None)
    val claims = RegisteredClaims(Some("test-issuer"), None, None, None, None, None, None)
    ZIO.serviceWithZIO[JwtIssuer](_.issue[Unit]((), claims))
      .map { token =>
        val raw = token.unwrap
        assertEquals(raw.count(_ == '.'), 2)
      }
      .provide(issuerLayer(issuerConfig, keySource))
  }

  testZ("HMAC HS256 issue-then-validate round-trip") {
    val jwk = Jwk.from(hmac256Key, Some(Kid.fromUnsafe("k1"))).toOption.get
    val keySource = KeySource.static(jwk)
    val issuerConfig = JwtIssuerConfig(Algorithm.HS256, Some(Kid.fromUnsafe("k1")), None, None)
    val claims = RegisteredClaims(Some("roundtrip-iss"), Some("user-1"), None, None, None, None, None)
    val layer = issuerLayer(issuerConfig, keySource) ++ validatorLayer(validConfig(Algorithm.HS256), keySource)
    (for
      token <- ZIO.serviceWithZIO[JwtIssuer](_.issue[Unit]((), claims))
      jwt   <- ZIO.serviceWithZIO[JwtValidator](_.validate[Unit](token))
    yield
      assertEquals(jwt.header.alg, Algorithm.HS256)
      assertEquals(jwt.registeredClaims.iss, Some("roundtrip-iss"))
      assertEquals(jwt.registeredClaims.sub, Some("user-1"))
    ).provide(layer)
  }

  // -- RSA issue and round-trip --

  testZ("RSA RS256 issue-then-validate round-trip") {
    val pubJwk = Jwk.from(rsaKeyPair.getPublic, Some(Kid.fromUnsafe("rsa1"))).toOption.get
    val privJwk = Jwk.from(rsaKeyPair.getPrivate, rsaKeyPair.getPublic, Some(Kid.fromUnsafe("rsa1"))).toOption.get
    val signingSource = KeySource.static(privJwk)
    val verifySource = KeySource.static(pubJwk)
    val issuerConfig = JwtIssuerConfig(Algorithm.RS256, Some(Kid.fromUnsafe("rsa1")), None, None)
    val claims = RegisteredClaims(None, Some("rsa-user"), None, None, None, None, None)
    val layer = issuerLayer(issuerConfig, signingSource) ++ validatorLayer(validConfig(Algorithm.RS256), verifySource)
    (for
      token <- ZIO.serviceWithZIO[JwtIssuer](_.issue[Unit]((), claims))
      jwt   <- ZIO.serviceWithZIO[JwtValidator](_.validate[Unit](token))
    yield
      assertEquals(jwt.header.alg, Algorithm.RS256)
      assertEquals(jwt.registeredClaims.sub, Some("rsa-user"))
    ).provide(layer)
  }

  // -- EC issue and round-trip --

  testZ("ECDSA ES256 issue-then-validate round-trip") {
    val pub = ec256KeyPair.getPublic.asInstanceOf[JcaEcPublicKey]
    val priv = ec256KeyPair.getPrivate.asInstanceOf[JcaEcPrivateKey]
    val pubJwk = Jwk.from(pub, Some(Kid.fromUnsafe("ec1"))).toOption.get
    val privJwk = Jwk.from(priv, pub, Some(Kid.fromUnsafe("ec1"))).toOption.get
    val signingSource = KeySource.static(privJwk)
    val verifySource = KeySource.static(pubJwk)
    val issuerConfig = JwtIssuerConfig(Algorithm.ES256, Some(Kid.fromUnsafe("ec1")), None, None)
    val claims = RegisteredClaims(None, Some("ec-user"), None, None, None, None, None)
    val layer = issuerLayer(issuerConfig, signingSource) ++ validatorLayer(validConfig(Algorithm.ES256), verifySource)
    (for
      token <- ZIO.serviceWithZIO[JwtIssuer](_.issue[Unit]((), claims))
      jwt   <- ZIO.serviceWithZIO[JwtValidator](_.validate[Unit](token))
    yield
      assertEquals(jwt.header.alg, Algorithm.ES256)
      assertEquals(jwt.registeredClaims.sub, Some("ec-user"))
    ).provide(layer)
  }

  // -- Registered claims round-trip --

  testZ("round-trip preserves registered claims") {
    val jwk = Jwk.from(hmac256Key, Some(Kid.fromUnsafe("k1"))).toOption.get
    val keySource = KeySource.static(jwk)
    val issuerConfig = JwtIssuerConfig(Algorithm.HS256, Some(Kid.fromUnsafe("k1")), Some("JWT"), None)
    val claims = RegisteredClaims(
      iss = Some("my-service"),
      sub = Some("subject-1"),
      aud = Some(Audience("client-a")),
      exp = Some(NumericDate.fromEpochSecond(9999999999L)),
      nbf = Some(NumericDate.fromEpochSecond(0L)),
      iat = Some(NumericDate.fromEpochSecond(1000000000L)),
      jti = Some("unique-id-123")
    )
    val config = validConfig(Algorithm.HS256).copy(requiredIssuer = Some("my-service"), requiredAudience = Some("client-a"))
    val layer = issuerLayer(issuerConfig, keySource) ++ validatorLayer(config, keySource)
    (for
      token <- ZIO.serviceWithZIO[JwtIssuer](_.issue[Unit]((), claims))
      jwt   <- ZIO.serviceWithZIO[JwtValidator](_.validate[Unit](token))
    yield
      assertEquals(jwt.header.typ, Some("JWT"))
      assertEquals(jwt.registeredClaims.iss, Some("my-service"))
      assertEquals(jwt.registeredClaims.sub, Some("subject-1"))
      assert(jwt.registeredClaims.aud.exists(_.contains("client-a")))
      assertEquals(jwt.registeredClaims.exp, Some(NumericDate.fromEpochSecond(9999999999L)))
      assertEquals(jwt.registeredClaims.nbf, Some(NumericDate.fromEpochSecond(0L)))
      assertEquals(jwt.registeredClaims.iat, Some(NumericDate.fromEpochSecond(1000000000L)))
      assertEquals(jwt.registeredClaims.jti, Some("unique-id-123"))
    ).provide(layer)
  }

  // -- Header fields from config --

  testZ("issuer constructs header with typ and kid from config") {
    val jwk = Jwk.from(hmac256Key, Some(Kid.fromUnsafe("cfg-kid"))).toOption.get
    val keySource = KeySource.static(jwk)
    val issuerConfig = JwtIssuerConfig(Algorithm.HS256, Some(Kid.fromUnsafe("cfg-kid")), Some("JWT"), Some("jwt"))
    val claims = RegisteredClaims(None, None, None, None, None, None, None)
    val config = validConfig(Algorithm.HS256)
    val layer = issuerLayer(issuerConfig, keySource) ++ validatorLayer(config, keySource)
    (for
      token <- ZIO.serviceWithZIO[JwtIssuer](_.issue[Unit]((), claims))
      jwt   <- ZIO.serviceWithZIO[JwtValidator](_.validate[Unit](token))
    yield
      assertEquals(jwt.header.alg, Algorithm.HS256)
      assertEquals(jwt.header.typ, Some("JWT"))
      assertEquals(jwt.header.cty, Some("jwt"))
      assertEquals(jwt.header.kid, Some(Kid.fromUnsafe("cfg-kid")))
    ).provide(layer)
  }
