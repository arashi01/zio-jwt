package zio.jwt

import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey as JcaEcPublicKey
import java.security.spec.ECGenParameterSpec
import java.time.Duration
import java.time.Instant
import javax.crypto.KeyGenerator

import munit.ZSuite

import zio.NonEmptyChunk
import zio.ZIO
import zio.ZLayer

import boilerplate.unwrap

import zio.jwt.crypto.SignatureEngine
import zio.jwt.jsoniter.JwtCodecInstances.given
import zio.jwt.jsoniter.codecs.given

class JwtValidatorSuite extends ZSuite:

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

  // -- Token construction helper --

  private def createToken(
      header: JoseHeader,
      claims: RegisteredClaims,
      signFn: Array[Byte] => Either[JwtError, Array[Byte]]
  ): Either[JwtError, TokenString] =
    import scala.language.unsafeNulls
    val encoder = java.util.Base64.getUrlEncoder.withoutPadding()
    val headerCodec = summon[JwtCodec[JoseHeader]]
    val claimsCodec = summon[JwtCodec[RegisteredClaims]]
    val headerB64 = encoder.encodeToString(headerCodec.encode(header))
    val payloadB64 = encoder.encodeToString(claimsCodec.encode(claims))
    val signingInput = s"$headerB64.$payloadB64".getBytes(StandardCharsets.US_ASCII)
    for
      sig <- signFn(signingInput)
      sigB64 = encoder.encodeToString(sig)
      token <- TokenString.from(s"$headerB64.$payloadB64.$sigB64").left.map(e => JwtError.MalformedToken(e))
    yield token

  private def validConfig(allowedAlgs: NonEmptyChunk[Algorithm]): ValidationConfig =
    ValidationConfig(
      clockSkew = Duration.ZERO,
      requiredIssuer = None,
      requiredAudience = None,
      requiredTyp = None,
      allowedAlgorithms = allowedAlgs
    )

  private def validatorLayer(config: ValidationConfig, keySource: KeySource): ZLayer[Any, Nothing, JwtValidator] =
    ZLayer.succeed(config) ++ ZLayer.succeed(keySource) >>> JwtValidator.live

  // -- HMAC validation --

  testZ("validates a valid HMAC HS256 token") {
    val jwk = Jwk.from(hmac256Key, Some(Kid.fromUnsafe("k1"))).toOption.get
    val keySource = KeySource.static(jwk)
    val header = JoseHeader(Algorithm.HS256, None, None, Some(Kid.fromUnsafe("k1")))
    val claims = RegisteredClaims(None, Some("test"), None, None, None, None, None)
    val token = createToken(header, claims, data => SignatureEngine.sign(data, hmac256Key, Algorithm.HS256))
    val config = validConfig(NonEmptyChunk(Algorithm.HS256))
    ZIO.serviceWithZIO[JwtValidator](_.validate[Unit](token.toOption.get))
      .map { jwt =>
        assertEquals(jwt.header.alg, Algorithm.HS256)
        assertEquals(jwt.registeredClaims.sub, Some("test"))
      }
      .provide(validatorLayer(config, keySource))
  }

  // -- RSA validation --

  testZ("validates a valid RSA RS256 token") {
    val jwk = Jwk.from(rsaKeyPair.getPublic, Some(Kid.fromUnsafe("rsa1"))).toOption.get
    val keySource = KeySource.static(jwk)
    val header = JoseHeader(Algorithm.RS256, None, None, Some(Kid.fromUnsafe("rsa1")))
    val claims = RegisteredClaims(None, Some("rsa-test"), None, None, None, None, None)
    val token = createToken(header, claims, data => SignatureEngine.sign(data, rsaKeyPair.getPrivate, Algorithm.RS256))
    val config = validConfig(NonEmptyChunk(Algorithm.RS256))
    ZIO.serviceWithZIO[JwtValidator](_.validate[Unit](token.toOption.get))
      .map(jwt => assertEquals(jwt.registeredClaims.sub, Some("rsa-test")))
      .provide(validatorLayer(config, keySource))
  }

  // -- EC validation --

  testZ("validates a valid ECDSA ES256 token") {
    val pub = ec256KeyPair.getPublic.asInstanceOf[JcaEcPublicKey]
    val jwk = Jwk.from(pub, Some(Kid.fromUnsafe("ec1"))).toOption.get
    val keySource = KeySource.static(jwk)
    val header = JoseHeader(Algorithm.ES256, None, None, Some(Kid.fromUnsafe("ec1")))
    val claims = RegisteredClaims(None, Some("ec-test"), None, None, None, None, None)
    val token = createToken(header, claims, data => SignatureEngine.sign(data, ec256KeyPair.getPrivate, Algorithm.ES256))
    val config = validConfig(NonEmptyChunk(Algorithm.ES256))
    ZIO.serviceWithZIO[JwtValidator](_.validate[Unit](token.toOption.get))
      .map(jwt => assertEquals(jwt.registeredClaims.sub, Some("ec-test")))
      .provide(validatorLayer(config, keySource))
  }

  // -- Expired token --

  testZ("rejects an expired token") {
    val jwk = Jwk.from(hmac256Key, Some(Kid.fromUnsafe("k1"))).toOption.get
    val keySource = KeySource.static(jwk)
    val header = JoseHeader(Algorithm.HS256, None, None, Some(Kid.fromUnsafe("k1")))
    val claims = RegisteredClaims(None, None, None, Some(NumericDate.fromEpochSecond(0L)), None, None, None)
    val token = createToken(header, claims, data => SignatureEngine.sign(data, hmac256Key, Algorithm.HS256))
    val config = validConfig(NonEmptyChunk(Algorithm.HS256))
    ZIO.serviceWithZIO[JwtValidator](_.validate[Unit](token.toOption.get))
      .either
      .map { result =>
        assert(result.isLeft)
        result.swap.toOption.get match
          case JwtError.Expired(_, _) => ()
          case other => fail(s"Expected Expired, got $other")
      }
      .provide(validatorLayer(config, keySource))
  }

  // -- Not yet valid token --

  testZ("rejects a not-yet-valid token") {
    val jwk = Jwk.from(hmac256Key, Some(Kid.fromUnsafe("k1"))).toOption.get
    val keySource = KeySource.static(jwk)
    val header = JoseHeader(Algorithm.HS256, None, None, Some(Kid.fromUnsafe("k1")))
    val claims = RegisteredClaims(None, None, None, None, Some(NumericDate.fromEpochSecond(9999999999L)), None, None)
    val token = createToken(header, claims, data => SignatureEngine.sign(data, hmac256Key, Algorithm.HS256))
    val config = validConfig(NonEmptyChunk(Algorithm.HS256))
    ZIO.serviceWithZIO[JwtValidator](_.validate[Unit](token.toOption.get))
      .either
      .map { result =>
        assert(result.isLeft)
        result.swap.toOption.get match
          case JwtError.NotYetValid(_, _) => ()
          case other => fail(s"Expected NotYetValid, got $other")
      }
      .provide(validatorLayer(config, keySource))
  }

  // -- Clock skew acceptance --

  testZ("accepts a recently expired token within clock skew") {
    val jwk = Jwk.from(hmac256Key, Some(Kid.fromUnsafe("k1"))).toOption.get
    val keySource = KeySource.static(jwk)
    val expTime = Instant.now().minusSeconds(300)
    val header = JoseHeader(Algorithm.HS256, None, None, Some(Kid.fromUnsafe("k1")))
    val claims = RegisteredClaims(None, None, None, Some(NumericDate.wrap(expTime)), None, None, None)
    val token = createToken(header, claims, data => SignatureEngine.sign(data, hmac256Key, Algorithm.HS256))
    val config = ValidationConfig(
      clockSkew = Duration.ofHours(1),
      requiredIssuer = None,
      requiredAudience = None,
      requiredTyp = None,
      allowedAlgorithms = NonEmptyChunk(Algorithm.HS256)
    )
    ZIO.serviceWithZIO[JwtValidator](_.validate[Unit](token.toOption.get))
      .map(_ => ())
      .provide(validatorLayer(config, keySource))
  }

  // -- Wrong issuer --

  testZ("rejects token with wrong issuer") {
    val jwk = Jwk.from(hmac256Key, Some(Kid.fromUnsafe("k1"))).toOption.get
    val keySource = KeySource.static(jwk)
    val header = JoseHeader(Algorithm.HS256, None, None, Some(Kid.fromUnsafe("k1")))
    val claims = RegisteredClaims(Some("wrong-issuer"), None, None, None, None, None, None)
    val token = createToken(header, claims, data => SignatureEngine.sign(data, hmac256Key, Algorithm.HS256))
    val config = validConfig(NonEmptyChunk(Algorithm.HS256)).copy(requiredIssuer = Some("expected-issuer"))
    ZIO.serviceWithZIO[JwtValidator](_.validate[Unit](token.toOption.get))
      .either
      .map { result =>
        assert(result.isLeft)
        result.swap.toOption.get match
          case JwtError.InvalidIssuer(expected, _) =>
            assertEquals(expected, "expected-issuer")
          case other => fail(s"Expected InvalidIssuer, got $other")
      }
      .provide(validatorLayer(config, keySource))
  }

  // -- Missing issuer --

  testZ("rejects token with missing issuer when required") {
    val jwk = Jwk.from(hmac256Key, Some(Kid.fromUnsafe("k1"))).toOption.get
    val keySource = KeySource.static(jwk)
    val header = JoseHeader(Algorithm.HS256, None, None, Some(Kid.fromUnsafe("k1")))
    val claims = RegisteredClaims(None, None, None, None, None, None, None)
    val token = createToken(header, claims, data => SignatureEngine.sign(data, hmac256Key, Algorithm.HS256))
    val config = validConfig(NonEmptyChunk(Algorithm.HS256)).copy(requiredIssuer = Some("expected-issuer"))
    ZIO.serviceWithZIO[JwtValidator](_.validate[Unit](token.toOption.get))
      .either
      .map { result =>
        assert(result.isLeft)
        result.swap.toOption.get match
          case JwtError.InvalidIssuer(_, actual) => assertEquals(actual, None)
          case other => fail(s"Expected InvalidIssuer, got $other")
      }
      .provide(validatorLayer(config, keySource))
  }

  // -- Wrong audience --

  testZ("rejects token with wrong audience") {
    val jwk = Jwk.from(hmac256Key, Some(Kid.fromUnsafe("k1"))).toOption.get
    val keySource = KeySource.static(jwk)
    val header = JoseHeader(Algorithm.HS256, None, None, Some(Kid.fromUnsafe("k1")))
    val claims = RegisteredClaims(None, None, Some(Audience("wrong-aud")), None, None, None, None)
    val token = createToken(header, claims, data => SignatureEngine.sign(data, hmac256Key, Algorithm.HS256))
    val config = validConfig(NonEmptyChunk(Algorithm.HS256)).copy(requiredAudience = Some("expected-aud"))
    ZIO.serviceWithZIO[JwtValidator](_.validate[Unit](token.toOption.get))
      .either
      .map { result =>
        assert(result.isLeft)
        result.swap.toOption.get match
          case JwtError.InvalidAudience(expected, _) =>
            assertEquals(expected, "expected-aud")
          case other => fail(s"Expected InvalidAudience, got $other")
      }
      .provide(validatorLayer(config, keySource))
  }

  // -- Unsupported algorithm --

  testZ("rejects token with unsupported algorithm") {
    val jwk = Jwk.from(hmac256Key, Some(Kid.fromUnsafe("k1"))).toOption.get
    val keySource = KeySource.static(jwk)
    val header = JoseHeader(Algorithm.HS256, None, None, Some(Kid.fromUnsafe("k1")))
    val claims = RegisteredClaims(None, None, None, None, None, None, None)
    val token = createToken(header, claims, data => SignatureEngine.sign(data, hmac256Key, Algorithm.HS256))
    // Only allow RS256, not HS256
    val config = validConfig(NonEmptyChunk(Algorithm.RS256))
    ZIO.serviceWithZIO[JwtValidator](_.validate[Unit](token.toOption.get))
      .either
      .map { result =>
        assert(result.isLeft)
        result.swap.toOption.get match
          case JwtError.UnsupportedAlgorithm(_) => ()
          case other => fail(s"Expected UnsupportedAlgorithm, got $other")
      }
      .provide(validatorLayer(config, keySource))
  }

  // -- Invalid signature --

  testZ("rejects token with tampered signature") {
    val jwk = Jwk.from(hmac256Key, Some(Kid.fromUnsafe("k1"))).toOption.get
    val keySource = KeySource.static(jwk)
    val header = JoseHeader(Algorithm.HS256, None, None, Some(Kid.fromUnsafe("k1")))
    val claims = RegisteredClaims(None, None, None, None, None, None, None)
    val validToken = createToken(header, claims, data => SignatureEngine.sign(data, hmac256Key, Algorithm.HS256)).toOption.get
    // Tamper: flip a character in the signature segment
    val raw = validToken.unwrap
    val lastDot = raw.lastIndexOf('.')
    val tampered = raw.substring(0, lastDot + 1) + "AAAA" + raw.substring(lastDot + 5)
    val tamperedToken = TokenString.from(tampered).toOption.get
    val config = validConfig(NonEmptyChunk(Algorithm.HS256))
    ZIO.serviceWithZIO[JwtValidator](_.validate[Unit](tamperedToken))
      .either
      .map(result => assert(result.isLeft))
      .provide(validatorLayer(config, keySource))
  }

  // -- Correct issuer passes --

  testZ("accepts token with correct issuer") {
    val jwk = Jwk.from(hmac256Key, Some(Kid.fromUnsafe("k1"))).toOption.get
    val keySource = KeySource.static(jwk)
    val header = JoseHeader(Algorithm.HS256, None, None, Some(Kid.fromUnsafe("k1")))
    val claims = RegisteredClaims(Some("correct-issuer"), None, None, None, None, None, None)
    val token = createToken(header, claims, data => SignatureEngine.sign(data, hmac256Key, Algorithm.HS256))
    val config = validConfig(NonEmptyChunk(Algorithm.HS256)).copy(requiredIssuer = Some("correct-issuer"))
    ZIO.serviceWithZIO[JwtValidator](_.validate[Unit](token.toOption.get))
      .map(jwt => assertEquals(jwt.registeredClaims.iss, Some("correct-issuer")))
      .provide(validatorLayer(config, keySource))
  }

  // -- Correct audience passes --

  testZ("accepts token with correct audience") {
    val jwk = Jwk.from(hmac256Key, Some(Kid.fromUnsafe("k1"))).toOption.get
    val keySource = KeySource.static(jwk)
    val header = JoseHeader(Algorithm.HS256, None, None, Some(Kid.fromUnsafe("k1")))
    val claims = RegisteredClaims(None, None, Some(Audience("correct-aud")), None, None, None, None)
    val token = createToken(header, claims, data => SignatureEngine.sign(data, hmac256Key, Algorithm.HS256))
    val config = validConfig(NonEmptyChunk(Algorithm.HS256)).copy(requiredAudience = Some("correct-aud"))
    ZIO.serviceWithZIO[JwtValidator](_.validate[Unit](token.toOption.get))
      .map(jwt => assert(jwt.registeredClaims.aud.exists(_.contains("correct-aud"))))
      .provide(validatorLayer(config, keySource))
  }

  // -- Typ validation --

  testZ("rejects token with wrong typ") {
    val jwk = Jwk.from(hmac256Key, Some(Kid.fromUnsafe("k1"))).toOption.get
    val keySource = KeySource.static(jwk)
    val header = JoseHeader(Algorithm.HS256, Some("at+jwt"), None, Some(Kid.fromUnsafe("k1")))
    val claims = RegisteredClaims(None, None, None, None, None, None, None)
    val token = createToken(header, claims, data => SignatureEngine.sign(data, hmac256Key, Algorithm.HS256))
    val config = validConfig(NonEmptyChunk(Algorithm.HS256)).copy(requiredTyp = Some("JWT"))
    ZIO.serviceWithZIO[JwtValidator](_.validate[Unit](token.toOption.get))
      .either
      .map { result =>
        assert(result.isLeft)
        result.swap.toOption.get match
          case JwtError.MalformedToken(_) => ()
          case other => fail(s"Expected MalformedToken for typ mismatch, got $other")
      }
      .provide(validatorLayer(config, keySource))
  }

  testZ("accepts token with matching typ") {
    val jwk = Jwk.from(hmac256Key, Some(Kid.fromUnsafe("k1"))).toOption.get
    val keySource = KeySource.static(jwk)
    val header = JoseHeader(Algorithm.HS256, Some("JWT"), None, Some(Kid.fromUnsafe("k1")))
    val claims = RegisteredClaims(None, None, None, None, None, None, None)
    val token = createToken(header, claims, data => SignatureEngine.sign(data, hmac256Key, Algorithm.HS256))
    val config = validConfig(NonEmptyChunk(Algorithm.HS256)).copy(requiredTyp = Some("JWT"))
    ZIO.serviceWithZIO[JwtValidator](_.validate[Unit](token.toOption.get))
      .map(jwt => assertEquals(jwt.header.typ, Some("JWT")))
      .provide(validatorLayer(config, keySource))
  }
