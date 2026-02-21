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

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey as JcaEcPrivateKey
import java.security.interfaces.ECPublicKey as JcaEcPublicKey
import java.security.interfaces.RSAPrivateCrtKey as JcaRsaPrivateCrtKey
import java.security.interfaces.RSAPublicKey as JcaRsaPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAPublicKeySpec
import javax.crypto.KeyGenerator

import zio.Chunk

// scalafix:off DisableSyntax.asInstanceOf, DisableSyntax.isInstanceOf; JCA KeyPair returns java.security.Key requiring type-narrowing casts

class JwkSuite extends munit.FunSuite:

  // -- Test key generation helpers --

  private def generateEcKeyPair(curve: String) =
    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(ECGenParameterSpec(curve))
    kpg.generateKeyPair()

  private def generateRsaKeyPair(bits: Int) =
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(bits)
    kpg.generateKeyPair()

  private def generateHmacKey() =
    val kg = KeyGenerator.getInstance("HmacSHA256")
    kg.init(256)
    kg.generateKey()

  // -- EC public key round-trip tests --

  test("EC P-256 public key round-trip: JCA -> JWK -> JCA") {
    val kp = generateEcKeyPair("secp256r1")
    val pub = kp.getPublic.asInstanceOf[JcaEcPublicKey]
    val jwkResult = Jwk.from(pub, None)
    assert(jwkResult.isRight, jwkResult)
    val jwk = jwkResult.toOption.get
    assert(jwk.isInstanceOf[Jwk.EcPublicKey])
    val ecJwk = jwk.asInstanceOf[Jwk.EcPublicKey]
    assertEquals(ecJwk.crv, EcCurve.P256)

    val pubKeyResult = jwk.toPublicKey
    assert(pubKeyResult.isRight, pubKeyResult)
    val restored = pubKeyResult.toOption.get.asInstanceOf[JcaEcPublicKey]
    assertEquals(restored.getW.getAffineX, pub.getW.getAffineX)
    assertEquals(restored.getW.getAffineY, pub.getW.getAffineY)
  }

  test("EC P-384 public key round-trip: JCA -> JWK -> JCA") {
    val kp = generateEcKeyPair("secp384r1")
    val pub = kp.getPublic.asInstanceOf[JcaEcPublicKey]
    val jwkResult = Jwk.from(pub, None)
    assert(jwkResult.isRight, jwkResult)
    val ecJwk = jwkResult.toOption.get.asInstanceOf[Jwk.EcPublicKey]
    assertEquals(ecJwk.crv, EcCurve.P384)

    val pubKeyResult = jwkResult.toOption.get.toPublicKey
    assert(pubKeyResult.isRight, pubKeyResult)
  }

  test("EC P-521 public key round-trip: JCA -> JWK -> JCA") {
    val kp = generateEcKeyPair("secp521r1")
    val pub = kp.getPublic.asInstanceOf[JcaEcPublicKey]
    val jwkResult = Jwk.from(pub, None)
    assert(jwkResult.isRight, jwkResult)
    val ecJwk = jwkResult.toOption.get.asInstanceOf[Jwk.EcPublicKey]
    assertEquals(ecJwk.crv, EcCurve.P521)

    val pubKeyResult = jwkResult.toOption.get.toPublicKey
    assert(pubKeyResult.isRight, pubKeyResult)
  }

  // -- EC private key round-trip tests --

  test("EC P-256 private key round-trip: JCA -> JWK -> JCA") {
    val kp = generateEcKeyPair("secp256r1")
    val pub = kp.getPublic.asInstanceOf[JcaEcPublicKey]
    val priv = kp.getPrivate.asInstanceOf[JcaEcPrivateKey]
    val jwkResult = Jwk.from(priv, pub, Some(Kid.fromUnsafe("ec-test")))
    assert(jwkResult.isRight, jwkResult)
    val jwk = jwkResult.toOption.get
    assert(jwk.isInstanceOf[Jwk.EcPrivateKey])
    val ecJwk = jwk.asInstanceOf[Jwk.EcPrivateKey]
    assertEquals(ecJwk.crv, EcCurve.P256)
    assertEquals(ecJwk.kid, Some(Kid.fromUnsafe("ec-test")))

    val privKeyResult = jwk.toPrivateKey
    assert(privKeyResult.isRight, privKeyResult)

    // Public key extraction from private JWK also works
    val pubKeyResult = jwk.toPublicKey
    assert(pubKeyResult.isRight, pubKeyResult)
  }

  // -- RSA public key round-trip tests --

  test("RSA 2048 public key round-trip: JCA -> JWK -> JCA") {
    val kp = generateRsaKeyPair(2048)
    val pub = kp.getPublic.asInstanceOf[JcaRsaPublicKey]
    val jwkResult = Jwk.from(pub, Some(Kid.fromUnsafe("rsa-test")))
    assert(jwkResult.isRight, jwkResult)
    val jwk = jwkResult.toOption.get
    assert(jwk.isInstanceOf[Jwk.RsaPublicKey])
    assertEquals(jwk.keyId, Some(Kid.fromUnsafe("rsa-test")))

    val pubKeyResult = jwk.toPublicKey
    assert(pubKeyResult.isRight, pubKeyResult)
    val restored = pubKeyResult.toOption.get.asInstanceOf[JcaRsaPublicKey]
    assertEquals(restored.getModulus, pub.getModulus)
    assertEquals(restored.getPublicExponent, pub.getPublicExponent)
  }

  test("RSA 4096 public key round-trip: JCA -> JWK -> JCA") {
    val kp = generateRsaKeyPair(4096)
    val pub = kp.getPublic.asInstanceOf[JcaRsaPublicKey]
    val jwkResult = Jwk.from(pub, None)
    assert(jwkResult.isRight, jwkResult)
    val pubKeyResult = jwkResult.toOption.get.toPublicKey
    assert(pubKeyResult.isRight, pubKeyResult)
  }

  // -- RSA private key round-trip tests --

  test("RSA 2048 private key round-trip: JCA -> JWK -> JCA") {
    val kp = generateRsaKeyPair(2048)
    val pub = kp.getPublic.asInstanceOf[JcaRsaPublicKey]
    val priv = kp.getPrivate.asInstanceOf[JcaRsaPrivateCrtKey]
    val jwkResult = Jwk.from(priv, pub, Some(Kid.fromUnsafe("rsa-priv")))
    assert(jwkResult.isRight, jwkResult)
    val jwk = jwkResult.toOption.get
    assert(jwk.isInstanceOf[Jwk.RsaPrivateKey])

    val privKeyResult = jwk.toPrivateKey
    assert(privKeyResult.isRight, privKeyResult)

    // Public key also extractable
    val pubKeyResult = jwk.toPublicKey
    assert(pubKeyResult.isRight, pubKeyResult)
  }

  // -- Symmetric key round-trip --

  test("Symmetric key round-trip: JCA -> JWK -> JCA") {
    val key = generateHmacKey()
    val jwkResult = Jwk.from(key, Some(Kid.fromUnsafe("hmac-1")))
    assert(jwkResult.isRight, jwkResult)
    val jwk = jwkResult.toOption.get
    assert(jwk.isInstanceOf[Jwk.SymmetricKey])
    assertEquals(jwk.keyId, Some(Kid.fromUnsafe("hmac-1")))

    val secretKeyResult = jwk.toSecretKey
    assert(secretKeyResult.isRight, secretKeyResult)
    val restored = secretKeyResult.toOption.get
    assert(java.util.Arrays.equals(key.getEncoded, restored.getEncoded))
  }

  test("Symmetric key round-trip without kid") {
    val key = generateHmacKey()
    val jwkResult = Jwk.from(key)
    assert(jwkResult.isRight, jwkResult)
    assertEquals(jwkResult.toOption.get.keyId, None)
  }

  // -- RSA key size rejection --

  test("RSA key < 2048 bits rejected on JWK -> JCA conversion") {
    // Construct a small RSA JWK manually
    val smallN = Base64UrlString.fromUnsafe("AQAB") // too small
    val smallE = Base64UrlString.fromUnsafe("AQAB")
    val jwk = Jwk.RsaPublicKey(n = smallN, e = smallE, use = None, keyOps = None, alg = None, kid = None)
    val result = jwk.toPublicKey
    assert(result.isLeft)
    assert(result.swap.toOption.get.getMessage.contains("2048"))
  }

  test("RSA key < 2048 bits rejected on JCA -> JWK creation") {
    // Use a small key pair -- KeyFactory allows creating sub-2048 RSA keys
    val smallModulus = BigInteger.probablePrime(1024, java.security.SecureRandom())
    val exponent = BigInteger.valueOf(65537)
    val spec = RSAPublicKeySpec(smallModulus, exponent)
    val kf = KeyFactory.getInstance("RSA")
    val smallPub = kf.generatePublic(spec).asInstanceOf[JcaRsaPublicKey]

    val result = Jwk.from(smallPub, None)
    assert(result.isLeft)
    assert(result.swap.toOption.get.getMessage.contains("2048"))
  }

  // -- Type mismatch errors --

  test("toPublicKey fails for SymmetricKey") {
    val jwk = Jwk.SymmetricKey(
      k = Base64UrlString.fromUnsafe("dGVzdA"),
      use = None,
      keyOps = None,
      alg = None,
      kid = None
    )
    assert(jwk.toPublicKey.isLeft)
  }

  test("toPrivateKey fails for EcPublicKey") {
    val kp = generateEcKeyPair("secp256r1")
    val pub = kp.getPublic.asInstanceOf[JcaEcPublicKey]
    val jwk = Jwk.from(pub, None).toOption.get
    assert(jwk.toPrivateKey.isLeft)
  }

  test("toPrivateKey fails for RsaPublicKey") {
    val kp = generateRsaKeyPair(2048)
    val pub = kp.getPublic.asInstanceOf[JcaRsaPublicKey]
    val jwk = Jwk.from(pub, None).toOption.get
    assert(jwk.toPrivateKey.isLeft)
  }

  test("toPrivateKey fails for SymmetricKey") {
    val jwk = Jwk.SymmetricKey(
      k = Base64UrlString.fromUnsafe("dGVzdA"),
      use = None,
      keyOps = None,
      alg = None,
      kid = None
    )
    assert(jwk.toPrivateKey.isLeft)
  }

  test("toSecretKey fails for EcPublicKey") {
    val kp = generateEcKeyPair("secp256r1")
    val pub = kp.getPublic.asInstanceOf[JcaEcPublicKey]
    val jwk = Jwk.from(pub, None).toOption.get
    assert(jwk.toSecretKey.isLeft)
  }

  // -- Common field accessors --

  test("keyUse returns use for all variants") {
    val ecJwk = Jwk.EcPublicKey(
      crv = EcCurve.P256,
      x = Base64UrlString.fromUnsafe("dGVzdA"),
      y = Base64UrlString.fromUnsafe("dGVzdA"),
      use = Some(KeyUse.Sig),
      keyOps = None,
      alg = None,
      kid = None
    )
    assertEquals(ecJwk.keyUse, Some(KeyUse.Sig))

    val rsaJwk = Jwk.RsaPublicKey(
      n = Base64UrlString.fromUnsafe("dGVzdA"),
      e = Base64UrlString.fromUnsafe("AQAB"),
      use = Some(KeyUse.Enc),
      keyOps = None,
      alg = None,
      kid = None
    )
    assertEquals(rsaJwk.keyUse, Some(KeyUse.Enc))

    val symJwk = Jwk.SymmetricKey(
      k = Base64UrlString.fromUnsafe("dGVzdA"),
      use = None,
      keyOps = None,
      alg = None,
      kid = None
    )
    assertEquals(symJwk.keyUse, None)
  }

  test("keyOperations returns key_ops for all variants") {
    val ops = Chunk(KeyOp.Sign, KeyOp.Verify)
    val jwk = Jwk.EcPublicKey(
      crv = EcCurve.P384,
      x = Base64UrlString.fromUnsafe("dGVzdA"),
      y = Base64UrlString.fromUnsafe("dGVzdA"),
      use = None,
      keyOps = Some(ops),
      alg = None,
      kid = None
    )
    assertEquals(jwk.keyOperations, Some(ops))
  }

  test("keyAlgorithm returns alg for all variants") {
    val jwk = Jwk.SymmetricKey(
      k = Base64UrlString.fromUnsafe("dGVzdA"),
      use = None,
      keyOps = None,
      alg = Some(Algorithm.HS256),
      kid = None
    )
    assertEquals(jwk.keyAlgorithm, Some(Algorithm.HS256))
  }

  test("keyId returns kid for all variants") {
    val kid = Kid.fromUnsafe("test-kid")
    val jwk = Jwk.RsaPublicKey(
      n = Base64UrlString.fromUnsafe("dGVzdA"),
      e = Base64UrlString.fromUnsafe("AQAB"),
      use = None,
      keyOps = None,
      alg = None,
      kid = Some(kid)
    )
    assertEquals(jwk.keyId, Some(kid))
  }

  // -- Filtering tests (ss8.5) --

  test("suitableForVerification: no constraints passes") {
    val jwk = Jwk.EcPublicKey(
      crv = EcCurve.P256,
      x = Base64UrlString.fromUnsafe("dGVzdA"),
      y = Base64UrlString.fromUnsafe("dGVzdA"),
      use = None,
      keyOps = None,
      alg = None,
      kid = None
    )
    assert(jwk.suitableForVerification(Algorithm.ES256))
  }

  test("suitableForVerification: use=Sig passes") {
    val jwk = Jwk.EcPublicKey(
      crv = EcCurve.P256,
      x = Base64UrlString.fromUnsafe("dGVzdA"),
      y = Base64UrlString.fromUnsafe("dGVzdA"),
      use = Some(KeyUse.Sig),
      keyOps = None,
      alg = None,
      kid = None
    )
    assert(jwk.suitableForVerification(Algorithm.ES256))
  }

  test("suitableForVerification: use=Enc fails") {
    val jwk = Jwk.EcPublicKey(
      crv = EcCurve.P256,
      x = Base64UrlString.fromUnsafe("dGVzdA"),
      y = Base64UrlString.fromUnsafe("dGVzdA"),
      use = Some(KeyUse.Enc),
      keyOps = None,
      alg = None,
      kid = None
    )
    assert(!jwk.suitableForVerification(Algorithm.ES256))
  }

  test("suitableForVerification: key_ops containing Verify passes") {
    val jwk = Jwk.EcPublicKey(
      crv = EcCurve.P256,
      x = Base64UrlString.fromUnsafe("dGVzdA"),
      y = Base64UrlString.fromUnsafe("dGVzdA"),
      use = None,
      keyOps = Some(Chunk(KeyOp.Verify)),
      alg = None,
      kid = None
    )
    assert(jwk.suitableForVerification(Algorithm.ES256))
  }

  test("suitableForVerification: key_ops without Verify fails") {
    val jwk = Jwk.EcPublicKey(
      crv = EcCurve.P256,
      x = Base64UrlString.fromUnsafe("dGVzdA"),
      y = Base64UrlString.fromUnsafe("dGVzdA"),
      use = None,
      keyOps = Some(Chunk(KeyOp.Sign)),
      alg = None,
      kid = None
    )
    assert(!jwk.suitableForVerification(Algorithm.ES256))
  }

  test("suitableForVerification: matching alg passes") {
    val jwk = Jwk.EcPublicKey(
      crv = EcCurve.P256,
      x = Base64UrlString.fromUnsafe("dGVzdA"),
      y = Base64UrlString.fromUnsafe("dGVzdA"),
      use = None,
      keyOps = None,
      alg = Some(Algorithm.ES256),
      kid = None
    )
    assert(jwk.suitableForVerification(Algorithm.ES256))
  }

  test("suitableForVerification: mismatched alg fails") {
    val jwk = Jwk.EcPublicKey(
      crv = EcCurve.P256,
      x = Base64UrlString.fromUnsafe("dGVzdA"),
      y = Base64UrlString.fromUnsafe("dGVzdA"),
      use = None,
      keyOps = None,
      alg = Some(Algorithm.ES384),
      kid = None
    )
    assert(!jwk.suitableForVerification(Algorithm.ES256))
  }

  test("suitableForSigning: use=Sig, key_ops=Sign, matching alg passes") {
    val jwk = Jwk.EcPrivateKey(
      crv = EcCurve.P256,
      x = Base64UrlString.fromUnsafe("dGVzdA"),
      y = Base64UrlString.fromUnsafe("dGVzdA"),
      d = Base64UrlString.fromUnsafe("dGVzdA"),
      use = Some(KeyUse.Sig),
      keyOps = Some(Chunk(KeyOp.Sign)),
      alg = Some(Algorithm.ES256),
      kid = None
    )
    assert(jwk.suitableForSigning(Algorithm.ES256))
  }

  test("suitableForVerification companion alias works") {
    val jwk = Jwk.EcPublicKey(
      crv = EcCurve.P256,
      x = Base64UrlString.fromUnsafe("dGVzdA"),
      y = Base64UrlString.fromUnsafe("dGVzdA"),
      use = None,
      keyOps = None,
      alg = None,
      kid = None
    )
    // Companion alias (non-curried)
    assert(Jwk.suitableForVerification(jwk, Algorithm.ES256))
  }

  // -- EC point-on-curve validation during conversion --

  test("EC JWK with invalid point rejected") {
    // Use coordinates that are valid base64url but represent an invalid point
    val jwk = Jwk.EcPublicKey(
      crv = EcCurve.P256,
      x = Base64UrlString.fromUnsafe("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
      y = Base64UrlString.fromUnsafe("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
      use = None,
      keyOps = None,
      alg = None,
      kid = None
    )
    val result = jwk.toPublicKey
    assert(result.isLeft)
  }

  // -- CanEqual --

  test("Jwk derives CanEqual") {
    val a: Jwk = Jwk.SymmetricKey(
      k = Base64UrlString.fromUnsafe("dGVzdA"),
      use = None,
      keyOps = None,
      alg = None,
      kid = None
    )
    val b: Jwk = Jwk.SymmetricKey(
      k = Base64UrlString.fromUnsafe("dGVzdA"),
      use = None,
      keyOps = None,
      alg = None,
      kid = None
    )
    assertEquals(a, b)
  }
end JwkSuite
