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
package zio.jwt.crypto

import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

import zio.jwt.*

class SignatureEngineSuite extends munit.FunSuite:

  // -- Key fixtures (lazy to avoid generation cost when not needed) --

  private lazy val hmac256Key: SecretKey =
    val kg = KeyGenerator.getInstance("HmacSHA256")
    kg.generateKey()

  private lazy val hmac384Key: SecretKey =
    val kg = KeyGenerator.getInstance("HmacSHA384")
    kg.generateKey()

  private lazy val hmac512Key: SecretKey =
    val kg = KeyGenerator.getInstance("HmacSHA512")
    kg.generateKey()

  private lazy val rsaKeyPair =
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(2048)
    kpg.generateKeyPair()

  private lazy val weakRsaKeyPair =
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(1024)
    kpg.generateKeyPair()

  private lazy val ec256KeyPair =
    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(ECGenParameterSpec("secp256r1"))
    kpg.generateKeyPair()

  private lazy val ec384KeyPair =
    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(ECGenParameterSpec("secp384r1"))
    kpg.generateKeyPair()

  private lazy val ec521KeyPair =
    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(ECGenParameterSpec("secp521r1"))
    kpg.generateKeyPair()

  private val testData = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0".getBytes(java.nio.charset.StandardCharsets.US_ASCII)

  // -- HMAC tests --

  test("HMAC HS256 sign and verify round-trip") {
    assertHmacRoundTrip(hmac256Key, Algorithm.HS256)
  }

  test("HMAC HS384 sign and verify round-trip") {
    assertHmacRoundTrip(hmac384Key, Algorithm.HS384)
  }

  test("HMAC HS512 sign and verify round-trip") {
    assertHmacRoundTrip(hmac512Key, Algorithm.HS512)
  }

  test("HMAC HS256 rejects short key (RFC 7518 ss3.2)") {
    val shortKey = SecretKeySpec(new Array[Byte](16), "HmacSHA256")
    val result = SignatureEngine.sign(testData, shortKey, Algorithm.HS256)
    assert(result.isLeft)
    result.left.toOption.get match
      case JwtError.InvalidKey(msg) => assert(msg.contains("256 bits"), s"Unexpected message: $msg")
      case other                    => fail(s"Expected InvalidKey, got $other")
  }

  test("HMAC HS384 rejects short key (RFC 7518 ss3.2)") {
    val shortKey = SecretKeySpec(new Array[Byte](32), "HmacSHA384")
    val result = SignatureEngine.sign(testData, shortKey, Algorithm.HS384)
    assert(result.isLeft)
    result.left.toOption.get match
      case JwtError.InvalidKey(msg) => assert(msg.contains("384 bits"), s"Unexpected message: $msg")
      case other                    => fail(s"Expected InvalidKey, got $other")
  }

  test("HMAC HS512 rejects short key (RFC 7518 ss3.2)") {
    val shortKey = SecretKeySpec(new Array[Byte](48), "HmacSHA512")
    val result = SignatureEngine.sign(testData, shortKey, Algorithm.HS512)
    assert(result.isLeft)
    result.left.toOption.get match
      case JwtError.InvalidKey(msg) => assert(msg.contains("512 bits"), s"Unexpected message: $msg")
      case other                    => fail(s"Expected InvalidKey, got $other")
  }

  test("HMAC verify also rejects short key (RFC 7518 ss3.2)") {
    val shortKey = SecretKeySpec(new Array[Byte](16), "HmacSHA256")
    val result = SignatureEngine.verify(testData, new Array[Byte](32), shortKey, Algorithm.HS256)
    assert(result.isLeft)
    result.left.toOption.get match
      case JwtError.InvalidKey(_) => () // expected
      case other                  => fail(s"Expected InvalidKey, got $other")
  }

  test("HMAC accepts exact minimum key size") {
    val exactKey = SecretKeySpec(new Array[Byte](32), "HmacSHA256")
    val result = SignatureEngine.sign(testData, exactKey, Algorithm.HS256)
    assert(result.isRight, s"Expected Right but got $result")
  }

  test("HMAC rejects tampered signature") {
    val sig = SignatureEngine.sign(testData, hmac256Key, Algorithm.HS256)
    assert(sig.isRight)
    val bytes = sig.toOption.get
    bytes(0) = (bytes(0) ^ 0xff).toByte // flip bits
    val result = SignatureEngine.verify(testData, bytes, hmac256Key, Algorithm.HS256)
    assertEquals(result, Left(JwtError.InvalidSignature))
  }

  test("HMAC rejects tampered data") {
    val sig = SignatureEngine.sign(testData, hmac256Key, Algorithm.HS256)
    assert(sig.isRight)
    val tampered = "tampered.data".getBytes("US-ASCII")
    val result = SignatureEngine.verify(tampered, sig.toOption.get, hmac256Key, Algorithm.HS256)
    assertEquals(result, Left(JwtError.InvalidSignature))
  }

  // -- RSA tests --

  test("RSA RS256 sign and verify round-trip") {
    assertAsymmetricRoundTrip(Algorithm.RS256)
  }

  test("RSA RS384 sign and verify round-trip") {
    assertAsymmetricRoundTrip(Algorithm.RS384)
  }

  test("RSA RS512 sign and verify round-trip") {
    assertAsymmetricRoundTrip(Algorithm.RS512)
  }

  test("RSA rejects weak key on sign") {
    val result = SignatureEngine.sign(testData, weakRsaKeyPair.getPrivate, Algorithm.RS256)
    assert(result.isLeft)
    result.left.toOption.get match
      case JwtError.InvalidKey(_) => () // expected
      case other                  => fail(s"Expected InvalidKey, got $other")
  }

  test("RSA rejects weak key on verify") {
    val result = SignatureEngine.verify(testData, Array[Byte](1), weakRsaKeyPair.getPublic, Algorithm.RS256)
    assert(result.isLeft)
    result.left.toOption.get match
      case JwtError.InvalidKey(_) => () // expected
      case other                  => fail(s"Expected InvalidKey, got $other")
  }

  // -- ECDSA tests --

  test("ECDSA ES256 sign and verify round-trip") {
    assertEcRoundTrip(ec256KeyPair, Algorithm.ES256)
  }

  test("ECDSA ES384 sign and verify round-trip") {
    assertEcRoundTrip(ec384KeyPair, Algorithm.ES384)
  }

  test("ECDSA ES512 sign and verify round-trip") {
    assertEcRoundTrip(ec521KeyPair, Algorithm.ES512)
  }

  test("ECDSA produces fixed-length signature") {
    val sig = SignatureEngine.sign(testData, ec256KeyPair.getPrivate, Algorithm.ES256)
    assert(sig.isRight)
    assertEquals(sig.toOption.get.length, 64)
  }

  test("ECDSA rejects tampered signature") {
    val sig = SignatureEngine.sign(testData, ec256KeyPair.getPrivate, Algorithm.ES256)
    assert(sig.isRight)
    val bytes = sig.toOption.get
    bytes(0) = (bytes(0) ^ 0xff).toByte
    val result = SignatureEngine.verify(testData, bytes, ec256KeyPair.getPublic, Algorithm.ES256)
    assert(result.isLeft)
  }

  test("ECDSA rejects all-zero signature (CVE-2022-21449)") {
    val sig = new Array[Byte](64)
    val result = SignatureEngine.verify(testData, sig, ec256KeyPair.getPublic, Algorithm.ES256)
    assertEquals(result, Left(JwtError.InvalidSignature))
  }

  // -- RSA-PSS tests --

  test("RSA-PSS PS256 sign and verify round-trip") {
    assertAsymmetricRoundTrip(Algorithm.PS256)
  }

  test("RSA-PSS PS384 sign and verify round-trip") {
    assertAsymmetricRoundTrip(Algorithm.PS384)
  }

  test("RSA-PSS PS512 sign and verify round-trip") {
    assertAsymmetricRoundTrip(Algorithm.PS512)
  }

  test("RSA-PSS rejects weak key") {
    val result = SignatureEngine.sign(testData, weakRsaKeyPair.getPrivate, Algorithm.PS256)
    assert(result.isLeft)
    result.left.toOption.get match
      case JwtError.InvalidKey(_) => ()
      case other                  => fail(s"Expected InvalidKey, got $other")
  }

  // -- EdDSA tests --

  private lazy val ed25519KeyPair =
    val kpg = KeyPairGenerator.getInstance("Ed25519")
    kpg.generateKeyPair()

  test("EdDSA Ed25519 sign and verify round-trip") {
    val sig = SignatureEngine.sign(testData, ed25519KeyPair.getPrivate, Algorithm.EdDSA)
    assert(sig.isRight, s"sign failed: ${sig.left.toOption}")
    val result = SignatureEngine.verify(testData, sig.toOption.get, ed25519KeyPair.getPublic, Algorithm.EdDSA)
    assertEquals(result, Right(()))
  }

  test("EdDSA rejects zero-length signature") {
    val result = SignatureEngine.verify(testData, Array.emptyByteArray, ed25519KeyPair.getPublic, Algorithm.EdDSA)
    assertEquals(result, Left(JwtError.InvalidSignature))
  }

  test("EdDSA rejects wrong-length signature (truncated)") {
    val sig = SignatureEngine.sign(testData, ed25519KeyPair.getPrivate, Algorithm.EdDSA)
    assert(sig.isRight)
    val truncated = sig.toOption.get.take(32)
    val result = SignatureEngine.verify(testData, truncated, ed25519KeyPair.getPublic, Algorithm.EdDSA)
    assertEquals(result, Left(JwtError.InvalidSignature))
  }

  test("EdDSA rejects all-zero 64-byte signature") {
    val allZero = new Array[Byte](64)
    val result = SignatureEngine.verify(testData, allZero, ed25519KeyPair.getPublic, Algorithm.EdDSA)
    assertEquals(result, Left(JwtError.InvalidSignature))
  }

  test("EdDSA rejects oversized signature") {
    val oversized = new Array[Byte](128)
    val result = SignatureEngine.verify(testData, oversized, ed25519KeyPair.getPublic, Algorithm.EdDSA)
    assertEquals(result, Left(JwtError.InvalidSignature))
  }

  // -- Key type mismatch tests --

  test("sign with SecretKey rejects non-HMAC algorithm") {
    val result = SignatureEngine.sign(testData, hmac256Key, Algorithm.RS256)
    assert(result.isLeft)
  }

  test("sign with PrivateKey rejects HMAC algorithm") {
    val result = SignatureEngine.sign(testData, rsaKeyPair.getPrivate, Algorithm.HS256)
    assert(result.isLeft)
  }

  test("verify with SecretKey rejects non-HMAC algorithm") {
    val result = SignatureEngine.verify(testData, Array[Byte](1), hmac256Key, Algorithm.RS256)
    assert(result.isLeft)
  }

  test("verify with PublicKey rejects HMAC algorithm") {
    val result = SignatureEngine.verify(testData, Array[Byte](1), rsaKeyPair.getPublic, Algorithm.HS256)
    assert(result.isLeft)
  }

  // -- Helpers --

  private def assertHmacRoundTrip(key: SecretKey, alg: Algorithm)(using loc: munit.Location): Unit =
    val sig = SignatureEngine.sign(testData, key, alg)
    assert(sig.isRight, s"sign failed: ${sig.left.toOption}")
    val result = SignatureEngine.verify(testData, sig.toOption.get, key, alg)
    assertEquals(result, Right(()))

  private def assertAsymmetricRoundTrip(alg: Algorithm)(using loc: munit.Location): Unit =
    val sig = SignatureEngine.sign(testData, rsaKeyPair.getPrivate, alg)
    assert(sig.isRight, s"sign failed: ${sig.left.toOption}")
    val result = SignatureEngine.verify(testData, sig.toOption.get, rsaKeyPair.getPublic, alg)
    assertEquals(result, Right(()))

  private def assertEcRoundTrip(kp: java.security.KeyPair, alg: Algorithm)(using loc: munit.Location): Unit =
    val sig = SignatureEngine.sign(testData, kp.getPrivate, alg)
    assert(sig.isRight, s"sign failed: ${sig.left.toOption}")
    val result = SignatureEngine.verify(testData, sig.toOption.get, kp.getPublic, alg)
    assertEquals(result, Right(()))
end SignatureEngineSuite
