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
package zio.jwt.http

import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey as JcaEcPrivateKey
import java.security.interfaces.ECPublicKey as JcaEcPublicKey
import java.security.interfaces.EdECPrivateKey as JcaEdEcPrivateKey
import java.security.interfaces.EdECPublicKey as JcaEdEcPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator

import zio.Chunk

import com.github.plokhotnyuk.jsoniter_scala.core.*
import munit.FunSuite

import zio.jwt.*

class JwkCodecSuite extends FunSuite:

  // -- EcCurve codec --

  test("EcCurve round-trips through JSON") {
    for crv <- List(EcCurve.P256, EcCurve.P384, EcCurve.P521) do
      val bytes = writeToArray(crv)
      val decoded = readFromArray[EcCurve](bytes)
      assertEquals(decoded, crv)
  }

  test("EcCurve rejects unknown curve") {
    val ex = intercept[JsonReaderException] {
      readFromArray[EcCurve]("""  "P-999"  """.trim.getBytes)
    }
    assert(ex.getMessage.contains("unsupported EC curve"))
  }

  // -- KeyUse codec --

  test("KeyUse round-trips through JSON") {
    for u <- List(KeyUse.Sig, KeyUse.Enc) do
      val bytes = writeToArray(u)
      val decoded = readFromArray[KeyUse](bytes)
      assertEquals(decoded, u)
  }

  // -- KeyOp codec --

  test("KeyOp round-trips all variants") {
    val allOps = List(
      KeyOp.Sign,
      KeyOp.Verify,
      KeyOp.Encrypt,
      KeyOp.Decrypt,
      KeyOp.WrapKey,
      KeyOp.UnwrapKey,
      KeyOp.DeriveKey,
      KeyOp.DeriveBits
    )
    for op <- allOps do
      val bytes = writeToArray(op)
      val decoded = readFromArray[KeyOp](bytes)
      assertEquals(decoded, op)
  }

  // -- Jwk EC codec --

  test("EC public key round-trips through JSON") {
    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(ECGenParameterSpec("secp256r1"))
    val kp = kpg.generateKeyPair()
    val jwk = Jwk.from(kp.getPublic, Some(Kid.fromUnsafe("ec-pub-1"))).toOption.get
    val bytes = writeToArray(jwk)
    val decoded = readFromArray[Jwk](bytes)
    assertEquals(decoded, jwk)
  }

  test("EC private key round-trips through JSON") {
    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(ECGenParameterSpec("secp256r1"))
    val kp = kpg.generateKeyPair()
    val pub = kp.getPublic.asInstanceOf[JcaEcPublicKey] // scalafix:ok DisableSyntax.asInstanceOf; JCA KeyPair type narrowing
    val priv = kp.getPrivate.asInstanceOf[JcaEcPrivateKey] // scalafix:ok DisableSyntax.asInstanceOf; JCA KeyPair type narrowing
    val jwk = Jwk.from(priv, pub, Some(Kid.fromUnsafe("ec-priv-1"))).toOption.get
    val bytes = writeToArray(jwk)
    val decoded = readFromArray[Jwk](bytes)
    assertEquals(decoded, jwk)
  }

  // -- Jwk RSA codec --

  test("RSA public key round-trips through JSON") {
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(2048)
    val kp = kpg.generateKeyPair()
    val jwk = Jwk.from(kp.getPublic, Some(Kid.fromUnsafe("rsa-pub-1"))).toOption.get
    val bytes = writeToArray(jwk)
    val decoded = readFromArray[Jwk](bytes)
    assertEquals(decoded, jwk)
  }

  test("RSA private key round-trips through JSON") {
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(2048)
    val kp = kpg.generateKeyPair()
    val jwk = Jwk.from(kp.getPrivate, kp.getPublic, Some(Kid.fromUnsafe("rsa-priv-1"))).toOption.get
    val bytes = writeToArray(jwk)
    val decoded = readFromArray[Jwk](bytes)
    assertEquals(decoded, jwk)
  }

  // -- Jwk symmetric codec --

  test("symmetric key round-trips through JSON") {
    val kg = KeyGenerator.getInstance("HmacSHA256")
    kg.init(256)
    val key = kg.generateKey()
    val jwk = Jwk.from(key, Some(Kid.fromUnsafe("sym-1"))).toOption.get
    val bytes = writeToArray(jwk)
    val decoded = readFromArray[Jwk](bytes)
    assertEquals(decoded, jwk)
  }

  // -- Jwk with optional fields --

  test("Jwk encodes and decodes use and key_ops fields") {
    val jwk = Jwk.SymmetricKey(
      k = Base64UrlString.fromUnsafe("dGVzdA"),
      use = Some(KeyUse.Sig),
      keyOps = Some(Chunk(KeyOp.Sign, KeyOp.Verify)),
      alg = Some(Algorithm.HS256),
      kid = Some(Kid.fromUnsafe("test-kid"))
    )
    val bytes = writeToArray(jwk)
    val decoded = readFromArray[Jwk](bytes)
    assertEquals(decoded.use, Some(KeyUse.Sig))
    assertEquals(decoded.keyOps, Some(Chunk(KeyOp.Sign, KeyOp.Verify)))
    assertEquals(decoded.alg, Some(Algorithm.HS256))
    assertEquals(decoded.kid, Some(Kid.fromUnsafe("test-kid")))
  }

  // -- Jwk decoding errors --

  test("Jwk rejects missing kty") {
    val ex = intercept[JsonReaderException] {
      readFromArray[Jwk]("""{"k":"dGVzdA"}""".getBytes)
    }
    assert(ex.getMessage.contains("missing required field: kty"))
  }

  test("Jwk rejects unsupported kty") {
    val ex = intercept[JsonReaderException] {
      readFromArray[Jwk]("""{"kty":"UNKNOWN","x":"dGVzdA"}""".getBytes)
    }
    assert(ex.getMessage.contains("unsupported key type"))
  }

  // -- JwkSet codec --

  test("JwkSet round-trips through JSON") {
    val kg = KeyGenerator.getInstance("HmacSHA256")
    kg.init(256)
    val jwk1 = Jwk.from(kg.generateKey(), Some(Kid.fromUnsafe("k1"))).toOption.get
    val jwk2 = Jwk.from(kg.generateKey(), Some(Kid.fromUnsafe("k2"))).toOption.get
    val jwkSet = JwkSet(Chunk(jwk1, jwk2))
    val bytes = writeToArray(jwkSet)
    val decoded = readFromArray[JwkSet](bytes)
    assertEquals(decoded.keys.size, 2)
    assertEquals(decoded, jwkSet)
  }

  test("JwkSet decodes empty keys array") {
    val bytes = """{"keys":[]}""".getBytes
    val decoded = readFromArray[JwkSet](bytes)
    assertEquals(decoded.keys.size, 0)
  }

  test("JwkSet decodes object without keys field") {
    val bytes = """{"other":"value"}""".getBytes
    val decoded = readFromArray[JwkSet](bytes)
    assertEquals(decoded.keys.size, 0)
  }

  // -- Jwk JSON structure verification --

  test("EC public key JSON contains kty=EC and no d field") {
    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(ECGenParameterSpec("secp256r1"))
    val kp = kpg.generateKeyPair()
    val jwk = Jwk.from(kp.getPublic, None).toOption.get
    val json = new String(writeToArray(jwk))
    assert(json.contains(""""kty":"EC""""))
    assert(json.contains(""""crv":"P-256""""))
    assert(json.contains(""""x":"""))
    assert(json.contains(""""y":"""))
    assert(!json.contains(""""d":"""))
  }

  test("RSA private key JSON contains CRT parameters") {
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(2048)
    val kp = kpg.generateKeyPair()
    val jwk = Jwk.from(kp.getPrivate, kp.getPublic, None).toOption.get
    val json = new String(writeToArray(jwk))
    assert(json.contains(""""kty":"RSA""""))
    assert(json.contains(""""d":"""))
    assert(json.contains(""""p":"""))
    assert(json.contains(""""q":"""))
    assert(json.contains(""""dp":"""))
    assert(json.contains(""""dq":"""))
    assert(json.contains(""""qi":"""))
  }

  // -- Jwk OKP codec --

  test("OKP public key round-trips through JSON") {
    val kpg = KeyPairGenerator.getInstance("Ed25519")
    val kp = kpg.generateKeyPair()
    val jwk = Jwk.from(kp.getPublic, Some(Kid.fromUnsafe("okp-pub-1"))).toOption.get
    val bytes = writeToArray(jwk)
    val decoded = readFromArray[Jwk](bytes)
    assertEquals(decoded, jwk)
  }

  test("OKP private key round-trips through JSON") {
    val kpg = KeyPairGenerator.getInstance("Ed25519")
    val kp = kpg.generateKeyPair()
    val pub = kp.getPublic.asInstanceOf[JcaEdEcPublicKey] // scalafix:ok DisableSyntax.asInstanceOf; JCA KeyPair type narrowing
    val priv = kp.getPrivate.asInstanceOf[JcaEdEcPrivateKey] // scalafix:ok DisableSyntax.asInstanceOf; JCA KeyPair type narrowing
    val jwk = Jwk.from(priv, pub, Some(Kid.fromUnsafe("okp-priv-1"))).toOption.get
    val bytes = writeToArray(jwk)
    val decoded = readFromArray[Jwk](bytes)
    assertEquals(decoded, jwk)
  }

  test("OKP public key JSON contains kty=OKP and no d field") {
    val kpg = KeyPairGenerator.getInstance("Ed25519")
    val kp = kpg.generateKeyPair()
    val jwk = Jwk.from(kp.getPublic, None).toOption.get
    val json = new String(writeToArray(jwk))
    assert(json.contains(""""kty":"OKP""""))
    assert(json.contains(""""crv":"Ed25519""""))
    assert(json.contains(""""x":"""))
    assert(!json.contains(""""d":"""))
  }

  // -- OkpCurve codec --

  test("OkpCurve round-trips through JSON") {
    for crv <- List(OkpCurve.Ed25519, OkpCurve.Ed448) do
      val bytes = writeToArray(crv)
      val decoded = readFromArray[OkpCurve](bytes)
      assertEquals(decoded, crv)
  }

  test("OkpCurve rejects unknown curve") {
    val ex = intercept[JsonReaderException] {
      readFromArray[OkpCurve]("""  "X25519"  """.trim.getBytes)
    }
    assert(ex.getMessage.contains("unsupported OKP curve"))
  }
end JwkCodecSuite
