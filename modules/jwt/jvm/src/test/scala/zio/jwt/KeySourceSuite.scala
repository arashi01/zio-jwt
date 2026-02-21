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

import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey as JcaEcPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator

import zio.Chunk

import munit.ZSuite

class KeySourceSuite extends ZSuite:

  // -- Test key generation helpers --

  private def generateEcKeyPair(curve: String) =
    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(ECGenParameterSpec(curve))
    kpg.generateKeyPair()

  private def generateHmacKey() =
    val kg = KeyGenerator.getInstance("HmacSHA256")
    kg.init(256)
    kg.generateKey()

  private def ecJwk(kid: Option[Kid], alg: Option[Algorithm], use: Option[KeyUse], keyOps: Option[Chunk[KeyOp]]): Jwk =
    val kp = generateEcKeyPair("secp256r1")
    val pub = kp.getPublic.asInstanceOf[JcaEcPublicKey] // scalafix:ok DisableSyntax.asInstanceOf; JCA KeyPair type narrowing
    val base = Jwk.from(pub, kid).toOption.get.asInstanceOf[Jwk.EcPublicKey] // scalafix:ok DisableSyntax.asInstanceOf; JWK variant narrowing
    base.copy(alg = alg, use = use, keyOps = keyOps)

  // -- Static factory --

  testZ("KeySource.static(Chunk) returns all keys") {
    val key1 = ecJwk(Some(Kid.fromUnsafe("k1")), None, None, None)
    val key2 = ecJwk(Some(Kid.fromUnsafe("k2")), None, None, None)
    val source = KeySource.static(Chunk(key1, key2))
    source.keys.map(keys => assertEquals(keys.size, 2))
  }

  testZ("KeySource.static(jwk) wraps single key") {
    val key = ecJwk(Some(Kid.fromUnsafe("k1")), None, None, None)
    val source = KeySource.static(key)
    source.keys.map(keys => assertEquals(keys.size, 1))
  }

  // -- Key resolution by kid --

  testZ("resolvePublicKey selects key with matching kid") {
    val key1 = ecJwk(Some(Kid.fromUnsafe("k1")), None, None, None)
    val key2 = ecJwk(Some(Kid.fromUnsafe("k2")), None, None, None)
    val source = KeySource.static(Chunk(key1, key2))
    val header = JoseHeader(alg = Algorithm.ES256, typ = None, cty = None, kid = Some(Kid.fromUnsafe("k2")))
    source.resolvePublicKey(header).map(k => assert(k != null)) // scalafix:ok DisableSyntax.null; asserting JCA key resolved
  }

  testZ("resolvePublicKey fails with KeyNotFound for missing kid") {
    val key1 = ecJwk(Some(Kid.fromUnsafe("k1")), None, None, None)
    val source = KeySource.static(key1)
    val header = JoseHeader(alg = Algorithm.ES256, typ = None, cty = None, kid = Some(Kid.fromUnsafe("missing")))
    source.resolvePublicKey(header).either.map { result =>
      assert(result.isLeft)
      result.swap.toOption.get match
        case JwtError.KeyNotFound(kid) =>
          assertEquals(kid, Some(Kid.fromUnsafe("missing")))
        case other => fail(s"Expected KeyNotFound, got $other")
    }
  }

  // -- Key resolution without kid --

  testZ("resolvePublicKey succeeds when no kid and exactly one key matches") {
    val key = ecJwk(None, None, None, None)
    val source = KeySource.static(key)
    val header = JoseHeader(alg = Algorithm.ES256, typ = None, cty = None, kid = None)
    source.resolvePublicKey(header).map(k => assert(k != null)) // scalafix:ok DisableSyntax.null; asserting JCA key resolved
  }

  testZ("resolvePublicKey fails when no kid and multiple keys match") {
    val key1 = ecJwk(None, None, None, None)
    val key2 = ecJwk(None, None, None, None)
    val source = KeySource.static(Chunk(key1, key2))
    val header = JoseHeader(alg = Algorithm.ES256, typ = None, cty = None, kid = None)
    source.resolvePublicKey(header).either.map { result =>
      assert(result.isLeft)
      result.swap.toOption.get match
        case JwtError.KeyNotFound(None) => () // expected
        case other                      => fail(s"Expected KeyNotFound(None), got $other")
    }
  }

  testZ("resolvePublicKey fails when no keys at all") {
    val source = KeySource.static(Chunk.empty[Jwk])
    val header = JoseHeader(alg = Algorithm.ES256, typ = None, cty = None, kid = None)
    source.resolvePublicKey(header).either.map { result =>
      assert(result.isLeft)
      result.swap.toOption.get match
        case JwtError.KeyNotFound(_) => () // expected
        case other                   => fail(s"Expected KeyNotFound, got $other")
    }
  }

  // -- Filtering by use --

  testZ("resolvePublicKey filters by use=Sig") {
    val sigKey = ecJwk(Some(Kid.fromUnsafe("sig")), None, Some(KeyUse.Sig), None)
    val encKey = ecJwk(Some(Kid.fromUnsafe("enc")), None, Some(KeyUse.Enc), None)
    val source = KeySource.static(Chunk(sigKey, encKey))
    val header = JoseHeader(alg = Algorithm.ES256, typ = None, cty = None, kid = Some(Kid.fromUnsafe("sig")))
    source.resolvePublicKey(header).map(_ => ())
  }

  testZ("resolvePublicKey rejects key with use=Enc") {
    val encKey = ecJwk(Some(Kid.fromUnsafe("enc")), None, Some(KeyUse.Enc), None)
    val source = KeySource.static(encKey)
    val header = JoseHeader(alg = Algorithm.ES256, typ = None, cty = None, kid = Some(Kid.fromUnsafe("enc")))
    source.resolvePublicKey(header).either.map(r => assert(r.isLeft))
  }

  // -- Filtering by key_ops --

  testZ("resolvePublicKey filters by key_ops containing Verify") {
    val verifyKey = ecJwk(Some(Kid.fromUnsafe("v")), None, None, Some(Chunk(KeyOp.Verify)))
    val signKey = ecJwk(Some(Kid.fromUnsafe("s")), None, None, Some(Chunk(KeyOp.Sign)))
    val source = KeySource.static(Chunk(verifyKey, signKey))
    val header = JoseHeader(alg = Algorithm.ES256, typ = None, cty = None, kid = Some(Kid.fromUnsafe("v")))
    source.resolvePublicKey(header).map(_ => ())
  }

  testZ("resolvePublicKey rejects key with key_ops=Sign only") {
    val signKey = ecJwk(Some(Kid.fromUnsafe("s")), None, None, Some(Chunk(KeyOp.Sign)))
    val source = KeySource.static(signKey)
    val header = JoseHeader(alg = Algorithm.ES256, typ = None, cty = None, kid = Some(Kid.fromUnsafe("s")))
    source.resolvePublicKey(header).either.map(r => assert(r.isLeft))
  }

  // -- Filtering by alg --

  testZ("resolvePublicKey filters by matching alg") {
    val es256Key = ecJwk(Some(Kid.fromUnsafe("k1")), Some(Algorithm.ES256), None, None)
    val es384Key = ecJwk(Some(Kid.fromUnsafe("k2")), Some(Algorithm.ES384), None, None)
    val source = KeySource.static(Chunk(es256Key, es384Key))
    val header = JoseHeader(alg = Algorithm.ES256, typ = None, cty = None, kid = Some(Kid.fromUnsafe("k1")))
    source.resolvePublicKey(header).map(_ => ())
  }

  testZ("resolvePublicKey rejects key with mismatched alg") {
    val es384Key = ecJwk(Some(Kid.fromUnsafe("k1")), Some(Algorithm.ES384), None, None)
    val source = KeySource.static(es384Key)
    val header = JoseHeader(alg = Algorithm.ES256, typ = None, cty = None, kid = Some(Kid.fromUnsafe("k1")))
    source.resolvePublicKey(header).either.map(r => assert(r.isLeft))
  }

  // -- Secret key resolution --

  testZ("resolveSecretKey succeeds for symmetric key") {
    val hmacKey = generateHmacKey()
    val jwk = Jwk.from(hmacKey, Some(Kid.fromUnsafe("hmac-1"))).toOption.get
    val source = KeySource.static(jwk)
    val header = JoseHeader(alg = Algorithm.HS256, typ = None, cty = None, kid = Some(Kid.fromUnsafe("hmac-1")))
    source.resolveSecretKey(header).map(_ => ())
  }

  // -- Companion alias for resolution --

  testZ("KeySource.resolvePublicKey companion alias works") {
    val key = ecJwk(None, None, None, None)
    val source = KeySource.static(key)
    val header = JoseHeader(alg = Algorithm.ES256, typ = None, cty = None, kid = None)
    KeySource.resolvePublicKey(source, header).map(_ => ())
  }
end KeySourceSuite
