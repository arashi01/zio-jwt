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

import zio.Chunk

/** Cross-platform tests for [[Jwk]] data type (pure, no JCA). JVM-specific JCA conversion tests are
  * in `JwkJvmSuite`.
  */
class JwkSuite extends munit.FunSuite:

  // -- Common field accessor tests --

  test("use returns use for all variants") {
    val ecJwk = Jwk.EcPublicKey(
      crv = EcCurve.P256,
      x = Base64UrlString.fromUnsafe("dGVzdA"),
      y = Base64UrlString.fromUnsafe("dGVzdA"),
      use = Some(KeyUse.Sig),
      keyOps = None,
      alg = None,
      kid = None
    )
    assertEquals(ecJwk.use, Some(KeyUse.Sig))

    val rsaJwk = Jwk.RsaPublicKey(
      n = Base64UrlString.fromUnsafe("dGVzdA"),
      e = Base64UrlString.fromUnsafe("AQAB"),
      use = Some(KeyUse.Enc),
      keyOps = None,
      alg = None,
      kid = None
    )
    assertEquals(rsaJwk.use, Some(KeyUse.Enc))

    val symJwk = Jwk.SymmetricKey(
      k = Base64UrlString.fromUnsafe("dGVzdA"),
      use = None,
      keyOps = None,
      alg = None,
      kid = None
    )
    assertEquals(symJwk.use, None)
  }

  test("keyOps returns key_ops for all variants") {
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
    assertEquals(jwk.keyOps, Some(ops))
  }

  test("alg returns alg for all variants") {
    val jwk = Jwk.SymmetricKey(
      k = Base64UrlString.fromUnsafe("dGVzdA"),
      use = None,
      keyOps = None,
      alg = Some(Algorithm.HS256),
      kid = None
    )
    assertEquals(jwk.alg, Some(Algorithm.HS256))
  }

  test("kid returns kid for all variants") {
    val kid = Kid.fromUnsafe("test-kid")
    val jwk = Jwk.RsaPublicKey(
      n = Base64UrlString.fromUnsafe("dGVzdA"),
      e = Base64UrlString.fromUnsafe("AQAB"),
      use = None,
      keyOps = None,
      alg = None,
      kid = Some(kid)
    )
    assertEquals(jwk.kid, Some(kid))
  }

  // -- suitableForVerification / suitableForSigning tests --

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
