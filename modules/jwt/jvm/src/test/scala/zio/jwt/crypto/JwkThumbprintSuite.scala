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

import zio.jwt.*

class JwkThumbprintSuite extends munit.FunSuite:

  // -- RFC 7638 §3.1 test vector --
  // The RSA public key from the RFC example:
  // {"e":"AQAB","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}
  // Expected thumbprint (SHA-256): NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs

  test("sha256 matches RFC 7638 §3.1 RSA test vector") {
    val rsaJwk = Jwk.RsaPublicKey(
      n =
        Base64UrlString.wrap("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"),
      e = Base64UrlString.wrap("AQAB"),
      use = None,
      keyOps = None,
      alg = None,
      kid = None
    )
    val result = JwkThumbprint.sha256(rsaJwk)
    assert(result.isRight, s"sha256 failed: ${result.left.toOption}")
    assertEquals(Base64UrlString.unwrap(result.toOption.get), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
  }

  test("sha256 ignores metadata fields (use, kid, key_ops, alg)") {
    // Same key as RFC test vector but with metadata
    val rsaJwkWithMeta = Jwk.RsaPublicKey(
      n =
        Base64UrlString.wrap("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"),
      e = Base64UrlString.wrap("AQAB"),
      use = Some(KeyUse.Sig),
      keyOps = None,
      alg = Some(Algorithm.RS256),
      kid = Some(Kid.wrap("my-key"))
    )
    val result = JwkThumbprint.sha256(rsaJwkWithMeta)
    assertEquals(Base64UrlString.unwrap(result.toOption.get), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
  }

  test("sha256 computes deterministic thumbprint for EC key") {
    val ecJwk = Jwk.EcPublicKey(
      crv = EcCurve.P256,
      x = Base64UrlString.wrap("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"),
      y = Base64UrlString.wrap("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"),
      use = None,
      keyOps = None,
      alg = None,
      kid = None
    )
    val result = JwkThumbprint.sha256(ecJwk)
    assert(result.isRight, s"sha256 failed: ${result.left.toOption}")
    // Verify determinism: compute twice
    val result2 = JwkThumbprint.sha256(ecJwk)
    assertEquals(result, result2)
  }

  test("sha256 produces same thumbprint for EC public and private key with same coordinates") {
    val pub = Jwk.EcPublicKey(
      crv = EcCurve.P256,
      x = Base64UrlString.wrap("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"),
      y = Base64UrlString.wrap("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"),
      use = None,
      keyOps = None,
      alg = None,
      kid = None
    )
    val priv = Jwk.EcPrivateKey(
      crv = EcCurve.P256,
      x = Base64UrlString.wrap("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"),
      y = Base64UrlString.wrap("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"),
      d = Base64UrlString.wrap("jpsQnnGQmL-YBIffS1BSyVKhrlRhDyL7JKFL6nt_C1M"),
      use = None,
      keyOps = None,
      alg = None,
      kid = None
    )
    val pubThumb = JwkThumbprint.sha256(pub)
    val privThumb = JwkThumbprint.sha256(priv)
    assertEquals(pubThumb, privThumb)
  }

  test("sha256 computes deterministic thumbprint for oct key") {
    val octJwk = Jwk.SymmetricKey(
      k = Base64UrlString.wrap("AyM32fdsuDqk442L4OA1m3LxpaT9zEv3vF46GAqR5EQ"),
      use = None,
      keyOps = None,
      alg = None,
      kid = None
    )
    val result = JwkThumbprint.sha256(octJwk)
    assert(result.isRight)
    val result2 = JwkThumbprint.sha256(octJwk)
    assertEquals(result, result2)
  }

  test("sha256 computes deterministic thumbprint for OKP key") {
    val okpJwk = Jwk.OkpPublicKey(
      crv = OkpCurve.Ed25519,
      x = Base64UrlString.wrap("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"),
      use = None,
      keyOps = None,
      alg = None,
      kid = None
    )
    val result = JwkThumbprint.sha256(okpJwk)
    assert(result.isRight)
    val result2 = JwkThumbprint.sha256(okpJwk)
    assertEquals(result, result2)
  }

  test("sha256 produces same thumbprint for OKP public and private key with same x coordinate") {
    val pub = Jwk.OkpPublicKey(
      crv = OkpCurve.Ed25519,
      x = Base64UrlString.wrap("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"),
      use = None,
      keyOps = None,
      alg = None,
      kid = None
    )
    val priv = Jwk.OkpPrivateKey(
      crv = OkpCurve.Ed25519,
      x = Base64UrlString.wrap("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"),
      d = Base64UrlString.wrap("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"),
      use = None,
      keyOps = None,
      alg = None,
      kid = None
    )
    val pubThumb = JwkThumbprint.sha256(pub)
    val privThumb = JwkThumbprint.sha256(priv)
    assertEquals(pubThumb, privThumb)
  }

  test("asKid returns a valid Kid from SHA-256 thumbprint") {
    val rsaJwk = Jwk.RsaPublicKey(
      n =
        Base64UrlString.wrap("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"),
      e = Base64UrlString.wrap("AQAB"),
      use = None,
      keyOps = None,
      alg = None,
      kid = None
    )
    val result = JwkThumbprint.asKid(rsaJwk)
    assert(result.isRight, s"asKid failed: ${result.left.toOption}")
    assertEquals(Kid.unwrap(result.toOption.get), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
  }

  test("compute with SHA-512 produces different thumbprint than SHA-256") {
    val rsaJwk = Jwk.RsaPublicKey(
      n =
        Base64UrlString.wrap("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"),
      e = Base64UrlString.wrap("AQAB"),
      use = None,
      keyOps = None,
      alg = None,
      kid = None
    )
    val sha256 = JwkThumbprint.sha256(rsaJwk)
    val sha512 = JwkThumbprint.compute(rsaJwk, "SHA-512")
    assert(sha256.isRight)
    assert(sha512.isRight)
    assertNotEquals(sha256, sha512)
  }

  test("compute with unknown algorithm returns Left") {
    val rsaJwk = Jwk.RsaPublicKey(
      n = Base64UrlString.wrap("AQAB"),
      e = Base64UrlString.wrap("AQAB"),
      use = None,
      keyOps = None,
      alg = None,
      kid = None
    )
    val result = JwkThumbprint.compute(rsaJwk, "UNKNOWN-HASH-ALG")
    assert(result.isLeft)
  }

end JwkThumbprintSuite
