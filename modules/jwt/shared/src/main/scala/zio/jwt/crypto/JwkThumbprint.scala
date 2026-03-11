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

import java.nio.charset.StandardCharsets

import boilerplate.nullable.*

import zio.jwt.*

/** JWK Thumbprint computation per RFC 7638. Computes a deterministic hash of a JWK's required
  * members, enabling key identification by content hash rather than `kid`.
  *
  * The thumbprint is computed by constructing a canonical JSON representation of the required
  * members (sorted in lexicographic order per RFC 7638 ss3.2), hashing with the specified
  * algorithm, and base64url-encoding the result.
  */
object JwkThumbprint:

  /** Computes the JWK Thumbprint using SHA-256 (the default per RFC 7638 ss3.1). */
  def sha256(jwk: Jwk): Either[JwtError, Base64UrlString] =
    compute(jwk, "SHA-256")

  /** Computes the JWK Thumbprint using the specified hash algorithm. */
  def compute(jwk: Jwk, hashAlgorithm: String): Either[JwtError, Base64UrlString] =
    val canonicalJson = canonicalMembers(jwk)
    val jsonBytes = canonicalJson.getBytes(StandardCharsets.UTF_8)
    PlatformDigest
      .digest(hashAlgorithm, jsonBytes)
      .map(hash => Base64UrlString.encode(hash))

  /** Computes the SHA-256 thumbprint and wraps it as a [[Kid]] for use as a key identifier. */
  def asKid(jwk: Jwk): Either[JwtError, Kid] =
    sha256(jwk).flatMap(b64 => Kid.from(Base64UrlString.unwrap(b64)).left.map(e => JwtError.InvalidKey(e.getMessage.getOrElse("invalid kid"))))

  // -- Canonical JSON per RFC 7638 §3.2 --
  // Required members in Unicode code-point order per key type.

  private def canonicalMembers(jwk: Jwk): String = jwk match
    case ec: Jwk.EcPublicKey    => ecCanonical(ec.crv, ec.x, ec.y)
    case ec: Jwk.EcPrivateKey   => ecCanonical(ec.crv, ec.x, ec.y)
    case rsa: Jwk.RsaPublicKey  => rsaCanonical(rsa.e, rsa.n)
    case rsa: Jwk.RsaPrivateKey => rsaCanonical(rsa.e, rsa.n)
    case sym: Jwk.SymmetricKey  => octCanonical(sym.k)
    case okp: Jwk.OkpPublicKey  => okpCanonical(okp.crv, okp.x)
    case okp: Jwk.OkpPrivateKey => okpCanonical(okp.crv, okp.x)

  // EC: {"crv":"...","kty":"EC","x":"...","y":"..."}
  private inline def ecCanonical(crv: EcCurve, x: Base64UrlString, y: Base64UrlString): String =
    val c = crv.name
    val xStr = Base64UrlString.unwrap(x)
    val yStr = Base64UrlString.unwrap(y)
    s"""{"crv":"$c","kty":"EC","x":"$xStr","y":"$yStr"}"""

  // RSA: {"e":"...","kty":"RSA","n":"..."}
  private inline def rsaCanonical(e: Base64UrlString, n: Base64UrlString): String =
    val eStr = Base64UrlString.unwrap(e)
    val nStr = Base64UrlString.unwrap(n)
    s"""{"e":"$eStr","kty":"RSA","n":"$nStr"}"""

  // oct: {"k":"...","kty":"oct"}
  private inline def octCanonical(k: Base64UrlString): String =
    val kStr = Base64UrlString.unwrap(k)
    s"""{"k":"$kStr","kty":"oct"}"""

  // OKP: {"crv":"...","kty":"OKP","x":"..."}
  private inline def okpCanonical(crv: OkpCurve, x: Base64UrlString): String =
    val c = crv.name
    val xStr = Base64UrlString.unwrap(x)
    s"""{"crv":"$c","kty":"OKP","x":"$xStr"}"""

end JwkThumbprint
