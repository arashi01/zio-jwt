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

import scala.annotation.targetName

import zio.Chunk

/** JSON Web Key (RFC 7517) ADT. Instances may be constructed directly or via platform-specific
  * factory methods (e.g. `Jwk.from` on JVM).
  *
  * Extends [[JwkMetadata]] so that common parameters (`use`, `keyOps`, `alg`, `kid`) are accessible
  * without pattern matching.
  */
enum Jwk extends JwkMetadata derives CanEqual:
  case EcPublicKey(
    crv: EcCurve,
    x: Base64UrlString,
    y: Base64UrlString,
    use: Option[KeyUse],
    keyOps: Option[Chunk[KeyOp]],
    alg: Option[Algorithm],
    kid: Option[Kid]
  )
  case EcPrivateKey(
    crv: EcCurve,
    x: Base64UrlString,
    y: Base64UrlString,
    d: Base64UrlString,
    use: Option[KeyUse],
    keyOps: Option[Chunk[KeyOp]],
    alg: Option[Algorithm],
    kid: Option[Kid]
  )
  case RsaPublicKey(
    n: Base64UrlString,
    e: Base64UrlString,
    use: Option[KeyUse],
    keyOps: Option[Chunk[KeyOp]],
    alg: Option[Algorithm],
    kid: Option[Kid]
  )
  case RsaPrivateKey(
    n: Base64UrlString,
    e: Base64UrlString,
    d: Base64UrlString,
    p: Base64UrlString,
    q: Base64UrlString,
    dp: Base64UrlString,
    dq: Base64UrlString,
    qi: Base64UrlString,
    use: Option[KeyUse],
    keyOps: Option[Chunk[KeyOp]],
    alg: Option[Algorithm],
    kid: Option[Kid]
  )
  case SymmetricKey(
    k: Base64UrlString,
    use: Option[KeyUse],
    keyOps: Option[Chunk[KeyOp]],
    alg: Option[Algorithm],
    kid: Option[Kid]
  )
  case OkpPublicKey(
    crv: OkpCurve,
    x: Base64UrlString,
    use: Option[KeyUse],
    keyOps: Option[Chunk[KeyOp]],
    alg: Option[Algorithm],
    kid: Option[Kid]
  )
  case OkpPrivateKey(
    crv: OkpCurve,
    x: Base64UrlString,
    d: Base64UrlString,
    use: Option[KeyUse],
    keyOps: Option[Chunk[KeyOp]],
    alg: Option[Algorithm],
    kid: Option[Kid]
  )
end Jwk

/** Companion for [[Jwk]]. Provides filtering extensions and multi-parameter aliases. */
object Jwk:

  extension (jwk: Jwk)

    /** Tests whether this key is suitable for signature verification. */
    @targetName("jwkSuitableForVerification")
    def suitableForVerification(headerAlg: Algorithm): Boolean =
      val useOk = jwk.use.forall(_ == KeyUse.Sig)
      val opsOk = jwk.keyOps.forall(_.contains(KeyOp.Verify))
      val algOk = jwk.alg.forall(_ == headerAlg)
      useOk && opsOk && algOk

    /** Tests whether this key is suitable for signing. */
    @targetName("jwkSuitableForSigning")
    def suitableForSigning(headerAlg: Algorithm): Boolean =
      val useOk = jwk.use.forall(_ == KeyUse.Sig)
      val opsOk = jwk.keyOps.forall(_.contains(KeyOp.Sign))
      val algOk = jwk.alg.forall(_ == headerAlg)
      useOk && opsOk && algOk
  end extension

  // Multi-parameter extension aliases

  /** Tests whether a key is suitable for signature verification with the given algorithm. */
  inline def suitableForVerification(jwk: Jwk, alg: Algorithm): Boolean =
    jwk.suitableForVerification(alg)

  /** Tests whether a key is suitable for signing with the given algorithm. */
  inline def suitableForSigning(jwk: Jwk, alg: Algorithm): Boolean =
    jwk.suitableForSigning(alg)
end Jwk
