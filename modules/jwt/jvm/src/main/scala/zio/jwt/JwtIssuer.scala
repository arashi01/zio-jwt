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

import java.nio.charset.StandardCharsets

import zio.IO
import zio.ZIO
import zio.ZLayer

import zio.jwt.crypto.SignatureEngine

/** Service for issuing JWT tokens. Instances live in the ZIO environment; construct via
  * [[JwtIssuer$ JwtIssuer]].live.
  */
trait JwtIssuer:
  def issue[A: JwtCodec](claims: A, registeredClaims: RegisteredClaims): IO[JwtError, TokenString]

/** Companion for [[JwtIssuer]]. Provides the live layer. */
object JwtIssuer:

  /** Constructs a [[JwtIssuer]] layer from [[JwtIssuerConfig]] and [[KeySource]]. Codec instances
    * are injected via `using` parameters.
    */
  def live(using
    headerCodec: JwtCodec[JoseHeader],
    claimsCodec: JwtCodec[RegisteredClaims]
  ): ZLayer[JwtIssuerConfig & KeySource, Nothing, JwtIssuer] =
    ZLayer.fromZIO {
      for
        config <- ZIO.service[JwtIssuerConfig]
        keySource <- ZIO.service[KeySource]
      yield LiveIssuer(config, keySource, headerCodec, claimsCodec)
    }

  private val base64UrlEncoder = java.util.Base64.getUrlEncoder.withoutPadding()

  private inline def base64UrlEncode(bytes: Array[Byte]): String =
    import scala.language.unsafeNulls
    base64UrlEncoder.encodeToString(bytes)

  /** Merges two JSON objects at byte level. Fields from `secondary` appear after `primary` in the
    * output, giving secondary precedence on field collisions (last-occurrence-wins).
    */
  private inline def mergeJsonObjects(primary: Array[Byte], secondary: Array[Byte]): Array[Byte] =
    val pLen = primary.length
    val sLen = secondary.length
    if pLen <= 2 then secondary
    else if sLen <= 2 then primary
    else
      // primary = { ...contents1... }  (pLen bytes)
      // secondary = { ...contents2... }  (sLen bytes)
      // result = { contents1 , contents2 }
      val result = new Array[Byte](pLen + sLen - 1)
      result(0) = '{'.toByte
      System.arraycopy(primary, 1, result, 1, pLen - 2)
      result(pLen - 1) = ','.toByte
      System.arraycopy(secondary, 1, result, pLen, sLen - 2)
      result(pLen + sLen - 2) = '}'.toByte
      result
    end if
  end mergeJsonObjects

  // -- Live implementation --

  final private class LiveIssuer(
    config: JwtIssuerConfig,
    keySource: KeySource,
    headerCodec: JwtCodec[JoseHeader],
    claimsCodec: JwtCodec[RegisteredClaims]
  ) extends JwtIssuer:

    def issue[A: JwtCodec](claims: A, registeredClaims: RegisteredClaims): IO[JwtError, TokenString] =
      val header = JoseHeader(config.algorithm, config.typ, config.cty, config.kid)
      val headerB64 = base64UrlEncode(headerCodec.encode(header))
      val customBytes = summon[JwtCodec[A]].encode(claims)
      val registeredBytes = claimsCodec.encode(registeredClaims)
      val payloadB64 = base64UrlEncode(mergeJsonObjects(customBytes, registeredBytes))
      val signingInput = s"$headerB64.$payloadB64".getBytes(StandardCharsets.US_ASCII)
      for
        signatureBytes <- sign(header, signingInput)
        signatureB64 = base64UrlEncode(signatureBytes)
        tokenRaw = s"$headerB64.$payloadB64.$signatureB64"
        token <- ZIO.fromEither(TokenString.from(tokenRaw).left.map(e => JwtError.MalformedToken(e)))
      yield token
    end issue

    private inline def sign(header: JoseHeader, data: Array[Byte]): IO[JwtError, Array[Byte]] =
      header.alg.family match
        case AlgorithmFamily.HMAC =>
          keySource.resolveSigningSecretKey(header).flatMap { key =>
            ZIO.fromEither(SignatureEngine.sign(data, key, header.alg))
          }
        case _ =>
          keySource.resolveSigningPrivateKey(header).flatMap { key =>
            ZIO.fromEither(SignatureEngine.sign(data, key, header.alg))
          }
  end LiveIssuer
end JwtIssuer
