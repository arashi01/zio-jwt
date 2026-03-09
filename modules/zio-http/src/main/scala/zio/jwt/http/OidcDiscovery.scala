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

import java.net.URI
import java.time.Duration

import zio.Scope
import zio.ZIO
import zio.ZLayer
import zio.http.Client
import zio.http.Request
import zio.http.URL

import boilerplate.nullable.*
import com.github.plokhotnyuk.jsoniter_scala.core.*

import zio.jwt.JwkSet
import zio.jwt.JwtCodec
import zio.jwt.JwtError

// scalafix:off DisableSyntax.var, DisableSyntax.null, DisableSyntax.asInstanceOf; jsoniter-scala codec API requires mutable state and null sentinels

/** OpenID Connect Discovery 1.0. Fetches provider metadata from
  * `{issuerUrl}/.well-known/openid-configuration` and extracts the JWKS URI.
  */
object OidcDiscovery:

  /** Fetches the `jwks_uri` from the OIDC discovery document at
    * `{issuerUrl}/.well-known/openid-configuration`.
    */
  def jwksUri(issuerUrl: URI): ZIO[Client, JwtError, URI] =
    for
      _ <- ZIO.fromEither(validateHttpsIssuer(issuerUrl))
      discoveryUrl <- ZIO.fromEither(buildDiscoveryUrl(issuerUrl))
      uri <- fetchJwksUri(discoveryUrl)
      _ <- ZIO.fromEither(validateHttpsJwks(uri))
    yield uri

  /** Constructs a complete [[JwksProvider]] layer from an OIDC issuer URL. Internally fetches the
    * discovery document, extracts `jwks_uri`, and delegates to [[JwksProvider.fromUrl]].
    */
  def provider(
    issuerUrl: URI,
    refreshInterval: Duration,
    minRefreshInterval: Duration
  )(using JwtCodec[JwkSet]): ZLayer[Client & Scope, JwtError, JwksProvider] =
    ZLayer.fromZIO {
      jwksUri(issuerUrl).flatMap { uri =>
        JwksProvider
          .fromUrl(uri, refreshInterval, minRefreshInterval)
          .build
          .map(_.get[JwksProvider])
      }
    }

  // -- Private helpers --

  private inline def validateHttpsIssuer(url: URI): Either[JwtError, Unit] =
    val scheme = url.getScheme.option.getOrElse("null")
    Either.cond(
      scheme == "https",
      (),
      JwtError.FetchError(s"OIDC issuer URL must use HTTPS scheme, got: $scheme")
    )

  private inline def validateHttpsJwks(url: URI): Either[JwtError, Unit] =
    val scheme = url.getScheme.option.getOrElse("null")
    Either.cond(
      scheme == "https",
      (),
      JwtError.FetchError(s"OIDC jwks_uri must use HTTPS scheme, got: $scheme")
    )

  private def buildDiscoveryUrl(issuerUrl: URI): Either[JwtError, URL] =
    val issuerStr = issuerUrl.toString.stripSuffix("/")
    val discoveryStr = s"$issuerStr/.well-known/openid-configuration"
    scala.util
      .Try(URI.create(discoveryStr))
      .toEither
      .left
      .map(e => JwtError.FetchError(s"Invalid discovery URL: ${e.getMessage.option.getOrElse("unknown")}"))
      .flatMap { uri =>
        URL.fromURI(uri).toRight(JwtError.FetchError(s"Invalid discovery URL: $discoveryStr"))
      }

  private def fetchJwksUri(discoveryUrl: URL): ZIO[Client, JwtError, URI] =
    for
      client <- ZIO.service[Client]
      response <- Client
                    .batched(Request.get(discoveryUrl))
                    .mapError(e => JwtError.FetchError(s"OIDC discovery fetch failed: ${e.getMessage.option.getOrElse("unknown")}"))
                    .provideEnvironment(zio.ZEnvironment(client))
      _ <- ZIO.when(!response.status.isSuccess)(
             ZIO.fail(JwtError.FetchError(s"OIDC discovery returned HTTP ${response.status.code}"))
           )
      bytes <- response.body.asArray
                 .mapError(e => JwtError.FetchError(s"OIDC discovery body read failed: ${e.getMessage.option.getOrElse("unknown")}"))
      jwksUriStr <- ZIO.fromEither(parseJwksUri(bytes))
      uri <- ZIO
               .attempt(URI.create(jwksUriStr))
               .mapError(e => JwtError.FetchError(s"Invalid jwks_uri value: ${e.getMessage.option.getOrElse("unknown")}"))
    yield uri

  /** Minimal JSON parser: extracts only the `jwks_uri` field from the discovery document. */
  private def parseJwksUri(bytes: Array[Byte]): Either[JwtError, String] =
    scala.util
      .Try {
        readFromArray(bytes)(using discoveryCodec)
      }
      .toEither
      .left
      .map {
        case e: JsonReaderException => JwtError.DecodeError(s"OIDC discovery parse error: ${e.getMessage.option.getOrElse("unknown")}")
        case e                      => JwtError.FetchError(s"OIDC discovery parse error: ${e.getMessage.option.getOrElse("unknown")}")
      }

  /** Private codec that extracts only the `jwks_uri` field, ignoring everything else. */
  private val discoveryCodec: JsonValueCodec[String] = new JsonValueCodec[String]:
    override def decodeValue(in: JsonReader, default: String): String =
      if !in.isNextToken('{') then in.decodeError("expected '{'")
      var jwksUri: String | Null = null
      var seen = false
      if !in.isNextToken('}') then
        in.rollbackToken()
        while
          val key = in.readKeyAsString()
          if key == "jwks_uri" then
            seen = true
            jwksUri = in.readString("")
          else in.skip()
          in.isNextToken(',')
        do ()
      if !seen then in.decodeError("missing required field: jwks_uri")
      jwksUri.asInstanceOf[String] // scalafix:ok
    end decodeValue

    override def encodeValue(x: String, out: JsonWriter): Unit =
      out.writeObjectStart()
      out.writeKey("jwks_uri")
      out.writeVal(x)
      out.writeObjectEnd()

    override def nullValue: String = null.asInstanceOf[String]
  end discoveryCodec

  // scalafix:on

end OidcDiscovery
