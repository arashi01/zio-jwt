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

import zio.IO
import zio.ZIO
import zio.ZLayer
import zio.http.Client
import zio.http.Request
import zio.http.URL

import zio.jwt.JwkSet
import zio.jwt.JwtCodec
import zio.jwt.JwtError

/** Service for fetching a [[JwkSet]] from a remote JWKS endpoint. Construct via
  * [[JwksFetcher$ JwksFetcher]].live.
  */
trait JwksFetcher:
  def fetch: IO[JwtError, JwkSet]

/** Companion for [[JwksFetcher]]. Provides the live layer backed by [[zio.http.Client]]. */
object JwksFetcher:

  /** Constructs a [[JwksFetcher]] layer from [[Client]] and [[JwksProviderConfig]]. The JWK Set
    * codec is injected via `using`.
    */
  def live(using jwkSetCodec: JwtCodec[JwkSet]): ZLayer[Client & JwksProviderConfig, Nothing, JwksFetcher] =
    ZLayer.fromZIO {
      for
        client <- ZIO.service[Client]
        config <- ZIO.service[JwksProviderConfig]
      yield LiveFetcher(client, config, jwkSetCodec)
    }

  final private class LiveFetcher(
    client: Client,
    config: JwksProviderConfig,
    jwkSetCodec: JwtCodec[JwkSet]
  ) extends JwksFetcher:

    def fetch: IO[JwtError, JwkSet] =
      URL.fromURI(config.jwksUrl) match
        case None =>
          ZIO.fail(JwtError.MalformedToken(IllegalArgumentException(s"Invalid JWKS URL: ${config.jwksUrl}")))
        case Some(url) =>
          val request = Request.get(url)
          (for
            response <- Client.batched(request).mapError(e => JwtError.MalformedToken(e))
            _ <- ZIO.when(!response.status.isSuccess)(
                   ZIO.fail(
                     JwtError.MalformedToken(
                       RuntimeException(s"JWKS fetch returned HTTP ${response.status.code}")
                     )
                   )
                 )
            bytes <- response.body.asArray.mapError(e => JwtError.MalformedToken(e))
            jwkSet <- ZIO.fromEither(jwkSetCodec.decode(bytes).left.map(JwtError.MalformedToken(_)))
          yield jwkSet).provideEnvironment(zio.ZEnvironment(client))
  end LiveFetcher
end JwksFetcher
