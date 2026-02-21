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

/**
 * Service for fetching a [[JwkSet]] from a remote JWKS endpoint.
 * Construct via [[JwksFetcher$ JwksFetcher]].live.
 */
trait JwksFetcher:
  def fetch: IO[JwtError, JwkSet]

/**
 * Companion for [[JwksFetcher]]. Provides the live layer backed by [[zio.http.Client]].
 */
object JwksFetcher:

  /**
   * Constructs a [[JwksFetcher]] layer from [[Client]] and [[JwksProviderConfig]].
   * The JWK Set codec is injected via `using`.
   */
  def live(using jwkSetCodec: JwtCodec[JwkSet]): ZLayer[Client & JwksProviderConfig, Nothing, JwksFetcher] =
    ZLayer.fromZIO {
      for
        client <- ZIO.service[Client]
        config <- ZIO.service[JwksProviderConfig]
      yield LiveFetcher(client, config, jwkSetCodec)
    }

  private final class LiveFetcher(
      client: Client,
      config: JwksProviderConfig,
      jwkSetCodec: JwtCodec[JwkSet]
  ) extends JwksFetcher:

    def fetch: IO[JwtError, JwkSet] =
      val url = URL.fromURI(config.jwksUrl)
        .getOrElse(throw IllegalArgumentException(s"Invalid JWKS URL: ${config.jwksUrl}"))
      val request = Request.get(url)
      (for
        response <- Client.batched(request).mapError(e => JwtError.MalformedToken(e))
        _        <- ZIO.when(!response.status.isSuccess)(
                      ZIO.fail(JwtError.MalformedToken(
                        RuntimeException(s"JWKS fetch returned HTTP ${response.status.code}")
                      ))
                    )
        bytes    <- response.body.asArray.mapError(e => JwtError.MalformedToken(e))
        jwkSet   <- ZIO.fromEither(jwkSetCodec.decode(bytes).left.map(JwtError.MalformedToken(_)))
      yield jwkSet).provideEnvironment(zio.ZEnvironment(client))
