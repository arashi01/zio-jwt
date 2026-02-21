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

import java.time.Duration

import zio.Chunk
import zio.Promise
import zio.Ref
import zio.Schedule
import zio.Scope
import zio.UIO
import zio.ZIO
import zio.ZLayer

import zio.jwt.Jwk
import zio.jwt.JwtError
import zio.jwt.KeySource

/** A [[KeySource]] backed by a remote JWKS endpoint with automatic background refresh. Uses a
  * [[Ref.Synchronized]] with [[Promise]] for stampede prevention -- concurrent callers during the
  * initial fetch await the same in-flight request.
  *
  * Construct via [[JwksProvider$ JwksProvider]].live.
  */
trait JwksProvider extends KeySource

/** Companion for [[JwksProvider]]. Provides the scoped live layer with background refresh. */
object JwksProvider:

  /** Constructs a scoped [[JwksProvider]] layer. A background fibre periodically refreshes keys
    * from the [[JwksFetcher]]. The fibre lifecycle is tied to the [[Scope]] -- releasing the scope
    * interrupts the fibre.
    *
    * Initial fetch retries with exponential backoff until successful. After the first success,
    * fetch failures retain last-known-good data.
    */
  def live: ZLayer[JwksFetcher & JwksProviderConfig & Scope, Nothing, JwksProvider] =
    ZLayer.fromZIO {
      for
        fetcher <- ZIO.service[JwksFetcher]
        config <- ZIO.service[JwksProviderConfig]
        initial <- Promise.make[Nothing, Chunk[Jwk]]
        ref <- Ref.Synchronized.make[ProviderState](ProviderState(initial, lastRefresh = None))
        provider = LiveProvider(ref)
        _ <- refreshLoop(fetcher, ref, config).forkScoped
      yield provider
    }

  final private case class ProviderState(
    promise: Promise[Nothing, Chunk[Jwk]],
    lastRefresh: Option[java.time.Instant]
  )

  final private class LiveProvider(
    ref: Ref.Synchronized[ProviderState]
  ) extends JwksProvider:
    def keys: UIO[Chunk[Jwk]] =
      ref.get.flatMap(_.promise.await)

  private def refreshLoop(
    fetcher: JwksFetcher,
    ref: Ref.Synchronized[ProviderState],
    config: JwksProviderConfig
  ): UIO[Unit] =
    val initialFetch = doFetch(fetcher, ref, config)
      .retry(Schedule.exponential(Duration.ofSeconds(1)) && Schedule.recurs(20))
      .orDie
    val periodicRefresh = (
      ZIO.sleep(zio.Duration.fromJava(config.refreshInterval)) *>
        doFetch(fetcher, ref, config).catchAll(_ => ZIO.unit)
    ).forever
    initialFetch *> periodicRefresh
  end refreshLoop

  private def doFetch(
    fetcher: JwksFetcher,
    ref: Ref.Synchronized[ProviderState],
    config: JwksProviderConfig
  ): ZIO[Any, JwtError, Unit] =
    zio.Clock.instant.flatMap { now =>
      ref.updateZIO { state =>
        val tooSoon = state.lastRefresh.exists { last =>
          java.time.Duration.between(last, now).compareTo(config.minRefreshInterval) < 0
        }
        if tooSoon then ZIO.succeed(state)
        else
          fetcher.fetch.flatMap { jwkSet =>
            for
              _ <- state.promise.succeed(jwkSet.keys)
              newPromise <- Promise.make[Nothing, Chunk[Jwk]]
              _ <- newPromise.succeed(jwkSet.keys)
            yield ProviderState(newPromise, Some(now))
          }
      }
    }
end JwksProvider
