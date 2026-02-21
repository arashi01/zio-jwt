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
import javax.crypto.KeyGenerator

import zio.Chunk
import zio.IO
import zio.Ref
import zio.Scope
import zio.ZIO
import zio.ZLayer

import munit.ZSuite

import zio.jwt.*

class JwksProviderSuite extends ZSuite:

  // -- Test key generation --

  private def generateHmacJwk(kid: String): Jwk =
    val kg = KeyGenerator.getInstance("HmacSHA256")
    kg.init(256)
    Jwk.from(kg.generateKey(), Some(Kid.fromUnsafe(kid))).toOption.get

  // -- Stub JwksFetcher --

  private class StubFetcher(ref: Ref[Int], keys: Int => IO[JwtError, JwkSet]) extends JwksFetcher:
    def fetch: IO[JwtError, JwkSet] =
      ref.getAndUpdate(_ + 1).flatMap(keys)

  // -- Provider config with short intervals --

  private val quickConfig = JwksProviderConfig(
    jwksUrl = java.net.URI.create("https://example.com/.well-known/jwks.json"),
    refreshInterval = Duration.ofMillis(50),
    minRefreshInterval = Duration.ofMillis(10)
  )

  // -- Tests --

  testZ("provides keys from initial fetch") {
    val jwk = generateHmacJwk("k1")
    ZIO.scoped {
      for
        callCount <- Ref.make(0)
        fetcher = StubFetcher(callCount, _ => ZIO.succeed(JwkSet(Chunk(jwk))))
        provider <- JwksProvider.live.build
                      .provideSome[Scope](
                        ZLayer.succeed(fetcher: JwksFetcher),
                        ZLayer.succeed(quickConfig)
                      )
                      .map(_.get[JwksProvider])
        keys <- provider.keys
      yield assertEquals(keys.size, 1)
    }
  }

  testZ("refreshes keys periodically") {
    val jwk1 = generateHmacJwk("k1")
    val jwk2 = generateHmacJwk("k2")
    ZIO.scoped {
      for
        callCount <- Ref.make(0)
        fetcher = StubFetcher(callCount,
                              n =>
                                if n == 0 then ZIO.succeed(JwkSet(Chunk(jwk1)))
                                else ZIO.succeed(JwkSet(Chunk(jwk1, jwk2)))
                  )
        provider <- JwksProvider.live.build
                      .provideSome[Scope](
                        ZLayer.succeed(fetcher: JwksFetcher),
                        ZLayer.succeed(quickConfig)
                      )
                      .map(_.get[JwksProvider])
        // Wait for initial fetch + at least one refresh
        _ <- ZIO.sleep(zio.Duration.fromMillis(200))
        keys <- provider.keys
        count <- callCount.get
      yield
        assert(count >= 2, s"Expected at least 2 fetch calls, got $count")
        assertEquals(keys.size, 2)
    }
  }

  testZ("retains last-known-good keys on fetch failure after initial success") {
    val jwk = generateHmacJwk("good-key")
    ZIO.scoped {
      for
        callCount <- Ref.make(0)
        fetcher = StubFetcher(callCount,
                              n =>
                                if n == 0 then ZIO.succeed(JwkSet(Chunk(jwk)))
                                else ZIO.fail(JwtError.MalformedToken(RuntimeException("network error")))
                  )
        provider <- JwksProvider.live.build
                      .provideSome[Scope](
                        ZLayer.succeed(fetcher: JwksFetcher),
                        ZLayer.succeed(quickConfig)
                      )
                      .map(_.get[JwksProvider])
        // Wait for initial + failed refresh attempts
        _ <- ZIO.sleep(zio.Duration.fromMillis(200))
        keys <- provider.keys
      yield
        // Should still have the initial good keys
        assertEquals(keys.size, 1)
        assertEquals(keys.head.keyId, Some(Kid.fromUnsafe("good-key")))
    }
  }

  testZ("rate-limits fetches via minRefreshInterval") {
    val jwk = generateHmacJwk("rl")
    val slowConfig = quickConfig.copy(
      refreshInterval = Duration.ofMillis(10),
      minRefreshInterval = Duration.ofMillis(500)
    )
    ZIO.scoped {
      for
        callCount <- Ref.make(0)
        fetcher = StubFetcher(callCount, _ => ZIO.succeed(JwkSet(Chunk(jwk))))
        provider <- JwksProvider.live.build
                      .provideSome[Scope](
                        ZLayer.succeed(fetcher: JwksFetcher),
                        ZLayer.succeed(slowConfig)
                      )
                      .map(_.get[JwksProvider])
        _ <- ZIO.sleep(zio.Duration.fromMillis(200))
        count <- callCount.get
      yield
        // With 500ms min refresh and only 200ms elapsed, should be 1 (initial) + maybe 1 more
        assert(count <= 2, s"Expected at most 2 fetches, got $count (rate limiting should prevent more)")
    }
  }
end JwksProviderSuite
