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

import zio.Scope
import zio.ZIO
import zio.ZLayer
import zio.http.*

import munit.ZSuite

import zio.jwt.JwtError

class OidcDiscoverySuite extends ZSuite:

  // -- Mock Client via ZClient.Driver --

  /** Creates a Client layer backed by an in-memory driver that dispatches to the given routes. */
  private def mockClientLayer(routes: Routes[Any, Response]): ZLayer[Any, Nothing, Client] =
    val driver = new ZClient.Driver[Any, Scope, Throwable]:
      override def request(
        version: Version,
        method: Method,
        url: URL,
        headers: Headers,
        body: Body,
        sslConfig: Option[ClientSSLConfig],
        proxy: Option[Proxy]
      )(implicit trace: zio.Trace): ZIO[Scope, Throwable, Response] =
        val req = Request(
          body = body,
          headers = headers,
          method = method,
          url = url.relative,
          version = version,
          remoteAddress = None
        )
        routes(req).merge
      end request

      override def socket[Env1](
        version: Version,
        url: URL,
        headers: Headers,
        app: WebSocketApp[Env1]
      )(implicit trace: zio.Trace, ev: Scope =:= Scope): ZIO[Env1 & Scope, Throwable, Response] =
        ZIO.succeed(Response.status(Status.NotImplemented))
    ZLayer.succeed(ZClient.fromDriver(driver))
  end mockClientLayer

  /** Convenience: builds routes that respond to GET /.well-known/openid-configuration. */
  private def discoveryRoutes(body: String, status: Status = Status.Ok): Routes[Any, Response] =
    Routes(
      Method.GET / ".well-known" / "openid-configuration" -> handler(
        Response(status = status, body = Body.fromString(body))
      )
    ) // scalafix:ok

  // -- Tests --

  testZ("jwksUri extracts jwks_uri from discovery document") {
    val discovery =
      """{"issuer":"https://example.com","jwks_uri":"https://example.com/.well-known/jwks.json","token_endpoint":"https://example.com/oauth/token"}"""
    OidcDiscovery
      .jwksUri(URI.create("https://example.com"))
      .provide(mockClientLayer(discoveryRoutes(discovery)))
      .map { uri =>
        assertEquals(uri.toString, "https://example.com/.well-known/jwks.json")
      }
  }

  testZ("jwksUri works when jwks_uri appears after other fields") {
    val discovery =
      """{"issuer":"https://example.com","token_endpoint":"https://example.com/oauth/token","jwks_uri":"https://example.com/keys"}"""
    OidcDiscovery
      .jwksUri(URI.create("https://example.com"))
      .provide(mockClientLayer(discoveryRoutes(discovery)))
      .map { uri =>
        assertEquals(uri.toString, "https://example.com/keys")
      }
  }

  testZ("jwksUri strips trailing slash from issuer URL") {
    val discovery =
      """{"jwks_uri":"https://example.com/.well-known/jwks.json"}"""
    OidcDiscovery
      .jwksUri(URI.create("https://example.com/"))
      .provide(mockClientLayer(discoveryRoutes(discovery)))
      .map { uri =>
        assertEquals(uri.toString, "https://example.com/.well-known/jwks.json")
      }
  }

  testZ("jwksUri rejects non-HTTPS issuer URL") {
    OidcDiscovery
      .jwksUri(URI.create("http://example.com"))
      .provide(mockClientLayer(discoveryRoutes("{}")))
      .either
      .map { result =>
        assert(result.isLeft)
        result.left.toOption.get match
          case JwtError.FetchError(msg) =>
            assert(msg.contains("HTTPS"), s"Expected HTTPS error, got: $msg")
          case other =>
            fail(s"Expected FetchError, got: $other")
      }
  }

  testZ("jwksUri rejects non-HTTPS jwks_uri in discovery document") {
    val discovery = """{"jwks_uri":"http://example.com/keys"}"""
    OidcDiscovery
      .jwksUri(URI.create("https://example.com"))
      .provide(mockClientLayer(discoveryRoutes(discovery)))
      .either
      .map { result =>
        assert(result.isLeft)
        result.left.toOption.get match
          case JwtError.FetchError(msg) =>
            assert(msg.contains("HTTPS"), s"Expected HTTPS error, got: $msg")
          case other =>
            fail(s"Expected FetchError, got: $other")
      }
  }

  testZ("jwksUri fails when discovery document is missing jwks_uri") {
    val discovery = """{"issuer":"https://example.com"}"""
    OidcDiscovery
      .jwksUri(URI.create("https://example.com"))
      .provide(mockClientLayer(discoveryRoutes(discovery)))
      .either
      .map { result =>
        assert(result.isLeft)
      }
  }

  testZ("jwksUri fails when discovery endpoint returns HTTP error") {
    OidcDiscovery
      .jwksUri(URI.create("https://example.com"))
      .provide(mockClientLayer(discoveryRoutes("{}", Status.InternalServerError)))
      .either
      .map { result =>
        assert(result.isLeft)
        result.left.toOption.get match
          case JwtError.FetchError(msg) =>
            assert(msg.contains("500") || msg.contains("HTTP"), s"Expected HTTP error, got: $msg")
          case other =>
            fail(s"Expected FetchError, got: $other")
      }
  }

  testZ("jwksUri fails with malformed JSON") {
    OidcDiscovery
      .jwksUri(URI.create("https://example.com"))
      .provide(mockClientLayer(discoveryRoutes("not json")))
      .either
      .map { result =>
        assert(result.isLeft)
      }
  }

end OidcDiscoverySuite
