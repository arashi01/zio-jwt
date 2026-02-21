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

import zio.ZIO
import zio.http.HandlerAspect
import zio.http.Header
import zio.http.Headers
import zio.http.Status

import zio.jwt.Jwt
import zio.jwt.JwtCodec
import zio.jwt.JwtValidator
import zio.jwt.TokenString

/** JWT authentication middleware for zio-http. */
object JwtMiddleware:

  /** Bearer token authentication middleware. Extracts the `Authorization: Bearer <token>` header,
    * validates the token via [[JwtValidator]], and provides the decoded [[Jwt]] as handler context.
    *
    * Returns HTTP 401 Unauthorized with a `WWW-Authenticate: Bearer` header when the token is
    * missing or invalid.
    */
  def bearer[A: JwtCodec]: HandlerAspect[JwtValidator, Jwt[A]] =
    HandlerAspect.customAuthProvidingZIO(
      provide = request =>
        request.header(Header.Authorization) match
          case Some(Header.Authorization.Bearer(token)) =>
            val raw = token.value.asString
            TokenString.from(raw) match
              case Left(_)   => ZIO.succeed(None)
              case Right(ts) =>
                ZIO
                  .serviceWithZIO[JwtValidator](_.validate[A](ts))
                  .fold(_ => None, jwt => Some(jwt))
          case _ => ZIO.succeed(None),
      responseHeaders = Headers(Header.WWWAuthenticate.Bearer(realm = "Access")),
      responseStatus = Status.Unauthorized
    )
end JwtMiddleware
