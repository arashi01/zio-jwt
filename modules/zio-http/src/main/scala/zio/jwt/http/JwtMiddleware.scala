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

  /**
   * Bearer token authentication middleware.
   * Extracts the `Authorization: Bearer <token>` header, validates the token
   * via [[JwtValidator]], and provides the decoded [[Jwt]] as handler context.
   *
   * Returns HTTP 401 Unauthorized with a `WWW-Authenticate: Bearer` header
   * when the token is missing or invalid.
   */
  def bearer[A: JwtCodec]: HandlerAspect[JwtValidator, Jwt[A]] =
    HandlerAspect.customAuthProvidingZIO(
      provide = request =>
        request.header(Header.Authorization) match
          case Some(Header.Authorization.Bearer(token)) =>
            val raw = token.value.asString
            TokenString.from(raw) match
              case Left(_) => ZIO.succeed(None)
              case Right(ts) =>
                ZIO.serviceWithZIO[JwtValidator](_.validate[A](ts))
                  .fold(_ => None, jwt => Some(jwt))
          case _ => ZIO.succeed(None),
      responseHeaders = Headers(Header.WWWAuthenticate.Bearer(realm = "Access")),
      responseStatus = Status.Unauthorized
    )
