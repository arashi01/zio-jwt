package zio.jwt

/** Registered claim names (RFC 7519 ss4.1). */
final case class RegisteredClaims(
    iss: Option[String],
    sub: Option[String],
    aud: Option[Audience],
    exp: Option[NumericDate],
    nbf: Option[NumericDate],
    iat: Option[NumericDate],
    jti: Option[String]
) derives CanEqual

/** Companion for [[RegisteredClaims]]. */
object RegisteredClaims
