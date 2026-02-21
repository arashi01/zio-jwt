package zio.jwt

/** JOSE header (RFC 7515 ss4). */
final case class JoseHeader(
    alg: Algorithm,
    typ: Option[String],
    cty: Option[String],
    kid: Option[Kid]
) derives CanEqual

/** Companion for [[JoseHeader]]. */
object JoseHeader
