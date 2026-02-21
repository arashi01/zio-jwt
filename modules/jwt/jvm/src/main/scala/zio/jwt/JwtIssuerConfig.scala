package zio.jwt

/**
 * Configuration for JWT token issuance.
 * The issuer constructs the JOSE header from these settings.
 * Instances may be constructed via [[JwtIssuerConfig$ JwtIssuerConfig]].
 */
final case class JwtIssuerConfig(
    algorithm: Algorithm,
    kid: Option[Kid],
    typ: Option[String],
    cty: Option[String]
) derives CanEqual

/** Companion for [[JwtIssuerConfig]]. */
object JwtIssuerConfig
