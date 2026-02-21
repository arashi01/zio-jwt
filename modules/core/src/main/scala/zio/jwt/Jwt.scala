package zio.jwt

/**
 * Decoded JWT envelope carrying the header, user custom claims, and registered claims.
 * The custom claims type `A` is the full payload (or a projection thereof)
 * decoded by the user-supplied codec.
 */
final case class Jwt[+A](
    header: JoseHeader,
    claims: A,
    registeredClaims: RegisteredClaims
) derives CanEqual

/** Companion for [[Jwt]]. */
object Jwt
