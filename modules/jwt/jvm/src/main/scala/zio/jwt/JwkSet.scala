package zio.jwt

import zio.Chunk

/**
 * JSON Web Key Set (RFC 7517 ss5).
 * Instances may be constructed directly or decoded via [[JwkSet$ JwkSet]].
 */
final case class JwkSet(keys: Chunk[Jwk]) derives CanEqual

/** Companion for [[JwkSet]]. */
object JwkSet
