package zio.jwt

import java.time.Duration

import zio.NonEmptyChunk

/**
 * Configuration for JWT token validation.
 * Instances may be constructed via [[ValidationConfig$ ValidationConfig]].
 */
final case class ValidationConfig(
    clockSkew: Duration,
    requiredIssuer: Option[String],
    requiredAudience: Option[String],
    requiredTyp: Option[String],
    allowedAlgorithms: NonEmptyChunk[Algorithm]
) derives CanEqual

/** Companion for [[ValidationConfig]]. */
object ValidationConfig
