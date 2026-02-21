package zio.jwt

import scala.annotation.targetName

import zio.NonEmptyChunk

/**
 * JWT audience claim (RFC 7519 ss4.1.3).
 * May be a single string or a non-empty array of strings.
 */
enum Audience derives CanEqual:
  case Single(value: String)
  case Many(values: NonEmptyChunk[String])

/** Companion for [[Audience]]. Provides smart constructors and query extensions. */
object Audience:

  def apply(value: String): Audience = Audience.Single(value)

  def apply(values: NonEmptyChunk[String]): Audience =
    if values.size == 1 then Audience.Single(values.head)
    else Audience.Many(values)

  extension (aud: Audience)

    /** All audience values as a non-empty collection. */
    @targetName("audienceValues")
    def values: NonEmptyChunk[String] = aud match
      case Audience.Single(v)  => NonEmptyChunk(v)
      case Audience.Many(vs) => vs

    /** Whether the audience contains the given target string. */
    @targetName("audienceContains")
    def contains(target: String): Boolean = aud match
      case Audience.Single(v)  => v == target
      case Audience.Many(vs) => vs.contains(target)
