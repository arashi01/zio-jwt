package zio.jwt

import java.time.Instant

import scala.annotation.targetName

import boilerplate.OpaqueType

/** Epoch-seconds date as per RFC 7519 ss2. Wraps [[java.time.Instant]]. */
opaque type NumericDate = Instant

/** Companion and [[OpaqueType]] instance for [[NumericDate]]. */
object NumericDate extends OpaqueType[NumericDate]:
  type Type  = Instant
  type Error = IllegalArgumentException

  inline def wrap(value: Instant): NumericDate   = value
  inline def unwrap(value: NumericDate): Instant = value

  override protected inline def validate(value: Instant): Option[IllegalArgumentException] = None

  inline def fromEpochSecond(epoch: Long): NumericDate = Instant.ofEpochSecond(epoch)

  extension (nd: NumericDate)
    @targetName("numericDateToEpochSecond")
    inline def toEpochSecond: Long = nd.getEpochSecond
end NumericDate
