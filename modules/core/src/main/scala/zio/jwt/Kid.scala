package zio.jwt

import boilerplate.OpaqueType

/** Key identifier (RFC 7517 ss4.5). Non-empty string. */
opaque type Kid = String

/** Companion and [[OpaqueType]] instance for [[Kid]]. */
object Kid extends OpaqueType[Kid]:
  type Type  = String
  type Error = IllegalArgumentException

  inline def wrap(value: String): Kid   = value
  inline def unwrap(value: Kid): String = value

  override protected inline def validate(value: String): Option[IllegalArgumentException] =
    if value.isEmpty then Some(IllegalArgumentException("Kid must not be empty"))
    else None
end Kid
