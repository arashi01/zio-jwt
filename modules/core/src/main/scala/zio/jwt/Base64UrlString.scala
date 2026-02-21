package zio.jwt

import boilerplate.OpaqueType

/** Validated base64url-encoded string without padding (RFC 4648 ss5). */
opaque type Base64UrlString = String

/** Companion and [[OpaqueType]] instance for [[Base64UrlString]]. */
object Base64UrlString extends OpaqueType[Base64UrlString]:
  type Type  = String
  type Error = IllegalArgumentException

  inline def wrap(value: String): Base64UrlString   = value
  inline def unwrap(value: Base64UrlString): String = value

  // Hotpath: single-pass character scan avoids regex allocation and backtracking.
  override protected inline def validate(value: String): Option[IllegalArgumentException] =
    val len = value.length
    if len == 0 then Some(IllegalArgumentException("Base64UrlString must not be empty"))
    else
      var i     = 0
      var valid = true
      while i < len && valid do
        val c = value.charAt(i)
        if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') then
          valid = false
        i += 1
      if valid then None
      else Some(IllegalArgumentException("Base64UrlString contains invalid base64url characters"))
end Base64UrlString
