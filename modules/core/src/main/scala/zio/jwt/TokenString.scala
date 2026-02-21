package zio.jwt

import boilerplate.OpaqueType

/**
 * Validated compact-serialisation JWT token (three dot-separated base64url segments).
 * Validation is a single-pass character scan per ss15 (no regular expressions).
 */
opaque type TokenString = String

/** Companion and [[OpaqueType]] instance for [[TokenString]]. */
object TokenString extends OpaqueType[TokenString]:
  type Type  = String
  type Error = IllegalArgumentException

  inline def wrap(value: String): TokenString   = value
  inline def unwrap(value: TokenString): String = value

  // Hotpath: single-pass scan counts dot separators, validates base64url alphabet,
  // and rejects empty segments -- avoids regex and intermediate allocations.
  override protected inline def validate(value: String): Option[IllegalArgumentException] =
    val len = value.length
    if len == 0 then Some(IllegalArgumentException("TokenString must not be empty"))
    else
      var i             = 0
      var dots          = 0
      var segmentLength = 0
      var valid         = true
      while i < len && valid do
        val c = value.charAt(i)
        if c == '.' then
          if segmentLength == 0 then valid = false
          else
            dots += 1
            segmentLength = 0
        else if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' then
          segmentLength += 1
        else valid = false
        i += 1
      if valid && dots == 2 && segmentLength > 0 then None
      else
        Some(
          IllegalArgumentException(
            "TokenString must be exactly three non-empty base64url segments separated by '.'"
          )
        )
end TokenString
