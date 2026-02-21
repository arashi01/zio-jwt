/*
 * Copyright (c) 2026 Ali Rashid.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package zio.jwt

import boilerplate.OpaqueType

/** Validated compact-serialisation JWT token (three dot-separated base64url segments). Validation
  * is a single-pass character scan per ss15 (no regular expressions).
  */
opaque type TokenString = String

/** Companion and [[OpaqueType]] instance for [[TokenString]]. */
object TokenString extends OpaqueType[TokenString]:
  type Type = String
  type Error = IllegalArgumentException

  inline def wrap(value: String): TokenString = value
  inline def unwrap(value: TokenString): String = value

  // Hotpath: single-pass scan counts dot separators, validates base64url alphabet,
  // and rejects empty segments -- avoids regex and intermediate allocations.
  override protected inline def validate(value: String): Option[IllegalArgumentException] =
    val len = value.length
    if len == 0 then Some(IllegalArgumentException("TokenString must not be empty"))
    else
      // scalafix:off DisableSyntax.var, DisableSyntax.while; hotpath single-pass scan avoids regex and intermediate allocations
      var i = 0
      var dots = 0
      var segmentLength = 0
      var valid = true
      while i < len && valid do
        val c = value.charAt(i)
        if c == '.' then
          if segmentLength == 0 then valid = false
          else
            dots += 1
            segmentLength = 0
        else if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' then segmentLength += 1
        else valid = false
        i += 1
      // scalafix:on
      if valid && dots == 2 && segmentLength > 0 then None
      else
        Some(
          IllegalArgumentException(
            "TokenString must be exactly three non-empty base64url segments separated by '.'"
          )
        )
    end if
  end validate
end TokenString
