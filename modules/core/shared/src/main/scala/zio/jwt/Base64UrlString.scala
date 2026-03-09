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

/** Validated base64url-encoded string without padding (RFC 4648 ss5). */
opaque type Base64UrlString = String

/** Companion and [[OpaqueType]] instance for [[Base64UrlString]]. */
object Base64UrlString extends OpaqueType[Base64UrlString]:
  type Type = String
  type Error = IllegalArgumentException

  inline def wrap(value: String): Base64UrlString = value
  inline def unwrap(value: Base64UrlString): String = value

  override inline def validate(value: String): Option[IllegalArgumentException] =
    val len = value.length
    if len == 0 then Some(IllegalArgumentException("Base64UrlString must not be empty"))
    else
      // scalafix:off DisableSyntax.var, DisableSyntax.while; hotpath single-pass scan avoids regex
      var i = 0
      var valid = true
      while i < len && valid do
        val c = value.charAt(i)
        if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') then valid = false
        i += 1
      // scalafix:on
      if valid then None
      else Some(IllegalArgumentException("Base64UrlString contains invalid base64url characters"))
    end if
  end validate
end Base64UrlString
