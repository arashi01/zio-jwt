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

import boilerplate.codec.Base64

/** Base64url encoding and decoding per RFC 4648 ss5 (URL-safe alphabet, no padding).
  *
  * Delegates to [[boilerplate.codec.Base64]] with `urlSafe = true`.
  */
private[jwt] object Base64Url:

  /** Encodes binary data to a base64url string without padding. */
  inline def encode(data: Array[Byte]): String =
    Base64.encode(data, true)

  /** Decodes a base64url string to binary data. Returns `Left` for invalid input. */
  inline def decode(input: String): Either[JwtError, Array[Byte]] =
    Base64
      .decode(input, true)
      .left
      .map(e => JwtError.MalformedToken(e.getMessage))

end Base64Url
