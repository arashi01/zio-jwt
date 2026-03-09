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

import scala.scalajs.js

import boilerplate.nullable.*

/** JS base64url implementation backed by `globalThis.atob`/`globalThis.btoa`. */
private[jwt] object PlatformBase64:

  inline def urlDecode(input: String): Either[JwtError, Array[Byte]] =
    scala.util
      .Try {
        val padded = input.length % 4 match
          case 0 => input
          case 2 => input + "=="
          case 3 => input + "="
          case _ => throw IllegalArgumentException("Invalid base64url: length % 4 == 1") // inside Try; RFC 7515 Appendix C
        val standard = padded.replace('-', '+').replace('_', '/')
        val binary = js.Dynamic.global.atob(standard).asInstanceOf[String]
        val bytes = new Array[Byte](binary.length)
        var i = 0
        while i < binary.length do
          bytes(i) = binary.charAt(i).toByte
          i += 1
        bytes
      }
      .toEither
      .left
      .map(e => JwtError.MalformedToken(e.getMessage.getOrElse("base64 decode failed")))

  inline def urlEncode(data: Array[Byte]): String =
    val sb = new StringBuilder(data.length)
    var i = 0
    while i < data.length do
      sb.append((data(i) & 0xff).toChar)
      i += 1
    val binary = sb.result()
    val standard = js.Dynamic.global.btoa(binary).asInstanceOf[String]
    standard.replace('+', '-').replace('/', '_').replace("=", "") // scalafix:ok
end PlatformBase64
