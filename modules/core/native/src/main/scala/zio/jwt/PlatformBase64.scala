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

import boilerplate.nullable.*

/** Native base64url implementation using a lookup table. */
private[jwt] object PlatformBase64:

  // RFC 4648 §5 base64url alphabet
  private val EncodeTable: Array[Char] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".toCharArray

  // Decode table: maps ASCII code point → 6-bit value, -1 for invalid
  private val DecodeTable: Array[Int] =
    val t = Array.fill(128)(-1)
    // scalafix:off DisableSyntax.var, DisableSyntax.while; table initialisation
    var i = 0
    while i < EncodeTable.length do
      t(EncodeTable(i).toInt) = i
      i += 1
    // scalafix:on
    t

  inline def urlDecode(input: String): Either[JwtError, Array[Byte]] =
    scala.util
      .Try {
        val len = input.length
        val padding = (4 - len % 4) % 4
        val outLen = (len + padding) / 4 * 3 - padding
        val out = new Array[Byte](outLen)
        // scalafix:off DisableSyntax.var, DisableSyntax.while, DisableSyntax.throw; performance-critical decode loop
        var inIdx = 0
        var outIdx = 0
        while inIdx < len do
          val remaining = len - inIdx
          val a = DecodeTable(input.charAt(inIdx).toInt)
          val b = if inIdx + 1 < len then DecodeTable(input.charAt(inIdx + 1).toInt) else 0
          val c = if inIdx + 2 < len then DecodeTable(input.charAt(inIdx + 2).toInt) else 0
          val d = if inIdx + 3 < len then DecodeTable(input.charAt(inIdx + 3).toInt) else 0
          if a < 0 || b < 0 || c < 0 || d < 0 then throw IllegalArgumentException("Invalid base64url character")
          val triple = (a << 18) | (b << 12) | (c << 6) | d
          if outIdx < outLen then
            out(outIdx) = ((triple >> 16) & 0xff).toByte; outIdx += 1
          if outIdx < outLen then
            out(outIdx) = ((triple >> 8) & 0xff).toByte; outIdx += 1
          if outIdx < outLen then
            out(outIdx) = (triple & 0xff).toByte; outIdx += 1
          inIdx += 4.min(remaining)
        end while
        // scalafix:on
        out
      }
      .toEither
      .left
      .map(e => JwtError.MalformedToken(e.getMessage.getOrElse("base64 decode failed")))

  inline def urlEncode(data: Array[Byte]): String =
    val len = data.length
    val outLen = (len * 4 + 2) / 3
    val sb = new StringBuilder(outLen)
    // scalafix:off DisableSyntax.var, DisableSyntax.while; performance-critical encode loop
    var i = 0
    while i < len do
      val b0 = data(i) & 0xff
      sb.append(EncodeTable(b0 >> 2))
      if i + 1 < len then
        val b1 = data(i + 1) & 0xff
        sb.append(EncodeTable(((b0 & 0x03) << 4) | (b1 >> 4)))
        if i + 2 < len then
          val b2 = data(i + 2) & 0xff
          sb.append(EncodeTable(((b1 & 0x0f) << 2) | (b2 >> 6)))
          sb.append(EncodeTable(b2 & 0x3f))
        else sb.append(EncodeTable((b1 & 0x0f) << 2))
      else sb.append(EncodeTable((b0 & 0x03) << 4))
      i += 3
    end while
    // scalafix:on
    sb.result()
  end urlEncode
end PlatformBase64
