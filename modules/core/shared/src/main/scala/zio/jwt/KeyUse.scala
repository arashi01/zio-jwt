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

/** JWK public key use parameter (RFC 7517 ss4.2). */
enum KeyUse derives CanEqual:
  case Sig, Enc

/** Companion for [[KeyUse]]. Provides wire-format name conversions. */
object KeyUse:

  /** All key use names as (wire-format string, KeyUse) pairs. */
  val names: Array[(String, KeyUse)] = Array(
    "sig" -> KeyUse.Sig,
    "enc" -> KeyUse.Enc
  )

  private val stringToKeyUse: Map[String, KeyUse] = names.toMap
  private val keyUseToString: Map[KeyUse, String] = names.map((s, k) => k -> s).toMap

  /** Parses a key use from its wire-format string (e.g. "sig", "enc"). */
  def fromString(s: String): Option[KeyUse] = stringToKeyUse.get(s)

  extension (use: KeyUse)
    /** Wire-format name for JSON serialisation (e.g. "sig", "enc"). */
    inline def name: String = keyUseToString(use)
end KeyUse
