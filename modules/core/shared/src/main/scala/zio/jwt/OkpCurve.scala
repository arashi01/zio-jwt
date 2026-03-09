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

/** OKP (Octet Key Pair) curve identifiers for EdDSA (RFC 8037 ss2). */
enum OkpCurve derives CanEqual:
  case Ed25519, Ed448

/** Companion for [[OkpCurve]]. Provides JCA naming, sizing, and wire-format name conversions. */
object OkpCurve:

  /** All curve names as (wire-format string, OkpCurve) pairs. */
  val names: Array[(String, OkpCurve)] = Array(
    "Ed25519" -> OkpCurve.Ed25519,
    "Ed448" -> OkpCurve.Ed448
  )

  private val stringToCurve: Map[String, OkpCurve] = names.toMap
  private val curveToString: Map[OkpCurve, String] = names.map((s, c) => c -> s).toMap

  /** Parses an OKP curve from its wire-format string (e.g. "Ed25519"). */
  def fromString(s: String): Option[OkpCurve] = stringToCurve.get(s)

  extension (crv: OkpCurve)

    /** Wire-format name for JSON serialisation (e.g. "Ed25519", "Ed448"). */
    inline def name: String = curveToString(crv)

    /** JCA named curve identifier. Identical to [[name]] for OKP curves (unlike [[EcCurve]] where
      * wire-format and JCA names differ).
      */
    inline def jcaName: String = crv match
      case Ed25519 => "Ed25519"
      case Ed448   => "Ed448"

    /** Byte length of the public key `x` coordinate. */
    inline def keyLength: Int = crv match
      case Ed25519 => 32
      case Ed448   => 57
  end extension
end OkpCurve
