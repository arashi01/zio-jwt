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

/** JOSE elliptic curve identifiers (RFC 7518 ss6.2.1.1). */
enum EcCurve derives CanEqual:
  case P256, P384, P521

/** Companion for [[EcCurve]]. Provides JCA naming, sizing, and wire-format name conversions. */
object EcCurve:

  /** All curve names as (wire-format string, EcCurve) pairs. */
  val names: Array[(String, EcCurve)] = Array(
    "P-256" -> EcCurve.P256,
    "P-384" -> EcCurve.P384,
    "P-521" -> EcCurve.P521
  )

  private val stringToCurve: Map[String, EcCurve] = names.toMap
  private val curveToString: Map[EcCurve, String] = names.map((s, c) => c -> s).toMap

  /** Parses an EC curve from its wire-format string (e.g. "P-256"). */
  def fromString(s: String): Option[EcCurve] = stringToCurve.get(s)

  extension (crv: EcCurve)

    /** Wire-format name for JSON serialisation (e.g. "P-256", "P-384", "P-521"). */
    inline def name: String = curveToString(crv)

    /** JCA named curve identifier (e.g. "secp256r1"). */
    inline def jcaName: String = crv match
      case P256 => "secp256r1"
      case P384 => "secp384r1"
      case P521 => "secp521r1"

    /** Byte length of a single field element (coordinate or private key). */
    inline def componentLength: Int = crv match
      case P256 => 32
      case P384 => 48
      case P521 => 66
  end extension
end EcCurve
