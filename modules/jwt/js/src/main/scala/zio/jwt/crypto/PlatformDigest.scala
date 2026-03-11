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
package zio.jwt.crypto

import scala.scalajs.js
import scala.scalajs.js.typedarray.Uint8Array

import zio.jwt.JwtError

/** JS cryptographic digest backed by Node.js `crypto.createHash`.
  *
  * Not `private[jwt]` due to Scala.js backend limitation with package-qualified access across
  * sub-packages (assertion failure: "Cannot use package as value").
  */
object PlatformDigest:

  private val crypto: js.Dynamic = js.Dynamic.global.require("crypto") // scalafix:ok

  /** Maps JCA algorithm names to Node.js hash algorithm names. */
  private def nodeAlgorithm(jcaName: String): String = jcaName match
    case "SHA-1"   => "sha1"
    case "SHA-256" => "sha256"
    case "SHA-384" => "sha384"
    case "SHA-512" => "sha512"
    case other     => other.toLowerCase.nn

  def digest(algorithm: String, data: Array[Byte]): Either[JwtError, Array[Byte]] =
    try
      val nodeAlg = nodeAlgorithm(algorithm)
      val hash = crypto.createHash(nodeAlg)
      // Convert Array[Byte] to Uint8Array for Node.js
      // scalafix:off DisableSyntax.var, DisableSyntax.while; hotpath byte-level conversion
      val input = new Uint8Array(data.length)
      var i = 0
      while i < data.length do
        input(i) = (data(i) & 0xff).toShort
        i += 1
      // scalafix:on
      val _ = hash.update(input)
      // Node.js Buffer extends Uint8Array
      val result = new Uint8Array(hash.digest().asInstanceOf[js.typedarray.ArrayBuffer]) // scalafix:ok DisableSyntax.asInstanceOf; Node.js Buffer/ArrayBuffer coercion
      Right(Array.tabulate(result.length)(j => result(j).toByte))
    catch case e: Exception => Left(JwtError.InvalidKey(Option(e.getMessage).getOrElse("digest failed")))
end PlatformDigest
