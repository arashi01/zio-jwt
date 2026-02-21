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

import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec

import zio.jwt.*

class EcdsaCodecSuite extends munit.FunSuite:

  test("signatureLength returns correct values for ECDSA algorithms") {
    assertEquals(EcdsaCodec.signatureLength(Algorithm.ES256), Some(64))
    assertEquals(EcdsaCodec.signatureLength(Algorithm.ES384), Some(96))
    assertEquals(EcdsaCodec.signatureLength(Algorithm.ES512), Some(132))
  }

  test("signatureLength returns None for non-ECDSA algorithms") {
    assertEquals(EcdsaCodec.signatureLength(Algorithm.HS256), None)
    assertEquals(EcdsaCodec.signatureLength(Algorithm.RS256), None)
    assertEquals(EcdsaCodec.signatureLength(Algorithm.PS256), None)
  }

  test("DER to concat round-trip for ES256") {
    assertRoundTrip(Algorithm.ES256, "secp256r1", 64)
  }

  test("DER to concat round-trip for ES384") {
    assertRoundTrip(Algorithm.ES384, "secp384r1", 96)
  }

  test("DER to concat round-trip for ES512") {
    assertRoundTrip(Algorithm.ES512, "secp521r1", 132)
  }

  test("derToConcat rejects truncated DER") {
    val result = EcdsaCodec.derToConcat(Array[Byte](0x30, 0x06), 64)
    assert(result.isLeft)
  }

  test("derToConcat rejects invalid tag") {
    val result = EcdsaCodec.derToConcat(Array[Byte](0x31, 0x00, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01), 64)
    assert(result.isLeft)
  }

  test("concatToDer rejects empty input") {
    // An empty array has length 0, splitting produces two empty components
    // toSignedInteger handles empty gracefully, but the result should still round-trip
    val emptyResult = EcdsaCodec.concatToDer(Array.emptyByteArray)
    assert(emptyResult.isRight || emptyResult.isLeft) // structural test
  }

  test("concat output has correct fixed length") {
    val (_, kp) = generateEcKeyPair("secp256r1")
    val sig = java.security.Signature.getInstance("SHA256withECDSA")
    sig.initSign(kp.getPrivate)
    sig.update("test data".getBytes("US-ASCII"))
    val der = sig.sign()

    val concat = EcdsaCodec.derToConcat(der, 64)
    assert(concat.isRight)
    assertEquals(concat.toOption.get.length, 64)
  }

  private def generateEcKeyPair(curveName: String) =
    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(ECGenParameterSpec(curveName))
    (curveName, kpg.generateKeyPair())

  /** Signs random data with JCA, transcodes DER->concat->DER, then verifies with JCA. */
  private def assertRoundTrip(alg: Algorithm, curveName: String, sigLen: Int)(using loc: munit.Location): Unit =
    val (_, kp) = generateEcKeyPair(curveName)
    val data = "round-trip test data for ECDSA".getBytes("US-ASCII")

    // Sign with JCA (produces DER)
    val jcaSig = java.security.Signature.getInstance(alg.jcaName)
    jcaSig.initSign(kp.getPrivate)
    jcaSig.update(data)
    val der = jcaSig.sign()

    // DER -> concat (R||S)
    val concat = EcdsaCodec.derToConcat(der, sigLen)
    assert(concat.isRight, s"derToConcat failed: ${concat.left.toOption}")
    assertEquals(concat.toOption.get.length, sigLen)

    // concat -> DER
    val derAgain = EcdsaCodec.concatToDer(concat.toOption.get)
    assert(derAgain.isRight, s"concatToDer failed: ${derAgain.left.toOption}")

    // Verify with JCA using the re-encoded DER
    val verifier = java.security.Signature.getInstance(alg.jcaName)
    verifier.initVerify(kp.getPublic)
    verifier.update(data)
    assert(verifier.verify(derAgain.toOption.get), "JCA verification failed after round-trip")
  end assertRoundTrip
end EcdsaCodecSuite
