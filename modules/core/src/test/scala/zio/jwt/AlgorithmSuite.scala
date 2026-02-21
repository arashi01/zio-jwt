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

class AlgorithmSuite extends munit.FunSuite:

  test("jcaName returns correct JCA identifier for HMAC family") {
    assertEquals(Algorithm.HS256.jcaName, "HmacSHA256")
    assertEquals(Algorithm.HS384.jcaName, "HmacSHA384")
    assertEquals(Algorithm.HS512.jcaName, "HmacSHA512")
  }

  test("jcaName returns correct JCA identifier for RSA family") {
    assertEquals(Algorithm.RS256.jcaName, "SHA256withRSA")
    assertEquals(Algorithm.RS384.jcaName, "SHA384withRSA")
    assertEquals(Algorithm.RS512.jcaName, "SHA512withRSA")
  }

  test("jcaName returns correct JCA identifier for EC family") {
    assertEquals(Algorithm.ES256.jcaName, "SHA256withECDSA")
    assertEquals(Algorithm.ES384.jcaName, "SHA384withECDSA")
    assertEquals(Algorithm.ES512.jcaName, "SHA512withECDSA")
  }

  test("jcaName returns RSASSA-PSS for all PSS variants") {
    assertEquals(Algorithm.PS256.jcaName, "RSASSA-PSS")
    assertEquals(Algorithm.PS384.jcaName, "RSASSA-PSS")
    assertEquals(Algorithm.PS512.jcaName, "RSASSA-PSS")
  }

  test("family classifies HMAC algorithms") {
    assertEquals(Algorithm.HS256.family, AlgorithmFamily.HMAC)
    assertEquals(Algorithm.HS384.family, AlgorithmFamily.HMAC)
    assertEquals(Algorithm.HS512.family, AlgorithmFamily.HMAC)
  }

  test("family classifies RSA algorithms") {
    assertEquals(Algorithm.RS256.family, AlgorithmFamily.RSA)
    assertEquals(Algorithm.RS384.family, AlgorithmFamily.RSA)
    assertEquals(Algorithm.RS512.family, AlgorithmFamily.RSA)
  }

  test("family classifies EC algorithms") {
    assertEquals(Algorithm.ES256.family, AlgorithmFamily.EC)
    assertEquals(Algorithm.ES384.family, AlgorithmFamily.EC)
    assertEquals(Algorithm.ES512.family, AlgorithmFamily.EC)
  }

  test("family classifies RSA-PSS algorithms") {
    assertEquals(Algorithm.PS256.family, AlgorithmFamily.RSAPSS)
    assertEquals(Algorithm.PS384.family, AlgorithmFamily.RSAPSS)
    assertEquals(Algorithm.PS512.family, AlgorithmFamily.RSAPSS)
  }

  test("all 12 algorithms are present") {
    assertEquals(Algorithm.values.length, 12)
  }
end AlgorithmSuite
