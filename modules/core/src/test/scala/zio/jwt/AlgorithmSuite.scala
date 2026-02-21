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
