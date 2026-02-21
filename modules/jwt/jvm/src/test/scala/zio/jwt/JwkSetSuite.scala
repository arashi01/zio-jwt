package zio.jwt

import zio.Chunk

class JwkSetSuite extends munit.FunSuite:

  private val sampleKey = Jwk.SymmetricKey(
    k = Base64UrlString.fromUnsafe("dGVzdA"),
    use = None, keyOps = None, alg = None, kid = None
  )

  test("JwkSet can hold multiple keys") {
    val set = JwkSet(Chunk(sampleKey, sampleKey))
    assertEquals(set.keys.size, 2)
  }

  test("JwkSet can be empty") {
    val set = JwkSet(Chunk.empty)
    assert(set.keys.isEmpty)
  }

  test("JwkSet derives CanEqual") {
    val a = JwkSet(Chunk(sampleKey))
    val b = JwkSet(Chunk(sampleKey))
    assertEquals(a, b)
  }
