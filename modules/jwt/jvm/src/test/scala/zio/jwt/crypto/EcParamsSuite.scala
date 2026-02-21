package zio.jwt.crypto

import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint

import zio.jwt.*

class EcParamsSuite extends munit.FunSuite:

  // -- Extension method tests --

  test("jcaName maps curves correctly") {
    assertEquals(EcCurve.P256.jcaName, "secp256r1")
    assertEquals(EcCurve.P384.jcaName, "secp384r1")
    assertEquals(EcCurve.P521.jcaName, "secp521r1")
  }

  test("componentLength is correct per curve") {
    assertEquals(EcCurve.P256.componentLength, 32)
    assertEquals(EcCurve.P384.componentLength, 48)
    assertEquals(EcCurve.P521.componentLength, 66)
  }

  test("spec returns valid ECParameterSpec for each curve") {
    // Just verify they load without exception and have the right curve sizes
    val p256 = EcCurve.P256.spec
    val p384 = EcCurve.P384.spec
    val p521 = EcCurve.P521.spec
    assertEquals(p256.getOrder.bitLength(), 256)
    assertEquals(p384.getOrder.bitLength(), 384)
    assert(p521.getOrder.bitLength() >= 520) // P-521 order is 521 bits
  }

  test("order returns correct curve orders") {
    // Verify against known bit lengths
    assertEquals(EcCurve.P256.order.bitLength(), 256)
    assertEquals(EcCurve.P384.order.bitLength(), 384)
    assertEquals(EcCurve.P521.order.bitLength(), 521)
  }

  // -- curveForAlgorithm tests --

  test("curve maps ECDSA algorithms") {
    assertEquals(Algorithm.ES256.curve, Some(EcCurve.P256))
    assertEquals(Algorithm.ES384.curve, Some(EcCurve.P384))
    assertEquals(Algorithm.ES512.curve, Some(EcCurve.P521))
  }

  test("curve returns None for non-ECDSA") {
    assertEquals(Algorithm.HS256.curve, None)
    assertEquals(Algorithm.RS256.curve, None)
    assertEquals(Algorithm.PS256.curve, None)
  }

  // -- validateSignature tests --

  test("validateSignature rejects all-zero signature") {
    val sig = new Array[Byte](64)
    assertEquals(EcParams.validateSignature(Algorithm.ES256, sig), Left(JwtError.InvalidSignature))
  }

  test("validateSignature rejects wrong length") {
    val sig = new Array[Byte](63) // ES256 expects 64
    sig(0) = 1
    assertEquals(EcParams.validateSignature(Algorithm.ES256, sig), Left(JwtError.InvalidSignature))
  }

  test("validateSignature accepts valid JCA-produced signature") {
    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(ECGenParameterSpec("secp256r1"))
    val kp = kpg.generateKeyPair()

    val signer = java.security.Signature.getInstance("SHA256withECDSA")
    signer.initSign(kp.getPrivate)
    signer.update("test".getBytes("US-ASCII"))
    val der = signer.sign()

    val concat = EcdsaCodec.derToConcat(der, 64)
    assert(concat.isRight)

    val result = EcParams.validateSignature(Algorithm.ES256, concat.toOption.get)
    assertEquals(result, Right(()))
  }

  test("validateSignature rejects R = 0") {
    // Build a 64-byte signature where R = 0 (first 32 bytes all zero) and S = 1
    val sig = new Array[Byte](64)
    sig(63) = 1 // S = 1
    assertEquals(EcParams.validateSignature(Algorithm.ES256, sig), Left(JwtError.InvalidSignature))
  }

  test("validateSignature rejects S = 0") {
    val sig = new Array[Byte](64)
    sig(0) = 1 // R = 1
    assertEquals(EcParams.validateSignature(Algorithm.ES256, sig), Left(JwtError.InvalidSignature))
  }

  test("validateSignature rejects R >= curve order") {
    // Construct a signature where R = P-256 order (should be rejected)
    val order = EcCurve.P256.order.toByteArray
    val sig = new Array[Byte](64)
    // order.toByteArray may have a leading 0x00 sign byte
    val orderOffset = if order.length > 32 then order.length - 32 else 0
    val destOffset = if order.length < 32 then 32 - order.length else 0
    val copyLen = math.min(order.length - orderOffset, 32 - destOffset)
    System.arraycopy(order, orderOffset, sig, destOffset, copyLen)
    // S = 1
    sig(63) = 1
    assertEquals(EcParams.validateSignature(Algorithm.ES256, sig), Left(JwtError.InvalidSignature))
  }

  // -- validatePointOnCurve tests --

  test("validatePoint accepts a valid generated point") {
    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(ECGenParameterSpec("secp256r1"))
    val kp = kpg.generateKeyPair()
    val pub = kp.getPublic.asInstanceOf[java.security.interfaces.ECPublicKey]

    val result = EcCurve.P256.validatePoint(pub.getW)
    assertEquals(result, Right(()))
  }

  test("validatePoint rejects an off-curve point") {
    // (1, 1) is not on P-256
    val badPoint = ECPoint(BigInteger.ONE, BigInteger.ONE)
    val result = EcCurve.P256.validatePoint(badPoint)
    assert(result.isLeft)
  }

  test("validatePoint accepts generator point for P-384") {
    val spec = EcCurve.P384.spec
    val result = EcCurve.P384.validatePoint(spec.getGenerator)
    assertEquals(result, Right(()))
  }

  test("validatePoint accepts generator point for P-521") {
    val spec = EcCurve.P521.spec
    val result = EcCurve.P521.validatePoint(spec.getGenerator)
    assertEquals(result, Right(()))
  }
