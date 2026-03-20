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

import java.math.BigInteger
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPrivateKey as JcaEcPrivateKey
import java.security.interfaces.ECPublicKey as JcaEcPublicKey
import java.security.interfaces.EdECPrivateKey as JcaEdEcPrivateKey
import java.security.interfaces.EdECPublicKey as JcaEdEcPublicKey
import java.security.interfaces.RSAPrivateCrtKey as JcaRsaPrivateCrtKey
import java.security.interfaces.RSAPublicKey as JcaRsaPublicKey
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.NamedParameterSpec
import java.security.spec.RSAPrivateCrtKeySpec
import java.security.spec.RSAPublicKeySpec
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

import scala.util.Try

import boilerplate.nullable.*

import zio.jwt.crypto.EcParams
import zio.jwt.crypto.validatePointOnCurve

// JVM-specific JCA conversion extensions and factory methods on Jwk.
// Discoverable via `import zio.jwt.*`.

/** Decodes a base64url-encoded string to a positive BigInteger. */
private inline def decodeBigInt(b64: Base64UrlString): Either[JwtError, BigInteger] =
  b64.decodeBytes.map(bytes => BigInteger(1, bytes))

/** Encodes a positive BigInteger as base64url without padding, stripping the sign byte. */
private inline def encodeBigInt(value: BigInteger): Base64UrlString =
  val bytes = value.toByteArray
  // Strip leading zero sign byte if present
  val unsigned = if bytes.length > 1 && bytes(0) == 0.toByte then bytes.drop(1) else bytes
  Base64UrlString.encode(unsigned)

/** Encodes a positive BigInteger as base64url, padded to the given field size in bytes. Used for EC
  * coordinates which must be padded to the curve's field element size.
  */
private inline def encodeBigIntPadded(value: BigInteger, fieldSize: Int): Base64UrlString =
  val bytes = value.toByteArray
  val unsigned = if bytes.length > 1 && bytes(0) == 0.toByte then bytes.drop(1) else bytes
  val padded =
    if unsigned.length >= fieldSize then unsigned
    else
      val buf = new Array[Byte](fieldSize)
      System.arraycopy(unsigned, 0, buf, fieldSize - unsigned.length, unsigned.length)
      buf
  Base64UrlString.encode(padded)

private val MinRsaKeyBits = 2048

// -- JWK -> JCA key conversion --

extension (jwk: Jwk)

  /** Converts this JWK to a JCA [[PublicKey]]. */
  def toPublicKey: Either[JwtError, PublicKey] = jwk match
    case ec: Jwk.EcPublicKey    => ecToPublicKey(ec.crv, ec.x, ec.y)
    case ec: Jwk.EcPrivateKey   => ecToPublicKey(ec.crv, ec.x, ec.y)
    case rsa: Jwk.RsaPublicKey  => rsaToPublicKey(rsa.n, rsa.e)
    case rsa: Jwk.RsaPrivateKey => rsaToPublicKey(rsa.n, rsa.e)
    case okp: Jwk.OkpPublicKey  => okpToPublicKey(okp.crv, okp.x)
    case okp: Jwk.OkpPrivateKey => okpToPublicKey(okp.crv, okp.x)
    case _: Jwk.SymmetricKey    =>
      Left(JwtError.InvalidKey("Symmetric keys do not have a public key"))

  /** Converts this JWK to a JCA [[PrivateKey]]. */
  def toPrivateKey: Either[JwtError, PrivateKey] = jwk match
    case ec: Jwk.EcPrivateKey   => ecToPrivateKey(ec.crv, ec.d)
    case rsa: Jwk.RsaPrivateKey => rsaToPrivateKey(rsa.n, rsa.e, rsa.d, rsa.p, rsa.q, rsa.dp, rsa.dq, rsa.qi)
    case okp: Jwk.OkpPrivateKey => okpToPrivateKey(okp.crv, okp.d)
    case _: Jwk.EcPublicKey     =>
      Left(JwtError.InvalidKey("EC public key does not contain a private key"))
    case _: Jwk.RsaPublicKey =>
      Left(JwtError.InvalidKey("RSA public key does not contain a private key"))
    case _: Jwk.OkpPublicKey =>
      Left(JwtError.InvalidKey("OKP public key does not contain a private key"))
    case _: Jwk.SymmetricKey =>
      Left(JwtError.InvalidKey("Symmetric keys do not have a private key"))

  /** Converts this JWK to a JCA [[SecretKey]]. */
  def toSecretKey: Either[JwtError, SecretKey] = jwk match
    case sym: Jwk.SymmetricKey => symmetricToSecretKey(sym.k, sym.alg)
    case _                     =>
      Left(JwtError.InvalidKey("Only symmetric keys can be converted to SecretKey"))
end extension

// -- JCA key -> JWK factory methods (augment Jwk companion) --

extension (companion: Jwk.type)

  /** Creates a [[Jwk]] from a JCA [[PublicKey]]. */
  def from(key: PublicKey, kid: Option[Kid]): Either[JwtError, Jwk] =
    import scala.language.unsafeNulls // hotpath: unsafeNulls justified — JCA type-match dispatch, getClass.getName non-null
    key match
      case ec: JcaEcPublicKey     => fromEcPublicKey(ec, kid)
      case rsa: JcaRsaPublicKey   => fromRsaPublicKey(rsa, kid)
      case edec: JcaEdEcPublicKey => fromEdEcPublicKey(edec, kid)
      case _                      => Left(JwtError.InvalidKey(s"Unsupported public key type: ${key.getClass.getName}"))

  /** Creates a [[Jwk]] from a JCA [[PublicKey]] without a key identifier. */
  def from(key: PublicKey): Either[JwtError, Jwk] = companion.from(key, None)

  /** Creates a [[Jwk]] from a JCA [[PrivateKey]] (includes public components). */
  def from(key: PrivateKey, publicKey: PublicKey, kid: Option[Kid]): Either[JwtError, Jwk] =
    import scala.language.unsafeNulls // hotpath: unsafeNulls justified — JCA type-match dispatch, getClass.getName non-null
    (key, publicKey) match
      case (ec: JcaEcPrivateKey, ecPub: JcaEcPublicKey)         => fromEcPrivateKey(ec, ecPub, kid)
      case (rsa: JcaRsaPrivateCrtKey, rsaPub: JcaRsaPublicKey)  => fromRsaPrivateKey(rsa, rsaPub, kid)
      case (edec: JcaEdEcPrivateKey, edecPub: JcaEdEcPublicKey) => fromEdEcPrivateKey(edec, edecPub, kid)
      case _                                                    =>
        Left(
          JwtError.InvalidKey(
            s"Unsupported key pair types: ${key.getClass.getName}, ${publicKey.getClass.getName}"
          )
        )
  end from

  /** Creates a [[Jwk]] from a JCA [[PrivateKey]] without a key identifier. */
  def from(key: PrivateKey, publicKey: PublicKey): Either[JwtError, Jwk] = companion.from(key, publicKey, None)

  /** Creates a [[Jwk]] from a JCA [[SecretKey]]. */
  def from(key: SecretKey, kid: Option[Kid]): Either[JwtError, Jwk] =
    val encoded = key.getEncoded.option
    encoded match
      case Some(bytes) if bytes.nonEmpty =>
        val b64 = Base64UrlString.encode(bytes)
        Right(Jwk.SymmetricKey(k = b64, use = None, keyOps = None, alg = None, kid = kid))
      case _ =>
        Left(JwtError.InvalidKey("SecretKey has no encoded form"))

  /** Creates a [[Jwk]] from a JCA [[SecretKey]] without a key identifier. */
  def from(key: SecretKey): Either[JwtError, Jwk] = companion.from(key, None)
end extension

// -- Internal EC conversion helpers --

private inline def ecToPublicKey(crv: EcCurve, xB64: Base64UrlString, yB64: Base64UrlString): Either[JwtError, PublicKey] =
  for
    x <- decodeBigInt(xB64)
    y <- decodeBigInt(yB64)
    point = ECPoint(x, y)
    _ <- EcParams.validatePointOnCurve(crv, point)
    key <- Try {
             import scala.language.unsafeNulls // hotpath: unsafeNulls justified — JCA KeyFactory.generatePublic non-null
             val spec = ECPublicKeySpec(point, crv.spec)
             KeyFactory.getInstance("EC").generatePublic(spec)
           }.toEither.left.map(e => JwtError.InvalidKey(e.getMessage.option.getOrElse("EC public key generation failed")))
  yield key

private inline def ecToPrivateKey(crv: EcCurve, dB64: Base64UrlString): Either[JwtError, PrivateKey] =
  for
    d <- decodeBigInt(dB64)
    key <- Try {
             import scala.language.unsafeNulls // hotpath: unsafeNulls justified — JCA KeyFactory.generatePrivate non-null
             val spec = ECPrivateKeySpec(d, crv.spec)
             KeyFactory.getInstance("EC").generatePrivate(spec)
           }.toEither.left.map(e => JwtError.InvalidKey(e.getMessage.option.getOrElse("EC private key generation failed")))
  yield key

private inline def rsaToPublicKey(nB64: Base64UrlString, eB64: Base64UrlString): Either[JwtError, PublicKey] =
  for
    n <- decodeBigInt(nB64)
    _ <- Either.cond(
           n.bitLength() >= MinRsaKeyBits,
           (),
           JwtError.InvalidKey(
             s"RSA key must be at least $MinRsaKeyBits bits, got ${n.bitLength()}"
           )
         )
    e <- decodeBigInt(eB64)
    key <- Try {
             import scala.language.unsafeNulls // hotpath: unsafeNulls justified — JCA KeyFactory.generatePublic non-null
             val spec = RSAPublicKeySpec(n, e)
             KeyFactory.getInstance("RSA").generatePublic(spec)
           }.toEither.left.map(e => JwtError.InvalidKey(e.getMessage.option.getOrElse("RSA public key generation failed")))
  yield key

private inline def rsaToPrivateKey(
  nB64: Base64UrlString,
  eB64: Base64UrlString,
  dB64: Base64UrlString,
  pB64: Base64UrlString,
  qB64: Base64UrlString,
  dpB64: Base64UrlString,
  dqB64: Base64UrlString,
  qiB64: Base64UrlString
): Either[JwtError, PrivateKey] =
  for
    n <- decodeBigInt(nB64)
    _ <- Either.cond(
           n.bitLength() >= MinRsaKeyBits,
           (),
           JwtError.InvalidKey(
             s"RSA key must be at least $MinRsaKeyBits bits, got ${n.bitLength()}"
           )
         )
    e <- decodeBigInt(eB64)
    d <- decodeBigInt(dB64)
    p <- decodeBigInt(pB64)
    q <- decodeBigInt(qB64)
    dp <- decodeBigInt(dpB64)
    dq <- decodeBigInt(dqB64)
    qi <- decodeBigInt(qiB64)
    key <- Try {
             import scala.language.unsafeNulls // hotpath: unsafeNulls justified — JCA KeyFactory.generatePrivate non-null
             val spec = RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, qi)
             KeyFactory.getInstance("RSA").generatePrivate(spec)
           }.toEither.left.map(e => JwtError.InvalidKey(e.getMessage.option.getOrElse("RSA private key generation failed")))
  yield key

private inline def symmetricToSecretKey(kB64: Base64UrlString, alg: Option[Algorithm]): Either[JwtError, SecretKey] =
  kB64.decodeBytes.map { bytes =>
    val jcaAlg = alg.fold("HmacSHA256")(_.jcaName)
    SecretKeySpec(bytes, jcaAlg): SecretKey
  }

// -- Internal JCA -> JWK helpers --

private inline def curveFromSpec(ecPub: JcaEcPublicKey): Either[JwtError, EcCurve] =
  // hotpath: unsafeNulls justified — JCA getParams/getCurve/getField chain, all non-null for valid keys
  import scala.language.unsafeNulls
  val fieldSize = ecPub.getParams.getCurve.getField.getFieldSize
  fieldSize match
    case 256 => Right(EcCurve.P256)
    case 384 => Right(EcCurve.P384)
    case 521 => Right(EcCurve.P521)
    case _   => Left(JwtError.InvalidKey(s"Unsupported EC field size: $fieldSize"))

private inline def fromEcPublicKey(ec: JcaEcPublicKey, kid: Option[Kid]): Either[JwtError, Jwk] =
  // hotpath: unsafeNulls justified — JCA getW/getAffineX/getAffineY chain, all non-null for valid keys
  import scala.language.unsafeNulls
  for crv <- curveFromSpec(ec)
  yield
    val fieldLen = crv.componentLength
    val x = encodeBigIntPadded(ec.getW.getAffineX, fieldLen)
    val y = encodeBigIntPadded(ec.getW.getAffineY, fieldLen)
    Jwk.EcPublicKey(crv = crv, x = x, y = y, use = None, keyOps = None, alg = None, kid = kid)

private inline def fromEcPrivateKey(ec: JcaEcPrivateKey, ecPub: JcaEcPublicKey, kid: Option[Kid]): Either[JwtError, Jwk] =
  // hotpath: unsafeNulls justified — JCA getW/getAffineX/getAffineY/getS chain
  import scala.language.unsafeNulls
  for crv <- curveFromSpec(ecPub)
  yield
    val fieldLen = crv.componentLength
    val x = encodeBigIntPadded(ecPub.getW.getAffineX, fieldLen)
    val y = encodeBigIntPadded(ecPub.getW.getAffineY, fieldLen)
    val d = encodeBigIntPadded(ec.getS, fieldLen)
    Jwk.EcPrivateKey(crv = crv, x = x, y = y, d = d, use = None, keyOps = None, alg = None, kid = kid)

private inline def fromRsaPublicKey(rsa: JcaRsaPublicKey, kid: Option[Kid]): Either[JwtError, Jwk] =
  // hotpath: unsafeNulls justified — JCA getModulus/getPublicExponent chain
  import scala.language.unsafeNulls
  val n = encodeBigInt(rsa.getModulus)
  val e = encodeBigInt(rsa.getPublicExponent)
  Either.cond(
    rsa.getModulus.bitLength() >= MinRsaKeyBits,
    Jwk.RsaPublicKey(n = n, e = e, use = None, keyOps = None, alg = None, kid = kid),
    JwtError.InvalidKey(
      s"RSA key must be at least $MinRsaKeyBits bits, got ${rsa.getModulus.bitLength()}"
    )
  )
end fromRsaPublicKey

private inline def fromRsaPrivateKey(rsa: JcaRsaPrivateCrtKey, rsaPub: JcaRsaPublicKey, kid: Option[Kid]): Either[JwtError, Jwk] =
  // hotpath: unsafeNulls justified — JCA CRT parameter chain
  import scala.language.unsafeNulls
  Either.cond(
    rsaPub.getModulus.bitLength() >= MinRsaKeyBits,
    Jwk.RsaPrivateKey(
      n = encodeBigInt(rsaPub.getModulus),
      e = encodeBigInt(rsaPub.getPublicExponent),
      d = encodeBigInt(rsa.getPrivateExponent),
      p = encodeBigInt(rsa.getPrimeP),
      q = encodeBigInt(rsa.getPrimeQ),
      dp = encodeBigInt(rsa.getPrimeExponentP),
      dq = encodeBigInt(rsa.getPrimeExponentQ),
      qi = encodeBigInt(rsa.getCrtCoefficient),
      use = None,
      keyOps = None,
      alg = None,
      kid = kid
    ),
    JwtError.InvalidKey(
      s"RSA key must be at least $MinRsaKeyBits bits, got ${rsaPub.getModulus.bitLength()}"
    )
  )
end fromRsaPrivateKey

// -- Internal OKP/EdDSA conversion helpers --

private inline def okpCurveFromEdEcKey(edec: JcaEdEcPublicKey): Either[JwtError, OkpCurve] =
  // hotpath: unsafeNulls justified — JCA getParams/getName chain
  import scala.language.unsafeNulls
  edec.getParams match
    case ns: NamedParameterSpec =>
      ns.getName match
        case "Ed25519" => Right(OkpCurve.Ed25519)
        case "Ed448"   => Right(OkpCurve.Ed448)
        case other     => Left(JwtError.InvalidKey(s"Unsupported EdDSA curve: $other"))
    case null => Left(JwtError.InvalidKey("EdEC key has no NamedParameterSpec")) // scalafix:ok DisableSyntax.null; JCA getParams may return null

/** Encodes an EdEC public key's point as the RFC 8032 x-coordinate (little-endian). */
private inline def edEcPublicKeyToX(edec: JcaEdEcPublicKey, crv: OkpCurve): Base64UrlString =
  // hotpath: unsafeNulls justified — per-key-import byte manipulation, RFC 8032 encoding
  import scala.language.unsafeNulls
  val point = edec.getPoint
  val yBytes = point.getY.toByteArray
  // Convert BigInteger (big-endian, unsigned) to little-endian RFC 8032 encoding
  val keyLen = crv.keyLength
  val leBytes = new Array[Byte](keyLen)
  // yBytes may be shorter than keyLen (leading zeros) or have a leading sign byte
  val unsigned = if yBytes.length > 1 && yBytes(0) == 0.toByte then yBytes.drop(1) else yBytes
  val copyLen = math.min(unsigned.length, keyLen)
  // scalafix:off DisableSyntax.var, DisableSyntax.while; hot-path byte-level RFC 8032 encoding
  // Reverse big-endian to little-endian
  var i = 0
  while i < copyLen do
    leBytes(i) = unsigned(unsigned.length - 1 - i)
    i += 1
  // scalafix:on DisableSyntax.var, DisableSyntax.while
  // Set the high bit of the last byte if x is odd (RFC 8032)
  if point.isXOdd then leBytes(keyLen - 1) = (leBytes(keyLen - 1) | 0x80).toByte
  Base64UrlString.encode(leBytes)
end edEcPublicKeyToX

private inline def okpToPublicKey(crv: OkpCurve, xB64: Base64UrlString): Either[JwtError, PublicKey] =
  xB64.decodeBytes.flatMap { xBytes =>
    Try {
      // hotpath: unsafeNulls justified — per-key-import byte manipulation, RFC 8032 decoding
      import scala.language.unsafeNulls
      // Decode RFC 8032 little-endian encoding back to EdECPoint
      val keyLen = crv.keyLength
      val leBytes = if xBytes.length == keyLen then xBytes else java.util.Arrays.copyOf(xBytes, keyLen)
      val isXOdd = (leBytes(keyLen - 1) & 0x80) != 0
      leBytes(keyLen - 1) = (leBytes(keyLen - 1) & 0x7f).toByte
      // scalafix:off DisableSyntax.var, DisableSyntax.while; hot-path byte-level RFC 8032 decoding
      // Reverse little-endian to big-endian for BigInteger
      val beBytes = new Array[Byte](keyLen)
      var i = 0
      while i < keyLen do
        beBytes(i) = leBytes(keyLen - 1 - i)
        i += 1
      // scalafix:on DisableSyntax.var, DisableSyntax.while
      val y = BigInteger(1, beBytes)
      val point = java.security.spec.EdECPoint(isXOdd, y)
      val spec = java.security.spec.EdECPublicKeySpec(NamedParameterSpec(crv.jcaName), point)
      KeyFactory.getInstance("EdDSA").generatePublic(spec)
    }.toEither.left.map(e => JwtError.InvalidKey(e.getMessage.option.getOrElse("OKP public key generation failed")))
  }

private inline def okpToPrivateKey(crv: OkpCurve, dB64: Base64UrlString): Either[JwtError, PrivateKey] =
  dB64.decodeBytes.flatMap { dBytes =>
    Try {
      import scala.language.unsafeNulls // hotpath: unsafeNulls justified — JCA KeyFactory.generatePrivate non-null
      val spec = java.security.spec.EdECPrivateKeySpec(NamedParameterSpec(crv.jcaName), dBytes)
      KeyFactory.getInstance("EdDSA").generatePrivate(spec)
    }.toEither.left.map(e => JwtError.InvalidKey(e.getMessage.option.getOrElse("OKP private key generation failed")))
  }

private inline def fromEdEcPublicKey(edec: JcaEdEcPublicKey, kid: Option[Kid]): Either[JwtError, Jwk] =
  for crv <- okpCurveFromEdEcKey(edec)
  yield
    val x = edEcPublicKeyToX(edec, crv)
    Jwk.OkpPublicKey(crv = crv, x = x, use = None, keyOps = None, alg = None, kid = kid)

private inline def fromEdEcPrivateKey(edec: JcaEdEcPrivateKey, edecPub: JcaEdEcPublicKey, kid: Option[Kid]): Either[JwtError, Jwk] =
  import scala.jdk.OptionConverters.*
  for
    crv <- okpCurveFromEdEcKey(edecPub)
    dBytes <- edec.getBytes.toScala.toRight(JwtError.InvalidKey("EdEC private key has no raw bytes"))
  yield
    val x = edEcPublicKeyToX(edecPub, crv)
    val dB64 = Base64UrlString.encode(dBytes)
    Jwk.OkpPrivateKey(crv = crv, x = x, d = dB64, use = None, keyOps = None, alg = None, kid = kid)
