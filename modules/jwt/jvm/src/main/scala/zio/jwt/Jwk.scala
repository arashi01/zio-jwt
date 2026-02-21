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
import java.security.interfaces.RSAPrivateCrtKey as JcaRsaPrivateCrtKey
import java.security.interfaces.RSAPublicKey as JcaRsaPublicKey
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.RSAPrivateCrtKeySpec
import java.security.spec.RSAPublicKeySpec
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

import scala.annotation.targetName
import scala.util.Try

import zio.Chunk

import zio.jwt.crypto.EcParams

/** JSON Web Key (RFC 7517) ADT. Instances may be constructed directly or via [[Jwk$ Jwk]].from
  * factory methods.
  */
enum Jwk derives CanEqual:
  case EcPublicKey(
    crv: EcCurve,
    x: Base64UrlString,
    y: Base64UrlString,
    use: Option[KeyUse],
    keyOps: Option[Chunk[KeyOp]],
    alg: Option[Algorithm],
    kid: Option[Kid]
  )
  case EcPrivateKey(
    crv: EcCurve,
    x: Base64UrlString,
    y: Base64UrlString,
    d: Base64UrlString,
    use: Option[KeyUse],
    keyOps: Option[Chunk[KeyOp]],
    alg: Option[Algorithm],
    kid: Option[Kid]
  )
  case RsaPublicKey(
    n: Base64UrlString,
    e: Base64UrlString,
    use: Option[KeyUse],
    keyOps: Option[Chunk[KeyOp]],
    alg: Option[Algorithm],
    kid: Option[Kid]
  )
  case RsaPrivateKey(
    n: Base64UrlString,
    e: Base64UrlString,
    d: Base64UrlString,
    p: Base64UrlString,
    q: Base64UrlString,
    dp: Base64UrlString,
    dq: Base64UrlString,
    qi: Base64UrlString,
    use: Option[KeyUse],
    keyOps: Option[Chunk[KeyOp]],
    alg: Option[Algorithm],
    kid: Option[Kid]
  )
  case SymmetricKey(
    k: Base64UrlString,
    use: Option[KeyUse],
    keyOps: Option[Chunk[KeyOp]],
    alg: Option[Algorithm],
    kid: Option[Kid]
  )
end Jwk

/** Companion for [[Jwk]]. Provides JCA key conversion, factory methods, and filtering extensions. */
object Jwk:

  // -- Base64url <-> BigInteger utilities (ss5.4) --

  private val base64UrlDecoder = java.util.Base64.getUrlDecoder
  private val base64UrlEncoder = java.util.Base64.getUrlEncoder.withoutPadding()

  /** Decodes a base64url-encoded string to a positive BigInteger. */
  private inline def decodeBigInt(b64: Base64UrlString): Either[JwtError, BigInteger] =
    Try {
      import scala.language.unsafeNulls
      val bytes = base64UrlDecoder.decode(b64.asInstanceOf[String]) // scalafix:ok DisableSyntax.asInstanceOf; Bypass opaque type allowing use of deferred inline methods.
      BigInteger(1, bytes)
    }.toEither.left.map(e => JwtError.MalformedToken(e))

  /** Encodes a positive BigInteger as base64url without padding, stripping the sign byte. */
  private inline def encodeBigInt(value: BigInteger): Base64UrlString =
    import scala.language.unsafeNulls
    val bytes = value.toByteArray
    // Strip leading zero sign byte if present
    val unsigned = if bytes.length > 1 && bytes(0) == 0.toByte then bytes.drop(1) else bytes
    Base64UrlString.wrap(base64UrlEncoder.encodeToString(unsigned))

  /** Encodes a positive BigInteger as base64url, padded to the given field size in bytes. Used for
    * EC coordinates which must be padded to the curve's field element size.
    */
  private inline def encodeBigIntPadded(value: BigInteger, fieldSize: Int): Base64UrlString =
    import scala.language.unsafeNulls
    val bytes = value.toByteArray
    val unsigned = if bytes.length > 1 && bytes(0) == 0.toByte then bytes.drop(1) else bytes
    val padded =
      if unsigned.length >= fieldSize then unsigned
      else
        val buf = new Array[Byte](fieldSize)
        System.arraycopy(unsigned, 0, buf, fieldSize - unsigned.length, unsigned.length)
        buf
    Base64UrlString.wrap(base64UrlEncoder.encodeToString(padded))

  private val MinRsaKeyBits = 2048

  // -- JWK -> JCA key conversion (ss8.3) --

  extension (jwk: Jwk)

    /** Converts this JWK to a JCA [[PublicKey]]. */
    def toPublicKey: Either[JwtError, PublicKey] = jwk match
      case ec: Jwk.EcPublicKey    => ecToPublicKey(ec.crv, ec.x, ec.y)
      case ec: Jwk.EcPrivateKey   => ecToPublicKey(ec.crv, ec.x, ec.y)
      case rsa: Jwk.RsaPublicKey  => rsaToPublicKey(rsa.n, rsa.e)
      case rsa: Jwk.RsaPrivateKey => rsaToPublicKey(rsa.n, rsa.e)
      case _: Jwk.SymmetricKey    =>
        Left(JwtError.MalformedToken(IllegalArgumentException("Symmetric keys do not have a public key")))

    /** Converts this JWK to a JCA [[PrivateKey]]. */
    def toPrivateKey: Either[JwtError, PrivateKey] = jwk match
      case ec: Jwk.EcPrivateKey   => ecToPrivateKey(ec.crv, ec.d)
      case rsa: Jwk.RsaPrivateKey => rsaToPrivateKey(rsa.n, rsa.e, rsa.d, rsa.p, rsa.q, rsa.dp, rsa.dq, rsa.qi)
      case _: Jwk.EcPublicKey     =>
        Left(JwtError.MalformedToken(IllegalArgumentException("EC public key does not contain a private key")))
      case _: Jwk.RsaPublicKey =>
        Left(JwtError.MalformedToken(IllegalArgumentException("RSA public key does not contain a private key")))
      case _: Jwk.SymmetricKey =>
        Left(JwtError.MalformedToken(IllegalArgumentException("Symmetric keys do not have a private key")))

    /** Converts this JWK to a JCA [[SecretKey]]. */
    def toSecretKey: Either[JwtError, SecretKey] = jwk match
      case sym: Jwk.SymmetricKey => symmetricToSecretKey(sym.k, sym.alg)
      case _                     =>
        Left(JwtError.MalformedToken(IllegalArgumentException("Only symmetric keys can be converted to SecretKey")))

    /** Tests whether this key is suitable for signature verification per ss8.5. */
    @targetName("jwkSuitableForVerification")
    def suitableForVerification(headerAlg: Algorithm): Boolean =
      val useOk = jwk.keyUse.forall(_ == KeyUse.Sig)
      val opsOk = jwk.keyOperations.forall(_.contains(KeyOp.Verify))
      val algOk = jwk.keyAlgorithm.forall(_ == headerAlg)
      useOk && opsOk && algOk

    /** Tests whether this key is suitable for signing per ss8.5 (mirror of verification). */
    @targetName("jwkSuitableForSigning")
    def suitableForSigning(headerAlg: Algorithm): Boolean =
      val useOk = jwk.keyUse.forall(_ == KeyUse.Sig)
      val opsOk = jwk.keyOperations.forall(_.contains(KeyOp.Sign))
      val algOk = jwk.keyAlgorithm.forall(_ == headerAlg)
      useOk && opsOk && algOk

    /** The `use` field, regardless of JWK variant. */
    def keyUse: Option[KeyUse] = jwk match
      case k: Jwk.EcPublicKey   => k.use
      case k: Jwk.EcPrivateKey  => k.use
      case k: Jwk.RsaPublicKey  => k.use
      case k: Jwk.RsaPrivateKey => k.use
      case k: Jwk.SymmetricKey  => k.use

    /** The `key_ops` field, regardless of JWK variant. */
    def keyOperations: Option[Chunk[KeyOp]] = jwk match
      case k: Jwk.EcPublicKey   => k.keyOps
      case k: Jwk.EcPrivateKey  => k.keyOps
      case k: Jwk.RsaPublicKey  => k.keyOps
      case k: Jwk.RsaPrivateKey => k.keyOps
      case k: Jwk.SymmetricKey  => k.keyOps

    /** The `alg` field, regardless of JWK variant. */
    def keyAlgorithm: Option[Algorithm] = jwk match
      case k: Jwk.EcPublicKey   => k.alg
      case k: Jwk.EcPrivateKey  => k.alg
      case k: Jwk.RsaPublicKey  => k.alg
      case k: Jwk.RsaPrivateKey => k.alg
      case k: Jwk.SymmetricKey  => k.alg

    /** The `kid` field, regardless of JWK variant. */
    def keyId: Option[Kid] = jwk match
      case k: Jwk.EcPublicKey   => k.kid
      case k: Jwk.EcPrivateKey  => k.kid
      case k: Jwk.RsaPublicKey  => k.kid
      case k: Jwk.RsaPrivateKey => k.kid
      case k: Jwk.SymmetricKey  => k.kid
  end extension

  // Multi-parameter extension aliases (ss1.4)

  /** Tests whether a key is suitable for signature verification with the given algorithm. */
  inline def suitableForVerification(jwk: Jwk, alg: Algorithm): Boolean =
    jwk.suitableForVerification(alg)

  /** Tests whether a key is suitable for signing with the given algorithm. */
  inline def suitableForSigning(jwk: Jwk, alg: Algorithm): Boolean =
    jwk.suitableForSigning(alg)

  // -- JCA key -> JWK factory methods (ss8.4) --

  /** Creates a [[Jwk]] from a JCA [[PublicKey]]. */
  def from(key: PublicKey, kid: Option[Kid]): Either[JwtError, Jwk] =
    import scala.language.unsafeNulls
    key match
      case ec: JcaEcPublicKey   => fromEcPublicKey(ec, kid)
      case rsa: JcaRsaPublicKey => fromRsaPublicKey(rsa, kid)
      case _ => Left(JwtError.MalformedToken(IllegalArgumentException(s"Unsupported public key type: ${key.getClass.getName}")))

  /** Creates a [[Jwk]] from a JCA [[PublicKey]] without a key identifier. */
  def from(key: PublicKey): Either[JwtError, Jwk] = from(key, None)

  /** Creates a [[Jwk]] from a JCA [[PrivateKey]] (includes public components). */
  def from(key: PrivateKey, publicKey: PublicKey, kid: Option[Kid]): Either[JwtError, Jwk] =
    import scala.language.unsafeNulls
    (key, publicKey) match
      case (ec: JcaEcPrivateKey, ecPub: JcaEcPublicKey)        => fromEcPrivateKey(ec, ecPub, kid)
      case (rsa: JcaRsaPrivateCrtKey, rsaPub: JcaRsaPublicKey) => fromRsaPrivateKey(rsa, rsaPub, kid)
      case _                                                   =>
        Left(
          JwtError.MalformedToken(
            IllegalArgumentException(s"Unsupported key pair types: ${key.getClass.getName}, ${publicKey.getClass.getName}")
          )
        )

  /** Creates a [[Jwk]] from a JCA [[SecretKey]]. */
  def from(key: SecretKey, kid: Option[Kid]): Either[JwtError, Jwk] =
    import scala.language.unsafeNulls
    val encoded = key.getEncoded
    if encoded == null || encoded.isEmpty then // scalafix:ok DisableSyntax.null; JCA SecretKey.getEncoded may return null
      Left(JwtError.MalformedToken(IllegalArgumentException("SecretKey has no encoded form")))
    else
      val b64 = Base64UrlString.wrap(base64UrlEncoder.encodeToString(encoded))
      Right(Jwk.SymmetricKey(k = b64, use = None, keyOps = None, alg = None, kid = kid))

  /** Creates a [[Jwk]] from a JCA [[SecretKey]] without a key identifier. */
  def from(key: SecretKey): Either[JwtError, Jwk] = from(key, None)

  // -- Internal EC conversion helpers --

  private inline def ecToPublicKey(crv: EcCurve, xB64: Base64UrlString, yB64: Base64UrlString): Either[JwtError, PublicKey] =
    for
      x <- decodeBigInt(xB64)
      y <- decodeBigInt(yB64)
      point = ECPoint(x, y)
      _ <- EcParams.validatePointOnCurve(crv, point)
      key <- Try {
               import scala.language.unsafeNulls
               val spec = ECPublicKeySpec(point, crv.spec)
               KeyFactory.getInstance("EC").generatePublic(spec)
             }.toEither.left.map(e => JwtError.MalformedToken(e))
    yield key

  private inline def ecToPrivateKey(crv: EcCurve, dB64: Base64UrlString): Either[JwtError, PrivateKey] =
    for
      d <- decodeBigInt(dB64)
      key <- Try {
               import scala.language.unsafeNulls
               val spec = ECPrivateKeySpec(d, crv.spec)
               KeyFactory.getInstance("EC").generatePrivate(spec)
             }.toEither.left.map(e => JwtError.MalformedToken(e))
    yield key

  private inline def rsaToPublicKey(nB64: Base64UrlString, eB64: Base64UrlString): Either[JwtError, PublicKey] =
    for
      n <- decodeBigInt(nB64)
      _ <- Either.cond(
             n.bitLength() >= MinRsaKeyBits,
             (),
             JwtError.MalformedToken(
               IllegalArgumentException(s"RSA key must be at least $MinRsaKeyBits bits, got ${n.bitLength()}")
             )
           )
      e <- decodeBigInt(eB64)
      key <- Try {
               import scala.language.unsafeNulls
               val spec = RSAPublicKeySpec(n, e)
               KeyFactory.getInstance("RSA").generatePublic(spec)
             }.toEither.left.map(e => JwtError.MalformedToken(e))
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
             JwtError.MalformedToken(
               IllegalArgumentException(s"RSA key must be at least $MinRsaKeyBits bits, got ${n.bitLength()}")
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
               import scala.language.unsafeNulls
               val spec = RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, qi)
               KeyFactory.getInstance("RSA").generatePrivate(spec)
             }.toEither.left.map(e => JwtError.MalformedToken(e))
    yield key

  private inline def symmetricToSecretKey(kB64: Base64UrlString, alg: Option[Algorithm]): Either[JwtError, SecretKey] =
    Try {
      import scala.language.unsafeNulls
      val bytes = base64UrlDecoder.decode(kB64.asInstanceOf[String]) // scalafix:ok DisableSyntax.asInstanceOf; Bypass opaque type allowing use of deferred inline methods.
      val jcaAlg = alg.fold("HmacSHA256")(_.jcaName)
      SecretKeySpec(bytes, jcaAlg): SecretKey
    }.toEither.left.map(e => JwtError.MalformedToken(e))

  // -- Internal JCA -> JWK helpers --

  private inline def curveFromSpec(ecPub: JcaEcPublicKey): Either[JwtError, EcCurve] =
    import scala.language.unsafeNulls
    val fieldSize = ecPub.getParams.getCurve.getField.getFieldSize
    fieldSize match
      case 256 => Right(EcCurve.P256)
      case 384 => Right(EcCurve.P384)
      case 521 => Right(EcCurve.P521)
      case _   => Left(JwtError.MalformedToken(IllegalArgumentException(s"Unsupported EC field size: $fieldSize")))

  private inline def fromEcPublicKey(ec: JcaEcPublicKey, kid: Option[Kid]): Either[JwtError, Jwk] =
    import scala.language.unsafeNulls
    for crv <- curveFromSpec(ec)
    yield
      val fieldLen = crv.componentLength
      val x = encodeBigIntPadded(ec.getW.getAffineX, fieldLen)
      val y = encodeBigIntPadded(ec.getW.getAffineY, fieldLen)
      Jwk.EcPublicKey(crv = crv, x = x, y = y, use = None, keyOps = None, alg = None, kid = kid)

  private inline def fromEcPrivateKey(ec: JcaEcPrivateKey, ecPub: JcaEcPublicKey, kid: Option[Kid]): Either[JwtError, Jwk] =
    import scala.language.unsafeNulls
    for crv <- curveFromSpec(ecPub)
    yield
      val fieldLen = crv.componentLength
      val x = encodeBigIntPadded(ecPub.getW.getAffineX, fieldLen)
      val y = encodeBigIntPadded(ecPub.getW.getAffineY, fieldLen)
      val d = encodeBigIntPadded(ec.getS, fieldLen)
      Jwk.EcPrivateKey(crv = crv, x = x, y = y, d = d, use = None, keyOps = None, alg = None, kid = kid)

  private inline def fromRsaPublicKey(rsa: JcaRsaPublicKey, kid: Option[Kid]): Either[JwtError, Jwk] =
    import scala.language.unsafeNulls
    val n = encodeBigInt(rsa.getModulus)
    val e = encodeBigInt(rsa.getPublicExponent)
    Either.cond(
      rsa.getModulus.bitLength() >= MinRsaKeyBits,
      Jwk.RsaPublicKey(n = n, e = e, use = None, keyOps = None, alg = None, kid = kid),
      JwtError.MalformedToken(
        IllegalArgumentException(
          s"RSA key must be at least $MinRsaKeyBits bits, got ${rsa.getModulus.bitLength()}"
        )
      )
    )
  end fromRsaPublicKey

  private inline def fromRsaPrivateKey(rsa: JcaRsaPrivateCrtKey, rsaPub: JcaRsaPublicKey, kid: Option[Kid]): Either[JwtError, Jwk] =
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
      JwtError.MalformedToken(
        IllegalArgumentException(
          s"RSA key must be at least $MinRsaKeyBits bits, got ${rsaPub.getModulus.bitLength()}"
        )
      )
    )
  end fromRsaPrivateKey
end Jwk
