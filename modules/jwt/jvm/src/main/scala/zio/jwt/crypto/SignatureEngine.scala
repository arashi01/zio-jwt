package zio.jwt.crypto

import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PSSParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.interfaces.RSAKey
import javax.crypto.Mac
import javax.crypto.SecretKey

import scala.annotation.targetName
import scala.util.Try

import zio.jwt.*

/**
 * Low-level JCA signing and verification for all JWS algorithm families.
 * Handles HMAC (constant-time), RSA, ECDSA (with DER transcoding), and RSA-PSS.
 */
object SignatureEngine:

  private val MinRsaKeyBits = 2048

  // -- Public API --

  /** Signs `data` with the given algorithm and key. Returns raw signature bytes. */
  def sign(data: Array[Byte], key: SecretKey, alg: Algorithm): Either[JwtError, Array[Byte]] =
    alg.family match
      case AlgorithmFamily.HMAC => hmacSign(data, key, alg)
      case _                    => Left(JwtError.MalformedToken(IllegalArgumentException("SecretKey is only valid for HMAC algorithms")))

  /** Signs `data` with the given algorithm and private key. Returns raw signature bytes. */
  @targetName("signWithPrivateKey")
  def sign(data: Array[Byte], key: PrivateKey, alg: Algorithm): Either[JwtError, Array[Byte]] =
    alg.family match
      case AlgorithmFamily.RSA   => validateRsaKeySize(key).flatMap(_ => jcaSign(data, key, alg.jcaName, None))
      case AlgorithmFamily.RSAPSS => validateRsaKeySize(key).flatMap(_ => jcaSign(data, key, alg.jcaName, pssSpec(alg)))
      case AlgorithmFamily.EC    =>
        for
          sigLen <- EcdsaCodec.signatureLength(alg).toRight(JwtError.MalformedToken(
            IllegalArgumentException(s"No signature length for ${alg.toString}")
          ))
          der    <- jcaSign(data, key, alg.jcaName, None)
          concat <- EcdsaCodec.derToConcat(der, sigLen)
        yield concat
      case AlgorithmFamily.HMAC  => Left(JwtError.MalformedToken(IllegalArgumentException("PrivateKey is not valid for HMAC algorithms")))

  /** Verifies `signature` against `data` using the given algorithm and secret key. */
  def verify(data: Array[Byte], signature: Array[Byte], key: SecretKey, alg: Algorithm): Either[JwtError, Unit] =
    alg.family match
      case AlgorithmFamily.HMAC =>
        hmacSign(data, key, alg).flatMap { computed =>
          Either.cond(ConstantTime.areEqual(computed, signature), (), JwtError.InvalidSignature)
        }
      case _ => Left(JwtError.MalformedToken(IllegalArgumentException("SecretKey is only valid for HMAC algorithms")))

  /** Verifies `signature` against `data` using the given algorithm and public key. */
  @targetName("verifyWithPublicKey")
  def verify(data: Array[Byte], signature: Array[Byte], key: PublicKey, alg: Algorithm): Either[JwtError, Unit] =
    alg.family match
      case AlgorithmFamily.RSA    => validateRsaKeySize(key).flatMap(_ => jcaVerify(data, signature, key, alg.jcaName, None))
      case AlgorithmFamily.RSAPSS => validateRsaKeySize(key).flatMap(_ => jcaVerify(data, signature, key, alg.jcaName, pssSpec(alg)))
      case AlgorithmFamily.EC     =>
        for
          _   <- EcParams.validateSignature(alg, signature)
          der <- EcdsaCodec.concatToDer(signature)
          _   <- jcaVerify(data, der, key, alg.jcaName, None)
        yield ()
      case AlgorithmFamily.HMAC => Left(JwtError.MalformedToken(IllegalArgumentException("PublicKey is not valid for HMAC algorithms")))

  // -- RSA-PSS parameter specs --

  private def pssSpec(alg: Algorithm): Option[PSSParameterSpec] =
    import scala.language.unsafeNulls
    alg match
      case Algorithm.PS256 => Some(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
      case Algorithm.PS384 => Some(PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1))
      case Algorithm.PS512 => Some(PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1))
      case _               => None

  // -- RSA key size validation --

  private def validateRsaKeySize(key: java.security.Key): Either[JwtError, Unit] =
    import scala.language.unsafeNulls
    key match
      case rsa: RSAKey =>
        val bits = rsa.getModulus.bitLength()
        Either.cond(bits >= MinRsaKeyBits, (), JwtError.MalformedToken(
          IllegalArgumentException(s"RSA key must be at least $MinRsaKeyBits bits, got $bits")
        ))
      case _ =>
        // Non-RSA key passed to RSA algorithm -- let JCA reject it downstream
        Right(())

  // -- HMAC --

  private def hmacSign(data: Array[Byte], key: SecretKey, alg: Algorithm): Either[JwtError, Array[Byte]] =
    import scala.language.unsafeNulls
    Try {
      val mac = Mac.getInstance(alg.jcaName)
      mac.init(key)
      mac.doFinal(data)
    }.toEither.left.map(e => JwtError.MalformedToken(e))

  // -- JCA Signature helpers --

  private def jcaSign(
      data: Array[Byte],
      key: PrivateKey,
      jcaAlg: String,
      params: Option[PSSParameterSpec]
  ): Either[JwtError, Array[Byte]] =
    import scala.language.unsafeNulls
    Try {
      val sig = java.security.Signature.getInstance(jcaAlg)
      params.foreach(sig.setParameter(_))
      sig.initSign(key)
      sig.update(data)
      sig.sign()
    }.toEither.left.map(e => JwtError.MalformedToken(e))

  private def jcaVerify(
      data: Array[Byte],
      signature: Array[Byte],
      key: PublicKey,
      jcaAlg: String,
      params: Option[PSSParameterSpec]
  ): Either[JwtError, Unit] =
    import scala.language.unsafeNulls
    Try {
      val sig = java.security.Signature.getInstance(jcaAlg)
      params.foreach(sig.setParameter(_))
      sig.initVerify(key)
      sig.update(data)
      sig.verify(signature)
    }.toEither match
      case Right(true)  => Right(())
      case Right(false) => Left(JwtError.InvalidSignature)
      case Left(e)      => Left(JwtError.InvalidSignature)
