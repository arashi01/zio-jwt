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

import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.EdECPublicKey
import java.security.interfaces.RSAKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.NamedParameterSpec
import java.security.spec.PSSParameterSpec
import javax.crypto.Mac
import javax.crypto.SecretKey

import scala.util.Try

import boilerplate.nullable.*

import zio.jwt.*

/** Low-level JCA signing and verification for all JWS algorithm families. Handles HMAC
  * (constant-time), RSA, ECDSA (with DER transcoding), and RSA-PSS.
  */
object SignatureEngine:

  private val MinRsaKeyBits = 2048

  // -- Public API --

  /** Signs `data` with the given algorithm and key. Returns raw signature bytes. */
  def sign(data: Array[Byte], key: SecretKey, alg: Algorithm): Either[JwtError, Array[Byte]] =
    alg.family match
      case AlgorithmFamily.HMAC => hmacSign(data, key, alg)
      case _                    => Left(JwtError.InvalidKey("SecretKey is only valid for HMAC algorithms"))

  /** Signs `data` with the given algorithm and private key. Returns raw signature bytes. */
  def sign(data: Array[Byte], key: PrivateKey, alg: Algorithm): Either[JwtError, Array[Byte]] =
    alg.family match
      case AlgorithmFamily.RSA    => validateRsaKeySize(key).flatMap(_ => jcaSign(data, key, alg.jcaName, None))
      case AlgorithmFamily.RSAPSS => validateRsaKeySize(key).flatMap(_ => jcaSign(data, key, alg.jcaName, pssSpec(alg)))
      case AlgorithmFamily.EC     =>
        for
          sigLen <- EcdsaCodec
                      .signatureLength(alg)
                      .toRight(
                        JwtError.InvalidKey(
                          s"No signature length for ${alg.name}"
                        )
                      )
          der <- jcaSign(data, key, alg.jcaName, None)
          concat <- EcdsaCodec.derToConcat(der, sigLen)
        yield concat
      case AlgorithmFamily.OKP  => jcaSign(data, key, "EdDSA", None)
      case AlgorithmFamily.HMAC => Left(JwtError.InvalidKey("PrivateKey is not valid for HMAC algorithms"))

  /** Verifies `signature` against `data` using the given algorithm and secret key. */
  def verify(data: Array[Byte], signature: Array[Byte], key: SecretKey, alg: Algorithm): Either[JwtError, Unit] =
    alg.family match
      case AlgorithmFamily.HMAC =>
        hmacSign(data, key, alg).flatMap { computed =>
          Either.cond(ConstantTime.areEqual(computed, signature), (), JwtError.InvalidSignature)
        }
      case _ => Left(JwtError.InvalidKey("SecretKey is only valid for HMAC algorithms"))

  /** Verifies `signature` against `data` using the given algorithm and public key. */
  def verify(data: Array[Byte], signature: Array[Byte], key: PublicKey, alg: Algorithm): Either[JwtError, Unit] =
    alg.family match
      case AlgorithmFamily.RSA    => validateRsaKeySize(key).flatMap(_ => jcaVerify(data, signature, key, alg.jcaName, None))
      case AlgorithmFamily.RSAPSS => validateRsaKeySize(key).flatMap(_ => jcaVerify(data, signature, key, alg.jcaName, pssSpec(alg)))
      case AlgorithmFamily.EC     =>
        for
          _ <- EcParams.validateSignature(alg, signature)
          der <- EcdsaCodec.concatToDer(signature)
          _ <- jcaVerify(data, der, key, alg.jcaName, None)
        yield ()
      case AlgorithmFamily.OKP =>
        validateEdDsaSignatureLength(key, signature).flatMap(_ => jcaVerify(data, signature, key, "EdDSA", None))
      case AlgorithmFamily.HMAC => Left(JwtError.InvalidKey("PublicKey is not valid for HMAC algorithms"))

  // -- EdDSA signature length validation --

  /** Rejects EdDSA signatures with incorrect length before calling JCA. Ed25519 signatures are
    * exactly 64 bytes; Ed448 signatures are exactly 114 bytes.
    */
  private def validateEdDsaSignatureLength(key: PublicKey, signature: Array[Byte]): Either[JwtError, Unit] =
    val expectedLen = key match
      case edec: EdECPublicKey =>
        edec.getParams.fold(-1) {
          case ns: NamedParameterSpec if ns.getName.getOrElse("") == "Ed25519" => 64
          case ns: NamedParameterSpec if ns.getName.getOrElse("") == "Ed448"   => 114
          case _                                                               => -1 // unknown curve; let JCA reject
        }
      case _ => -1 // not an EdEC key; let JCA reject
    if expectedLen > 0 && signature.length != expectedLen then Left(JwtError.InvalidSignature)
    else Right(())

  // -- RSA-PSS parameter specs --

  private def pssSpec(alg: Algorithm): Option[PSSParameterSpec] =
    alg match
      case Algorithm.PS256 => Some(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
      case Algorithm.PS384 => Some(PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1))
      case Algorithm.PS512 => Some(PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1))
      case _               => None

  // -- RSA key size validation --

  private def validateRsaKeySize(key: java.security.Key): Either[JwtError, Unit] =
    key match
      case rsa: RSAKey =>
        rsa.getModulus.fold[Either[JwtError, Unit]](Left(JwtError.InvalidKey("RSA key has null modulus"))) { mod =>
          val bits = mod.bitLength()
          Either.cond(bits >= MinRsaKeyBits,
                      (),
                      JwtError.InvalidKey(
                        s"RSA key must be at least $MinRsaKeyBits bits, got $bits"
                      )
          )
        }
      case _ =>
        // Non-RSA key passed to RSA algorithm -- let JCA reject it downstream
        Right(())
    end match
  end validateRsaKeySize

  // -- HMAC key size validation (RFC 7518 ss3.2) --

  /** Validates that the HMAC secret key meets the minimum size required by RFC 7518 ss3.2: a key of
    * the same size as the hash output or larger MUST be used. HSM-backed keys (where `getEncoded`
    * returns null) are allowed through -- their size cannot be inspected and JCA will handle
    * enforcement.
    */
  private def validateHmacKeySize(key: SecretKey, alg: Algorithm): Either[JwtError, Unit] =
    val minBytes = alg match
      case Algorithm.HS256 => 32
      case Algorithm.HS384 => 48
      case Algorithm.HS512 => 64
      case _               => 0 // unreachable for HMAC family
    key.getEncoded.fold(Right(())) { encoded =>
      Either.cond(
        encoded.length >= minBytes,
        (),
        JwtError.InvalidKey(s"HMAC key must be at least ${minBytes * 8} bits for ${alg.name}, got ${encoded.length * 8}")
      )
    }
  end validateHmacKeySize

  // -- HMAC --

  private def hmacSign(data: Array[Byte], key: SecretKey, alg: Algorithm): Either[JwtError, Array[Byte]] =
    validateHmacKeySize(key, alg).flatMap { _ =>
      Try {
        val mac = Mac.getInstance(alg.jcaName)
        mac.init(key)
        mac.doFinal(data).unsafe
      }.toEither.left.map(e => JwtError.InvalidKey(e.getMessage.getOrElse("HMAC signing failed")))
    }

  // -- JCA Signature helpers --

  private def jcaSign(
    data: Array[Byte],
    key: PrivateKey,
    jcaAlg: String,
    params: Option[PSSParameterSpec]
  ): Either[JwtError, Array[Byte]] =
    Try {
      val sig = java.security.Signature.getInstance(jcaAlg)
      params.foreach(sig.setParameter(_))
      sig.initSign(key)
      sig.update(data)
      sig.sign().unsafe
    }.toEither.left.map(e => JwtError.InvalidKey(e.getMessage.getOrElse("JCA signing failed")))
  end jcaSign

  private def jcaVerify(
    data: Array[Byte],
    signature: Array[Byte],
    key: PublicKey,
    jcaAlg: String,
    params: Option[PSSParameterSpec]
  ): Either[JwtError, Unit] =
    Try {
      val sig = java.security.Signature.getInstance(jcaAlg)
      params.foreach(sig.setParameter(_))
      sig.initVerify(key)
      sig.update(data)
      sig.verify(signature)
    }.toEither match
      case Right(true)  => Right(())
      case Right(false) => Left(JwtError.InvalidSignature)
      // Security: swallow JCA exception details to avoid leaking implementation info.
      // Configuration errors (e.g. algorithm mismatch) are indistinguishable from invalid
      // signatures by design.
      case Left(e) => Left(JwtError.InvalidSignature)
    end match
  end jcaVerify
end SignatureEngine
