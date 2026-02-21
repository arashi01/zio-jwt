package zio.jwt

import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.SecretKey

import scala.annotation.targetName

import zio.Chunk
import zio.IO
import zio.UIO
import zio.ZIO

/**
 * Source of [[Jwk]] keys for signature verification and signing.
 * Implementations provide keys as an infallible effect; structural validity
 * is checked lazily during key resolution (ss9.3).
 *
 * @see [[KeySource$ KeySource]] for static factory methods and key resolution.
 */
trait KeySource:
  def keys: UIO[Chunk[Jwk]]

/**
 * Companion for [[KeySource]]. Provides static factories and key resolution logic (ss9.3).
 */
object KeySource:

  /** Creates a [[KeySource]] backed by a fixed set of keys. */
  def static(jwks: Chunk[Jwk]): KeySource =
    new KeySource:
      def keys: UIO[Chunk[Jwk]] = ZIO.succeed(jwks)

  /** Creates a [[KeySource]] backed by a single key. */
  def static(jwk: Jwk): KeySource = static(Chunk(jwk))

  // -- Key resolution (ss9.3) --

  /**
   * Resolves a public key from the source matching the given header.
   * Filters by use/key_ops/alg (ss8.5), matches kid, then converts to JCA key.
   */
  def resolvePublicKey(source: KeySource, header: JoseHeader): IO[JwtError, PublicKey] =
    source.resolvePublicKey(header)

  /**
   * Resolves a private key from the source matching the given header.
   * Filters by use/key_ops/alg (ss8.5), matches kid, then converts to JCA key.
   */
  def resolvePrivateKey(source: KeySource, header: JoseHeader): IO[JwtError, PrivateKey] =
    source.resolvePrivateKey(header)

  /**
   * Resolves a secret key from the source matching the given header.
   * Filters by use/key_ops/alg (ss8.5), matches kid, then converts to JCA key.
   */
  def resolveSecretKey(source: KeySource, header: JoseHeader): IO[JwtError, SecretKey] =
    source.resolveSecretKey(header)

  extension (source: KeySource)

    /** Resolves a public key matching the given header (ss9.3). */
    @targetName("keySourceResolvePublicKey")
    def resolvePublicKey(header: JoseHeader): IO[JwtError, PublicKey] =
      resolveJwk(source, header).flatMap(jwk => ZIO.fromEither(jwk.toPublicKey))

    /** Resolves a private key matching the given header (ss9.3). */
    @targetName("keySourceResolvePrivateKey")
    def resolvePrivateKey(header: JoseHeader): IO[JwtError, PrivateKey] =
      resolveJwk(source, header).flatMap(jwk => ZIO.fromEither(jwk.toPrivateKey))

    /** Resolves a secret key matching the given header (ss9.3). */
    @targetName("keySourceResolveSecretKey")
    def resolveSecretKey(header: JoseHeader): IO[JwtError, SecretKey] =
      resolveJwk(source, header).flatMap(jwk => ZIO.fromEither(jwk.toSecretKey))

  // -- Internal resolution logic --

  private def resolveJwk(source: KeySource, header: JoseHeader): IO[JwtError, Jwk] =
    source.keys.flatMap { allKeys =>
      val filtered = allKeys.filter(_.suitableForVerification(header.alg))

      val selected = header.kid match
        case Some(headerKid) =>
          filtered.filter(_.keyId.contains(headerKid)) match
            case chunk if chunk.size == 1 => Right(chunk(0))
            case chunk if chunk.isEmpty   => Left(JwtError.KeyNotFound(Some(headerKid)))
            case _                        => Left(JwtError.KeyNotFound(Some(headerKid)))
        case None =>
          filtered match
            case chunk if chunk.size == 1 => Right(chunk(0))
            case _                        => Left(JwtError.KeyNotFound(None))

      ZIO.fromEither(selected)
    }
