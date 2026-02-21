package zio.jwt

/** Codec abstraction for JWT header, claims, and domain types. */
trait JwtCodec[A]:
  def decode(bytes: Array[Byte]): Either[Throwable, A]
  def encode(value: A): Array[Byte]
