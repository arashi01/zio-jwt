package zio.jwt.jsoniter

import scala.util.Try

import com.github.plokhotnyuk.jsoniter_scala.core.*

import zio.jwt.JwtCodec

/** Bridges jsoniter-scala [[JsonValueCodec]] instances into zio-jwt [[JwtCodec]] instances. */
object JwtCodecInstances:

  /** Derive a [[JwtCodec]] from an available [[JsonValueCodec]]. */
  given [A](using jvc: JsonValueCodec[A]): JwtCodec[A] = new JwtCodec[A]:
    def decode(bytes: Array[Byte]): Either[Throwable, A] =
      Try(readFromArray[A](bytes)).toEither

    def encode(value: A): Array[Byte] =
      writeToArray[A](value)
