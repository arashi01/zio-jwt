package zio.jwt

import zio.Chunk
import zio.NonEmptyChunk

/** Package-level [[CanEqual]] instances for ZIO container types under strict equality. */
given [A] => CanEqual[A, A] => CanEqual[Chunk[A], Chunk[A]]               = CanEqual.derived
given [A] => CanEqual[A, A] => CanEqual[NonEmptyChunk[A], NonEmptyChunk[A]] = CanEqual.derived
