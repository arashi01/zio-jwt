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

import zio.NonEmptyChunk

/** JWT audience claim (RFC 7519 ss4.1.3). May be a single string or a non-empty array of strings. */
enum Audience derives CanEqual:
  case Single(value: String)
  case Many(values: NonEmptyChunk[String])

/** Companion for [[Audience]]. Provides smart constructors and query extensions. */
object Audience:

  def apply(value: String): Audience = Audience.Single(value)

  def apply(values: NonEmptyChunk[String]): Audience =
    if values.size == 1 then Audience.Single(values.head)
    else Audience.Many(values)

  extension (aud: Audience)

    /** All audience values as a non-empty collection. */
    def values: NonEmptyChunk[String] = aud match
      case Audience.Single(v) => NonEmptyChunk(v)
      case Audience.Many(vs)  => vs

    /** Whether the audience contains the given target string. */
    def contains(target: String): Boolean = aud match
      case Audience.Single(v) => v == target
      case Audience.Many(vs)  => vs.contains(target)
end Audience
