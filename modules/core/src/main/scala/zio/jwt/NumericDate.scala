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

import java.time.Instant

import boilerplate.OpaqueType

/** Epoch-seconds date as per RFC 7519 ss2. Wraps [[java.time.Instant]]. */
opaque type NumericDate = Instant

/** Companion and [[OpaqueType]] instance for [[NumericDate]]. */
object NumericDate extends OpaqueType[NumericDate]:
  type Type = Instant
  type Error = IllegalArgumentException

  inline def wrap(value: Instant): NumericDate = value
  inline def unwrap(value: NumericDate): Instant = value

  override protected inline def validate(value: Instant): Option[IllegalArgumentException] = None

  inline def fromEpochSecond(epoch: Long): NumericDate = Instant.ofEpochSecond(epoch)

  extension (nd: NumericDate) inline def toEpochSecond: Long = nd.getEpochSecond
end NumericDate
