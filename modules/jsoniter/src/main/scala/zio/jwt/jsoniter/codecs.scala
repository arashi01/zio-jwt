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
package zio.jwt.jsoniter

import scala.util.Try

import zio.Chunk
import zio.NonEmptyChunk

import boilerplate.unwrap
import com.github.plokhotnyuk.jsoniter_scala.core.*

import zio.jwt.*

// scalafix:off DisableSyntax.var, DisableSyntax.null, DisableSyntax.asInstanceOf, DisableSyntax.while; jsoniter-scala codec API requires mutable state, null sentinels, and tight loops for streaming decode

/** jsoniter-scala [[JsonValueCodec]] instances for zio-jwt core types. */

given JsonValueCodec[NumericDate]:
  override def decodeValue(in: JsonReader, default: NumericDate): NumericDate =
    NumericDate.fromEpochSecond(in.readLong())

  override def encodeValue(x: NumericDate, out: JsonWriter): Unit =
    out.writeVal(x.toEpochSecond)

  override def nullValue: NumericDate = null.asInstanceOf[NumericDate]

given JsonValueCodec[Algorithm]:
  override def decodeValue(in: JsonReader, default: Algorithm): Algorithm =
    val s = in.readString("")
    Algorithm.fromString(s) match
      case Some(alg) => alg
      case None      => in.decodeError(s"unsupported or prohibited algorithm: $s")

  override def encodeValue(x: Algorithm, out: JsonWriter): Unit =
    out.writeVal(x.name)

  override def nullValue: Algorithm = null.asInstanceOf[Algorithm]

given JsonValueCodec[Kid]:
  override def decodeValue(in: JsonReader, default: Kid): Kid =
    Kid.from(in.readString("")) match
      case Right(k) => k
      case Left(e)  => in.decodeError(e.getMessage)

  override def encodeValue(x: Kid, out: JsonWriter): Unit =
    out.writeVal(x.unwrap)

  override def nullValue: Kid = null.asInstanceOf[Kid]

given JsonValueCodec[Audience]:
  override def decodeValue(in: JsonReader, default: Audience): Audience =
    val b = in.nextToken()
    if b == '"' then
      in.rollbackToken()
      Audience.Single(in.readString(""))
    else if b == '[' then
      if in.isNextToken(']') then in.decodeError("audience array must not be empty")
      else
        in.rollbackToken()
        val builder = Chunk.newBuilder[String]
        while
          builder += in.readString("")
          in.isNextToken(',')
        do ()
        if !in.isCurrentToken(']') then in.arrayEndError()
        NonEmptyChunk.fromChunk(builder.result()) match
          case Some(nec) => Audience(nec)
          case None      => in.decodeError("audience array must not be empty")
    else in.decodeError("expected string or array for audience")
    end if
  end decodeValue

  override def encodeValue(x: Audience, out: JsonWriter): Unit =
    x match
      case Audience.Single(v) => out.writeVal(v)
      case Audience.Many(vs)  =>
        out.writeArrayStart()
        vs.foreach(out.writeVal)
        out.writeArrayEnd()

  override def nullValue: Audience = null.asInstanceOf[Audience]
end given

given JsonValueCodec[JoseHeader]:
  override def decodeValue(in: JsonReader, default: JoseHeader): JoseHeader =
    var alg: Algorithm | Null = null
    var typ: Option[String] = None
    var cty: Option[String] = None
    var kid: Option[Kid] = None
    var x5t: Option[Base64UrlString] = None
    var x5tS256: Option[Base64UrlString] = None
    var crit: Option[Chunk[String]] = None
    var algSeen = false

    if !in.isNextToken('{') then in.decodeError("expected '{'")
    if !in.isNextToken('}') then
      in.rollbackToken()
      while
        val key = in.readKeyAsString()
        if key == "alg" then
          if algSeen then in.duplicatedKeyError(key.length)
          algSeen = true
          val algStr = in.readString("")
          if algStr.isEmpty || algStr == "none" then in.decodeError("algorithm 'none' is not permitted")
          else
            Algorithm.fromString(algStr) match
              case Some(a) => alg = a
              case None    => in.decodeError(s"unsupported algorithm: $algStr")
        else if key == "typ" then typ = readOptionalString(in)
        else if key == "cty" then cty = readOptionalString(in)
        else if key == "kid" then
          Kid.from(in.readString("")) match
            case Right(k) => kid = Some(k)
            case Left(e)  => in.decodeError(e.getMessage)
        else if key == "x5t" then
          Base64UrlString.from(in.readString("")) match
            case Right(b) => x5t = Some(b)
            case Left(e)  => in.decodeError(e.getMessage)
        else if key == "x5t#S256" then
          Base64UrlString.from(in.readString("")) match
            case Right(b) => x5tS256 = Some(b)
            case Left(e)  => in.decodeError(e.getMessage)
        else if key == "crit" then
          if !in.isNextToken('[') then in.decodeError("expected '[' for crit")
          if in.isNextToken(']') then crit = Some(Chunk.empty)
          else
            in.rollbackToken()
            val b = Chunk.newBuilder[String]
            while
              b += in.readString("")
              in.isNextToken(',')
            do ()
            if !in.isCurrentToken(']') then in.arrayEndError()
            crit = Some(b.result())
        else in.skip()
        end if
        in.isNextToken(',')
      do ()
      end while
    end if

    if !algSeen then in.decodeError("missing required field: alg")
    JoseHeader(alg.asInstanceOf[Algorithm], typ, cty, kid, x5t, x5tS256, crit)
  end decodeValue

  override def encodeValue(x: JoseHeader, out: JsonWriter): Unit =
    out.writeObjectStart()
    out.writeKey("alg")
    out.writeVal(x.alg.name)
    x.typ.foreach { t =>
      out.writeKey("typ")
      out.writeVal(t)
    }
    x.cty.foreach { c =>
      out.writeKey("cty")
      out.writeVal(c)
    }
    x.kid.foreach { k =>
      out.writeKey("kid")
      out.writeVal(k.unwrap)
    }
    x.x5t.foreach { t =>
      out.writeKey("x5t")
      out.writeVal(t.unwrap)
    }
    x.x5tS256.foreach { s =>
      out.writeKey("x5t#S256")
      out.writeVal(s.unwrap)
    }
    x.crit.foreach { params =>
      out.writeKey("crit")
      out.writeArrayStart()
      params.foreach(out.writeVal)
      out.writeArrayEnd()
    }
    out.writeObjectEnd()
  end encodeValue

  override def nullValue: JoseHeader = null.asInstanceOf[JoseHeader]
end given

given JsonValueCodec[RegisteredClaims]:
  override def decodeValue(in: JsonReader, default: RegisteredClaims): RegisteredClaims =
    var iss: Option[String] = None
    var sub: Option[String] = None
    var aud: Option[Audience] = None
    var exp: Option[NumericDate] = None
    var nbf: Option[NumericDate] = None
    var iat: Option[NumericDate] = None
    var jti: Option[String] = None

    if !in.isNextToken('{') then in.decodeError("expected '{'")
    if !in.isNextToken('}') then
      in.rollbackToken()
      while
        val key = in.readKeyAsString()
        if key == "iss" then iss = readOptionalString(in)
        else if key == "sub" then sub = readOptionalString(in)
        else if key == "aud" then
          val b = in.nextToken()
          if b == 'n' then
            in.readNullOrError((), "expected null")
            aud = None
          else
            in.rollbackToken()
            aud = Some(summon[JsonValueCodec[Audience]].decodeValue(in, null.asInstanceOf[Audience]))
        else if key == "exp" then exp = readOptionalNumericDate(in)
        else if key == "nbf" then nbf = readOptionalNumericDate(in)
        else if key == "iat" then iat = readOptionalNumericDate(in)
        else if key == "jti" then jti = readOptionalString(in)
        else in.skip()
        end if
        in.isNextToken(',')
      do ()
      end while
    end if

    RegisteredClaims(iss, sub, aud, exp, nbf, iat, jti)
  end decodeValue

  override def encodeValue(x: RegisteredClaims, out: JsonWriter): Unit =
    out.writeObjectStart()
    x.iss.foreach { v =>
      out.writeKey("iss")
      out.writeVal(v)
    }
    x.sub.foreach { v =>
      out.writeKey("sub")
      out.writeVal(v)
    }
    x.aud.foreach { a =>
      out.writeKey("aud")
      summon[JsonValueCodec[Audience]].encodeValue(a, out)
    }
    x.exp.foreach { v =>
      out.writeKey("exp")
      out.writeVal(v.toEpochSecond)
    }
    x.nbf.foreach { v =>
      out.writeKey("nbf")
      out.writeVal(v.toEpochSecond)
    }
    x.iat.foreach { v =>
      out.writeKey("iat")
      out.writeVal(v.toEpochSecond)
    }
    x.jti.foreach { v =>
      out.writeKey("jti")
      out.writeVal(v)
    }
    out.writeObjectEnd()
  end encodeValue

  override def nullValue: RegisteredClaims = null.asInstanceOf[RegisteredClaims]
end given

// -- Shared helpers --

private def readOptionalString(in: JsonReader): Option[String] =
  val b = in.nextToken()
  if b == 'n' then
    in.readNullOrError((), "expected null or string")
    None
  else
    in.rollbackToken()
    Some(in.readString(""))

private def readOptionalNumericDate(in: JsonReader): Option[NumericDate] =
  val b = in.nextToken()
  if b == 'n' then
    in.readNullOrError((), "expected null or number")
    None
  else
    in.rollbackToken()
    Some(NumericDate.fromEpochSecond(in.readLong()))

/** Derive a [[JwtCodec]] from an available [[JsonValueCodec]]. */
given [A] => (jvc: JsonValueCodec[A]) => JwtCodec[A]:
  inline def decode(bytes: Array[Byte]): Either[Throwable, A] =
    Try(readFromArray[A](bytes)).toEither

  inline def encode(value: A): Either[Throwable, Array[Byte]] =
    Try(writeToArray[A](value)).toEither
