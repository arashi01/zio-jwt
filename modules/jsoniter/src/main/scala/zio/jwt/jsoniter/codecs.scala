package zio.jwt.jsoniter

import com.github.plokhotnyuk.jsoniter_scala.core.*

import boilerplate.unwrap

import zio.Chunk
import zio.NonEmptyChunk
import zio.jwt.*

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
    algorithmFromString(s) match
      case Some(alg) => alg
      case None      => in.decodeError(s"unsupported or prohibited algorithm: $s")

  override def encodeValue(x: Algorithm, out: JsonWriter): Unit =
    out.writeVal(algorithmToString(x))

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

  override def encodeValue(x: Audience, out: JsonWriter): Unit =
    x match
      case Audience.Single(v) => out.writeVal(v)
      case Audience.Many(vs) =>
        out.writeArrayStart()
        vs.foreach(out.writeVal)
        out.writeArrayEnd()

  override def nullValue: Audience = null.asInstanceOf[Audience]

given JsonValueCodec[JoseHeader]:
  override def decodeValue(in: JsonReader, default: JoseHeader): JoseHeader =
    var alg: Algorithm | Null = null
    var typ: Option[String]   = None
    var cty: Option[String]   = None
    var kid: Option[Kid]      = None
    var algSeen                = false

    if !in.isNextToken('{') then in.decodeError("expected '{'")
    if !in.isNextToken('}') then
      in.rollbackToken()
      while
        val key = in.readKeyAsString()
        if key == "alg" then
          if algSeen then in.duplicatedKeyError(key.length)
          algSeen = true
          val algStr = in.readString("")
          if algStr.isEmpty || algStr == "none" then
            in.decodeError("algorithm 'none' is not permitted")
          else
            algorithmFromString(algStr) match
              case Some(a) => alg = a
              case None    => in.decodeError(s"unsupported algorithm: $algStr")
        else if key == "typ" then typ = readOptionalString(in)
        else if key == "cty" then cty = readOptionalString(in)
        else if key == "kid" then
          Kid.from(in.readString("")) match
            case Right(k) => kid = Some(k)
            case Left(e)  => in.decodeError(e.getMessage)
        else in.skip()
        in.isNextToken(',')
      do ()

    if !algSeen then in.decodeError("missing required field: alg")
    JoseHeader(alg.asInstanceOf[Algorithm], typ, cty, kid)

  override def encodeValue(x: JoseHeader, out: JsonWriter): Unit =
    out.writeObjectStart()
    out.writeKey("alg")
    out.writeVal(algorithmToString(x.alg))
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
    out.writeObjectEnd()

  override def nullValue: JoseHeader = null.asInstanceOf[JoseHeader]

given JsonValueCodec[RegisteredClaims]:
  override def decodeValue(in: JsonReader, default: RegisteredClaims): RegisteredClaims =
    var iss: Option[String]      = None
    var sub: Option[String]      = None
    var aud: Option[Audience]    = None
    var exp: Option[NumericDate] = None
    var nbf: Option[NumericDate] = None
    var iat: Option[NumericDate] = None
    var jti: Option[String]      = None

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
        in.isNextToken(',')
      do ()

    RegisteredClaims(iss, sub, aud, exp, nbf, iat, jti)

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

  override def nullValue: RegisteredClaims = null.asInstanceOf[RegisteredClaims]

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

private val algorithmNames: Array[(String, Algorithm)] = Array(
  "HS256" -> Algorithm.HS256,
  "HS384" -> Algorithm.HS384,
  "HS512" -> Algorithm.HS512,
  "RS256" -> Algorithm.RS256,
  "RS384" -> Algorithm.RS384,
  "RS512" -> Algorithm.RS512,
  "ES256" -> Algorithm.ES256,
  "ES384" -> Algorithm.ES384,
  "ES512" -> Algorithm.ES512,
  "PS256" -> Algorithm.PS256,
  "PS384" -> Algorithm.PS384,
  "PS512" -> Algorithm.PS512
)

private val stringToAlgorithm: Map[String, Algorithm] =
  algorithmNames.toMap

private val algorithmToStringMap: Map[Algorithm, String] =
  algorithmNames.map((s, a) => a -> s).toMap

private def algorithmFromString(s: String): Option[Algorithm] =
  stringToAlgorithm.get(s)

private def algorithmToString(alg: Algorithm): String =
  algorithmToStringMap(alg)
