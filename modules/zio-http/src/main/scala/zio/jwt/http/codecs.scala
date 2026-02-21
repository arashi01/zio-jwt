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
package zio.jwt.http

import zio.Chunk

import boilerplate.unwrap
import com.github.plokhotnyuk.jsoniter_scala.core.*

import zio.jwt.*

// scalafix:off DisableSyntax.var, DisableSyntax.null, DisableSyntax.asInstanceOf, DisableSyntax.while; jsoniter-scala codec API requires mutable state, null sentinels, and tight loops for streaming decode

/** jsoniter-scala [[JsonValueCodec]] instances for JWK and JWK Set types. */

given JsonValueCodec[EcCurve]:
  override def decodeValue(in: JsonReader, default: EcCurve): EcCurve =
    val s = in.readString("")
    s match
      case "P-256" => EcCurve.P256
      case "P-384" => EcCurve.P384
      case "P-521" => EcCurve.P521
      case _       => in.decodeError(s"unsupported EC curve: $s")

  override def encodeValue(x: EcCurve, out: JsonWriter): Unit =
    out.writeVal(ecCurveToString(x))

  override def nullValue: EcCurve = null.asInstanceOf[EcCurve]
end given

given JsonValueCodec[KeyUse]:
  override def decodeValue(in: JsonReader, default: KeyUse): KeyUse =
    val s = in.readString("")
    s match
      case "sig" => KeyUse.Sig
      case "enc" => KeyUse.Enc
      case _     => in.decodeError(s"unsupported key use: $s")

  override def encodeValue(x: KeyUse, out: JsonWriter): Unit =
    out.writeVal(keyUseToString(x))

  override def nullValue: KeyUse = null.asInstanceOf[KeyUse]
end given

given JsonValueCodec[KeyOp]:
  override def decodeValue(in: JsonReader, default: KeyOp): KeyOp =
    val s = in.readString("")
    stringToKeyOp.get(s) match
      case Some(op) => op
      case None     => in.decodeError(s"unsupported key operation: $s")

  override def encodeValue(x: KeyOp, out: JsonWriter): Unit =
    out.writeVal(keyOpToStringMap(x))

  override def nullValue: KeyOp = null.asInstanceOf[KeyOp]

given JsonValueCodec[Jwk]:
  override def decodeValue(in: JsonReader, default: Jwk): Jwk =
    import scala.language.unsafeNulls
    if !in.isNextToken('{') then in.decodeError("expected '{'")
    if in.isNextToken('}') then in.decodeError("JWK object must not be empty")
    in.rollbackToken()

    // Common fields
    var kty: String | Null = null
    var use: Option[KeyUse] = None
    var keyOps: Option[Chunk[KeyOp]] = None
    var alg: Option[Algorithm] = None
    var kid: Option[Kid] = None
    // EC fields
    var crv: EcCurve | Null = null
    var x: String | Null = null
    var y: String | Null = null
    // EC/RSA private
    var d: String | Null = null
    // RSA fields
    var n: String | Null = null
    var e: String | Null = null
    var p: String | Null = null
    var q: String | Null = null
    var dp: String | Null = null
    var dq: String | Null = null
    var qi: String | Null = null
    // Symmetric
    var k: String | Null = null

    while
      val key = in.readKeyAsString()
      key match
        case "kty"     => kty = in.readString("")
        case "use"     => use = Some(summon[JsonValueCodec[KeyUse]].decodeValue(in, null.asInstanceOf[KeyUse]))
        case "key_ops" => keyOps = Some(readKeyOpsArray(in))
        case "alg"     => alg = readOptionalAlgorithm(in)
        case "kid"     =>
          Kid.from(in.readString("")) match
            case Right(v)  => kid = Some(v)
            case Left(err) => in.decodeError(err.getMessage)
        case "crv" => crv = summon[JsonValueCodec[EcCurve]].decodeValue(in, null.asInstanceOf[EcCurve])
        case "x"   => x = in.readString("")
        case "y"   => y = in.readString("")
        case "d"   => d = in.readString("")
        case "n"   => n = in.readString("")
        case "e"   => e = in.readString("")
        case "p"   => p = in.readString("")
        case "q"   => q = in.readString("")
        case "dp"  => dp = in.readString("")
        case "dq"  => dq = in.readString("")
        case "qi"  => qi = in.readString("")
        case "k"   => k = in.readString("")
        case _     => in.skip()
      end match
      in.isNextToken(',')
    do ()
    end while

    if kty == null then in.decodeError("missing required field: kty")
    kty match
      case "EC"  => buildEcKey(in, crv, x, y, d, use, keyOps, alg, kid)
      case "RSA" => buildRsaKey(in, n, e, d, p, q, dp, dq, qi, use, keyOps, alg, kid)
      case "oct" => buildSymmetricKey(in, k, use, keyOps, alg, kid)
      case other => in.decodeError(s"unsupported key type: $other")
  end decodeValue

  override def encodeValue(x: Jwk, out: JsonWriter): Unit =
    out.writeObjectStart()
    x match
      case ec: Jwk.EcPublicKey =>
        out.writeKey("kty"); out.writeVal("EC")
        out.writeKey("crv"); summon[JsonValueCodec[EcCurve]].encodeValue(ec.crv, out)
        out.writeKey("x"); out.writeVal(ec.x.unwrap)
        out.writeKey("y"); out.writeVal(ec.y.unwrap)
        writeCommonFields(ec.use, ec.keyOps, ec.alg, ec.kid, out)
      case ec: Jwk.EcPrivateKey =>
        out.writeKey("kty"); out.writeVal("EC")
        out.writeKey("crv"); summon[JsonValueCodec[EcCurve]].encodeValue(ec.crv, out)
        out.writeKey("x"); out.writeVal(ec.x.unwrap)
        out.writeKey("y"); out.writeVal(ec.y.unwrap)
        out.writeKey("d"); out.writeVal(ec.d.unwrap)
        writeCommonFields(ec.use, ec.keyOps, ec.alg, ec.kid, out)
      case rsa: Jwk.RsaPublicKey =>
        out.writeKey("kty"); out.writeVal("RSA")
        out.writeKey("n"); out.writeVal(rsa.n.unwrap)
        out.writeKey("e"); out.writeVal(rsa.e.unwrap)
        writeCommonFields(rsa.use, rsa.keyOps, rsa.alg, rsa.kid, out)
      case rsa: Jwk.RsaPrivateKey =>
        out.writeKey("kty"); out.writeVal("RSA")
        out.writeKey("n"); out.writeVal(rsa.n.unwrap)
        out.writeKey("e"); out.writeVal(rsa.e.unwrap)
        out.writeKey("d"); out.writeVal(rsa.d.unwrap)
        out.writeKey("p"); out.writeVal(rsa.p.unwrap)
        out.writeKey("q"); out.writeVal(rsa.q.unwrap)
        out.writeKey("dp"); out.writeVal(rsa.dp.unwrap)
        out.writeKey("dq"); out.writeVal(rsa.dq.unwrap)
        out.writeKey("qi"); out.writeVal(rsa.qi.unwrap)
        writeCommonFields(rsa.use, rsa.keyOps, rsa.alg, rsa.kid, out)
      case sym: Jwk.SymmetricKey =>
        out.writeKey("kty"); out.writeVal("oct")
        out.writeKey("k"); out.writeVal(sym.k.unwrap)
        writeCommonFields(sym.use, sym.keyOps, sym.alg, sym.kid, out)
    end match
    out.writeObjectEnd()
  end encodeValue

  override def nullValue: Jwk = null.asInstanceOf[Jwk]
end given

given JsonValueCodec[JwkSet]:
  override def decodeValue(in: JsonReader, default: JwkSet): JwkSet =
    if !in.isNextToken('{') then in.decodeError("expected '{'")
    var keys: Chunk[Jwk] = Chunk.empty
    if !in.isNextToken('}') then
      in.rollbackToken()
      while
        val key = in.readKeyAsString()
        if key == "keys" then keys = readJwkArray(in)
        else in.skip()
        in.isNextToken(',')
      do ()
    JwkSet(keys)
  end decodeValue

  override def encodeValue(x: JwkSet, out: JsonWriter): Unit =
    val jwkCodec = summon[JsonValueCodec[Jwk]]
    out.writeObjectStart()
    out.writeKey("keys")
    out.writeArrayStart()
    x.keys.foreach(jwk => jwkCodec.encodeValue(jwk, out))
    out.writeArrayEnd()
    out.writeObjectEnd()

  override def nullValue: JwkSet = null.asInstanceOf[JwkSet]
end given

// -- Shared helpers --

private def ecCurveToString(crv: EcCurve): String = crv match
  case EcCurve.P256 => "P-256"
  case EcCurve.P384 => "P-384"
  case EcCurve.P521 => "P-521"

private def keyUseToString(u: KeyUse): String = u match
  case KeyUse.Sig => "sig"
  case KeyUse.Enc => "enc"

private val keyOpNames: Array[(String, KeyOp)] = Array(
  "sign" -> KeyOp.Sign,
  "verify" -> KeyOp.Verify,
  "encrypt" -> KeyOp.Encrypt,
  "decrypt" -> KeyOp.Decrypt,
  "wrapKey" -> KeyOp.WrapKey,
  "unwrapKey" -> KeyOp.UnwrapKey,
  "deriveKey" -> KeyOp.DeriveKey,
  "deriveBits" -> KeyOp.DeriveBits
)

private val stringToKeyOp: Map[String, KeyOp] = keyOpNames.toMap
private val keyOpToStringMap: Map[KeyOp, String] = keyOpNames.map((s, o) => o -> s).toMap

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

private val stringToAlgorithm: Map[String, Algorithm] = algorithmNames.toMap
private val algorithmToStringMap: Map[Algorithm, String] = algorithmNames.map((s, a) => a -> s).toMap

private def readOptionalAlgorithm(in: JsonReader): Option[Algorithm] =
  val s = in.readString("")
  if s.isEmpty then None
  else
    stringToAlgorithm.get(s) match
      case Some(a) => Some(a)
      case None    => in.decodeError(s"unsupported algorithm: $s")

private def readKeyOpsArray(in: JsonReader): Chunk[KeyOp] =
  if !in.isNextToken('[') then in.decodeError("expected '[' for key_ops")
  if in.isNextToken(']') then Chunk.empty
  else
    in.rollbackToken()
    val builder = Chunk.newBuilder[KeyOp]
    while
      builder += summon[JsonValueCodec[KeyOp]].decodeValue(in, null.asInstanceOf[KeyOp])
      in.isNextToken(',')
    do ()
    if !in.isCurrentToken(']') then in.arrayEndError()
    builder.result()
end readKeyOpsArray

private def readJwkArray(in: JsonReader): Chunk[Jwk] =
  val jwkCodec = summon[JsonValueCodec[Jwk]]
  if !in.isNextToken('[') then in.decodeError("expected '[' for keys")
  if in.isNextToken(']') then Chunk.empty
  else
    in.rollbackToken()
    val builder = Chunk.newBuilder[Jwk]
    while
      builder += jwkCodec.decodeValue(in, null.asInstanceOf[Jwk])
      in.isNextToken(',')
    do ()
    if !in.isCurrentToken(']') then in.arrayEndError()
    builder.result()
end readJwkArray

private def writeCommonFields(
  use: Option[KeyUse],
  keyOps: Option[Chunk[KeyOp]],
  alg: Option[Algorithm],
  kid: Option[Kid],
  out: JsonWriter
): Unit =
  use.foreach { u =>
    out.writeKey("use"); out.writeVal(keyUseToString(u))
  }
  keyOps.foreach { ops =>
    out.writeKey("key_ops")
    out.writeArrayStart()
    ops.foreach(op => out.writeVal(keyOpToStringMap(op)))
    out.writeArrayEnd()
  }
  alg.foreach { a =>
    out.writeKey("alg"); out.writeVal(algorithmToStringMap(a))
  }
  kid.foreach { k =>
    out.writeKey("kid"); out.writeVal(k.unwrap)
  }
end writeCommonFields

private def requireB64(in: JsonReader, value: String | Null, field: String): Base64UrlString =
  import scala.language.unsafeNulls
  if value == null then in.decodeError(s"missing required field: $field")
  Base64UrlString.from(value) match
    case Right(b)  => b
    case Left(err) => in.decodeError(err.getMessage)

private def buildEcKey(
  in: JsonReader,
  crv: EcCurve | Null,
  x: String | Null,
  y: String | Null,
  d: String | Null,
  use: Option[KeyUse],
  keyOps: Option[Chunk[KeyOp]],
  alg: Option[Algorithm],
  kid: Option[Kid]
): Jwk =
  import scala.language.unsafeNulls
  if crv == null then in.decodeError("missing required field: crv for EC key")
  val xB64 = requireB64(in, x, "x")
  val yB64 = requireB64(in, y, "y")
  if d != null then
    val dB64 = requireB64(in, d, "d")
    Jwk.EcPrivateKey(crv, xB64, yB64, dB64, use, keyOps, alg, kid)
  else Jwk.EcPublicKey(crv, xB64, yB64, use, keyOps, alg, kid)
end buildEcKey

private def buildRsaKey(
  in: JsonReader,
  n: String | Null,
  e: String | Null,
  d: String | Null,
  p: String | Null,
  q: String | Null,
  dp: String | Null,
  dq: String | Null,
  qi: String | Null,
  use: Option[KeyUse],
  keyOps: Option[Chunk[KeyOp]],
  alg: Option[Algorithm],
  kid: Option[Kid]
): Jwk =
  import scala.language.unsafeNulls
  val nB64 = requireB64(in, n, "n")
  val eB64 = requireB64(in, e, "e")
  if d != null then
    val dB64 = requireB64(in, d, "d")
    val pB64 = requireB64(in, p, "p")
    val qB64 = requireB64(in, q, "q")
    val dpB64 = requireB64(in, dp, "dp")
    val dqB64 = requireB64(in, dq, "dq")
    val qiB64 = requireB64(in, qi, "qi")
    Jwk.RsaPrivateKey(nB64, eB64, dB64, pB64, qB64, dpB64, dqB64, qiB64, use, keyOps, alg, kid)
  else Jwk.RsaPublicKey(nB64, eB64, use, keyOps, alg, kid)
end buildRsaKey

private def buildSymmetricKey(
  in: JsonReader,
  k: String | Null,
  use: Option[KeyUse],
  keyOps: Option[Chunk[KeyOp]],
  alg: Option[Algorithm],
  kid: Option[Kid]
): Jwk =
  val kB64 = requireB64(in, k, "k")
  Jwk.SymmetricKey(kB64, use, keyOps, alg, kid)
