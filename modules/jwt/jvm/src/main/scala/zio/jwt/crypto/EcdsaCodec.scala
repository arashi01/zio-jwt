package zio.jwt.crypto

import scala.util.Try

import zio.jwt.*

/** ECDSA DER <-> R||S transcoding and signature length constants. */
object EcdsaCodec:

  /** Expected R||S byte length per ECDSA algorithm. */
  def signatureLength(alg: Algorithm): Option[Int] = alg match
    case Algorithm.ES256 => Some(64)
    case Algorithm.ES384 => Some(96)
    case Algorithm.ES512 => Some(132)
    case _               => None

  /**
   * Transcodes a DER-encoded ECDSA signature to fixed-length R||S concatenation.
   * Adapted from jwt-scala's `transcodeSignatureToConcat`.
   */
  def derToConcat(der: Array[Byte], outputLength: Int): Either[JwtError, Array[Byte]] =
    Try {
      require(der.length >= 8 && der(0) == 0x30.toByte, "Invalid DER: too short or missing SEQUENCE tag")

      // Determine offset past the SEQUENCE length encoding
      val offset: Int =
        if (der(1) & 0xff) < 0x80 then 2
        else if der(1) == 0x81.toByte then 3
        else throw IllegalArgumentException("Invalid DER: unsupported length encoding")

      // Validate SEQUENCE structure
      val seqLen = der(offset - 1) & 0xff
      require(seqLen == der.length - offset, "Invalid DER: SEQUENCE length mismatch")
      require(der(offset) == 0x02.toByte, "Invalid DER: missing INTEGER tag for R")

      // Extract R
      val rLen = der(offset + 1) & 0xff
      require(der(offset + 2 + rLen) == 0x02.toByte, "Invalid DER: missing INTEGER tag for S")

      // Extract S
      val sLen = der(offset + 2 + rLen + 1) & 0xff
      require(seqLen == 2 + rLen + 2 + sLen, "Invalid DER: content length mismatch")

      // Strip leading zero bytes from R
      var rStart = offset + 2
      var rEffLen = rLen
      while rEffLen > 0 && der(rStart) == 0.toByte do
        rStart += 1
        rEffLen -= 1

      // Strip leading zero bytes from S
      var sStart = offset + 2 + rLen + 2
      var sEffLen = sLen
      while sEffLen > 0 && der(sStart) == 0.toByte do
        sStart += 1
        sEffLen -= 1

      val componentLen = outputLength / 2
      val result       = new Array[Byte](outputLength)
      System.arraycopy(der, rStart, result, componentLen - rEffLen, rEffLen)
      System.arraycopy(der, sStart, result, outputLength - sEffLen, sEffLen)
      result
    }.toEither.left.map(_ => JwtError.InvalidSignature)

  /**
   * Transcodes a fixed-length R||S concatenated ECDSA signature to DER encoding.
   * Adapted from jwt-scala's `transcodeSignatureToDER`.
   */
  def concatToDer(sig: Array[Byte]): Either[JwtError, Array[Byte]] =
    Try {
      val mid = sig.length / 2
      val rBytes = toSignedInteger(sig, 0, mid)
      val sBytes = toSignedInteger(sig, mid, sig.length)

      val contentLen = 2 + rBytes.length + 2 + sBytes.length
      require(contentLen <= 255, "Invalid signature: DER content too long")

      // Build DER SEQUENCE
      val useLongForm = contentLen >= 128
      val headerLen   = if useLongForm then 3 else 2
      val result      = new Array[Byte](headerLen + contentLen)
      var pos         = 0

      // SEQUENCE tag + length
      result(pos) = 0x30.toByte; pos += 1
      if useLongForm then
        result(pos) = 0x81.toByte; pos += 1
      result(pos) = contentLen.toByte; pos += 1

      // INTEGER R
      result(pos) = 0x02.toByte; pos += 1
      result(pos) = rBytes.length.toByte; pos += 1
      System.arraycopy(rBytes, 0, result, pos, rBytes.length); pos += rBytes.length

      // INTEGER S
      result(pos) = 0x02.toByte; pos += 1
      result(pos) = sBytes.length.toByte; pos += 1
      System.arraycopy(sBytes, 0, result, pos, sBytes.length)

      result
    }.toEither.left.map(_ => JwtError.InvalidSignature)

  /** Extracts a component from a concatenated signature and prepares it for ASN.1 INTEGER encoding. */
  private def toSignedInteger(sig: Array[Byte], from: Int, to: Int): Array[Byte] =
    // Strip leading zeros
    var start = from
    while start < to - 1 && sig(start) == 0.toByte do start += 1

    val len = to - start
    if len == 0 then
      // All zeros -- represent as single zero byte
      Array(0.toByte)
    else if (sig(start) & 0x80) != 0 then
      // High bit set -- prepend 0x00 sign byte for positive ASN.1 INTEGER
      val out = new Array[Byte](len + 1)
      System.arraycopy(sig, start, out, 1, len)
      out
    else
      val out = new Array[Byte](len)
      System.arraycopy(sig, start, out, 0, len)
      out
