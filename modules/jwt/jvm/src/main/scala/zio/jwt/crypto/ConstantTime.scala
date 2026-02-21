package zio.jwt.crypto

/** Constant-time byte array comparison to prevent timing side-channel attacks. */
object ConstantTime:

  /**
   * Compares two byte arrays in constant time.
   * On length mismatch, compares `a` against itself (always zero) but returns `false`
   * via the `lenMatch` guard -- no short-circuit, no recursion, single pass.
   */
  def areEqual(a: Array[Byte], b: Array[Byte]): Boolean =
    // Hotpath: single-pass constant-time comparison avoids timing side-channels.
    // Mutable accumulator + tight loop prevents branch-based short-circuit that
    // would leak information about which byte position differs.
    val lenMatch = a.length == b.length
    val cmp      = if lenMatch then b else a
    var result   = 0
    var i        = 0
    while i < a.length do
      result |= (a(i) ^ cmp(i))
      i += 1
    result == 0 && lenMatch
