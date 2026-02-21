package zio.jwt

/** JOSE elliptic curve identifiers (RFC 7518 ss6.2.1.1). */
enum EcCurve derives CanEqual:
  case P256, P384, P521
