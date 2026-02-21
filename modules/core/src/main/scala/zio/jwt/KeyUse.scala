package zio.jwt

/** JWK public key use parameter (RFC 7517 ss4.2). */
enum KeyUse derives CanEqual:
  case Sig, Enc
