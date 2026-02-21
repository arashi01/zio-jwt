package zio.jwt

/** JWK key operations parameter (RFC 7517 ss4.3). */
enum KeyOp derives CanEqual:
  case Sign, Verify, Encrypt, Decrypt, WrapKey, UnwrapKey, DeriveKey, DeriveBits
