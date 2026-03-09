# zio-jwt

Pure Scala 3 JWT library built on [ZIO](https://zio.dev) — signing, verification, validation, JWK, JWKS rotation, OIDC discovery, and zio-http middleware in a single dependency.

## Features

| Feature | Description |
|---|---|
| Token validation | Fail-fast and accumulating modes with configurable clock skew, issuer, audience, and algorithm allowlists |
| Token issuance | Sign tokens with HMAC, RSA, ECDSA, RSA-PSS, or EdDSA |
| JWK / JWK Set | Full key model (EC, RSA, symmetric, OKP) with JCA conversion and key-filtering by `kid`, `use`, `key_ops`, `alg` |
| JWKS background refresh | Non-blocking fetch with exponential backoff, stampede prevention, last-known-good retention, and rate limiting |
| OIDC Discovery | Auto-discover JWKS URLs from `/.well-known/openid-configuration` |
| zio-http middleware | `HandlerAspect` extracting `Authorization: Bearer` tokens with typed context |
| Cross-platform decoding | Decode tokens without signature verification on JVM, JS, and Native |
| Structured errors | `JwtError` enum for pattern matching in the ZIO error channel |
| Pluggable JSON | `JwtCodec[A]` trait — bring your own serialiser or use the provided jsoniter-scala codecs |
| Strict equality | All types derive `CanEqual` for `-language:strictEquality` |

### Algorithms

| Family | Algorithms |
|---|---|
| HMAC | HS256, HS384, HS512 |
| RSA PKCS#1 v1.5 | RS256, RS384, RS512 |
| ECDSA | ES256 (P-256), ES384 (P-384), ES512 (P-521) |
| RSA-PSS | PS256, PS384, PS512 |
| EdDSA | Ed25519, Ed448 |

`alg:none` is unconditionally rejected — the `Algorithm` enum has no `None` variant.

### Standards

| Standard | Coverage |
|---|---|
| RFC 7519 — JWT | Complete |
| RFC 7515 — JWS | Complete (incl. `crit` header processing) |
| RFC 7517 — JWK | Complete (EC, RSA, oct, OKP) |
| RFC 7518 — JWA | Complete (HMAC, RSA, ECDSA, RSA-PSS, EdDSA) |
| RFC 8037 — EdDSA / OKP | Complete |
| OpenID Connect Discovery 1.0 | JWKS URI resolution |

---

## Installation

```scala
// build.sbt — pick the modules you need
libraryDependencies ++= Seq(
  "io.github.arashi01" %%% "zio-jwt-core"     % "<version>", // cross-platform types and decoding
  "io.github.arashi01" %%% "zio-jwt-jsoniter"  % "<version>", // jsoniter-scala codec instances
  "io.github.arashi01" %%  "zio-jwt"           % "<version>", // JVM — signing, verification, JWK
  "io.github.arashi01" %%  "zio-http-jwt"      % "<version>"  // JVM — zio-http middleware, JWKS, OIDC
)
```

### Modules

```
zio-jwt-core       (JVM / JS / Native)   Types, error ADT, codec trait, JwtDecoder
zio-jwt-jsoniter   (JVM / JS / Native)   jsoniter-scala codec instances
zio-jwt            (JVM)                 JCA signing, verification, validation, JWK
zio-http-jwt       (JVM)                 zio-http middleware, JWKS client, OIDC discovery
```

```
zio-jwt-core  ◂──  zio-jwt  ◂──  zio-http-jwt
      ▴                ▴
      └────────────────┴──  zio-jwt-jsoniter
```

Most JVM applications need `zio-http-jwt` (which transitively brings `zio-jwt`, `zio-jwt-core`, and `zio-jwt-jsoniter`).

### Imports

```scala
import zio.jwt.*               // core types, errors, config, validator, issuer, JWK
import zio.jwt.jsoniter.given  // jsoniter-scala codecs (JoseHeader, RegisteredClaims, etc.)
import zio.jwt.http.*          // JwtMiddleware, JwksProvider, OidcDiscovery, JWK codecs
```

---

## Quick Start

### Validate a Token

```scala
import zio.*
import zio.jwt.*
import zio.jwt.jsoniter.given

final case class MyClaims(sub: String, role: String) derives CanEqual
given JwtCodec[MyClaims] = ??? // your codec instance

val config = ValidationConfig(
  clockSkew = java.time.Duration.ofSeconds(30),
  requiredIssuer = Some("https://auth.example.com"),
  requiredAudience = Some("my-api"),
  requiredTyp = None,
  allowedAlgorithms = NonEmptyChunk(Algorithm.RS256, Algorithm.ES256)
)

val program: IO[JwtError, Jwt[MyClaims]] =
  ZIO.serviceWithZIO[JwtValidator](_.validate[MyClaims](token))
    .provide(
      JwtValidator.live,
      ZLayer.succeed(config),
      ZLayer.succeed(KeySource.static(myJwk))
    )
```

Validation is fail-fast: parse → decode header → reject disallowed algorithms → resolve key → verify signature → decode claims → validate `exp`, `nbf`, `iss`, `aud`, `typ`.

Use `validateAll` to accumulate all claim errors instead of failing on the first:

```scala
val program: IO[NonEmptyChunk[JwtError], Jwt[MyClaims]] =
  ZIO.serviceWithZIO[JwtValidator](_.validateAll[MyClaims](token))
```

### Issue a Token

```scala
import zio.*
import zio.jwt.*
import zio.jwt.jsoniter.given

val issuerConfig = JwtIssuerConfig(
  algorithm = Algorithm.ES256,
  kid = Some(Kid.fromUnsafe("my-key-1")),
  typ = Some("JWT"),
  cty = None,
  x5t = None,
  x5tS256 = None,
  crit = None
)

val program: IO[JwtError, TokenString] =
  ZIO.serviceWithZIO[JwtIssuer](
    _.issue(
      MyClaims("user-42", "admin"),
      RegisteredClaims(
        iss = Some("https://auth.example.com"),
        sub = Some("user-42"),
        aud = Some(Audience("my-api")),
        exp = Some(NumericDate.fromEpochSecond(1740000000L)),
        nbf = None,
        iat = Some(NumericDate.fromEpochSecond(1739990000L)),
        jti = None
      )
    )
  ).provide(
    JwtIssuer.live,
    ZLayer.succeed(issuerConfig),
    ZLayer.succeed(keySource)
  )
```

The JOSE header is constructed from `JwtIssuerConfig` — callers provide only claims.

### zio-http Middleware

```scala
import zio.*
import zio.http.*
import zio.jwt.*
import zio.jwt.http.*
import zio.jwt.jsoniter.given

val authed: Routes[JwtValidator, Response] =
  Routes(
    Method.GET / "protected" -> handler((_: Request) =>
      withContext((jwt: Jwt[MyClaims]) =>
        Response.text(s"Hello ${jwt.claims.sub}")
      )
    )
  ) @@ JwtMiddleware.bearer[MyClaims]
```

Extracts `Authorization: Bearer <token>`, validates via `JwtValidator`, and provides the decoded `Jwt[A]` as handler context. Returns `401 Unauthorized` with `WWW-Authenticate: Bearer` when the token is missing or invalid.

An overload accepts a custom error handler for differentiated responses:

```scala
JwtMiddleware.bearer[MyClaims](err => Response.text(err.getMessage).status(Status.Unauthorized))
```

### JWKS with Background Refresh

```scala
import zio.*
import zio.http.*
import zio.jwt.*
import zio.jwt.http.*
import zio.jwt.jsoniter.given

val jwksConfig = JwksProviderConfig(
  jwksUrl = java.net.URI("https://auth.example.com/.well-known/jwks.json"),
  refreshInterval = java.time.Duration.ofMinutes(15),
  minRefreshInterval = java.time.Duration.ofMinutes(1)
)

val appLayer: ZLayer[Any, Throwable, JwtValidator] =
  ZLayer.make[JwtValidator](
    JwtValidator.live,
    ZLayer.succeed(validationConfig),
    JwksProvider.live,
    JwksFetcher.live,
    ZLayer.succeed(jwksConfig),
    Client.default,
    Scope.default
  )
```

`JwksProvider` extends `KeySource` with automatic background refresh:

- Exponential backoff on initial fetch
- Stampede prevention — concurrent callers await the same in-flight request
- Last-known-good keyset retained on fetch failure
- `minRefreshInterval` rate-limits refresh requests
- Background fibre lifecycle tied to `Scope`

### OIDC Discovery

Automatically discover the JWKS URI from an issuer's OpenID configuration:

```scala
import zio.jwt.http.*

// One-shot: resolve the JWKS URI
val jwksUri: ZIO[Client, JwtError, java.net.URI] =
  OidcDiscovery.jwksUri(java.net.URI("https://auth.example.com"))

// Full layer: discover + background refresh
val layer: ZLayer[Client & Scope, JwtError, JwksProvider] =
  OidcDiscovery.provider(
    issuerUrl = java.net.URI("https://auth.example.com"),
    refreshInterval = java.time.Duration.ofMinutes(15),
    minRefreshInterval = java.time.Duration.ofMinutes(1)
  )
```

---

## JWK Handling

```scala
import zio.jwt.*

// JCA key → JWK
val jwk: Either[JwtError, Jwk] = Jwk.from(rsaPublicKey, Some(Kid.fromUnsafe("rsa-1")))

// JWK → JCA key
val key: Either[JwtError, java.security.PublicKey] = jwk.flatMap(_.toPublicKey)

// Static key source
val source: KeySource = KeySource.static(myJwk)
val multiSource: KeySource = KeySource.static(Chunk(jwk1, jwk2))
```

**JWK variants:** `EcPublicKey`, `EcPrivateKey`, `RsaPublicKey`, `RsaPrivateKey`, `SymmetricKey`, `OkpPublicKey`, `OkpPrivateKey`.

Key resolution filters by `use`, `key_ops`, `alg`, and `kid` before converting to JCA keys.

---

## Error Handling

All operations return `IO[JwtError, A]`. `JwtError` is a sealed enum extending `Throwable` with `NoStackTrace`:

| Variant | Meaning |
|---|---|
| `Expired(exp, now)` | Token `exp` claim is in the past |
| `NotYetValid(nbf, now)` | Token `nbf` claim is in the future |
| `InvalidAudience(expected, actual)` | `aud` claim does not match |
| `InvalidIssuer(expected, actual)` | `iss` claim does not match |
| `InvalidSignature` | Cryptographic signature verification failed |
| `MalformedToken(message)` | Token structure is not valid compact JWS |
| `DecodeError(message)` | JSON decoding failure |
| `EncodeError(message)` | JSON encoding failure |
| `InvalidKey(message)` | Key type mismatch or JCA conversion error |
| `InvalidTyp(expected, actual)` | JOSE header `typ` does not match |
| `UnsupportedAlgorithm(alg)` | Algorithm not in the allowlist |
| `KeyNotFound(kid)` | No matching key in the key source |
| `AmbiguousKey(kid, count)` | Multiple keys match — cannot select one |
| `FetchError(message)` | Remote resource fetch failure (e.g. JWKS endpoint) |
| `MissingToken` | No authentication token present |
| `CriticalHeaderUnsupported(parameters)` | Unrecognised `crit` header parameters |

Pattern match on the error channel:

```scala
result.catchAll {
  case JwtError.Expired(_, _)    => ZIO.succeed(Response.text("Token expired").status(Status.Unauthorized))
  case JwtError.KeyNotFound(kid) => ZIO.succeed(Response.text("Unknown key").status(Status.Unauthorized))
  case other                     => ZIO.succeed(Response.text(other.getMessage).status(Status.Unauthorized))
}
```

---

## Security

| Measure | Detail |
|---|---|
| `alg:none` rejection | No `Algorithm.None` variant; rejected at both codec and type level |
| ECDSA signature validation | Rejects zero-value R/S, validates R and S against curve order (CVE-2022-21449) |
| EC point-on-curve validation | Independent of JCA provider — prevents invalid-curve attacks |
| RSA minimum key size | Rejects modulus below 2048 bits |
| HMAC minimum key size | Rejects keys shorter than hash output per RFC 7518 §3.2 |
| Constant-time HMAC comparison | Single-pass XOR accumulation, no short-circuit |
| EdDSA signature length | Pre-verify: Ed25519 = 64 bytes, Ed448 = 114 bytes |
| `crit` header processing | Rejects unrecognised or empty critical header parameters (RFC 7515 §4.1.11) |
| OIDC HTTPS enforcement | `OidcDiscovery` rejects non-HTTPS issuer and JWKS URIs |

---

## Codec Abstraction

JSON serialisation is pluggable via `JwtCodec[A]`:

```scala
trait JwtCodec[A]:
  def decode(bytes: Array[Byte]): Either[Throwable, A]
  def encode(value: A): Either[Throwable, Array[Byte]]
```

`zio-jwt-jsoniter` provides instances for all library types. A conditional given bridges any `JsonValueCodec[A]` to `JwtCodec[A]` automatically — bring your custom jsoniter codecs into scope and they work with `JwtValidator` and `JwtIssuer` out of the box.

To use a different JSON library, implement `JwtCodec` for `JoseHeader`, `RegisteredClaims`, and your custom claims type.

---

## Licence

[MIT](LICENSE)
