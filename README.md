# zio-jwt

Pure Scala 3 JWT library built on [ZIO](https://zio.dev) -- signing, validation, JWK, JWKS rotation, and zio-http middleware in a single dependency.

---

## Motivation

No existing JVM JWT library provides ZIO-native token handling, non-blocking JWKS rotation, and HTTP middleware as a single cohesive dependency:

| Library | Limitation |
|---|---|
| **jwt-scala** | `Try`-based API -- not ZIO-native. No JWKS support. No key rotation or background refresh. |
| **nimbus-jose-jwt** | Java. `RemoteJWKSet` uses blocking `java.net.URL.openStream()` -- incompatible with ZIO fibres. Mutable builders. Gson transitive dependency. |
| **jose4j** | Java. Same blocking HTTP problem. Builder patterns throughout. No Scala 3 idioms. |
| **auth0/java-jwt** | Java. No built-in JWKS (requires separate `jwks-rsa-java`). Jackson transitive dependency. Two libraries for one concern. |

With any of these, you must still build:

- Non-blocking JWKS fetching via zio-http (or equivalent)
- Key caching with background refresh and stampede prevention
- Typed claim extraction with a codec abstraction
- Structured error types for pattern matching in ZIO error channels
- HTTP middleware integration (e.g. zio-http `HandlerAspect`)
- `ZLayer` service composition wiring all of the above together

The third-party library contributes only the JWT decode/verify/encode calls -- thin wrappers around `java.security.Signature` and base64url encoding.

zio-jwt provides all of the above as a single library, eliminating the third-party dependency along with its transitive classpath.

---

## Modules

```
zio-jwt-core       (JVM / JS / Native)   Data types, error ADT, codec trait
zio-jwt-jsoniter   (JVM / JS / Native)   jsoniter-scala codec instances
zio-jwt            (JVM)                 JCA crypto, signing, validation, JWK, KeySource
zio-http-jwt       (JVM)                 zio-http middleware, JWKS client, background refresh
```

```
zio-jwt-core  <--  zio-jwt  <--  zio-http-jwt
      ^                ^
      +----------------+----  zio-jwt-jsoniter
```

---

## Installation

```scala
// build.sbt
val zioJwtVersion = "<version>"

libraryDependencies += "io.github.arashi01" %%% "zio-jwt-core"     % zioJwtVersion // cross-platform
libraryDependencies += "io.github.arashi01" %%% "zio-jwt-jsoniter" % zioJwtVersion // cross-platform
libraryDependencies += "io.github.arashi01" %%  "zio-jwt"          % zioJwtVersion // JVM only
libraryDependencies += "io.github.arashi01" %%  "zio-http-jwt"     % zioJwtVersion // JVM only
```

---

## Usage

### Imports

```scala
import zio.jwt.*                  // core types, errors, config, validator, issuer
import zio.jwt.jsoniter.given     // jsoniter codec instances (JoseHeader, RegisteredClaims, etc.)
import zio.jwt.http.given         // JWK/JwkSet codec instances (zio-http module)
```

### Token Validation

```scala
import zio.*
import zio.jwt.{given, *}
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

Validation is fail-fast: parse segments, decode header, reject disallowed algorithms, resolve key (by `kid` + `use`/`key_ops`/`alg` filtering), verify signature, decode claims, then validate `exp`, `nbf`, `iss`, `aud`, `typ`.

### Token Issuance

```scala
import zio.*
import zio.jwt.{given, *}
import zio.jwt.jsoniter.given

val issuerConfig = JwtIssuerConfig(
  algorithm = Algorithm.ES256,
  kid = Some(Kid.fromUnsafe("my-key-1")),
  typ = Some("JWT"),
  cty = None
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

The issuer constructs the JOSE header from `JwtIssuerConfig` internally -- callers provide only claims.

### zio-http Middleware

```scala
import zio.*
import zio.http.*
import zio.jwt.*
import zio.jwt.http.*
import zio.jwt.jsoniter.given
import zio.jwt.http.given

val authed: Routes[JwtValidator, Nothing] =
  Routes(
    Method.GET / "protected" -> handler { (req: Request) =>
      val jwt: Jwt[MyClaims] = req.context[Jwt[MyClaims]]
      Response.text(s"Hello ${jwt.claims.sub}")
    }
  ) @@ JwtMiddleware.bearer[MyClaims]
```

Extracts `Authorization: Bearer <token>`, validates via `JwtValidator`, and provides `Jwt[A]` as handler context. Returns `401 Unauthorized` with `WWW-Authenticate: Bearer` when the token is missing or invalid.

### JWKS with Background Refresh

```scala
import zio.*
import zio.http.*
import zio.jwt.*
import zio.jwt.http.*
import zio.jwt.jsoniter.given
import zio.jwt.http.given

val jwksConfig = JwksProviderConfig(
  jwksUrl = java.net.URI("https://auth.example.com/.well-known/jwks.json"),
  refreshInterval = java.time.Duration.ofMinutes(15),
  minRefreshInterval = java.time.Duration.ofMinutes(1)
)

val appLayer: ZLayer[Any, Throwable, JwtValidator] =
  ZLayer.make[JwtValidator](
    JwtValidator.live,
    ZLayer.succeed(validationConfig),
    JwksProvider.live,   // extends KeySource
    JwksFetcher.live,
    ZLayer.succeed(jwksConfig),
    Client.default,
    Scope.default
  )
```

`JwksProvider` extends `KeySource` with automatic background refresh:

- Initial fetch retries with exponential backoff
- Concurrent callers during initial fetch await the same in-flight request (stampede prevention)
- After first success, fetch failures retain last-known-good keyset
- `minRefreshInterval` rate-limits refresh requests
- Background fibre lifecycle is tied to the `Scope`

### JWK Handling

```scala
import zio.jwt.*

// JCA key -> JWK
val jwk: Either[JwtError, Jwk] = Jwk.from(rsaPublicKey, Some(Kid.fromUnsafe("rsa-1")))

// JWK -> JCA key
val key: Either[JwtError, java.security.PublicKey] = jwk.flatMap(_.toPublicKey)

// Static key source
val source: KeySource = KeySource.static(myJwk)
val source2: KeySource = KeySource.static(Chunk(jwk1, jwk2))
```

JWK variants: `EcPublicKey`, `EcPrivateKey`, `RsaPublicKey`, `RsaPrivateKey`, `SymmetricKey`. Key resolution filters by `use`, `key_ops`, `alg`, and `kid` before converting to JCA keys.

---

## Algorithms

| Family | Algorithms |
|---|---|
| HMAC | HS256, HS384, HS512 |
| RSA PKCS#1 v1.5 | RS256, RS384, RS512 |
| ECDSA | ES256 (P-256), ES384 (P-384), ES512 (P-521) |
| RSA-PSS | PS256, PS384, PS512 |

`alg:none` is unconditionally rejected. There is no `Algorithm.None` variant.

---

## Security

- **alg:none rejection** at both codec and type level -- the `Algorithm` ADT has no `None` variant
- **ECDSA signature validation** (CVE-2022-21449) -- rejects zero-value R/S, validates R and S against curve order
- **EC point-on-curve validation** -- independent of JCA provider, prevents invalid-curve attacks
- **RSA minimum key size** -- rejects keys with modulus below 2048 bits
- **Constant-time HMAC comparison** -- single-pass XOR accumulation, no short-circuit

---

## Error Handling

All operations return `IO[JwtError, A]`. `JwtError` is a structured enum:

```scala
enum JwtError extends Throwable with NoStackTrace:
  case Expired(exp: NumericDate, now: Instant)
  case NotYetValid(nbf: NumericDate, now: Instant)
  case InvalidAudience(expected: String, actual: Option[Audience])
  case InvalidIssuer(expected: String, actual: Option[String])
  case InvalidSignature
  case MalformedToken(cause: Throwable)
  case UnsupportedAlgorithm(alg: String)
  case KeyNotFound(kid: Option[Kid])
```

Pattern match directly on the error channel:

```scala
result.catchAll {
  case JwtError.Expired(_, _)    => ZIO.succeed(Response.text("Token expired").status(Status.Unauthorized))
  case JwtError.KeyNotFound(kid) => ZIO.succeed(Response.text("Unknown key").status(Status.Unauthorized))
  case other                     => ZIO.succeed(Response.text(other.getMessage).status(Status.Unauthorized))
}
```

---

## Codec Abstraction

JSON serialisation is pluggable via `JwtCodec[A]`:

```scala
trait JwtCodec[A]:
  def decode(bytes: Array[Byte]): Either[Throwable, A]
  def encode(value: A): Array[Byte]
```

`zio-jwt-jsoniter` provides instances for all library types. Instances are injected into `JwtValidator.live` and `JwtIssuer.live` via `using` parameters -- bring them into scope with `import zio.jwt.jsoniter.given`.

To use a different JSON library, implement `JwtCodec` for `JoseHeader`, `RegisteredClaims`, and your custom claims type.

---

## Strict Equality

All library types derive `CanEqual`, so they work seamlessly with `-language:strictEquality`. Package-level `CanEqual` instances are provided for `Chunk[A]` and `NonEmptyChunk[A]` (ZIO does not ship these).

---

## Roadmap

The following are under consideration for future releases:

- **JWE (encrypted JWT)** -- `JweDecryptor` / `JweEncryptor` services with `AES-GCM` and `RSA-OAEP` key management
- **Nested JWT** -- sign-then-encrypt and encrypt-then-sign composition via `cty: "JWT"`
- **Custom JOSE header fields** -- type-safe extensible header model beyond `alg`, `typ`, `cty`, `kid`
- **kid-absent token handling** -- relaxed key resolution accepting a single-key `KeySource` without requiring `kid` in the token header

---

## Licence

[MIT](LICENSE)
