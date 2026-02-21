package zio.jwt.http

import java.net.URI
import java.time.Duration

/** Configuration for [[JwksProvider]] refresh behaviour. */
final case class JwksProviderConfig(
    jwksUrl: URI,
    refreshInterval: Duration,
    minRefreshInterval: Duration
) derives CanEqual
