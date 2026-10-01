//! The OTLP/HTTP exporter transport: HTTPS only, origin-pinned, no redirects.
//!
//! Trace export is optional telemetry, but it carries deployment-configured
//! exporter credentials, so its transport is treated as a trust boundary:
//!
//! - the connector is HTTPS-only with certificate and hostname validation, and
//!   there is no way to disable either;
//! - every request URI must match the configured endpoint origin exactly, so a
//!   library default, environment variable, or remote response cannot redirect
//!   export to another origin;
//! - configured headers are attached here, after that origin check, so
//!   credentials cannot reach any other origin;
//! - every `3xx` response is an export failure whose `Location` is never read
//!   and never requested.

use std::{error::Error, fmt, time::Duration};

use async_trait::async_trait;
use http::{
    HeaderMap, Request, Response, Uri,
    header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderName, HeaderValue},
    uri::Scheme,
};
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use opentelemetry_http::{Bytes, HttpClient, HttpError, hyper::HyperClient};

/// The default effective port for an HTTPS OTLP endpoint.
const HTTPS_PORT: u16 = 443;

/// The scheme, host, and effective port that configured exporter credentials
/// may be sent to, and the only origin this client will request.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ExporterOrigin {
    host: String,
    port: u16,
}

impl ExporterOrigin {
    /// Derives the origin of an already-validated HTTPS endpoint.
    pub(crate) fn of(endpoint: &Uri) -> Option<Self> {
        Some(Self {
            host: endpoint.host()?.to_owned(),
            port: endpoint.port_u16().unwrap_or(HTTPS_PORT),
        })
    }

    /// Returns whether a request URI is the same HTTPS origin.
    ///
    /// The comparison is scheme, host, and effective port. There is no
    /// same-origin exception, no allowlist, and no suffix matching.
    fn matches(&self, uri: &Uri) -> bool {
        uri.scheme() == Some(&Scheme::HTTPS)
            && uri.host() == Some(self.host.as_str())
            && uri.port_u16().unwrap_or(HTTPS_PORT) == self.port
    }
}

/// A coarse, safe exporter transport failure.
///
/// It never renders the endpoint, a redirect target, or a configured header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExportTransportFailure {
    /// The request URI was not the configured endpoint origin.
    ForeignOrigin,
    /// The endpoint answered with a redirect, which is never followed.
    RedirectRefused,
}

impl fmt::Display for ExportTransportFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ForeignOrigin => "trace export to a non-configured origin was refused",
            Self::RedirectRefused => "trace export redirect was refused",
        })
    }
}

impl Error for ExportTransportFailure {}

/// An OTLP/HTTP client pinned to one configured HTTPS origin.
///
/// This type owns configured exporter credentials, so its `Debug` output is a
/// fixed string.
pub(crate) struct PinnedExporterClient {
    inner: HyperClient<HttpsConnector<HttpConnector>>,
    origin: ExporterOrigin,
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl PinnedExporterClient {
    /// Builds the exporter client from validated tracing configuration.
    ///
    /// `tls` already enforces certificate and hostname validation; this adds
    /// HTTPS-only connection establishment so no plaintext fallback exists.
    pub(crate) fn new(
        tls: native_tls::TlsConnector,
        origin: ExporterOrigin,
        headers: Vec<(HeaderName, HeaderValue)>,
        export_timeout: Duration,
    ) -> Self {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let mut https = HttpsConnector::from((http, tls.into()));
        https.https_only(true);

        Self {
            inner: HyperClient::new(https, export_timeout, None),
            origin,
            headers,
        }
    }

    /// Rebuilds the outgoing header map from the protocol headers the exporter
    /// produced plus exactly the configured exporter headers.
    ///
    /// Rebuilding rather than extending means no ambient header, including one
    /// the OpenTelemetry crates may derive from environment variables, can
    /// reach the endpoint: only this file-configured set does.
    fn outgoing_headers(&self, produced: &HeaderMap) -> HeaderMap {
        let mut headers = HeaderMap::with_capacity(self.headers.len() + 2);
        for protocol_header in [CONTENT_TYPE, CONTENT_LENGTH] {
            if let Some(value) = produced.get(&protocol_header) {
                headers.insert(protocol_header, value.clone());
            }
        }
        for (name, value) in &self.headers {
            headers.insert(name.clone(), value.clone());
        }
        headers
    }
}

impl fmt::Debug for PinnedExporterClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PinnedExporterClient")
    }
}

#[async_trait]
impl HttpClient for PinnedExporterClient {
    async fn send_bytes(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let (mut parts, body) = request.into_parts();

        // Credentials are attached only after the origin is proven, so a
        // foreign origin never sees a configured header.
        if !self.origin.matches(&parts.uri) {
            return Err(Box::new(ExportTransportFailure::ForeignOrigin));
        }
        parts.headers = self.outgoing_headers(&parts.headers);

        let response = self
            .inner
            .send_bytes(Request::from_parts(parts, body))
            .await?;

        // Every 3xx is an export failure. The response is discarded without
        // reading `Location`, so no remote response can widen the configured
        // trust boundary.
        if response.status().is_redirection() {
            return Err(Box::new(ExportTransportFailure::RedirectRefused));
        }

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::{ExportTransportFailure, ExporterOrigin};
    use http::Uri;

    fn origin(endpoint: &str) -> ExporterOrigin {
        ExporterOrigin::of(&endpoint.parse::<Uri>().unwrap()).unwrap()
    }

    #[test]
    fn origin_matching_uses_scheme_host_and_effective_port() {
        let pinned = origin("https://otlp.example.test/v1/traces");

        for same in [
            "https://otlp.example.test/v1/traces",
            "https://otlp.example.test:443/v1/traces",
            "https://otlp.example.test/v1/other",
        ] {
            assert!(
                pinned.matches(&same.parse::<Uri>().unwrap()),
                "{same} must match"
            );
        }

        for foreign in [
            "http://otlp.example.test/v1/traces",
            "https://otlp.example.test:4318/v1/traces",
            "https://other.example.test/v1/traces",
            "https://otlp.example.test.evil.test/v1/traces",
            "https://evil.test/https://otlp.example.test/v1/traces",
        ] {
            assert!(
                !pinned.matches(&foreign.parse::<Uri>().unwrap()),
                "{foreign} must not match"
            );
        }
    }

    #[test]
    fn a_non_default_port_is_part_of_the_pinned_origin() {
        let pinned = origin("https://otlp.example.test:4318/v1/traces");

        assert!(
            pinned.matches(
                &"https://otlp.example.test:4318/v1/traces"
                    .parse::<Uri>()
                    .unwrap()
            )
        );
        assert!(
            !pinned.matches(
                &"https://otlp.example.test/v1/traces"
                    .parse::<Uri>()
                    .unwrap()
            )
        );
    }

    #[test]
    fn transport_failures_render_only_fixed_safe_text() {
        for failure in [
            ExportTransportFailure::ForeignOrigin,
            ExportTransportFailure::RedirectRefused,
        ] {
            for rendered in [failure.to_string(), format!("{failure:?}")] {
                for sensitive in [
                    "otlp.example.test",
                    "ApiKey",
                    "sentinel-exporter-credential",
                    "Location",
                ] {
                    assert!(
                        !rendered.contains(sensitive),
                        "{rendered} leaked {sensitive}"
                    );
                }
            }
        }
    }
}
