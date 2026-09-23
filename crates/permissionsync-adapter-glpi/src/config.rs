//! Adapter-local configuration: construction-time validation only.
//!
//! This is construction input for one concrete [`crate::GlpiAdapter`]
//! instance, not the eventual global PermissionSync runtime configuration
//! schema (deferred; see ADR 0006/0009).

use std::time::Duration;

use native_tls::{Certificate, Protocol, TlsConnector as NativeTlsConnector};
use url::Url;

use crate::error::GlpiAdapterConfigError;

/// The GLPI service-account long-lived user token.
///
/// Intentionally has no `Debug`/`Display` implementation.
pub struct GlpiUserToken(String);

impl GlpiUserToken {
    /// Creates a user token from its raw value.
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// The GLPI API client `App-Token`.
///
/// Intentionally has no `Debug`/`Display` implementation.
pub struct GlpiAppToken(String);

impl GlpiAppToken {
    /// Creates an App-Token from its raw value.
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// The narrow, typed missing-user authentication-source fields required by
/// the deployment-selected GLPI authentication source, per ADR 0009. Never
/// derived from Provider payload; never includes a password.
#[derive(Clone, Copy, Debug, Default)]
pub struct GlpiAuthenticationSource {
    /// The GLPI `authtype` value required for user creation, when needed.
    pub authtype: Option<i64>,
    /// The GLPI `auths_id` value required for user creation, when needed.
    pub auths_id: Option<i64>,
}

/// Construction input for one [`crate::GlpiAdapter`] instance.
pub struct GlpiAdapterConfig {
    /// The configured GLPI `apirest.php` HTTPS endpoint.
    pub endpoint: String,
    /// The GLPI API client App-Token.
    pub app_token: GlpiAppToken,
    /// The GLPI service-account long-lived user token.
    pub user_token: GlpiUserToken,
    /// The bounded per-operation timeout for every GLPI request.
    pub operation_timeout: Duration,
    /// Additional PEM-encoded private trust anchors, in addition to system roots.
    pub additional_trust_anchors_pem: Vec<Vec<u8>>,
    /// Missing-user authentication-source fields, when the deployment-selected
    /// GLPI authentication source requires them for user creation.
    pub authentication_source: GlpiAuthenticationSource,
}

pub(crate) struct ValidatedConfig {
    pub(crate) base: Url,
    pub(crate) app_token: GlpiAppToken,
    pub(crate) user_token: GlpiUserToken,
    pub(crate) operation_timeout: Duration,
    pub(crate) authentication_source: GlpiAuthenticationSource,
    pub(crate) tls_connector: tokio_native_tls::TlsConnector,
}

pub(crate) fn validate(
    config: GlpiAdapterConfig,
) -> Result<ValidatedConfig, GlpiAdapterConfigError> {
    let base = parse_base(&config.endpoint)?;

    if config.operation_timeout.is_zero() {
        return Err(GlpiAdapterConfigError::new());
    }

    if config.app_token.as_str().is_empty() || config.user_token.as_str().is_empty() {
        return Err(GlpiAdapterConfigError::new());
    }

    let tls_connector = build_tls_connector(&config.additional_trust_anchors_pem)?;

    Ok(ValidatedConfig {
        base,
        app_token: config.app_token,
        user_token: config.user_token,
        operation_timeout: config.operation_timeout,
        authentication_source: config.authentication_source,
        tls_connector,
    })
}

/// Parses and validates the configured `apirest.php` base endpoint.
///
/// Requires an absolute `https` URI with a non-empty host, no userinfo, no
/// fragment, and no pre-existing query string. Its terminal path component
/// must be exactly `apirest.php`, with an optional trailing slash. The
/// accepted endpoint is then normalized to one trailing `/` so later
/// `Url::join` calls compose operation paths correctly and safely (never
/// through string interpolation).
fn parse_base(endpoint: &str) -> Result<Url, GlpiAdapterConfigError> {
    let mut url = Url::parse(endpoint).map_err(|_| GlpiAdapterConfigError::new())?;

    if url.scheme() != "https"
        || url.host_str().is_none_or(str::is_empty)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err(GlpiAdapterConfigError::new());
    }

    let path_without_trailing_slash = url.path().strip_suffix('/').unwrap_or(url.path());
    if path_without_trailing_slash
        .rsplit_once('/')
        .map(|(_, terminal)| terminal)
        != Some("apirest.php")
    {
        return Err(GlpiAdapterConfigError::new());
    }
    url.set_path(&format!("{path_without_trailing_slash}/"));

    Ok(url)
}

fn build_tls_connector(
    additional_trust_anchors_pem: &[Vec<u8>],
) -> Result<tokio_native_tls::TlsConnector, GlpiAdapterConfigError> {
    let mut builder = NativeTlsConnector::builder();
    builder
        .min_protocol_version(Some(Protocol::Tlsv12))
        .danger_accept_invalid_certs(false)
        .danger_accept_invalid_hostnames(false)
        .use_sni(true);

    for trust_anchor_pem in additional_trust_anchors_pem {
        let certificates = Certificate::stack_from_pem(trust_anchor_pem)
            .map_err(|_| GlpiAdapterConfigError::new())?;
        if certificates.is_empty() {
            return Err(GlpiAdapterConfigError::new());
        }
        for certificate in certificates {
            builder.add_root_certificate(certificate);
        }
    }

    let tls = builder.build().map_err(|_| GlpiAdapterConfigError::new())?;
    Ok(tokio_native_tls::TlsConnector::from(tls))
}

#[cfg(test)]
mod tests {
    use super::{
        GlpiAdapterConfig, GlpiAppToken, GlpiAuthenticationSource, GlpiUserToken, validate,
    };
    use std::time::Duration;

    fn config(endpoint: &str) -> GlpiAdapterConfig {
        GlpiAdapterConfig {
            endpoint: endpoint.to_owned(),
            app_token: GlpiAppToken::new("app-token".to_owned()),
            user_token: GlpiUserToken::new("user-token".to_owned()),
            operation_timeout: Duration::from_secs(5),
            additional_trust_anchors_pem: Vec::new(),
            authentication_source: GlpiAuthenticationSource::default(),
        }
    }

    #[test]
    fn accepts_a_well_formed_https_endpoint() {
        assert!(validate(config("https://glpi.example.test/apirest.php")).is_ok());
    }

    #[test]
    fn accepts_deployment_prefix_and_normalizes_one_trailing_slash() {
        let validated = validate(config("https://glpi.example.test/glpi/apirest.php"))
            .expect("prefixed apirest.php endpoint");
        assert_eq!(validated.base.path(), "/glpi/apirest.php/");

        let validated = validate(config("https://glpi.example.test/apirest.php/"))
            .expect("trailing slash is accepted");
        assert_eq!(validated.base.path(), "/apirest.php/");
    }

    #[test]
    fn rejects_non_terminal_apirest_php_paths() {
        for endpoint in [
            "https://glpi.example.test/",
            "https://glpi.example.test/api",
            "https://glpi.example.test/foo.php",
            "https://glpi.example.test/apirest.php/extra",
            "https://glpi.example.test/apirest.php//",
        ] {
            assert!(
                validate(config(endpoint)).is_err(),
                "must reject {endpoint}"
            );
        }
    }

    #[test]
    fn rejects_plaintext_http() {
        assert!(validate(config("http://glpi.example.test/apirest.php")).is_err());
    }

    #[test]
    fn rejects_missing_host() {
        assert!(validate(config("https://")).is_err());
    }

    #[test]
    fn rejects_userinfo() {
        assert!(validate(config("https://user:pass@glpi.example.test/apirest.php")).is_err());
    }

    #[test]
    fn rejects_fragment() {
        assert!(validate(config("https://glpi.example.test/apirest.php#frag")).is_err());
    }

    #[test]
    fn rejects_pre_existing_query_string() {
        assert!(validate(config("https://glpi.example.test/apirest.php?x=1")).is_err());
    }

    #[test]
    fn rejects_malformed_uri() {
        assert!(validate(config("not-a-uri")).is_err());
    }

    #[test]
    fn rejects_zero_operation_timeout() {
        let mut cfg = config("https://glpi.example.test/apirest.php");
        cfg.operation_timeout = Duration::ZERO;
        assert!(validate(cfg).is_err());
    }

    #[test]
    fn rejects_empty_tokens() {
        let mut cfg = config("https://glpi.example.test/apirest.php");
        cfg.app_token = GlpiAppToken::new(String::new());
        assert!(validate(cfg).is_err());

        let mut cfg = config("https://glpi.example.test/apirest.php");
        cfg.user_token = GlpiUserToken::new(String::new());
        assert!(validate(cfg).is_err());
    }

    #[test]
    fn rejects_malformed_trust_anchor_pem() {
        let mut cfg = config("https://glpi.example.test/apirest.php");
        cfg.additional_trust_anchors_pem = vec![vec![0, 1, 2, 3]];
        assert!(validate(cfg).is_err());
    }

    #[test]
    fn rejects_a_pem_blob_with_no_usable_certificate() {
        let mut cfg = config("https://glpi.example.test/apirest.php");
        cfg.additional_trust_anchors_pem = vec![b"not a pem certificate\n".to_vec()];
        assert!(validate(cfg).is_err());
    }
}
