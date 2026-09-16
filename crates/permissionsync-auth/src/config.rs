//! Static, validated authenticator configuration.

use std::{collections::BTreeSet, error::Error, fmt, time::Duration};

use hyper::Uri;
use native_tls::{Certificate, Protocol, TlsConnector as NativeTlsConnector};

use crate::MAX_TEXT_BYTES;

const MAX_CLOCK_SKEW: Duration = Duration::from_secs(5 * 60);

/// A configured asymmetric JWS algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum JwtAlgorithm {
    /// RSASSA-PKCS1-v1_5 using SHA-256.
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384.
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512.
    RS512,
    /// RSASSA-PSS using SHA-256.
    PS256,
    /// RSASSA-PSS using SHA-384.
    PS384,
    /// RSASSA-PSS using SHA-512.
    PS512,
    /// ECDSA P-256 using SHA-256.
    ES256,
    /// ECDSA P-384 using SHA-384.
    ES384,
    /// ECDSA P-521 using SHA-512.
    ES512,
    /// Ed25519/Ed448 as selected by the trusted JWK.
    EdDSA,
}

impl JwtAlgorithm {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::RS256 => "RS256",
            Self::RS384 => "RS384",
            Self::RS512 => "RS512",
            Self::PS256 => "PS256",
            Self::PS384 => "PS384",
            Self::PS512 => "PS512",
            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
            Self::ES512 => "ES512",
            Self::EdDSA => "EdDSA",
        }
    }
}

/// The one configured remote source of trusted verification material.
///
/// Does not derive `Debug`: the contained URI is deployment-specific
/// configuration and has no current need to flow through generic formatting.
#[derive(Clone, Eq, PartialEq)]
pub enum TrustedVerificationSource {
    /// Fetch a JWKS directly from this configured HTTPS URI.
    DirectJwks { uri: String },
    /// Fetch OIDC discovery from this configured HTTPS URI, then its JWKS URI.
    OidcDiscovery { uri: String },
}

/// Bounded in-memory verification-cache policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationCachePolicy {
    pub(crate) freshness: Duration,
    pub(crate) stale_if_error: Duration,
}

impl VerificationCachePolicy {
    /// Constructs a candidate cache policy value. This constructor performs no
    /// validation; [`TechnicalCallerAuthenticatorConfig::new`] rejects a zero
    /// `freshness` or a `freshness + stale_if_error` sum that overflows
    /// `Duration` with [`AuthenticatorConfigurationError::InvalidCachePolicy`].
    pub fn new(freshness: Duration, stale_if_error: Duration) -> Self {
        Self {
            freshness,
            stale_if_error,
        }
    }

    /// Returns the maximum age for fresh verification material.
    pub fn freshness(&self) -> Duration {
        self.freshness
    }

    /// Returns the additional bounded stale-if-error grace.
    pub fn stale_if_error(&self) -> Duration {
        self.stale_if_error
    }
}

/// Eager configuration failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatorConfigurationError {
    /// Issuer configuration is unusable.
    InvalidIssuer,
    /// Expected audience configuration is unusable.
    InvalidAudience,
    /// A trusted source URI is unusable.
    InvalidSource,
    /// The algorithm allowlist is empty or has duplicates.
    InvalidAlgorithms,
    /// The metadata timeout is zero.
    InvalidMetadataTimeout,
    /// The cache freshness is zero, or `freshness + stale_if_error` overflows
    /// `Duration`.
    InvalidCachePolicy,
    /// Clock skew exceeds the fixed maximum.
    InvalidClockSkew,
    /// Private trust-anchor PEM is malformed.
    InvalidTrustAnchor,
    /// The local TLS client could not be constructed.
    TlsConfiguration,
}

impl fmt::Display for AuthenticatorConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid technical-caller authenticator configuration")
    }
}

impl Error for AuthenticatorConfigurationError {}

/// Validated immutable authenticator configuration.
pub struct TechnicalCallerAuthenticatorConfig {
    pub(crate) issuer: String,
    pub(crate) audience: String,
    pub(crate) source: SourceUri,
    pub(crate) algorithms: BTreeSet<JwtAlgorithm>,
    pub(crate) metadata_timeout: Duration,
    pub(crate) cache_policy: VerificationCachePolicy,
    pub(crate) clock_skew: Duration,
    pub(crate) tls: hyper_tls::native_tls::TlsConnector,
}

impl TechnicalCallerAuthenticatorConfig {
    /// Validates all static authentication configuration and constructs strict
    /// TLS state. PEM input is consumed and is not retained.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer: String,
        expected_audience: String,
        source: TrustedVerificationSource,
        algorithms: Vec<JwtAlgorithm>,
        metadata_timeout: Duration,
        cache_policy: VerificationCachePolicy,
        clock_skew: Duration,
        additional_trust_anchors_pem: Vec<Vec<u8>>,
    ) -> Result<Self, AuthenticatorConfigurationError> {
        if !valid_text(&issuer) || parse_issuer_uri(&issuer).is_err() {
            return Err(AuthenticatorConfigurationError::InvalidIssuer);
        }
        if !valid_text(&expected_audience) {
            return Err(AuthenticatorConfigurationError::InvalidAudience);
        }
        let source = SourceUri::from_public(source)?;
        if algorithms.is_empty()
            || algorithms.iter().copied().collect::<BTreeSet<_>>().len() != algorithms.len()
        {
            return Err(AuthenticatorConfigurationError::InvalidAlgorithms);
        }
        if metadata_timeout.is_zero() {
            return Err(AuthenticatorConfigurationError::InvalidMetadataTimeout);
        }
        if cache_policy.freshness.is_zero()
            || cache_policy
                .freshness
                .checked_add(cache_policy.stale_if_error)
                .is_none()
        {
            return Err(AuthenticatorConfigurationError::InvalidCachePolicy);
        }
        if clock_skew > MAX_CLOCK_SKEW {
            return Err(AuthenticatorConfigurationError::InvalidClockSkew);
        }

        let mut builder = NativeTlsConnector::builder();
        builder
            .min_protocol_version(Some(Protocol::Tlsv12))
            .danger_accept_invalid_certs(false)
            .danger_accept_invalid_hostnames(false)
            .use_sni(true);
        for pem in additional_trust_anchors_pem {
            let certificates = Certificate::stack_from_pem(&pem)
                .map_err(|_| AuthenticatorConfigurationError::InvalidTrustAnchor)?;
            if certificates.is_empty() {
                return Err(AuthenticatorConfigurationError::InvalidTrustAnchor);
            }
            for certificate in certificates {
                builder.add_root_certificate(certificate);
            }
        }
        let tls = builder
            .build()
            .map_err(|_| AuthenticatorConfigurationError::TlsConfiguration)?;

        Ok(Self {
            issuer,
            audience: expected_audience,
            source,
            algorithms: algorithms.into_iter().collect(),
            metadata_timeout,
            cache_policy,
            clock_skew,
            tls,
        })
    }
}

/// Validated, internal authenticator configuration used by the running
/// authenticator (as opposed to [`TechnicalCallerAuthenticatorConfig`], the
/// public constructor-validated input).
pub(crate) struct Config {
    pub(crate) issuer: String,
    pub(crate) audience: String,
    pub(crate) source: SourceUri,
    pub(crate) algorithms: BTreeSet<JwtAlgorithm>,
    pub(crate) metadata_timeout: Duration,
    pub(crate) cache_policy: VerificationCachePolicy,
    pub(crate) clock_skew: Duration,
}

pub(crate) enum SourceUri {
    Direct(Uri),
    Discovery(Uri),
}

impl SourceUri {
    fn from_public(
        source: TrustedVerificationSource,
    ) -> Result<Self, AuthenticatorConfigurationError> {
        match source {
            TrustedVerificationSource::DirectJwks { uri } => parse_metadata_uri(&uri)
                .map(Self::Direct)
                .map_err(|_| AuthenticatorConfigurationError::InvalidSource),
            TrustedVerificationSource::OidcDiscovery { uri } => parse_metadata_uri(&uri)
                .map(Self::Discovery)
                .map_err(|_| AuthenticatorConfigurationError::InvalidSource),
        }
    }
}

/// Validates the configured trusted issuer identifier. OIDC issuer semantics
/// require an exact, case-sensitive, unambiguous identifier: HTTPS, a present
/// host, and no userinfo, query, or fragment component.
pub(crate) fn parse_issuer_uri(value: &str) -> Result<Uri, ()> {
    if value.contains(['?', '#']) {
        return Err(());
    }
    parse_https_authority(value)
}

/// Validates a trusted metadata URI: a configured direct JWKS URI, a
/// configured OIDC discovery URI, or a discovered `jwks_uri`. Unlike an
/// issuer identifier, a metadata URI may legitimately carry a query
/// component; a query is part of the already-trusted, configured/discovered
/// URL, not a redirect, and does not itself expand trust. A fragment and
/// userinfo remain refused.
pub(crate) fn parse_metadata_uri(value: &str) -> Result<Uri, ()> {
    if value.contains('#') {
        return Err(());
    }
    parse_https_authority(value)
}

/// Shared strict-HTTPS-authority rules for both issuer and metadata URIs:
/// bounded length, no template braces, HTTPS scheme, a present host, and no
/// userinfo. Query/fragment handling differs by caller and is checked before
/// this function runs.
fn parse_https_authority(value: &str) -> Result<Uri, ()> {
    if value.len() > MAX_TEXT_BYTES || value.contains(['{', '}']) {
        return Err(());
    }
    let uri: Uri = value.parse().map_err(|_| ())?;
    if uri.scheme_str() != Some("https")
        || uri.host().is_none_or(str::is_empty)
        || uri.authority().is_none()
        || uri
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
    {
        return Err(());
    }
    Ok(uri)
}

pub(crate) fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT_BYTES
}

#[cfg(test)]
mod tests {
    use super::{parse_issuer_uri, parse_metadata_uri};

    #[test]
    fn issuer_uris_reject_query_fragment_and_authority_extensions() {
        assert!(parse_issuer_uri("https://issuer.test").is_ok());
        for invalid in [
            "http://issuer.test",
            "https://user@issuer.test",
            "https://issuer.test?next=x",
            "https://issuer.test#fragment",
            "https://issuer.test/{realm}",
            "/issuer",
        ] {
            assert!(parse_issuer_uri(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn metadata_uris_allow_a_query_but_reject_fragment_and_authority_extensions() {
        assert!(parse_metadata_uri("https://issuer.test/keys").is_ok());
        assert!(parse_metadata_uri("https://issuer.test/keys?realm=main").is_ok());
        for invalid in [
            "http://issuer.test/keys",
            "https://user@issuer.test/keys",
            "https://issuer.test/keys#fragment",
            "https://issuer.test/{realm}/keys",
            "/keys",
        ] {
            assert!(parse_metadata_uri(invalid).is_err(), "{invalid}");
        }
    }
}
