//! Internal technical-caller authentication boundary.
//!
//! This crate deliberately exposes no HTTP, TLS, JOSE, JSON, or clock types.
//!
//! Security/architecture notes for integrators:
//! - This crate receives an already-extracted raw bearer token; it does not
//!   parse HTTP `Authorization` headers. That remains an inbound boundary
//!   responsibility (see
//!   [ADR 0001](../../../docs/adr/0001-inbound-synchronization-contract.md)).
//! - Signature verification always precedes any claim or authorization
//!   decision (see
//!   [ADR 0002](../../../docs/adr/0002-receiver-side-jwt-verification.md)).
//! - Trusted metadata retrieval never expands beyond configuration: a
//!   discovery document is fetched only from the configured trusted source;
//!   its `issuer` must exactly equal the configured trusted issuer; only
//!   after that check does its HTTPS `jwks_uri` become trusted metadata (see
//!   [ADR 0002](../../../docs/adr/0002-receiver-side-jwt-verification.md)
//!   and the runtime-configuration constraints in
//!   [ADR 0006](../../../docs/adr/0006-runtime-configuration-oci-and-observability.md)).
//!   No token-controlled URL ever participates in that selection; a
//!   discovered `jwks_uri` may legitimately point at a different HTTPS host
//!   than the issuer, as long as it was reached only through this chain.
//! - The raw input token survives only in the authenticated output, for
//!   later forwarding to the Provider boundary; it is never logged or
//!   otherwise retained.
//! - A successful JWKS/discovery refresh atomically replaces older trusted
//!   state; there is no background refresh, only opportunistic refresh
//!   during an authentication attempt.
//! - [`TargetSelection::NoTarget`] means only that scope granted no
//!   PermissionSync target; it does not itself imply a successful HTTP
//!   `204`, which remains a later boundary's decision.

mod authenticator;
mod claims;
mod clock;
mod config;
mod context;
mod error;
mod jwks;
mod types;

pub(crate) const MAX_TEXT_BYTES: usize = 4 * 1024;
pub(crate) const MAX_TOKEN_BYTES: usize = 16 * 1024;
/// Absolute ceiling on any single trusted metadata document (JWKS or OIDC
/// discovery) fetched from an untrusted-until-verified remote response. Large
/// enough for realistic OIDC discovery/JWKS documents, while bounding
/// allocation and parsing work driven by an untrusted remote response size.
pub(crate) const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_JWKS_KEYS: usize = 32;
pub(crate) const MAX_PUBLIC_COMPONENT_BYTES: usize = 1366;
pub(crate) const MAX_RSA_EXPONENT_BYTES: usize = 16;

pub use authenticator::TechnicalCallerAuthenticator;
pub use config::{
    AuthenticatorConfigurationError, JwtAlgorithm, TechnicalCallerAuthenticatorConfig,
    TrustedVerificationSource, VerificationCachePolicy,
};
pub use error::AuthenticationError;
pub use types::{
    AuthenticatedTechnicalCaller, AuthenticationRequest, TargetSelection, TechnicalCallerClientId,
};

#[cfg(test)]
mod adversarial_tests;
