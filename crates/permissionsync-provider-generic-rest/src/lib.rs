//! Concrete HTTPS Generic REST Permission Provider for PermissionSync.
//!
//! The Provider forwards the authenticated technical-caller bearer credential
//! unchanged to the configured remote Provider resource server. The remote
//! Provider owns independent JWT validation and target derivation. Every
//! Provider response body is bounded by a private, non-configurable 1 MiB
//! absolute safety ceiling; see that constant's documentation in the
//! transport module for rationale.
//!
//! For hostname endpoints, construction captures the first UDP nameserver from
//! platform DNS configuration. Each operation composes one A query and one
//! AAAA query into one logical DNS resolution. Neither query is retried or
//! fails over, and both operation-owned request futures are dropped together
//! when the operation ends.

#![forbid(unsafe_code)]

mod client;
mod error;
mod wire;

use std::time::Duration;

use permissionsync_core::{
    BoxFuture, DesiredStateEnvelope, PermissionProvider, PermissionProviderError,
    PermissionProviderRequest,
};

pub use error::GenericRestPermissionProviderConfigError;

/// Runtime values for one Generic REST Permission Provider.
///
/// The endpoint and additional trust anchors are deployment-specific values.
/// The raw technical-caller bearer credential is deliberately not configuration:
/// it is supplied by Core for each resolution attempt.
pub struct GenericRestPermissionProviderConfig {
    /// Complete HTTPS URI for the remote Provider request.
    pub endpoint: String,
    /// Positive upper bound for one Provider resolution attempt.
    pub operation_timeout: Duration,
    /// DER-encoded private trust anchors added to the platform system roots.
    pub additional_trust_anchors_der: Vec<Vec<u8>>,
}

/// A concrete HTTPS client for the Generic REST Permission Provider contract.
///
/// The client forwards the exact technical-caller bearer supplied by Core. It
/// neither parses that credential nor derives target semantics from it. Each
/// resolution attempt performs its own single DNS resolution, TCP connect,
/// and TLS/HTTP handshake using this reusable TLS connector; there is no
/// connection pool and no background connection-driving task.
pub struct GenericRestPermissionProvider {
    endpoint: hyper::Uri,
    endpoint_host: client::EndpointHost,
    operation_timeout: Duration,
    tls_connector: client::TlsConnector,
}

impl GenericRestPermissionProvider {
    /// Validates Provider configuration and builds a reusable TLS connector.
    ///
    /// System trust roots remain enabled. `additional_trust_anchors_der` may be
    /// empty and, when present, only adds private trust anchors.
    pub fn new(
        config: GenericRestPermissionProviderConfig,
    ) -> Result<Self, GenericRestPermissionProviderConfigError> {
        if config.operation_timeout.is_zero() {
            return Err(GenericRestPermissionProviderConfigError::new());
        }

        let endpoint = client::parse_endpoint(&config.endpoint)?;
        let endpoint_host = client::classify_endpoint_host(&endpoint)?;
        let tls_connector = client::build_tls_connector(&config.additional_trust_anchors_der)?;

        Ok(Self {
            endpoint,
            endpoint_host,
            operation_timeout: config.operation_timeout,
            tls_connector,
        })
    }
}

impl PermissionProvider for GenericRestPermissionProvider {
    fn resolve<'a>(
        &'a self,
        request: PermissionProviderRequest<'a>,
    ) -> BoxFuture<'a, Result<DesiredStateEnvelope, PermissionProviderError>> {
        Box::pin(async move {
            client::resolve(
                &self.tls_connector,
                &self.endpoint,
                &self.endpoint_host,
                self.operation_timeout,
                request,
            )
            .await
            .map_err(PermissionProviderError::new)
        })
    }
}
