//! Semantic runtime configuration independent of any delivery format.

use permissionsync_adapter_glpi::GlpiAdapterConfig;
use permissionsync_provider_generic_rest::GenericRestPermissionProviderConfig;

/// Semantic runtime configuration. This model selects no delivery format.
pub struct RuntimeConfiguration {
    /// The optional process-wide Permission Provider configuration.
    pub provider: Option<ProviderConfiguration>,
    /// The optional process-wide GLPI adapter configuration.
    pub glpi: Option<GlpiAdapterConfig>,
    /// Configured logical target routes in deliberate input order.
    pub targets: Vec<ConfiguredTarget>,
}

/// The supported v1 Permission Provider implementations.
pub enum ProviderConfiguration {
    /// The Generic REST Permission Provider.
    GenericRest(GenericRestPermissionProviderConfig),
}

/// One configured logical target selecting exactly one opaque adapter identifier.
pub struct ConfiguredTarget {
    /// The raw logical target validated during composition.
    pub logical_target: String,
    /// The exact opaque identifier of the selected adapter.
    pub adapter_identifier: String,
}
