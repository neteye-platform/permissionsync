//! Typed runtime configuration, deterministic application composition, and
//! selected-target orchestration wiring for PermissionSync.
//!
//! This crate receives semantic construction inputs directly and wires composed
//! state into selected-target orchestration. It deliberately selects no
//! configuration delivery format, loading mechanism, or startup behavior.

#![forbid(unsafe_code)]

pub mod composition;
pub mod configuration;

pub use composition::{
    ComposedApplication, CompositionError, GLPI_ADAPTER_IDENTIFIER, ProviderAvailability,
    TargetAvailability,
};
pub use configuration::{ConfiguredTarget, ProviderConfiguration, RuntimeConfiguration};
