//! Concrete GLPI Target Adapter for PermissionSync.
//!
//! Implements the GLPI Target Adapter contract defined by [ADR
//! 0009](../../../docs/adr/0009-glpi-target-adapter.md): it reconciles one
//! synchronized user's complete GLPI `Profile_User` assignment set against a
//! versioned v1 desired-state payload, using the production GLPI V1
//! `apirest.php` REST API only.
//!
//! This crate depends only on `permissionsync-core`'s public contract. It
//! does not depend on orchestration internals, routing internals, the
//! Generic REST Provider, or any other concrete adapter. Registration,
//! runtime configuration schema, and application composition are a later
//! task; this crate is independently buildable, testable, and usable.

#![forbid(unsafe_code)]

mod adapter;
mod config;
mod error;
mod mutation;
mod payload;
mod plan;
mod search;
mod session;
mod transport;

pub use adapter::GlpiAdapter;
pub use config::{GlpiAdapterConfig, GlpiAppToken, GlpiAuthenticationSource, GlpiUserToken};
pub use error::GlpiAdapterConfigError;
