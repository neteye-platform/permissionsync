//! Target-neutral PermissionSync domain types and asynchronous ports.
//!
//! This crate defines the boundary between Permission Providers, Core
//! orchestration, and Target Adapters. It does not implement transport,
//! authentication, routing, runtime configuration, or target semantics.
//! These Rust crate and trait boundaries provide modularity, not sandboxing or
//! isolation: linked code has PermissionSync process authority.
//!
//! Data-bearing Core types carrying potentially sensitive or unbounded
//! synchronized-user identity or desired-state payloads intentionally avoid
//! ordinary `Debug` implementations. Adding `Debug` for such types requires
//! deliberate review against ADR 0006's safe-observability requirements.

mod desired_state;
mod identity;
mod ports;
mod target;

pub use desired_state::{
    DesiredStateEnvelope, EnvelopeVersion, InvalidOpaquePayload, OpaquePayload,
};
pub use identity::IdentityContext;
pub use ports::{
    BoxFuture, CancellationSignal, PermissionProvider, PermissionProviderError,
    PermissionProviderRequest, ReconciliationOutcome, SynchronizationContext, TargetAdapter,
    TargetAdapterError, TargetAdapterRequest,
};
pub use target::{InvalidLogicalTarget, LogicalTarget};
