//! Selected-target synchronization orchestration for PermissionSync.
//!
//! This crate coordinates work for a request that already carries one valid,
//! selected [`LogicalTarget`](permissionsync_core::LogicalTarget). It owns:
//!
//! - resolving the selected target to its compiled adapter through the
//!   existing [`TargetRouter`](permissionsync_routing::TargetRouter);
//! - acquiring bounded synchronization capacity through a mechanism-neutral
//!   port before any downstream call;
//! - invoking [`PermissionProvider::resolve`](permissionsync_core::PermissionProvider::resolve)
//!   exactly once;
//! - invoking [`TargetAdapter::reconcile`](permissionsync_core::TargetAdapter::reconcile)
//!   exactly once with the opaque envelope the Provider returned;
//! - returning the Adapter's own
//!   [`ReconciliationOutcome`](permissionsync_core::ReconciliationOutcome).
//!
//! ## What this crate explicitly does not own
//!
//! - the targetless path: a caller must already hold one valid
//!   [`LogicalTarget`](permissionsync_core::LogicalTarget) before invoking
//!   this orchestration
//!   (see [ADR 0001](../../../docs/adr/0001-inbound-synchronization-contract.md));
//! - inbound HTTP, request parsing, or HTTP status mapping;
//! - authentication, authorization, JWT/OIDC/JWKS, or scope handling;
//! - a concrete synchronization-capacity mechanism
//!   (see [ADR 0006](../../../docs/adr/0006-runtime-configuration-oci-and-observability.md));
//! - a concrete Permission Provider or Target Adapter implementation;
//! - runtime configuration or composition.
//!
//! ## Selected-target-only boundary
//!
//! Every request accepted by [`SelectedTargetSynchronizer::synchronize`]
//! carries an already-selected, already-valid
//! [`LogicalTarget`](permissionsync_core::LogicalTarget). This crate
//! has no representation for "no target was selected"; that determination
//! belongs to the future inbound layer.
//!
//! ## Stage order
//!
//! 1. Check the overall deadline/cancellation.
//! 2. Resolve the selected target with [`TargetRouter`](permissionsync_routing::TargetRouter).
//! 3. Re-check the overall deadline/cancellation.
//! 4. Acquire bounded synchronization capacity and hold the permit.
//! 5. Re-check the overall deadline/cancellation.
//! 6. Invoke `PermissionProvider::resolve` exactly once.
//! 7. Re-check the overall deadline/cancellation.
//! 8. Invoke `TargetAdapter::reconcile` exactly once with the returned envelope.
//! 9. Re-check the overall deadline/cancellation before reporting success.
//!
//! An unknown target or a recognized target with an unavailable compiled
//! adapter returns immediately: no capacity, Provider, or Adapter work starts.
//!
//! ## At-most-once behavior
//!
//! One [`SelectedTargetSynchronizer::synchronize`] call causes at most one
//! capacity acquisition, one Provider invocation, and one Adapter invocation,
//! executed strictly in sequence. There is no retry, replay, deduplication, or
//! rollback (see [ADR 0003](../../../docs/adr/0003-at-most-once-delivery-and-idempotent-reconciliation.md)).
//!
//! ## Deadline and cancellation propagation
//!
//! The same overall [`SynchronizationContext`](permissionsync_core::SynchronizationContext)
//! deadline and cancellation signal reach capacity acquisition, the Provider,
//! and the Adapter. No stage recreates or extends the deadline, and no new
//! work starts once cancellation or expiry is observed.
//!
//! ## Dropping the synchronization future
//!
//! Dropping the future returned by [`SelectedTargetSynchronizer::synchronize`]
//! drops its currently awaited child port future and any held permit by normal
//! Rust drop, releasing local capacity. A permit is held while local
//! reconciliation work is alive and is released on normal completion or when
//! the parent future is dropped. For compliant ports, no detached or background
//! reconciliation continues. Dropping the parent future does not hard-interrupt
//! arbitrary in-process work or reverse already-issued downstream effects;
//! those effects may remain uncertain.
//!
//! ## Opaque desired state and Adapter-owned outcome
//!
//! The [`DesiredStateEnvelope`](permissionsync_core::DesiredStateEnvelope)
//! returned by the Provider is forwarded to the Adapter unexamined
//! (see [ADR 0005](../../../docs/adr/0005-versioned-adapter-specific-desired-state-envelope.md)).
//! Only the Adapter decides
//! [`ReconciliationOutcome::Changed`](permissionsync_core::ReconciliationOutcome::Changed)
//! versus
//! [`ReconciliationOutcome::Unchanged`](permissionsync_core::ReconciliationOutcome::Unchanged).

mod capacity;
mod error;
mod request;
mod synchronizer;

pub use capacity::{SynchronizationCapacity, SynchronizationCapacityError, SynchronizationPermit};
pub use error::SelectedTargetSynchronizationError;
pub use request::SelectedTargetSynchronizationRequest;
pub use synchronizer::SelectedTargetSynchronizer;
