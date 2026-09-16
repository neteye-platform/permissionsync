use std::fmt;

use permissionsync_core::{BoxFuture, SynchronizationContext};

/// A mechanism-neutral, bounded synchronization-capacity port.
///
/// This crate defines only the smallest contract required to express the
/// already-Accepted requirement that selected-target work acquire bounded
/// capacity before Provider work and hold it through Adapter completion (see
/// [ADR 0006](../../../docs/adr/0006-runtime-configuration-oci-and-observability.md)
/// and [ADR 0007](../../../docs/adr/0007-compile-time-rust-target-adapters.md)).
/// The concrete capacity mechanism, its limits, and any runtime configuration
/// representation remain deferred to later runtime/composition work.
pub trait SynchronizationCapacity: Send + Sync {
    /// Attempts to acquire one unit of bounded synchronization capacity.
    ///
    /// Implementations must honor the supplied deadline and cancellation
    /// signal to perform a bounded wait. On success, the returned permit
    /// represents held capacity; dropping it represents release.
    ///
    /// If the returned acquire future is dropped before it successfully returns
    /// a permit, no capacity reservation may remain held and no
    /// waiter/reservation resource may survive solely because acquisition was
    /// abandoned. Dropping the future must release or cancel any provisional
    /// reservation that the future owns.
    fn acquire<'a>(
        &'a self,
        context: &'a SynchronizationContext<'a>,
    ) -> BoxFuture<
        'a,
        Result<Box<dyn SynchronizationPermit + Send + 'a>, SynchronizationCapacityError>,
    >;
}

/// An opaque, held unit of synchronization capacity.
///
/// This trait carries no methods. A concrete implementation's [`Drop`]
/// behavior is what represents release; this crate never releases capacity by
/// any means other than dropping the permit it holds.
pub trait SynchronizationPermit: Send {}

/// A non-HTTP error returned by a synchronization-capacity implementation.
///
/// Its fixed display and debug representations are safe for callers and logs.
/// It retains no underlying cause and exposes no [`std::error::Error::source`].
pub struct SynchronizationCapacityError;

impl fmt::Debug for SynchronizationCapacityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SynchronizationCapacityError")
    }
}

impl fmt::Display for SynchronizationCapacityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("synchronization capacity acquisition failed")
    }
}

impl std::error::Error for SynchronizationCapacityError {}
