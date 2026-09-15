use std::{error::Error, fmt};

/// A coarse, safe selected-target synchronization failure category.
///
/// This type deliberately discards any Provider, Adapter, capacity, or
/// routing internal detail. Its `Display`, `Debug`, and
/// [`Error::source`] never expose identity, bearer, target, adapter
/// identifier, or opaque desired-state payload values.
///
/// Provider and Adapter errors may carry sensitive source chains. When mapping
/// them to these coarse categories, orchestration deliberately discards those
/// chains immediately and retains no source chain. Safe diagnostics remain the
/// responsibility of concrete ports and future runtime observability.
#[derive(Debug)]
pub enum SelectedTargetSynchronizationError {
    /// The overall deadline expired or cancellation was observed before or
    /// during selected-target work. This does not mean that no target effect
    /// occurred: it can be returned after Provider or Adapter work, including
    /// after the Adapter returns before the final check. Effects already issued
    /// remain uncertain; no automatic retry or rollback occurs.
    Cancelled,
    /// No configured route matches the selected logical target.
    UnknownTarget,
    /// The selected target is recognized, but its compiled adapter is unavailable.
    TargetUnavailable,
    /// Bounded synchronization capacity could not be acquired.
    CapacityUnavailable,
    /// The Permission Provider failed to resolve desired state.
    ProviderFailed,
    /// The Target Adapter failed to reconcile desired state.
    AdapterFailed,
}

impl fmt::Display for SelectedTargetSynchronizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Cancelled => "selected-target synchronization was cancelled or expired",
            Self::UnknownTarget => "selected target is unknown",
            Self::TargetUnavailable => "selected target is unavailable",
            Self::CapacityUnavailable => "synchronization capacity is unavailable",
            Self::ProviderFailed => "permission provider resolution failed",
            Self::AdapterFailed => "target adapter reconciliation failed",
        })
    }
}

impl Error for SelectedTargetSynchronizationError {}
