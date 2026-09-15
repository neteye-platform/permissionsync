use std::time::Instant;

use permissionsync_core::{
    BoxFuture, PermissionProvider, PermissionProviderRequest, ReconciliationOutcome,
    SynchronizationContext, TargetAdapterRequest,
};
use permissionsync_routing::{TargetResolutionError, TargetRouter};

use crate::{
    capacity::SynchronizationCapacity, error::SelectedTargetSynchronizationError,
    request::SelectedTargetSynchronizationRequest,
};

/// Coordinates one selected-target synchronization attempt.
///
/// This type invokes routing, bounded capacity, the Permission Provider, and
/// the Target Adapter in the exact order documented at the crate root. It
/// knows nothing about a concrete Provider or Adapter implementation; it only
/// consumes the existing Core ports and the existing [`TargetRouter`].
pub struct SelectedTargetSynchronizer<'a> {
    router: &'a TargetRouter,
    provider: &'a dyn PermissionProvider,
    capacity: &'a dyn SynchronizationCapacity,
}

impl<'a> SelectedTargetSynchronizer<'a> {
    /// Creates a synchronizer over an existing router, Provider, and capacity port.
    pub fn new(
        router: &'a TargetRouter,
        provider: &'a dyn PermissionProvider,
        capacity: &'a dyn SynchronizationCapacity,
    ) -> Self {
        Self {
            router,
            provider,
            capacity,
        }
    }

    /// Synchronizes one already-selected logical target.
    ///
    /// See the crate-level documentation for the exact stage order,
    /// at-most-once guarantees, and deadline/cancellation propagation.
    pub fn synchronize<'r>(
        &'r self,
        request: SelectedTargetSynchronizationRequest<'r>,
    ) -> BoxFuture<'r, Result<ReconciliationOutcome, SelectedTargetSynchronizationError>>
    where
        'a: 'r,
    {
        Box::pin(async move {
            if is_cancelled_or_expired(request.context()) {
                return Err(SelectedTargetSynchronizationError::Cancelled);
            }

            let adapter = match self.router.resolve(request.target()) {
                Ok(adapter) => adapter,
                Err(TargetResolutionError::UnknownLogicalTarget) => {
                    return Err(SelectedTargetSynchronizationError::UnknownTarget);
                }
                Err(TargetResolutionError::UnavailableCompiledAdapter { .. }) => {
                    return Err(SelectedTargetSynchronizationError::TargetUnavailable);
                }
            };

            if is_cancelled_or_expired(request.context()) {
                return Err(SelectedTargetSynchronizationError::Cancelled);
            }

            let _permit = self
                .capacity
                .acquire(request.context())
                .await
                .map_err(|_| SelectedTargetSynchronizationError::CapacityUnavailable)?;

            if is_cancelled_or_expired(request.context()) {
                return Err(SelectedTargetSynchronizationError::Cancelled);
            }

            let provider_request = PermissionProviderRequest::new(
                request.identity(),
                request.target(),
                request.technical_caller_bearer_token(),
                copy_context(request.context()),
            );

            let desired_state = self
                .provider
                .resolve(provider_request)
                .await
                .map_err(|_| SelectedTargetSynchronizationError::ProviderFailed)?;

            if is_cancelled_or_expired(request.context()) {
                return Err(SelectedTargetSynchronizationError::Cancelled);
            }

            let adapter_request =
                TargetAdapterRequest::new(&desired_state, copy_context(request.context()));

            let outcome = adapter
                .reconcile(adapter_request)
                .await
                .map_err(|_| SelectedTargetSynchronizationError::AdapterFailed)?;

            if is_cancelled_or_expired(request.context()) {
                return Err(SelectedTargetSynchronizationError::Cancelled);
            }

            Ok(outcome)
        })
    }
}

fn is_cancelled_or_expired(context: &SynchronizationContext<'_>) -> bool {
    context.cancellation().is_cancelled() || Instant::now() >= context.deadline()
}

fn copy_context<'a>(context: &'a SynchronizationContext<'a>) -> SynchronizationContext<'a> {
    SynchronizationContext::new(context.deadline(), context.cancellation())
}
