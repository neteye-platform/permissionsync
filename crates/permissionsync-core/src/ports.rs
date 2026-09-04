use std::{error::Error, fmt, future::Future, pin::Pin, time::Instant};

use crate::{DesiredStateEnvelope, IdentityContext, LogicalTarget};

/// A sendable future returned by a Core port.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A runtime-neutral signal that an in-flight synchronization should stop work.
pub trait CancellationSignal: Send + Sync {
    /// Returns whether cancellation has been requested.
    fn is_cancelled(&self) -> bool;
}

/// Deadline and cancellation information propagated to downstream work.
pub struct SynchronizationContext<'a> {
    deadline: Instant,
    cancellation: &'a dyn CancellationSignal,
}

impl<'a> SynchronizationContext<'a> {
    /// Creates context for a single synchronization request.
    pub fn new(deadline: Instant, cancellation: &'a dyn CancellationSignal) -> Self {
        Self {
            deadline,
            cancellation,
        }
    }

    /// Returns the monotonic deadline for the synchronization request.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Returns the propagated cooperative cancellation signal.
    pub fn cancellation(&self) -> &dyn CancellationSignal {
        self.cancellation
    }
}

/// Inputs for one Permission Provider desired-state resolution attempt.
pub struct PermissionProviderRequest<'a> {
    identity: &'a IdentityContext,
    target: &'a LogicalTarget,
    context: SynchronizationContext<'a>,
}

impl<'a> PermissionProviderRequest<'a> {
    /// Creates inputs for a Permission Provider operation.
    pub fn new(
        identity: &'a IdentityContext,
        target: &'a LogicalTarget,
        context: SynchronizationContext<'a>,
    ) -> Self {
        Self {
            identity,
            target,
            context,
        }
    }

    /// Returns the synchronized end-user identity context.
    pub fn identity(&self) -> &IdentityContext {
        self.identity
    }

    /// Returns the authorized logical target being resolved.
    pub fn target(&self) -> &LogicalTarget {
        self.target
    }

    /// Returns the request deadline and cancellation context.
    pub fn context(&self) -> &SynchronizationContext<'a> {
        &self.context
    }
}

/// Resolves what desired state should exist for a user and logical target.
pub trait PermissionProvider: Send + Sync {
    /// Resolves one structurally valid desired-state envelope.
    fn resolve<'a>(
        &'a self,
        request: PermissionProviderRequest<'a>,
    ) -> BoxFuture<'a, Result<DesiredStateEnvelope, PermissionProviderError>>;
}

/// A non-HTTP error returned by a Permission Provider.
pub struct PermissionProviderError {
    source: Box<dyn Error + Send + Sync + 'static>,
}

impl PermissionProviderError {
    /// Wraps an internal Provider failure without exposing it through outer formatting.
    pub fn new<E>(source: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self {
            source: Box::new(source),
        }
    }
}

impl fmt::Debug for PermissionProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PermissionProviderError")
    }
}

impl fmt::Display for PermissionProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("permission provider resolution failed")
    }
}

impl Error for PermissionProviderError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Inputs for one Target Adapter reconciliation attempt.
pub struct TargetAdapterRequest<'a> {
    desired_state: &'a DesiredStateEnvelope,
    context: SynchronizationContext<'a>,
}

impl<'a> TargetAdapterRequest<'a> {
    /// Creates inputs for a Target Adapter reconciliation operation.
    pub fn new(
        desired_state: &'a DesiredStateEnvelope,
        context: SynchronizationContext<'a>,
    ) -> Self {
        Self {
            desired_state,
            context,
        }
    }

    /// Returns the opaque desired state selected for this adapter.
    pub fn desired_state(&self) -> &DesiredStateEnvelope {
        self.desired_state
    }

    /// Returns the request deadline and cancellation context.
    pub fn context(&self) -> &SynchronizationContext<'a> {
        &self.context
    }
}

/// Reconciles opaque desired state against a selected target.
pub trait TargetAdapter: Send + Sync {
    /// Validates the complete adapter-specific payload before mutation and then
    /// reconciles idempotently toward the desired state.
    fn reconcile<'a>(
        &'a self,
        request: TargetAdapterRequest<'a>,
    ) -> BoxFuture<'a, Result<ReconciliationOutcome, TargetAdapterError>>;
}

/// A non-HTTP error returned by a Target Adapter.
pub struct TargetAdapterError {
    source: Box<dyn Error + Send + Sync + 'static>,
}

impl TargetAdapterError {
    /// Wraps an internal Adapter failure without exposing it through outer formatting.
    pub fn new<E>(source: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self {
            source: Box::new(source),
        }
    }
}

impl fmt::Debug for TargetAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TargetAdapterError")
    }
}

impl fmt::Display for TargetAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("target adapter reconciliation failed")
    }
}

impl Error for TargetAdapterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// The externally observable result of successful target reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum ReconciliationOutcome {
    /// The adapter changed target state to converge on the desired state.
    Changed,
    /// The target was already in the desired state.
    Unchanged,
}

#[cfg(test)]
mod tests {
    use std::{error::Error, fmt, future, sync::Mutex, time::Instant};

    use crate::{
        DesiredStateEnvelope, EnvelopeVersion, IdentityContext, LogicalTarget, OpaquePayload,
    };

    use super::{
        BoxFuture, CancellationSignal, PermissionProvider, PermissionProviderError,
        PermissionProviderRequest, ReconciliationOutcome, SynchronizationContext, TargetAdapter,
        TargetAdapterError, TargetAdapterRequest,
    };

    struct Cancelled;

    impl CancellationSignal for Cancelled {
        fn is_cancelled(&self) -> bool {
            true
        }
    }

    struct TestProvider;

    impl PermissionProvider for TestProvider {
        fn resolve<'a>(
            &'a self,
            request: PermissionProviderRequest<'a>,
        ) -> BoxFuture<'a, Result<DesiredStateEnvelope, PermissionProviderError>> {
            Box::pin(async move {
                let _ = request.identity().username();
                let _ = request.target().as_str();
                let _ = request.context().deadline();

                Err(PermissionProviderError::new(SensitiveSource))
            })
        }
    }

    struct TestAdapter;

    impl TargetAdapter for TestAdapter {
        fn reconcile<'a>(
            &'a self,
            request: TargetAdapterRequest<'a>,
        ) -> BoxFuture<'a, Result<ReconciliationOutcome, TargetAdapterError>> {
            Box::pin(async move {
                let _ = request.desired_state().payload().as_json();
                let _ = request.context().cancellation().is_cancelled();

                Ok(ReconciliationOutcome::Changed)
            })
        }
    }

    struct InspectingAdapter {
        payload: Mutex<Option<String>>,
    }

    impl TargetAdapter for InspectingAdapter {
        fn reconcile<'a>(
            &'a self,
            request: TargetAdapterRequest<'a>,
        ) -> BoxFuture<'a, Result<ReconciliationOutcome, TargetAdapterError>> {
            *self.payload.lock().unwrap() =
                Some(request.desired_state().payload().as_json().to_owned());

            Box::pin(future::ready(Ok(ReconciliationOutcome::Unchanged)))
        }
    }

    #[derive(Debug)]
    struct SensitiveSource;

    impl fmt::Display for SensitiveSource {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("sentinel source detail")
        }
    }

    impl Error for SensitiveSource {}

    #[test]
    fn context_preserves_deadline_and_cancellation_signal() {
        let cancellation = Cancelled;
        let deadline = Instant::now();
        let context = SynchronizationContext::new(deadline, &cancellation);

        assert_eq!(context.deadline(), deadline);
        assert!(context.cancellation().is_cancelled());
    }

    #[test]
    fn ports_are_object_safe_and_send_sync() {
        fn assert_send_sync<T: ?Sized + Send + Sync>() {}

        assert_send_sync::<dyn PermissionProvider>();
        assert_send_sync::<dyn TargetAdapter>();
        assert_send_sync::<dyn CancellationSignal>();

        let provider: &dyn PermissionProvider = &TestProvider;
        let adapter: &dyn TargetAdapter = &TestAdapter;
        let cancellation: &dyn CancellationSignal = &Cancelled;

        let _ = (provider, adapter, cancellation);
    }

    #[test]
    fn adapter_receives_opaque_payload_unchanged() {
        let adapter = InspectingAdapter {
            payload: Mutex::new(None),
        };
        let cancellation = Cancelled;
        let raw_payload = "{\"roles\": [\"operator\"], \"enabled\": true}";
        let desired_state = DesiredStateEnvelope::new(
            EnvelopeVersion::new(1),
            OpaquePayload::try_from(raw_payload.to_owned()).unwrap(),
        );
        let context = SynchronizationContext::new(Instant::now(), &cancellation);
        let request = TargetAdapterRequest::new(&desired_state, context);

        drop(adapter.reconcile(request));

        assert_eq!(
            adapter.payload.lock().unwrap().as_deref(),
            Some(raw_payload)
        );
    }

    #[test]
    fn outcomes_are_explicit_and_distinct() {
        assert_ne!(
            ReconciliationOutcome::Changed,
            ReconciliationOutcome::Unchanged
        );
    }

    #[test]
    fn port_errors_redact_outer_formatting() {
        let provider_error = PermissionProviderError::new(SensitiveSource);
        let adapter_error = TargetAdapterError::new(SensitiveSource);

        for error in [&provider_error as &dyn Error, &adapter_error as &dyn Error] {
            assert!(!error.to_string().contains("sentinel source detail"));
            assert!(!format!("{error:?}").contains("sentinel source detail"));
            assert_eq!(
                error.source().unwrap().to_string(),
                "sentinel source detail"
            );
        }
    }

    #[test]
    fn port_futures_can_borrow_request_inputs() {
        let provider = TestProvider;
        let adapter = TestAdapter;
        let cancellation = Cancelled;
        let identity = IdentityContext::new("jdoe".to_owned(), Vec::new());
        let target = LogicalTarget::try_from("target".to_owned()).unwrap();
        let desired_state = DesiredStateEnvelope::new(
            EnvelopeVersion::new(1),
            OpaquePayload::try_from("null".to_owned()).unwrap(),
        );

        let provider_context = SynchronizationContext::new(Instant::now(), &cancellation);
        let adapter_context = SynchronizationContext::new(Instant::now(), &cancellation);
        let provider_request = PermissionProviderRequest::new(&identity, &target, provider_context);
        let adapter_request = TargetAdapterRequest::new(&desired_state, adapter_context);

        drop(provider.resolve(provider_request));
        drop(adapter.reconcile(adapter_request));
    }
}
