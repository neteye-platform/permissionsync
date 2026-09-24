//! Selected-target synchronization orchestration contract tests.
//!
//! These tests use only the real public API of `permissionsync-orchestration`
//! together with a real `TargetRouter` and small deterministic in-memory
//! fakes for `PermissionProvider`, `TargetAdapter`, and
//! `SynchronizationCapacity`. No Tokio, sleeps, fixed ports, or network
//! access are used; all futures are driven synchronously with an immediate
//! no-op waker, matching the pattern already used by `permissionsync-core`.

use std::{
    error::Error,
    fmt,
    future::Future,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use permissionsync_core::{
    BoxFuture, CancellationSignal, DesiredStateEnvelope, EnvelopeVersion, IdentityContext,
    LogicalTarget, OpaquePayload, PermissionProvider, PermissionProviderError,
    PermissionProviderRequest, ReconciliationOutcome, SynchronizationContext, TargetAdapter,
    TargetAdapterError, TargetAdapterRequest, TechnicalCallerBearerToken,
};
use permissionsync_orchestration::{
    SelectedTargetSynchronizationError, SelectedTargetSynchronizationRequest,
    SelectedTargetSynchronizer, SynchronizationCapacity, SynchronizationCapacityError,
    SynchronizationPermit,
};
use permissionsync_routing::{AdapterIdentifier, AdapterRegistration, TargetRoute, TargetRouter};

fn poll_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = Box::pin(future);

    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test future unexpectedly returned Poll::Pending"),
    }
}

fn logical_target(value: &str) -> LogicalTarget {
    LogicalTarget::try_from(value.to_owned()).unwrap()
}

fn adapter_identifier(value: &str) -> AdapterIdentifier {
    AdapterIdentifier::new(value.to_owned())
}

fn not_deadline() -> Instant {
    Instant::now() + Duration::from_secs(3600)
}

fn expired_deadline() -> Instant {
    Instant::now() - Duration::from_secs(1)
}

#[derive(Debug)]
struct SentinelError(&'static str);

impl fmt::Display for SentinelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for SentinelError {}

struct NeverCancelled;

impl CancellationSignal for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

struct AlreadyCancelled;

impl CancellationSignal for AlreadyCancelled {
    fn is_cancelled(&self) -> bool {
        true
    }
}

/// A cancellation signal that flips to cancelled the first time a
/// participant (Provider or Adapter) explicitly requests it, and stays
/// cancelled afterward. This lets tests deterministically simulate
/// cancellation observed between orchestration stages.
struct FlipOnDemand {
    cancelled: AtomicBool,
}

impl FlipOnDemand {
    fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
        }
    }

    fn flip(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}

impl CancellationSignal for FlipOnDemand {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// A cancellation signal that reports not-cancelled for its first `threshold`
/// observations and cancelled afterward. Because the orchestrator observes
/// this signal at a fixed, known sequence of stage-boundary checks, tuning
/// `threshold` deterministically pinpoints exactly which boundary check
/// first observes cancellation, without relying on timing.
struct CancelAfterNCalls {
    threshold: usize,
    observed: AtomicUsize,
}

impl CancelAfterNCalls {
    fn new(threshold: usize) -> Self {
        Self {
            threshold,
            observed: AtomicUsize::new(0),
        }
    }

    fn observed(&self) -> usize {
        self.observed.load(Ordering::SeqCst)
    }
}

impl CancellationSignal for CancelAfterNCalls {
    fn is_cancelled(&self) -> bool {
        let observed = self.observed.fetch_add(1, Ordering::SeqCst);
        observed >= self.threshold
    }
}

/// A fake capacity implementation whose permit tracks active/inactive state
/// and records how many acquisitions were attempted.
struct FakeCapacity {
    active: Mutex<bool>,
    calls: AtomicUsize,
    fail: bool,
    record_context_observation: bool,
    context_observation: Mutex<Option<ContextObservation>>,
}

impl FakeCapacity {
    fn new(fail: bool) -> Self {
        Self {
            active: Mutex::new(false),
            calls: AtomicUsize::new(0),
            fail,
            record_context_observation: false,
            context_observation: Mutex::new(None),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn is_active(&self) -> bool {
        *self.active.lock().unwrap()
    }

    fn take_context_observation(&self) -> ContextObservation {
        self.context_observation.lock().unwrap().take().unwrap()
    }

    fn record_context_observation(&mut self) {
        self.record_context_observation = true;
    }
}

struct FakePermit<'a> {
    active: &'a Mutex<bool>,
}

impl<'a> SynchronizationPermit for FakePermit<'a> {}

impl<'a> Drop for FakePermit<'a> {
    fn drop(&mut self) {
        *self.active.lock().unwrap() = false;
    }
}

impl SynchronizationCapacity for FakeCapacity {
    fn acquire<'a>(
        &'a self,
        context: &'a SynchronizationContext<'a>,
    ) -> BoxFuture<
        'a,
        Result<Box<dyn SynchronizationPermit + Send + 'a>, SynchronizationCapacityError>,
    > {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.record_context_observation {
                *self.context_observation.lock().unwrap() = Some(ContextObservation {
                    deadline: context.deadline(),
                    cancelled_at_call_time: context.cancellation().is_cancelled(),
                });
            }

            if self.fail {
                return Err(SynchronizationCapacityError);
            }

            *self.active.lock().unwrap() = true;

            Ok(Box::new(FakePermit {
                active: &self.active,
            }) as Box<dyn SynchronizationPermit + Send + 'a>)
        })
    }
}

/// A fake Provider recording every input it receives and returning a fixed
/// envelope on success, or a sentinel error.
struct FakeProvider {
    calls: AtomicUsize,
    observation: Mutex<Option<Observation>>,
    envelope_json: &'static str,
    fail: bool,
    flip_before_return: Option<&'static FlipOnDemand>,
    capacity_active_during_call: Option<&'static FakeCapacity>,
}

struct Observation {
    username: String,
    groups: Vec<String>,
    target: String,
    bearer_token: String,
    deadline: Instant,
    cancelled_at_call_time: bool,
}

struct ContextObservation {
    deadline: Instant,
    cancelled_at_call_time: bool,
}

impl FakeProvider {
    fn new(envelope_json: &'static str, fail: bool) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            observation: Mutex::new(None),
            envelope_json,
            fail,
            flip_before_return: None,
            capacity_active_during_call: None,
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl PermissionProvider for FakeProvider {
    fn resolve<'a>(
        &'a self,
        request: PermissionProviderRequest<'a>,
    ) -> BoxFuture<'a, Result<DesiredStateEnvelope, PermissionProviderError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);

            if let Some(capacity) = self.capacity_active_during_call {
                assert!(
                    capacity.is_active(),
                    "capacity permit must be active during Provider work"
                );
            }

            *self.observation.lock().unwrap() = Some(Observation {
                username: request.identity().username().to_owned(),
                groups: request.identity().groups().to_vec(),
                target: request.target().as_str().to_owned(),
                bearer_token: request.technical_caller_bearer_token().as_str().to_owned(),
                deadline: request.context().deadline(),
                cancelled_at_call_time: request.context().cancellation().is_cancelled(),
            });

            if let Some(flip) = self.flip_before_return {
                flip.flip();
            }

            if self.fail {
                return Err(PermissionProviderError::new(SentinelError(
                    "sentinel provider failure",
                )));
            }

            Ok(DesiredStateEnvelope::new(
                EnvelopeVersion::new(7),
                OpaquePayload::try_from(self.envelope_json.to_owned()).unwrap(),
            ))
        })
    }
}

/// A fake Adapter recording the envelope it receives and returning a fixed
/// outcome, or a sentinel error.
///
/// Because the adapter is moved into the router as a boxed trait object,
/// tests that must inspect its recorded state after `synchronize` returns
/// supply `'static` external observation cells up front.
struct FakeAdapter {
    calls: AtomicUsize,
    received_version: Mutex<Option<u64>>,
    received_payload: Mutex<Option<String>>,
    received_username: Mutex<Option<String>>,
    received_groups: Mutex<Option<Vec<String>>>,
    outcome: ReconciliationOutcome,
    fail: bool,
    flip_before_return: Option<&'static FlipOnDemand>,
    capacity_active_during_call: Option<&'static FakeCapacity>,
    external_calls: Option<&'static AtomicUsize>,
    external_version: Option<&'static Mutex<Option<u64>>>,
    external_payload: Option<&'static Mutex<Option<String>>>,
    external_context_observation: Option<&'static Mutex<Option<ContextObservation>>>,
    external_username: Option<&'static Mutex<Option<String>>>,
    external_groups: Option<&'static Mutex<Option<Vec<String>>>>,
}

impl FakeAdapter {
    fn new(outcome: ReconciliationOutcome, fail: bool) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            received_version: Mutex::new(None),
            received_payload: Mutex::new(None),
            received_username: Mutex::new(None),
            received_groups: Mutex::new(None),
            outcome,
            fail,
            flip_before_return: None,
            capacity_active_during_call: None,
            external_calls: None,
            external_version: None,
            external_payload: None,
            external_context_observation: None,
            external_username: None,
            external_groups: None,
        }
    }
}

impl TargetAdapter for FakeAdapter {
    fn reconcile<'a>(
        &'a self,
        request: TargetAdapterRequest<'a>,
    ) -> BoxFuture<'a, Result<ReconciliationOutcome, TargetAdapterError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(external_calls) = self.external_calls {
                external_calls.fetch_add(1, Ordering::SeqCst);
            }

            if let Some(capacity) = self.capacity_active_during_call {
                assert!(
                    capacity.is_active(),
                    "capacity permit must be active during Adapter work"
                );
            }

            let version = request.desired_state().version().get();
            let payload = request.desired_state().payload().as_json().to_owned();
            *self.received_version.lock().unwrap() = Some(version);
            *self.received_payload.lock().unwrap() = Some(payload.clone());
            *self.received_username.lock().unwrap() =
                Some(request.identity().username().to_owned());
            *self.received_groups.lock().unwrap() = Some(request.identity().groups().to_vec());
            if let Some(external_username) = self.external_username {
                *external_username.lock().unwrap() = Some(request.identity().username().to_owned());
            }
            if let Some(external_groups) = self.external_groups {
                *external_groups.lock().unwrap() = Some(request.identity().groups().to_vec());
            }
            if let Some(external_version) = self.external_version {
                *external_version.lock().unwrap() = Some(version);
            }
            if let Some(external_payload) = self.external_payload {
                *external_payload.lock().unwrap() = Some(payload);
            }
            if let Some(external_context_observation) = self.external_context_observation {
                *external_context_observation.lock().unwrap() = Some(ContextObservation {
                    deadline: request.context().deadline(),
                    cancelled_at_call_time: request.context().cancellation().is_cancelled(),
                });
            }

            if let Some(flip) = self.flip_before_return {
                flip.flip();
            }

            if self.fail {
                return Err(TargetAdapterError::new(SentinelError(
                    "sentinel adapter failure",
                )));
            }

            Ok(self.outcome)
        })
    }
}

struct PanicOnReconcile;

impl TargetAdapter for PanicOnReconcile {
    fn reconcile<'a>(
        &'a self,
        _request: TargetAdapterRequest<'a>,
    ) -> BoxFuture<'a, Result<ReconciliationOutcome, TargetAdapterError>> {
        panic!("adapter must not be invoked for this scenario");
    }
}

struct PanicOnResolve;

impl PermissionProvider for PanicOnResolve {
    fn resolve<'a>(
        &'a self,
        _request: PermissionProviderRequest<'a>,
    ) -> BoxFuture<'a, Result<DesiredStateEnvelope, PermissionProviderError>> {
        panic!("provider must not be invoked for this scenario");
    }
}

struct PanicOnAcquire;

impl SynchronizationCapacity for PanicOnAcquire {
    fn acquire<'a>(
        &'a self,
        _context: &'a SynchronizationContext<'a>,
    ) -> BoxFuture<
        'a,
        Result<Box<dyn SynchronizationPermit + Send + 'a>, SynchronizationCapacityError>,
    > {
        panic!("capacity must not be acquired for this scenario");
    }
}

fn one_route_router(
    target: &str,
    identifier: &str,
    adapter: Box<dyn TargetAdapter>,
) -> TargetRouter {
    TargetRouter::new(
        vec![TargetRoute::new(
            logical_target(target),
            adapter_identifier(identifier),
        )],
        vec![AdapterRegistration::new(
            adapter_identifier(identifier),
            adapter,
        )],
    )
    .unwrap()
}

fn identity(username: &str, groups: &[&str]) -> IdentityContext {
    IdentityContext::new(
        username.to_owned(),
        groups.iter().map(|group| (*group).to_owned()).collect(),
    )
}

/// 15.1 Successful Changed path.
#[test]
fn successful_changed_path_invokes_every_stage_exactly_once() {
    let external_calls: &'static AtomicUsize = Box::leak(Box::new(AtomicUsize::new(0)));
    let mut adapter = FakeAdapter::new(ReconciliationOutcome::Changed, false);
    adapter.external_calls = Some(external_calls);
    let router = one_route_router("target-a", "adapter-a", Box::new(adapter));
    let provider = FakeProvider::new("{\"role\":\"operator\"}", false);
    let capacity = FakeCapacity::new(false);

    let target = logical_target("target-a");
    let ident = identity("jdoe", &["/staff"]);
    let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(not_deadline(), &cancellation);
    let request = SelectedTargetSynchronizationRequest::new(&ident, &target, &bearer, context);

    let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
    let outcome = poll_ready(synchronizer.synchronize(request)).unwrap();

    assert_eq!(outcome, ReconciliationOutcome::Changed);
    assert_eq!(capacity.calls(), 1);
    assert_eq!(provider.calls(), 1);
    assert_eq!(external_calls.load(Ordering::SeqCst), 1);
    assert!(!capacity.is_active());
}

/// Separate identical caller submissions are independent attempts, not retries
/// or deduplicated work.
#[test]
fn separate_identical_submissions_are_independent_attempts_not_retries() {
    let external_calls: &'static AtomicUsize = Box::leak(Box::new(AtomicUsize::new(0)));
    let mut adapter = FakeAdapter::new(ReconciliationOutcome::Changed, false);
    adapter.external_calls = Some(external_calls);
    let router = one_route_router("target-a", "adapter-a", Box::new(adapter));
    let provider = FakeProvider::new("null", false);
    let capacity = FakeCapacity::new(false);

    let target = logical_target("target-a");
    let ident = identity("jdoe", &["/staff"]);
    let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
    let cancellation = NeverCancelled;
    let deadline = not_deadline();
    let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);

    let first_request = SelectedTargetSynchronizationRequest::new(
        &ident,
        &target,
        &bearer,
        SynchronizationContext::new(deadline, &cancellation),
    );
    let first_outcome = poll_ready(synchronizer.synchronize(first_request)).unwrap();

    let second_request = SelectedTargetSynchronizationRequest::new(
        &ident,
        &target,
        &bearer,
        SynchronizationContext::new(deadline, &cancellation),
    );
    let second_outcome = poll_ready(synchronizer.synchronize(second_request)).unwrap();

    assert_eq!(first_outcome, ReconciliationOutcome::Changed);
    assert_eq!(second_outcome, ReconciliationOutcome::Changed);
    assert_eq!(capacity.calls(), 2);
    assert_eq!(provider.calls(), 2);
    assert_eq!(external_calls.load(Ordering::SeqCst), 2);
}

/// The original synchronization context is propagated unchanged to capacity,
/// Provider, and Adapter work.
#[test]
fn successful_path_propagates_the_same_context_to_every_stage() {
    let adapter_context: &'static Mutex<Option<ContextObservation>> =
        Box::leak(Box::new(Mutex::new(None)));
    let mut adapter = FakeAdapter::new(ReconciliationOutcome::Changed, false);
    adapter.external_context_observation = Some(adapter_context);
    let router = one_route_router("target-a", "adapter-a", Box::new(adapter));
    let provider = FakeProvider::new("null", false);
    let mut capacity = FakeCapacity::new(false);
    capacity.record_context_observation();

    let target = logical_target("target-a");
    let ident = identity("jdoe", &[]);
    let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
    let cancellation = NeverCancelled;
    let deadline = Instant::now() + Duration::from_secs(12_345) + Duration::from_nanos(678_901);
    let context = SynchronizationContext::new(deadline, &cancellation);
    let request = SelectedTargetSynchronizationRequest::new(&ident, &target, &bearer, context);

    let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
    let outcome = poll_ready(synchronizer.synchronize(request)).unwrap();

    let capacity_context = capacity.take_context_observation();
    let provider_context = provider.observation.lock().unwrap().take().unwrap();
    let adapter_context = adapter_context.lock().unwrap().take().unwrap();

    assert_eq!(outcome, ReconciliationOutcome::Changed);
    assert_eq!(capacity_context.deadline, deadline);
    assert_eq!(provider_context.deadline, deadline);
    assert_eq!(adapter_context.deadline, deadline);
    assert!(!capacity_context.cancelled_at_call_time);
    assert!(!provider_context.cancelled_at_call_time);
    assert!(!adapter_context.cancelled_at_call_time);
}

/// 15.2 Successful Unchanged path: Adapter alone determines the outcome.
#[test]
fn successful_unchanged_path_returns_exactly_adapter_outcome() {
    let adapter = FakeAdapter::new(ReconciliationOutcome::Unchanged, false);
    let router = one_route_router("target-a", "adapter-a", Box::new(adapter));
    let provider = FakeProvider::new("{\"role\":\"operator\"}", false);
    let capacity = FakeCapacity::new(false);

    let target = logical_target("target-a");
    let ident = identity("jdoe", &["/staff"]);
    let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(not_deadline(), &cancellation);
    let request = SelectedTargetSynchronizationRequest::new(&ident, &target, &bearer, context);

    let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
    let outcome = poll_ready(synchronizer.synchronize(request)).unwrap();

    assert_eq!(outcome, ReconciliationOutcome::Unchanged);
    assert_eq!(provider.calls(), 1);
}

/// 15.16 Adapter outcome is authoritative regardless of Provider payload.
#[test]
fn adapter_alone_decides_changed_vs_unchanged_for_identical_provider_output() {
    for outcome in [
        ReconciliationOutcome::Changed,
        ReconciliationOutcome::Unchanged,
    ] {
        let adapter = FakeAdapter::new(outcome, false);
        let router = one_route_router("target-a", "adapter-a", Box::new(adapter));
        let provider = FakeProvider::new("{\"same\":true}", false);
        let capacity = FakeCapacity::new(false);

        let target = logical_target("target-a");
        let ident = identity("jdoe", &[]);
        let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
        let cancellation = NeverCancelled;
        let context = SynchronizationContext::new(not_deadline(), &cancellation);
        let request = SelectedTargetSynchronizationRequest::new(&ident, &target, &bearer, context);

        let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
        let result = poll_ready(synchronizer.synchronize(request)).unwrap();

        assert_eq!(result, outcome);
    }
}

/// 15.3 Unknown target starts no downstream work.
#[test]
fn unknown_target_starts_no_downstream_work() {
    let router = TargetRouter::new(Vec::new(), Vec::new()).unwrap();
    let provider = PanicOnResolve;
    let capacity = PanicOnAcquire;

    let target = logical_target("target-x");
    let ident = identity("jdoe", &[]);
    let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(not_deadline(), &cancellation);
    let request = SelectedTargetSynchronizationRequest::new(&ident, &target, &bearer, context);

    let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
    let error = poll_ready(synchronizer.synchronize(request)).unwrap_err();

    assert!(matches!(
        error,
        SelectedTargetSynchronizationError::UnknownTarget
    ));
}

/// 15.4 Recognized target with unavailable compiled adapter starts no downstream work.
#[test]
fn recognized_target_with_unavailable_adapter_starts_no_downstream_work() {
    let router = TargetRouter::new(
        vec![TargetRoute::new(
            logical_target("target-b"),
            adapter_identifier("sensitive-adapter-identifier"),
        )],
        Vec::new(),
    )
    .unwrap();
    let provider = PanicOnResolve;
    let capacity = PanicOnAcquire;

    let target = logical_target("target-b");
    let ident = identity("jdoe", &[]);
    let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(not_deadline(), &cancellation);
    let request = SelectedTargetSynchronizationRequest::new(&ident, &target, &bearer, context);

    let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
    let error = poll_ready(synchronizer.synchronize(request)).unwrap_err();

    assert!(matches!(
        error,
        SelectedTargetSynchronizationError::TargetUnavailable
    ));
    for rendered in [error.to_string(), format!("{error:?}")] {
        assert!(!rendered.contains("sensitive-adapter-identifier"));
    }
}

/// 15.5 Capacity failure starts no Provider/Adapter work.
#[test]
fn capacity_failure_starts_no_provider_or_adapter_work() {
    let adapter = PanicOnReconcile;
    let router = one_route_router("target-a", "adapter-a", Box::new(adapter));
    let provider = PanicOnResolve;
    let capacity = FakeCapacity::new(true);

    let target = logical_target("target-a");
    let ident = identity("jdoe", &[]);
    let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(not_deadline(), &cancellation);
    let request = SelectedTargetSynchronizationRequest::new(&ident, &target, &bearer, context);

    let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
    let error = poll_ready(synchronizer.synchronize(request)).unwrap_err();

    assert!(matches!(
        error,
        SelectedTargetSynchronizationError::CapacityUnavailable
    ));
    assert_eq!(capacity.calls(), 1);
}

/// 15.6 Provider failure: capacity acquired once, Adapter never invoked, permit eventually released.
#[test]
fn provider_failure_invokes_no_adapter_and_releases_permit() {
    let adapter = PanicOnReconcile;
    let router = one_route_router("target-a", "adapter-a", Box::new(adapter));
    let provider = FakeProvider::new("null", true);
    let capacity = FakeCapacity::new(false);

    let target = logical_target("target-a");
    let ident = identity("jdoe", &[]);
    let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(not_deadline(), &cancellation);
    let request = SelectedTargetSynchronizationRequest::new(&ident, &target, &bearer, context);

    let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
    let error = poll_ready(synchronizer.synchronize(request)).unwrap_err();

    assert!(matches!(
        error,
        SelectedTargetSynchronizationError::ProviderFailed
    ));
    assert_eq!(capacity.calls(), 1);
    assert_eq!(provider.calls(), 1);
    assert!(
        !capacity.is_active(),
        "permit must be released after Provider failure"
    );
}

/// 15.7 Adapter failure: no retry/rollback; permit remains held during the call
/// and is released only after the Adapter returns.
#[test]
fn adapter_failure_holds_permit_during_call_and_releases_after_return() {
    let capacity_static: &'static FakeCapacity = Box::leak(Box::new(FakeCapacity::new(false)));
    let external_calls: &'static AtomicUsize = Box::leak(Box::new(AtomicUsize::new(0)));

    let mut adapter = FakeAdapter::new(ReconciliationOutcome::Changed, true);
    adapter.capacity_active_during_call = Some(capacity_static);
    adapter.external_calls = Some(external_calls);
    let router = one_route_router("target-a", "adapter-a", Box::new(adapter));

    let mut provider = FakeProvider::new("null", false);
    provider.capacity_active_during_call = Some(capacity_static);
    let provider = provider;

    let target = logical_target("target-a");
    let ident = identity("jdoe", &[]);
    let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(not_deadline(), &cancellation);
    let request = SelectedTargetSynchronizationRequest::new(&ident, &target, &bearer, context);

    let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, capacity_static);
    let error = poll_ready(synchronizer.synchronize(request)).unwrap_err();

    assert!(matches!(
        error,
        SelectedTargetSynchronizationError::AdapterFailed
    ));
    assert_eq!(capacity_static.calls(), 1);
    assert_eq!(provider.calls(), 1);
    assert_eq!(external_calls.load(Ordering::SeqCst), 1);
    assert!(
        !capacity_static.is_active(),
        "permit must be released once the synchronizer returns after Adapter failure"
    );
}

/// 15.8 Exact Provider inputs are preserved without normalization.
#[test]
fn provider_receives_exact_selected_target_inputs() {
    let adapter = FakeAdapter::new(ReconciliationOutcome::Unchanged, false);
    let router = one_route_router("target-a", "adapter-a", Box::new(adapter));
    let provider = FakeProvider::new("null", false);
    let capacity = FakeCapacity::new(false);

    let target = logical_target("target-a");
    let raw_username = "  m\u{00fc}ller\t";
    let groups = ["/staff", "/staff", "/staff/eng\u{00fc}"];
    let ident = identity(raw_username, &groups);
    let raw_bearer = "  raw-token\u{00a0}\t";
    let bearer = TechnicalCallerBearerToken::new(raw_bearer.to_owned());
    let deadline = not_deadline();
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(deadline, &cancellation);
    let request = SelectedTargetSynchronizationRequest::new(&ident, &target, &bearer, context);

    let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
    let _ = poll_ready(synchronizer.synchronize(request));

    let observation = provider.observation.lock().unwrap().take().unwrap();
    assert_eq!(observation.username, raw_username);
    assert_eq!(observation.groups, groups);
    assert_eq!(observation.target, "target-a");
    assert_eq!(observation.bearer_token, raw_bearer);
    assert_eq!(observation.deadline, deadline);
    assert!(!observation.cancelled_at_call_time);
}

/// The selected Target Adapter receives the same synchronized identity as the
/// Permission Provider, independently of the opaque desired-state payload, and
/// Core never injects identity into that payload.
#[test]
fn adapter_receives_the_same_identity_as_provider_independent_of_payload() {
    let external_username: &'static Mutex<Option<String>> = Box::leak(Box::new(Mutex::new(None)));
    let external_groups: &'static Mutex<Option<Vec<String>>> =
        Box::leak(Box::new(Mutex::new(None)));
    let external_payload: &'static Mutex<Option<String>> = Box::leak(Box::new(Mutex::new(None)));

    let mut adapter = FakeAdapter::new(ReconciliationOutcome::Unchanged, false);
    adapter.external_username = Some(external_username);
    adapter.external_groups = Some(external_groups);
    adapter.external_payload = Some(external_payload);
    let router = one_route_router("target-a", "adapter-a", Box::new(adapter));
    let distinctive_payload = "{\"roles\":[\"operator\"]}";
    let provider = FakeProvider::new(distinctive_payload, false);
    let capacity = FakeCapacity::new(false);

    let target = logical_target("target-a");
    let raw_username = "  m\u{00fc}ller\t";
    let groups = ["/staff", "/staff", "/staff/eng\u{00fc}"];
    let ident = identity(raw_username, &groups);
    let raw_bearer = "raw-token";
    let bearer = TechnicalCallerBearerToken::new(raw_bearer.to_owned());
    let deadline = not_deadline();
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(deadline, &cancellation);
    let request = SelectedTargetSynchronizationRequest::new(&ident, &target, &bearer, context);

    let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
    let outcome = poll_ready(synchronizer.synchronize(request)).unwrap();
    assert_eq!(outcome, ReconciliationOutcome::Unchanged);

    let provider_observation = provider.observation.lock().unwrap().take().unwrap();
    assert_eq!(provider_observation.username, raw_username);
    assert_eq!(provider_observation.groups, groups);

    // The Adapter received the identical identity independently of the
    // opaque payload, and Core did not inject the username into it.
    assert_eq!(
        external_username.lock().unwrap().as_deref(),
        Some(raw_username)
    );
    assert_eq!(
        external_groups.lock().unwrap().as_deref(),
        Some(groups.map(str::to_owned).as_slice())
    );
    assert_eq!(
        external_payload.lock().unwrap().as_deref(),
        Some(distinctive_payload)
    );
    assert!(
        !external_payload
            .lock()
            .unwrap()
            .as_deref()
            .unwrap()
            .contains("ller"),
        "Core must not inject username into the opaque desired-state payload"
    );
}

/// 15.9 Exact envelope forwarding: version and payload are preserved unchanged.
#[test]
fn envelope_is_forwarded_to_adapter_without_interpretation() {
    let distinctive_payload = "{\"sentinel\":[1,2,3],\"nested\":{\"k\":\"v\"}}";
    let external_calls: &'static AtomicUsize = Box::leak(Box::new(AtomicUsize::new(0)));
    let external_version: &'static Mutex<Option<u64>> = Box::leak(Box::new(Mutex::new(None)));
    let external_payload: &'static Mutex<Option<String>> = Box::leak(Box::new(Mutex::new(None)));

    let mut adapter = FakeAdapter::new(ReconciliationOutcome::Changed, false);
    adapter.external_calls = Some(external_calls);
    adapter.external_version = Some(external_version);
    adapter.external_payload = Some(external_payload);
    let router = one_route_router("target-a", "adapter-a", Box::new(adapter));
    let provider = FakeProvider::new(distinctive_payload, false);
    let capacity = FakeCapacity::new(false);

    let target = logical_target("target-a");
    let ident = identity("jdoe", &[]);
    let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(not_deadline(), &cancellation);
    let request = SelectedTargetSynchronizationRequest::new(&ident, &target, &bearer, context);

    let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
    let outcome = poll_ready(synchronizer.synchronize(request)).unwrap();

    assert_eq!(outcome, ReconciliationOutcome::Changed);
    assert_eq!(external_calls.load(Ordering::SeqCst), 1);
    assert_eq!(*external_version.lock().unwrap(), Some(7));
    assert_eq!(
        external_payload.lock().unwrap().as_deref(),
        Some(distinctive_payload)
    );
}

/// 15.11 Pre-cancelled context starts no work.
#[test]
fn pre_cancelled_context_starts_no_work() {
    let adapter = PanicOnReconcile;
    let router = one_route_router("target-a", "adapter-a", Box::new(adapter));
    let provider = PanicOnResolve;
    let capacity = PanicOnAcquire;

    let target = logical_target("target-a");
    let ident = identity("jdoe", &[]);
    let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
    let cancellation = AlreadyCancelled;
    let context = SynchronizationContext::new(not_deadline(), &cancellation);
    let request = SelectedTargetSynchronizationRequest::new(&ident, &target, &bearer, context);

    let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
    let error = poll_ready(synchronizer.synchronize(request)).unwrap_err();

    assert!(matches!(
        error,
        SelectedTargetSynchronizationError::Cancelled
    ));
}

/// 15.12 Already-expired deadline starts no work.
#[test]
fn already_expired_deadline_starts_no_work() {
    let adapter = PanicOnReconcile;
    let router = one_route_router("target-a", "adapter-a", Box::new(adapter));
    let provider = PanicOnResolve;
    let capacity = PanicOnAcquire;

    let target = logical_target("target-a");
    let ident = identity("jdoe", &[]);
    let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(expired_deadline(), &cancellation);
    let request = SelectedTargetSynchronizationRequest::new(&ident, &target, &bearer, context);

    let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
    let error = poll_ready(synchronizer.synchronize(request)).unwrap_err();

    assert!(matches!(
        error,
        SelectedTargetSynchronizationError::Cancelled
    ));
}

/// 15.13 Cancellation between Provider and Adapter prevents Adapter invocation.
#[test]
fn cancellation_between_provider_and_adapter_prevents_adapter_call() {
    let flip: &'static FlipOnDemand = Box::leak(Box::new(FlipOnDemand::new()));
    let adapter = PanicOnReconcile;
    let router = one_route_router("target-a", "adapter-a", Box::new(adapter));
    let mut provider = FakeProvider::new("null", false);
    provider.flip_before_return = Some(flip);
    let capacity = FakeCapacity::new(false);

    let target = logical_target("target-a");
    let ident = identity("jdoe", &[]);
    let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
    let context = SynchronizationContext::new(not_deadline(), flip);
    let request = SelectedTargetSynchronizationRequest::new(&ident, &target, &bearer, context);

    let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
    let error = poll_ready(synchronizer.synchronize(request)).unwrap_err();

    assert!(matches!(
        error,
        SelectedTargetSynchronizationError::Cancelled
    ));
    assert_eq!(provider.calls(), 1);
    assert!(
        !capacity.is_active(),
        "permit must be released after the cancelled return"
    );
}

/// 15.14 Cancellation observed after a successful Adapter return still fails
/// the overall selected-target result (no rollback; failure represents the
/// normal uncertainty allowed by the at-most-once contract).
#[test]
fn cancellation_after_successful_adapter_return_fails_overall_result() {
    let flip: &'static FlipOnDemand = Box::leak(Box::new(FlipOnDemand::new()));
    let capacity_static: &'static FakeCapacity = Box::leak(Box::new(FakeCapacity::new(false)));
    let mut adapter = FakeAdapter::new(ReconciliationOutcome::Changed, false);
    adapter.flip_before_return = Some(flip);
    adapter.capacity_active_during_call = Some(capacity_static);
    let router = one_route_router("target-a", "adapter-a", Box::new(adapter));
    let provider = FakeProvider::new("null", false);

    let target = logical_target("target-a");
    let ident = identity("jdoe", &[]);
    let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
    let context = SynchronizationContext::new(not_deadline(), flip);
    let request = SelectedTargetSynchronizationRequest::new(&ident, &target, &bearer, context);

    let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, capacity_static);
    let error = poll_ready(synchronizer.synchronize(request)).unwrap_err();

    assert!(matches!(
        error,
        SelectedTargetSynchronizationError::Cancelled
    ));
    assert_eq!(capacity_static.calls(), 1);
    assert_eq!(provider.calls(), 1);
    assert!(
        !capacity_static.is_active(),
        "permit must be released once the synchronizer returns after cancellation"
    );
}

/// Capacity errors retain no potentially sensitive source details.
#[test]
fn synchronization_capacity_error_has_fixed_safe_representations() {
    let error = SynchronizationCapacityError;

    assert_eq!(
        error.to_string(),
        "synchronization capacity acquisition failed"
    );
    assert_eq!(format!("{error:?}"), "SynchronizationCapacityError");
    assert!((&error as &dyn Error).source().is_none());
}

/// 15.15 No sensitive error leakage through Display, Debug, or Error::source.
#[test]
fn errors_do_not_leak_sensitive_downstream_details() {
    let adapter = FakeAdapter::new(ReconciliationOutcome::Changed, true);
    let router = one_route_router("target-a", "adapter-a", Box::new(adapter));
    let provider = FakeProvider::new("{\"sentinel-payload\":\"sentinel-payload-value\"}", false);
    let capacity = FakeCapacity::new(false);

    let target = logical_target("target-a");
    let ident = identity("sentinel-username", &["sentinel-group"]);
    let bearer = TechnicalCallerBearerToken::new("sentinel-bearer-token".to_owned());
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(not_deadline(), &cancellation);
    let request = SelectedTargetSynchronizationRequest::new(&ident, &target, &bearer, context);

    let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
    let error = poll_ready(synchronizer.synchronize(request)).unwrap_err();

    assert!(matches!(
        error,
        SelectedTargetSynchronizationError::AdapterFailed
    ));

    let sentinel_values = [
        "sentinel-username",
        "sentinel-group",
        "sentinel-bearer-token",
        "sentinel-payload",
        "sentinel-payload-value",
        "sentinel adapter failure",
        "sentinel provider failure",
        "sentinel capacity failure",
        "target-a",
        "adapter-a",
    ];

    let rendered_display = error.to_string();
    let rendered_debug = format!("{error:?}");
    let rendered_source = (&error as &dyn Error)
        .source()
        .map(|source| source.to_string())
        .unwrap_or_default();

    for sentinel in sentinel_values {
        assert!(
            !rendered_display.contains(sentinel),
            "display leaked {sentinel:?}"
        );
        assert!(
            !rendered_debug.contains(sentinel),
            "debug leaked {sentinel:?}"
        );
        assert!(
            !rendered_source.contains(sentinel),
            "source leaked {sentinel:?}"
        );
    }
    assert!((&error as &dyn Error).source().is_none());
}

/// 15.10 (companion) Unknown target never marks capacity as active.
#[test]
fn unknown_target_never_activates_capacity() {
    let router = TargetRouter::new(Vec::new(), Vec::new()).unwrap();
    let provider = PanicOnResolve;
    let capacity = FakeCapacity::new(false);

    let target = logical_target("target-x");
    let ident = identity("jdoe", &[]);
    let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(not_deadline(), &cancellation);
    let request = SelectedTargetSynchronizationRequest::new(&ident, &target, &bearer, context);

    let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
    let _ = poll_ready(synchronizer.synchronize(request));

    assert_eq!(capacity.calls(), 0);
    assert!(!capacity.is_active());
}

/// Proves the routing-to-capacity boundary re-check: cancellation observed
/// only after routing succeeds still starts no capacity/Provider/Adapter
/// work.
#[test]
fn cancellation_observed_after_routing_starts_no_capacity_work() {
    let adapter = PanicOnReconcile;
    let router = one_route_router("target-a", "adapter-a", Box::new(adapter));
    let provider = PanicOnResolve;
    let capacity = PanicOnAcquire;

    let target = logical_target("target-a");
    let ident = identity("jdoe", &[]);
    let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
    // The first check (before routing) observes not-cancelled; the second
    // check (before capacity, immediately after routing) observes cancelled.
    let cancellation = CancelAfterNCalls::new(1);
    let context = SynchronizationContext::new(not_deadline(), &cancellation);
    let request = SelectedTargetSynchronizationRequest::new(&ident, &target, &bearer, context);

    let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
    let error = poll_ready(synchronizer.synchronize(request)).unwrap_err();

    assert!(matches!(
        error,
        SelectedTargetSynchronizationError::Cancelled
    ));
    assert_eq!(cancellation.observed(), 2);
}

/// Proves the capacity-to-Provider boundary re-check: cancellation observed
/// only after capacity is acquired still starts no Provider/Adapter work,
/// and the permit is released.
#[test]
fn cancellation_observed_after_capacity_starts_no_provider_work() {
    let adapter = PanicOnReconcile;
    let router = one_route_router("target-a", "adapter-a", Box::new(adapter));
    let provider = PanicOnResolve;
    let capacity = FakeCapacity::new(false);

    let target = logical_target("target-a");
    let ident = identity("jdoe", &[]);
    let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
    // Check 1 (before routing) and check 2 (before capacity) observe
    // not-cancelled; check 3 (before Provider, after capacity is acquired)
    // observes cancelled.
    let cancellation = CancelAfterNCalls::new(2);
    let context = SynchronizationContext::new(not_deadline(), &cancellation);
    let request = SelectedTargetSynchronizationRequest::new(&ident, &target, &bearer, context);

    let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
    let error = poll_ready(synchronizer.synchronize(request)).unwrap_err();

    assert!(matches!(
        error,
        SelectedTargetSynchronizationError::Cancelled
    ));
    assert_eq!(cancellation.observed(), 3);
    assert_eq!(capacity.calls(), 1);
    assert!(
        !capacity.is_active(),
        "permit must be released after the cancelled return"
    );
}

/// A Target Adapter whose reconciliation future is genuinely suspended
/// (`Poll::Pending`) on its first poll and completes only on a later poll,
/// without any sleep, timer, or executor. This proves the capacity permit
/// remains held while Adapter work is actually in progress, not merely
/// during an immediately-ready call.
struct PendingOnceAdapter {
    outcome: ReconciliationOutcome,
    capacity: &'static FakeCapacity,
    dropped: Option<&'static AtomicBool>,
}

struct PendingOnceFuture<'a> {
    polls: usize,
    outcome: ReconciliationOutcome,
    capacity: &'a FakeCapacity,
    dropped: Option<&'static AtomicBool>,
}

impl Drop for PendingOnceFuture<'_> {
    fn drop(&mut self) {
        if let Some(dropped) = self.dropped {
            dropped.store(true, Ordering::SeqCst);
        }
    }
}

impl<'a> Future for PendingOnceFuture<'a> {
    type Output = Result<ReconciliationOutcome, TargetAdapterError>;

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.polls += 1;

        if self.polls == 1 {
            assert!(
                self.capacity.is_active(),
                "capacity permit must be active while Adapter work is pending"
            );
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        assert!(
            self.capacity.is_active(),
            "capacity permit must still be active on Adapter completion"
        );

        Poll::Ready(Ok(self.outcome))
    }
}

impl TargetAdapter for PendingOnceAdapter {
    fn reconcile<'a>(
        &'a self,
        _request: TargetAdapterRequest<'a>,
    ) -> BoxFuture<'a, Result<ReconciliationOutcome, TargetAdapterError>> {
        Box::pin(PendingOnceFuture {
            polls: 0,
            outcome: self.outcome,
            capacity: self.capacity,
            dropped: self.dropped,
        })
    }
}

/// 15.10 Capacity permit lifetime across a genuinely suspended Adapter
/// future: the permit remains active while the top-level synchronization
/// future itself returns `Poll::Pending`, and is released only once it
/// resolves to `Poll::Ready`.
#[test]
fn capacity_permit_remains_active_while_adapter_future_is_pending() {
    let capacity_static: &'static FakeCapacity = Box::leak(Box::new(FakeCapacity::new(false)));
    let adapter = PendingOnceAdapter {
        outcome: ReconciliationOutcome::Changed,
        capacity: capacity_static,
        dropped: None,
    };
    let router = one_route_router("target-a", "adapter-a", Box::new(adapter));
    let provider = FakeProvider::new("null", false);

    let target = logical_target("target-a");
    let ident = identity("jdoe", &[]);
    let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(not_deadline(), &cancellation);
    let request = SelectedTargetSynchronizationRequest::new(&ident, &target, &bearer, context);

    let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, capacity_static);
    let mut future = Box::pin(synchronizer.synchronize(request));
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    match future.as_mut().poll(&mut cx) {
        Poll::Pending => {
            assert!(
                capacity_static.is_active(),
                "permit must remain active while the Adapter future is suspended"
            );
        }
        Poll::Ready(_) => panic!("first poll unexpectedly completed immediately"),
    }

    let outcome = match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output.unwrap(),
        Poll::Pending => panic!("second poll unexpectedly remained pending"),
    };

    assert_eq!(outcome, ReconciliationOutcome::Changed);
    assert!(
        !capacity_static.is_active(),
        "permit must be released once the synchronization future resolves"
    );
}

/// Dropping a suspended parent synchronization future drops its live Adapter
/// future and releases the held capacity permit.
#[test]
fn dropping_pending_synchronization_drops_adapter_future_and_releases_capacity() {
    let capacity_static: &'static FakeCapacity = Box::leak(Box::new(FakeCapacity::new(false)));
    let adapter_dropped: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
    let adapter = PendingOnceAdapter {
        outcome: ReconciliationOutcome::Changed,
        capacity: capacity_static,
        dropped: Some(adapter_dropped),
    };
    let router = one_route_router("target-a", "adapter-a", Box::new(adapter));
    let provider = FakeProvider::new("null", false);

    let target = logical_target("target-a");
    let ident = identity("jdoe", &[]);
    let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(not_deadline(), &cancellation);
    let request = SelectedTargetSynchronizationRequest::new(&ident, &target, &bearer, context);

    let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, capacity_static);
    let mut future = Box::pin(synchronizer.synchronize(request));
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
    assert!(capacity_static.is_active());

    drop(future);

    assert!(adapter_dropped.load(Ordering::SeqCst));
    assert!(!capacity_static.is_active());
}
