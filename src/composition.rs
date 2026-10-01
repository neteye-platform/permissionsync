//! Deterministic construction of the configured PermissionSync application.

use std::{error::Error, fmt, time::Instant};

use metrics::{counter, histogram};
use permissionsync_adapter_glpi::GlpiAdapter;
use permissionsync_core::{
    BoxFuture, DesiredStateEnvelope, LogicalTarget, PermissionProvider, PermissionProviderError,
    PermissionProviderRequest, ReconciliationOutcome, TargetAdapter, TargetAdapterError,
    TargetAdapterRequest,
};
use permissionsync_orchestration::{SelectedTargetSynchronizer, SynchronizationCapacity};
use permissionsync_provider_generic_rest::GenericRestPermissionProvider;
use permissionsync_routing::{
    AdapterIdentifier, AdapterRegistration, TargetResolutionError, TargetRoute, TargetRouter,
};
use tracing::{Instrument, field::Empty, info_span};

use crate::configuration::{ProviderConfiguration, RuntimeConfiguration};

/// The stable exact adapter identifier for the GLPI adapter.
pub const GLPI_ADAPTER_IDENTIFIER: &str = "glpi";

/// The composed process-wide application state.
pub struct ComposedApplication {
    provider: ProviderState,
    router: TargetRouter,
}

enum ProviderState {
    Usable(Box<dyn PermissionProvider>),
    Unavailable,
}

/// The current availability of the configured Permission Provider.
pub enum ProviderAvailability<'a> {
    /// A locally usable Provider instance.
    Usable(&'a dyn PermissionProvider),
    /// Provider configuration is absent or could not produce a usable instance.
    Unavailable,
}

/// The current availability of one configured logical target.
pub enum TargetAvailability<'a> {
    /// A locally usable Target Adapter instance.
    Usable(&'a dyn TargetAdapter),
    /// The target is configured but its selected adapter is unavailable.
    Unavailable,
    /// No configured route recognizes the logical target.
    Unknown,
}

/// A safe, non-diagnostic error for globally invalid application composition.
///
/// Composition inputs can include sensitive trust material, credentials, and
/// configured identifiers, so this type intentionally retains neither those
/// details nor an error source. It reports only that static configuration was
/// globally unusable, such as a configured logical target outside the ADR 0001
/// grammar, a duplicate configured logical target, or a routing construction
/// state the current application cannot use.
pub struct CompositionError {
    _private: (),
}

impl CompositionError {
    /// Creates a non-diagnostic invalid-composition category.
    const fn new() -> Self {
        Self { _private: () }
    }
}

impl ComposedApplication {
    /// Composes the application deterministically from semantic runtime configuration.
    pub fn compose(configuration: RuntimeConfiguration) -> Result<Self, CompositionError> {
        let routes = configuration
            .targets
            .into_iter()
            .map(|target| {
                let logical_target = LogicalTarget::try_from(target.logical_target)
                    .map_err(|_| CompositionError::new())?;
                Ok(TargetRoute::new(
                    logical_target,
                    AdapterIdentifier::new(target.adapter_identifier),
                ))
            })
            .collect::<Result<Vec<_>, CompositionError>>()?;

        let registrations = match configuration.glpi {
            Some(configuration) => match GlpiAdapter::new(configuration) {
                Ok(adapter) => vec![AdapterRegistration::new(
                    AdapterIdentifier::new(GLPI_ADAPTER_IDENTIFIER.to_owned()),
                    Box::new(InstrumentedAdapter::new(Box::new(adapter))),
                )],
                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        };

        let router =
            TargetRouter::new(routes, registrations).map_err(|_| CompositionError::new())?;

        let provider = match configuration.provider {
            Some(ProviderConfiguration::GenericRest(configuration)) => {
                match GenericRestPermissionProvider::new(configuration) {
                    Ok(provider) => ProviderState::Usable(Box::new(InstrumentedProvider::new(
                        Box::new(provider),
                    ))),
                    Err(_) => ProviderState::Unavailable,
                }
            }
            None => ProviderState::Unavailable,
        };

        Ok(Self { provider, router })
    }

    /// Returns the local availability of the process-wide Permission Provider.
    pub fn provider(&self) -> ProviderAvailability<'_> {
        match &self.provider {
            ProviderState::Usable(provider) => ProviderAvailability::Usable(provider.as_ref()),
            ProviderState::Unavailable => ProviderAvailability::Unavailable,
        }
    }

    /// Resolves a validated logical target to its current availability.
    pub fn resolve_target(&self, target: &LogicalTarget) -> TargetAvailability<'_> {
        match self.router.resolve(target) {
            Ok(adapter) => TargetAvailability::Usable(adapter),
            Err(TargetResolutionError::UnknownLogicalTarget) => TargetAvailability::Unknown,
            Err(TargetResolutionError::UnavailableAdapter { .. }) => {
                TargetAvailability::Unavailable
            }
        }
    }

    /// Returns the underlying target router for selected-target orchestration wiring.
    pub fn router(&self) -> &TargetRouter {
        &self.router
    }

    /// Wires the composed runtime state into selected-target orchestration.
    ///
    /// Provider unavailability is represented explicitly and yields a
    /// server-side selected-target failure at request time, after target
    /// resolution.
    pub fn selected_target_synchronizer<'a>(
        &'a self,
        capacity: &'a dyn SynchronizationCapacity,
    ) -> SelectedTargetSynchronizer<'a> {
        let provider = match &self.provider {
            ProviderState::Usable(provider) => Some(provider.as_ref()),
            ProviderState::Unavailable => None,
        };

        SelectedTargetSynchronizer::new(&self.router, provider, capacity)
    }
}

/// Prometheus metric names for Provider and Adapter evidence.
///
/// Composition is the one place that owns construction and wiring, so it is
/// also where ADR 0006's required Provider and Adapter outcome and latency
/// evidence is captured. Instrumentation wraps the constructed instances
/// transparently: it performs exactly one inner call per invocation, preserves
/// ordering, adds no retry, and exposes no new public API.
const PROVIDER_OPERATIONS_TOTAL: &str = "permissionsync_provider_operations_total";
const PROVIDER_DURATION_SECONDS: &str = "permissionsync_provider_duration_seconds";
const ADAPTER_RECONCILIATIONS_TOTAL: &str = "permissionsync_adapter_reconciliations_total";
const ADAPTER_DURATION_SECONDS: &str = "permissionsync_adapter_duration_seconds";

/// The only metric label key these series use.
const OUTCOME_LABEL: &str = "outcome";

/// The closed Provider outcome categories.
const PROVIDER_SUCCESS: &str = "success";
const PROVIDER_FAILURE: &str = "failure";

/// The closed Adapter outcome categories.
const ADAPTER_CHANGED: &str = "changed";
const ADAPTER_UNCHANGED: &str = "unchanged";
const ADAPTER_FAILURE: &str = "failure";

/// A Permission Provider that records bounded outcome and latency evidence.
///
/// It records nothing derived from identity, groups, the bearer credential, the
/// endpoint, the desired-state payload, or an error message.
struct InstrumentedProvider {
    inner: Box<dyn PermissionProvider>,
}

impl InstrumentedProvider {
    fn new(inner: Box<dyn PermissionProvider>) -> Self {
        Self { inner }
    }
}

impl PermissionProvider for InstrumentedProvider {
    fn resolve<'a>(
        &'a self,
        request: PermissionProviderRequest<'a>,
    ) -> BoxFuture<'a, Result<DesiredStateEnvelope, PermissionProviderError>> {
        Box::pin(async move {
            let span = info_span!("permissionsync.provider", outcome = Empty);
            let started = Instant::now();
            let result = self.inner.resolve(request).instrument(span.clone()).await;
            let outcome = if result.is_ok() {
                PROVIDER_SUCCESS
            } else {
                PROVIDER_FAILURE
            };

            span.record(OUTCOME_LABEL, outcome);
            counter!(PROVIDER_OPERATIONS_TOTAL, OUTCOME_LABEL => outcome).increment(1);
            histogram!(PROVIDER_DURATION_SECONDS).record(started.elapsed().as_secs_f64());

            result
        })
    }
}

/// A Target Adapter that records bounded outcome and latency evidence.
///
/// The Adapter remains the sole authority for `changed` versus `unchanged`;
/// this only observes which one it reported.
struct InstrumentedAdapter {
    inner: Box<dyn TargetAdapter>,
}

impl InstrumentedAdapter {
    fn new(inner: Box<dyn TargetAdapter>) -> Self {
        Self { inner }
    }
}

impl TargetAdapter for InstrumentedAdapter {
    fn reconcile<'a>(
        &'a self,
        request: TargetAdapterRequest<'a>,
    ) -> BoxFuture<'a, Result<ReconciliationOutcome, TargetAdapterError>> {
        Box::pin(async move {
            let span = info_span!("permissionsync.adapter", outcome = Empty);
            let started = Instant::now();
            let result = self.inner.reconcile(request).instrument(span.clone()).await;
            let outcome = match result {
                Ok(ReconciliationOutcome::Changed) => ADAPTER_CHANGED,
                Ok(ReconciliationOutcome::Unchanged) => ADAPTER_UNCHANGED,
                Err(_) => ADAPTER_FAILURE,
            };

            span.record(OUTCOME_LABEL, outcome);
            counter!(ADAPTER_RECONCILIATIONS_TOTAL, OUTCOME_LABEL => outcome).increment(1);
            histogram!(ADAPTER_DURATION_SECONDS).record(started.elapsed().as_secs_f64());

            result
        })
    }
}

impl fmt::Debug for CompositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompositionError")
    }
}

impl fmt::Display for CompositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid application composition configuration")
    }
}

impl Error for CompositionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        future::Future,
        ptr,
        sync::Arc,
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Poll, Waker},
        time::{Duration, Instant},
    };

    use permissionsync_adapter_glpi::{
        GlpiAdapterConfig, GlpiAppToken, GlpiAuthenticationSource, GlpiUserToken,
    };
    use permissionsync_core::{
        CancellationSignal, IdentityContext, LogicalTarget, PermissionProvider,
        ReconciliationOutcome, SynchronizationContext, TargetAdapter, TechnicalCallerBearerToken,
    };
    use permissionsync_orchestration::{
        SelectedTargetSynchronizationError, SynchronizationCapacity, SynchronizationCapacityError,
        SynchronizationPermit,
    };
    use permissionsync_provider_generic_rest::GenericRestPermissionProviderConfig;

    use super::{
        ComposedApplication, CompositionError, GLPI_ADAPTER_IDENTIFIER, InstrumentedAdapter,
        InstrumentedProvider, ProviderAvailability, TargetAvailability,
    };
    use crate::configuration::{ConfiguredTarget, ProviderConfiguration, RuntimeConfiguration};

    fn glpi_configuration() -> GlpiAdapterConfig {
        GlpiAdapterConfig {
            endpoint: "https://glpi.example.test/apirest.php".to_owned(),
            app_token: GlpiAppToken::new("app-token".to_owned()),
            user_token: GlpiUserToken::new("user-token".to_owned()),
            operation_timeout: Duration::from_secs(5),
            additional_trust_anchors_pem: Vec::new(),
            authentication_source: GlpiAuthenticationSource::Default,
        }
    }

    fn provider_configuration() -> GenericRestPermissionProviderConfig {
        GenericRestPermissionProviderConfig {
            endpoint: "https://127.0.0.1/permissions".to_owned(),
            operation_timeout: Duration::from_secs(5),
            additional_trust_anchors_pem: Vec::new(),
        }
    }

    fn target(logical_target: &str, adapter_identifier: &str) -> ConfiguredTarget {
        ConfiguredTarget {
            logical_target: logical_target.to_owned(),
            adapter_identifier: adapter_identifier.to_owned(),
        }
    }

    fn logical_target(value: &str) -> LogicalTarget {
        LogicalTarget::try_from(value.to_owned()).unwrap()
    }

    fn configuration(
        provider: Option<ProviderConfiguration>,
        glpi: Option<GlpiAdapterConfig>,
        targets: Vec<ConfiguredTarget>,
    ) -> RuntimeConfiguration {
        RuntimeConfiguration {
            provider,
            glpi,
            targets,
        }
    }

    fn poll_ready<F: Future>(future: F) -> F::Output {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = Box::pin(future);

        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("test future unexpectedly returned Poll::Pending"),
        }
    }

    struct NeverCancelled;

    impl CancellationSignal for NeverCancelled {
        fn is_cancelled(&self) -> bool {
            false
        }
    }

    struct PanicOnAcquire;

    impl SynchronizationCapacity for PanicOnAcquire {
        fn acquire<'a>(
            &'a self,
            _context: &'a SynchronizationContext<'a>,
        ) -> permissionsync_core::BoxFuture<
            'a,
            Result<Box<dyn SynchronizationPermit + Send + 'a>, SynchronizationCapacityError>,
        > {
            panic!("capacity must not be acquired for this scenario");
        }
    }

    struct FailingCapacity {
        calls: AtomicUsize,
    }

    impl SynchronizationCapacity for FailingCapacity {
        fn acquire<'a>(
            &'a self,
            _context: &'a SynchronizationContext<'a>,
        ) -> permissionsync_core::BoxFuture<
            'a,
            Result<Box<dyn SynchronizationPermit + Send + 'a>, SynchronizationCapacityError>,
        > {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Err(SynchronizationCapacityError)
            })
        }
    }

    #[test]
    fn valid_generic_rest_provider_is_usable_without_remote_invocation() {
        let application = ComposedApplication::compose(configuration(
            Some(ProviderConfiguration::GenericRest(provider_configuration())),
            None,
            Vec::new(),
        ))
        .unwrap();

        assert!(matches!(
            application.provider(),
            ProviderAvailability::Usable(_)
        ));
    }

    #[test]
    fn invalid_provider_configuration_is_unavailable_without_failing_composition() {
        let mut provider = provider_configuration();
        provider.operation_timeout = Duration::ZERO;
        let application = ComposedApplication::compose(configuration(
            Some(ProviderConfiguration::GenericRest(provider)),
            None,
            Vec::new(),
        ))
        .unwrap();

        assert!(matches!(
            application.provider(),
            ProviderAvailability::Unavailable
        ));
    }

    #[test]
    fn absent_provider_configuration_is_unavailable_without_failing_composition() {
        let application =
            ComposedApplication::compose(configuration(None, None, Vec::new())).unwrap();

        assert!(matches!(
            application.provider(),
            ProviderAvailability::Unavailable
        ));
    }

    #[test]
    fn valid_glpi_configuration_makes_a_glpi_target_usable() {
        let application = ComposedApplication::compose(configuration(
            None,
            Some(glpi_configuration()),
            vec![target("target-a", GLPI_ADAPTER_IDENTIFIER)],
        ))
        .unwrap();

        assert!(matches!(
            application.resolve_target(&logical_target("target-a")),
            TargetAvailability::Usable(_)
        ));
    }

    #[test]
    fn glpi_targets_share_the_single_composed_adapter_instance() {
        let application = ComposedApplication::compose(configuration(
            None,
            Some(glpi_configuration()),
            vec![
                target("target-a", GLPI_ADAPTER_IDENTIFIER),
                target("target-b", GLPI_ADAPTER_IDENTIFIER),
            ],
        ))
        .unwrap();

        let TargetAvailability::Usable(first) =
            application.resolve_target(&logical_target("target-a"))
        else {
            panic!("first GLPI target was not usable");
        };
        let TargetAvailability::Usable(second) =
            application.resolve_target(&logical_target("target-b"))
        else {
            panic!("second GLPI target was not usable");
        };

        let first_data = first as *const dyn TargetAdapter as *const ();
        let second_data = second as *const dyn TargetAdapter as *const ();
        assert!(ptr::eq(first_data, second_data));
    }

    #[test]
    fn glpi_route_without_configuration_is_unavailable() {
        let application = ComposedApplication::compose(configuration(
            None,
            None,
            vec![target("target-a", GLPI_ADAPTER_IDENTIFIER)],
        ))
        .unwrap();

        assert!(matches!(
            application.resolve_target(&logical_target("target-a")),
            TargetAvailability::Unavailable
        ));
    }

    #[test]
    fn invalid_glpi_configuration_leaves_glpi_route_unavailable() {
        let mut glpi = glpi_configuration();
        glpi.endpoint = "http://glpi.example.test/apirest.php".to_owned();
        let application = ComposedApplication::compose(configuration(
            None,
            Some(glpi),
            vec![target("target-a", GLPI_ADAPTER_IDENTIFIER)],
        ))
        .unwrap();

        assert!(matches!(
            application.resolve_target(&logical_target("target-a")),
            TargetAvailability::Unavailable
        ));
    }

    #[test]
    fn route_selecting_an_uncompiled_adapter_is_unavailable() {
        let application = ComposedApplication::compose(configuration(
            None,
            None,
            vec![target("target-a", "some-other-adapter")],
        ))
        .unwrap();

        assert!(matches!(
            application.resolve_target(&logical_target("target-a")),
            TargetAvailability::Unavailable
        ));
    }

    #[test]
    fn unconfigured_target_is_unknown() {
        let application = ComposedApplication::compose(configuration(
            None,
            None,
            vec![target("target-a", "some-other-adapter")],
        ))
        .unwrap();

        assert!(matches!(
            application.resolve_target(&logical_target("target-b")),
            TargetAvailability::Unknown
        ));
    }

    #[test]
    fn glpi_identifier_is_exact_and_case_sensitive() {
        let application = ComposedApplication::compose(configuration(
            None,
            Some(glpi_configuration()),
            vec![
                target("target-a", "GLPI"),
                target("target-b", GLPI_ADAPTER_IDENTIFIER),
            ],
        ))
        .unwrap();

        assert!(matches!(
            application.resolve_target(&logical_target("target-a")),
            TargetAvailability::Unavailable
        ));
        assert!(matches!(
            application.resolve_target(&logical_target("target-b")),
            TargetAvailability::Usable(_)
        ));
    }

    #[test]
    fn invalid_logical_targets_fail_composition_without_leaking_values() {
        for invalid_target in ["-bad", "UPPER", ""] {
            let result = ComposedApplication::compose(configuration(
                None,
                None,
                vec![target(invalid_target, "adapter-identifier")],
            ));

            let Err(error) = result else {
                panic!("invalid logical target unexpectedly composed");
            };
            for rendered in [format!("{error:?}"), error.to_string()] {
                if !invalid_target.is_empty() {
                    assert!(!rendered.contains(invalid_target));
                }
            }
        }
    }

    #[test]
    fn duplicate_logical_targets_fail_composition_without_last_write_wins() {
        let result = ComposedApplication::compose(configuration(
            None,
            None,
            vec![
                target("target-a", "adapter-a"),
                target("target-a", "adapter-a"),
            ],
        ));

        assert!(result.is_err());
    }

    #[test]
    fn unavailable_targets_do_not_prevent_targetless_composition() {
        let application = ComposedApplication::compose(configuration(
            None,
            None,
            vec![
                target("target-a", GLPI_ADAPTER_IDENTIFIER),
                target("target-b", "some-other-adapter"),
            ],
        ))
        .unwrap();

        assert!(matches!(
            application.provider(),
            ProviderAvailability::Unavailable
        ));
        assert!(matches!(
            application.resolve_target(&logical_target("target-a")),
            TargetAvailability::Unavailable
        ));
        assert!(matches!(
            application.resolve_target(&logical_target("target-b")),
            TargetAvailability::Unavailable
        ));
    }

    #[test]
    fn unavailable_provider_unknown_target_precedes_capacity() {
        let application = ComposedApplication::compose(configuration(
            None,
            None,
            vec![target("target-b", "some-other-adapter")],
        ))
        .unwrap();
        let capacity = PanicOnAcquire;
        let target = logical_target("target-a");
        let identity = IdentityContext::new("jdoe".to_owned(), Vec::new());
        let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
        let cancellation = NeverCancelled;

        let synchronizer = application.selected_target_synchronizer(&capacity);
        let result = poll_ready(synchronizer.synchronize(
            permissionsync_orchestration::SelectedTargetSynchronizationRequest::new(
                &identity,
                &target,
                &bearer,
                SynchronizationContext::new(
                    Instant::now() + Duration::from_secs(3600),
                    &cancellation,
                ),
            ),
        ));

        assert!(matches!(
            result,
            Err(SelectedTargetSynchronizationError::UnknownTarget)
        ));
    }

    #[test]
    fn unavailable_provider_unavailable_target_precedes_capacity() {
        let application = ComposedApplication::compose(configuration(
            None,
            None,
            vec![target("target-a", "some-other-adapter")],
        ))
        .unwrap();
        let capacity = PanicOnAcquire;
        let target = logical_target("target-a");
        let identity = IdentityContext::new("jdoe".to_owned(), Vec::new());
        let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
        let cancellation = NeverCancelled;

        let synchronizer = application.selected_target_synchronizer(&capacity);
        let result = poll_ready(synchronizer.synchronize(
            permissionsync_orchestration::SelectedTargetSynchronizationRequest::new(
                &identity,
                &target,
                &bearer,
                SynchronizationContext::new(
                    Instant::now() + Duration::from_secs(3600),
                    &cancellation,
                ),
            ),
        ));

        assert!(matches!(
            result,
            Err(SelectedTargetSynchronizationError::TargetUnavailable)
        ));
    }

    #[test]
    fn unavailable_provider_usable_glpi_target_fails_before_capacity() {
        let application = ComposedApplication::compose(configuration(
            None,
            Some(glpi_configuration()),
            vec![target("target-a", GLPI_ADAPTER_IDENTIFIER)],
        ))
        .unwrap();
        let capacity = PanicOnAcquire;
        let target = logical_target("target-a");
        let identity = IdentityContext::new("jdoe".to_owned(), Vec::new());
        let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
        let cancellation = NeverCancelled;

        let synchronizer = application.selected_target_synchronizer(&capacity);
        let result = poll_ready(synchronizer.synchronize(
            permissionsync_orchestration::SelectedTargetSynchronizationRequest::new(
                &identity,
                &target,
                &bearer,
                SynchronizationContext::new(
                    Instant::now() + Duration::from_secs(3600),
                    &cancellation,
                ),
            ),
        ));

        assert!(matches!(
            result,
            Err(SelectedTargetSynchronizationError::ProviderFailed)
        ));
    }

    #[test]
    fn usable_provider_usable_glpi_target_reaches_capacity_before_provider_work() {
        let application = ComposedApplication::compose(configuration(
            Some(ProviderConfiguration::GenericRest(provider_configuration())),
            Some(glpi_configuration()),
            vec![target("target-a", GLPI_ADAPTER_IDENTIFIER)],
        ))
        .unwrap();
        let capacity = FailingCapacity {
            calls: AtomicUsize::new(0),
        };
        let target = logical_target("target-a");
        let identity = IdentityContext::new("jdoe".to_owned(), Vec::new());
        let bearer = TechnicalCallerBearerToken::new("bearer-token".to_owned());
        let cancellation = NeverCancelled;

        let synchronizer = application.selected_target_synchronizer(&capacity);
        let result = poll_ready(synchronizer.synchronize(
            permissionsync_orchestration::SelectedTargetSynchronizationRequest::new(
                &identity,
                &target,
                &bearer,
                SynchronizationContext::new(
                    Instant::now() + Duration::from_secs(3600),
                    &cancellation,
                ),
            ),
        ));

        assert!(matches!(
            result,
            Err(SelectedTargetSynchronizationError::CapacityUnavailable)
        ));
        assert_eq!(capacity.calls.load(Ordering::SeqCst), 1);
    }

    /// Sentinel values that must never reach a metric name, label, or value.
    const SENTINELS: [&str; 6] = [
        "sentinel-username",
        "/sentinel/group/path",
        "sentinel-bearer-token",
        "sentinel-client-id",
        "https://sentinel.example.test/permissions",
        "sentinel-payload-value",
    ];

    struct CountingProvider {
        calls: Arc<AtomicUsize>,
        succeed: bool,
    }

    impl permissionsync_core::PermissionProvider for CountingProvider {
        fn resolve<'a>(
            &'a self,
            request: permissionsync_core::PermissionProviderRequest<'a>,
        ) -> permissionsync_core::BoxFuture<
            'a,
            Result<
                permissionsync_core::DesiredStateEnvelope,
                permissionsync_core::PermissionProviderError,
            >,
        > {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let _ = request.identity().username();
                if self.succeed {
                    Ok(permissionsync_core::DesiredStateEnvelope::new(
                        permissionsync_core::EnvelopeVersion::new(1),
                        permissionsync_core::OpaquePayload::try_from(
                            "{\"permissions\":\"sentinel-payload-value\"}".to_owned(),
                        )
                        .unwrap(),
                    ))
                } else {
                    Err(permissionsync_core::PermissionProviderError::new(
                        SentinelFailure,
                    ))
                }
            })
        }
    }

    struct CountingAdapter {
        calls: Arc<AtomicUsize>,
        result: Option<permissionsync_core::ReconciliationOutcome>,
    }

    impl permissionsync_core::TargetAdapter for CountingAdapter {
        fn reconcile<'a>(
            &'a self,
            request: permissionsync_core::TargetAdapterRequest<'a>,
        ) -> permissionsync_core::BoxFuture<
            'a,
            Result<
                permissionsync_core::ReconciliationOutcome,
                permissionsync_core::TargetAdapterError,
            >,
        > {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let _ = request.desired_state().payload().as_json();
                match self.result {
                    Some(outcome) => Ok(outcome),
                    None => Err(permissionsync_core::TargetAdapterError::new(
                        SentinelFailure,
                    )),
                }
            })
        }
    }

    #[derive(Debug)]
    struct SentinelFailure;

    impl std::fmt::Display for SentinelFailure {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .write_str("sentinel-payload-value at https://sentinel.example.test/permissions")
        }
    }

    impl Error for SentinelFailure {}

    fn sentinel_identity() -> IdentityContext {
        IdentityContext::new(
            "sentinel-username".to_owned(),
            vec!["/sentinel/group/path".to_owned()],
        )
    }

    fn sentinel_bearer() -> TechnicalCallerBearerToken {
        TechnicalCallerBearerToken::new("sentinel-bearer-token".to_owned())
    }

    /// Renders the Prometheus exposition produced while `body` runs, using a
    /// recorder local to this thread so tests never share global state.
    fn rendered<T>(body: impl FnOnce() -> T) -> (T, String) {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let guard = metrics::set_default_local_recorder(&recorder);
        let value = body();
        drop(guard);
        (value, handle.render())
    }

    #[test]
    fn instrumented_provider_records_one_call_and_its_bounded_outcome() {
        for (succeed, expected) in [(true, "success"), (false, "failure")] {
            let calls = Arc::new(AtomicUsize::new(0));
            let instrumented = InstrumentedProvider::new(Box::new(CountingProvider {
                calls: Arc::clone(&calls),
                succeed,
            }));
            let identity = sentinel_identity();
            let target = logical_target("target-a");
            let bearer = sentinel_bearer();
            let cancellation = NeverCancelled;

            let ((), exposition) = rendered(|| {
                let request = permissionsync_core::PermissionProviderRequest::new(
                    &identity,
                    &target,
                    &bearer,
                    SynchronizationContext::new(
                        Instant::now() + Duration::from_secs(3600),
                        &cancellation,
                    ),
                );
                let result = poll_ready(instrumented.resolve(request));
                assert_eq!(result.is_ok(), succeed);
            });

            assert_eq!(calls.load(Ordering::SeqCst), 1, "exactly one Provider call");
            assert!(
                exposition.contains(&format!(
                    "permissionsync_provider_operations_total{{outcome=\"{expected}\"}} 1"
                )),
                "missing provider outcome counter in:\n{exposition}"
            );
            assert!(
                exposition.contains("permissionsync_provider_duration_seconds"),
                "missing provider latency evidence in:\n{exposition}"
            );
            for sentinel in SENTINELS {
                assert!(!exposition.contains(sentinel), "leaked {sentinel}");
            }
        }
    }

    #[test]
    fn instrumented_adapter_records_one_call_and_distinguishes_changed_from_unchanged() {
        for (result, expected) in [
            (Some(ReconciliationOutcome::Changed), "changed"),
            (Some(ReconciliationOutcome::Unchanged), "unchanged"),
            (None, "failure"),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let instrumented = InstrumentedAdapter::new(Box::new(CountingAdapter {
                calls: Arc::clone(&calls),
                result,
            }));
            let identity = sentinel_identity();
            let desired_state = permissionsync_core::DesiredStateEnvelope::new(
                permissionsync_core::EnvelopeVersion::new(1),
                permissionsync_core::OpaquePayload::try_from(
                    "{\"permissions\":\"sentinel-payload-value\"}".to_owned(),
                )
                .unwrap(),
            );
            let cancellation = NeverCancelled;

            let ((), exposition) = rendered(|| {
                let request = permissionsync_core::TargetAdapterRequest::new(
                    &identity,
                    &desired_state,
                    SynchronizationContext::new(
                        Instant::now() + Duration::from_secs(3600),
                        &cancellation,
                    ),
                );
                let outcome = poll_ready(instrumented.reconcile(request));
                assert_eq!(outcome.is_ok(), result.is_some());
            });

            assert_eq!(calls.load(Ordering::SeqCst), 1, "exactly one Adapter call");
            assert!(
                exposition.contains(&format!(
                    "permissionsync_adapter_reconciliations_total{{outcome=\"{expected}\"}} 1"
                )),
                "missing adapter outcome counter in:\n{exposition}"
            );
            assert!(
                exposition.contains("permissionsync_adapter_duration_seconds"),
                "missing adapter latency evidence in:\n{exposition}"
            );
            for sentinel in SENTINELS {
                assert!(!exposition.contains(sentinel), "leaked {sentinel}");
            }
        }
    }

    /// Instrumentation must not change the desired state the Adapter receives
    /// or the outcome the caller sees.
    #[test]
    fn instrumentation_forwards_the_opaque_envelope_and_outcome_unchanged() {
        let instrumented = InstrumentedProvider::new(Box::new(CountingProvider {
            calls: Arc::new(AtomicUsize::new(0)),
            succeed: true,
        }));
        let identity = sentinel_identity();
        let target = logical_target("target-a");
        let bearer = sentinel_bearer();
        let cancellation = NeverCancelled;
        let request = permissionsync_core::PermissionProviderRequest::new(
            &identity,
            &target,
            &bearer,
            SynchronizationContext::new(Instant::now() + Duration::from_secs(3600), &cancellation),
        );

        let envelope = poll_ready(instrumented.resolve(request)).expect("provider succeeds");
        assert_eq!(
            envelope.payload().as_json(),
            "{\"permissions\":\"sentinel-payload-value\"}"
        );
    }

    #[test]
    fn composition_errors_render_only_fixed_safe_text() {
        let supplied_values = [
            "sensitive-target",
            "sensitive-adapter",
            "https://sensitive.example.test/apirest.php",
            "sensitive-app-token",
            "sensitive-user-token",
            "sensitive-certificate",
        ];

        let error = CompositionError::new();

        assert!(error.source().is_none());
        for rendered in [format!("{error:?}"), error.to_string()] {
            for supplied_value in supplied_values {
                assert!(!rendered.contains(supplied_value));
            }
        }
    }
}
