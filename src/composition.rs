//! Deterministic construction of the configured PermissionSync application.

use std::{error::Error, fmt};

use permissionsync_adapter_glpi::GlpiAdapter;
use permissionsync_core::{LogicalTarget, PermissionProvider, TargetAdapter};
use permissionsync_orchestration::{SelectedTargetSynchronizer, SynchronizationCapacity};
use permissionsync_provider_generic_rest::GenericRestPermissionProvider;
use permissionsync_routing::{
    AdapterIdentifier, AdapterRegistration, TargetResolutionError, TargetRoute, TargetRouter,
};

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
                    Box::new(adapter),
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
                    Ok(provider) => ProviderState::Usable(Box::new(provider)),
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
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Poll, Waker},
        time::{Duration, Instant},
    };

    use permissionsync_adapter_glpi::{
        GlpiAdapterConfig, GlpiAppToken, GlpiAuthenticationSource, GlpiUserToken,
    };
    use permissionsync_core::{
        CancellationSignal, IdentityContext, LogicalTarget, SynchronizationContext, TargetAdapter,
        TechnicalCallerBearerToken,
    };
    use permissionsync_orchestration::{
        SelectedTargetSynchronizationError, SynchronizationCapacity, SynchronizationCapacityError,
        SynchronizationPermit,
    };
    use permissionsync_provider_generic_rest::GenericRestPermissionProviderConfig;

    use super::{
        ComposedApplication, CompositionError, GLPI_ADAPTER_IDENTIFIER, ProviderAvailability,
        TargetAvailability,
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
