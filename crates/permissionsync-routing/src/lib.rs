//! Deterministic resolution from validated logical targets to compiled adapters.
//!
//! This crate owns no configuration loading, authentication, HTTP transport,
//! Provider work, target context, or adapter reconciliation. It only selects a
//! registered [`TargetAdapter`] for a validated [`LogicalTarget`].

use std::{collections::HashMap, error::Error, fmt};

use permissionsync_core::{LogicalTarget, TargetAdapter};

/// An opaque identifier for one compiled Target Adapter implementation.
///
/// The identifier is preserved exactly as supplied. It has no routing-defined
/// grammar, length limit, normalization, or sanitization.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct AdapterIdentifier(String);

impl AdapterIdentifier {
    /// Creates an opaque adapter identifier without validation or normalization.
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Returns the exact identifier for deliberate inspection or configuration access.
    ///
    /// Callers are responsible for applying ADR 0006 safe-observability controls
    /// before recording this unbounded, unnormalized value in diagnostics.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One configured mapping from a validated logical target to an adapter identifier.
pub struct TargetRoute {
    logical_target: LogicalTarget,
    adapter_identifier: AdapterIdentifier,
}

impl TargetRoute {
    /// Creates one target route from a validated logical target and adapter identifier.
    pub fn new(logical_target: LogicalTarget, adapter_identifier: AdapterIdentifier) -> Self {
        Self {
            logical_target,
            adapter_identifier,
        }
    }
}

/// One compiled Target Adapter implementation registered under an adapter identifier.
pub struct AdapterRegistration {
    adapter_identifier: AdapterIdentifier,
    adapter: Box<dyn TargetAdapter>,
}

impl AdapterRegistration {
    /// Registers an owned, statically linked adapter implementation for construction.
    pub fn new(adapter_identifier: AdapterIdentifier, adapter: Box<dyn TargetAdapter>) -> Self {
        Self {
            adapter_identifier,
            adapter,
        }
    }
}

/// An immutable exact-match router over configured target routes and compiled adapters.
pub struct TargetRouter {
    routes: HashMap<String, AdapterIdentifier>,
    adapters: HashMap<AdapterIdentifier, Box<dyn TargetAdapter>>,
}

impl TargetRouter {
    /// Creates a router after rejecting duplicate route and adapter definitions.
    ///
    /// Every logical target must have exactly one route definition, even when
    /// duplicate definitions currently select the same adapter identifier.
    /// Missing adapter registrations remain target-local resolution failures.
    pub fn new(
        routes: Vec<TargetRoute>,
        registrations: Vec<AdapterRegistration>,
    ) -> Result<Self, TargetRouterBuildError> {
        let mut target_routes = HashMap::with_capacity(routes.len());

        for TargetRoute {
            logical_target,
            adapter_identifier,
        } in routes
        {
            if target_routes.contains_key(logical_target.as_str()) {
                return Err(TargetRouterBuildError::DuplicateLogicalTarget {
                    target: logical_target,
                });
            }

            target_routes.insert(logical_target.as_str().to_owned(), adapter_identifier);
        }

        let mut adapters = HashMap::with_capacity(registrations.len());

        for AdapterRegistration {
            adapter_identifier,
            adapter,
        } in registrations
        {
            if adapters.contains_key(&adapter_identifier) {
                return Err(TargetRouterBuildError::DuplicateAdapterIdentifier {
                    identifier: adapter_identifier,
                });
            }

            adapters.insert(adapter_identifier, adapter);
        }

        Ok(Self {
            routes: target_routes,
            adapters,
        })
    }

    /// Resolves a validated target to its exact compiled adapter without invoking it.
    pub fn resolve(
        &self,
        target: &LogicalTarget,
    ) -> Result<&dyn TargetAdapter, TargetResolutionError> {
        let identifier = self
            .routes
            .get(target.as_str())
            .ok_or(TargetResolutionError::UnknownLogicalTarget)?;

        self.adapters
            .get(identifier)
            .map(|adapter| adapter.as_ref())
            .ok_or_else(|| TargetResolutionError::UnavailableCompiledAdapter {
                identifier: identifier.clone(),
            })
    }
}

/// A global target-routing construction failure.
pub enum TargetRouterBuildError {
    /// More than one route definition used the same logical target.
    DuplicateLogicalTarget {
        /// The repeated logical target definition.
        target: LogicalTarget,
    },
    /// More than one compiled adapter registration used the same identifier.
    DuplicateAdapterIdentifier {
        /// The repeated adapter identifier.
        identifier: AdapterIdentifier,
    },
}

impl fmt::Debug for TargetRouterBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateLogicalTarget { .. } => {
                formatter.write_str("TargetRouterBuildError::DuplicateLogicalTarget")
            }
            Self::DuplicateAdapterIdentifier { .. } => {
                formatter.write_str("TargetRouterBuildError::DuplicateAdapterIdentifier")
            }
        }
    }
}

impl fmt::Display for TargetRouterBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateLogicalTarget { .. } => {
                formatter.write_str("duplicate logical target route")
            }
            Self::DuplicateAdapterIdentifier { .. } => {
                formatter.write_str("duplicate adapter registration")
            }
        }
    }
}

impl Error for TargetRouterBuildError {}

/// A request-time target-routing failure.
pub enum TargetResolutionError {
    /// No configured route matches the supplied logical target.
    UnknownLogicalTarget,
    /// A configured target selects an adapter absent from the compiled registry.
    UnavailableCompiledAdapter {
        /// The configured identifier without a compiled adapter registration.
        identifier: AdapterIdentifier,
    },
}

impl fmt::Debug for TargetResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownLogicalTarget => {
                formatter.write_str("TargetResolutionError::UnknownLogicalTarget")
            }
            Self::UnavailableCompiledAdapter { .. } => {
                formatter.write_str("TargetResolutionError::UnavailableCompiledAdapter")
            }
        }
    }
}

impl fmt::Display for TargetResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownLogicalTarget => formatter.write_str("unknown logical target"),
            Self::UnavailableCompiledAdapter { .. } => {
                formatter.write_str("configured adapter is unavailable")
            }
        }
    }
}

impl Error for TargetResolutionError {}

#[cfg(test)]
mod tests {
    use std::ptr;

    use permissionsync_core::{
        BoxFuture, LogicalTarget, ReconciliationOutcome, TargetAdapter, TargetAdapterError,
        TargetAdapterRequest,
    };

    use super::{
        AdapterIdentifier, AdapterRegistration, TargetResolutionError, TargetRoute, TargetRouter,
        TargetRouterBuildError,
    };

    struct PanicOnReconcile {
        marker: u8,
    }

    impl TargetAdapter for PanicOnReconcile {
        fn reconcile<'a>(
            &'a self,
            _request: TargetAdapterRequest<'a>,
        ) -> BoxFuture<'a, Result<ReconciliationOutcome, TargetAdapterError>> {
            let _ = self.marker;
            panic!("resolution must not invoke target adapter reconciliation");
        }
    }

    fn logical_target(value: &str) -> LogicalTarget {
        LogicalTarget::try_from(value.to_owned()).unwrap()
    }

    fn adapter_identifier(value: &str) -> AdapterIdentifier {
        AdapterIdentifier::new(value.to_owned())
    }

    fn test_adapter(marker: u8) -> Box<dyn TargetAdapter> {
        Box::new(PanicOnReconcile { marker })
    }

    #[test]
    fn resolves_the_exact_registered_adapter_without_reconciliation() {
        let resolved_target = logical_target("target-a");
        let identifier = adapter_identifier("adapter-a");
        let adapter = test_adapter(1);
        let expected = adapter.as_ref() as *const dyn TargetAdapter;
        let router = TargetRouter::new(
            vec![TargetRoute::new(
                logical_target("target-a"),
                identifier.clone(),
            )],
            vec![AdapterRegistration::new(identifier, adapter)],
        )
        .unwrap();

        let resolved = router.resolve(&resolved_target).unwrap();

        assert!(ptr::eq(resolved as *const dyn TargetAdapter, expected));
    }

    #[test]
    fn returns_unknown_target_for_an_empty_route_table() {
        let router = TargetRouter::new(Vec::new(), Vec::new()).unwrap();
        let logical_target = logical_target("target-x");

        let Err(error) = router.resolve(&logical_target) else {
            panic!("unknown target unexpectedly resolved");
        };

        assert!(matches!(error, TargetResolutionError::UnknownLogicalTarget));
    }

    #[test]
    fn returns_an_owned_error_for_a_recognized_target_without_an_adapter() {
        let error = {
            let router = TargetRouter::new(
                vec![TargetRoute::new(
                    logical_target("target-b"),
                    adapter_identifier("adapter-b"),
                )],
                Vec::new(),
            )
            .unwrap();
            let logical_target = logical_target("target-b");

            let Err(error) = router.resolve(&logical_target) else {
                panic!("target without an adapter unexpectedly resolved");
            };

            error
        };

        let TargetResolutionError::UnavailableCompiledAdapter { identifier } = error else {
            panic!("missing adapter returned the wrong error");
        };

        assert_eq!(identifier.as_str(), "adapter-b");
    }

    #[test]
    fn keeps_a_good_target_usable_when_another_target_is_broken() {
        let adapter = test_adapter(1);
        let expected = adapter.as_ref() as *const dyn TargetAdapter;
        let router = TargetRouter::new(
            vec![
                TargetRoute::new(logical_target("target-a"), adapter_identifier("adapter-a")),
                TargetRoute::new(logical_target("target-b"), adapter_identifier("adapter-b")),
            ],
            vec![AdapterRegistration::new(
                adapter_identifier("adapter-a"),
                adapter,
            )],
        )
        .unwrap();
        let broken_target = logical_target("target-b");
        let good_target = logical_target("target-a");

        let Err(error) = router.resolve(&broken_target) else {
            panic!("target without an adapter unexpectedly resolved");
        };

        assert!(matches!(
            error,
            TargetResolutionError::UnavailableCompiledAdapter { .. }
        ));
        assert!(ptr::eq(
            router.resolve(&good_target).unwrap() as *const dyn TargetAdapter,
            expected,
        ));
    }

    #[test]
    fn allows_multiple_logical_targets_to_select_one_adapter() {
        let identifier = adapter_identifier("adapter-a");
        let adapter = test_adapter(1);
        let expected = adapter.as_ref() as *const dyn TargetAdapter;
        let router = TargetRouter::new(
            vec![
                TargetRoute::new(logical_target("target-a"), identifier.clone()),
                TargetRoute::new(logical_target("target-b"), identifier.clone()),
            ],
            vec![AdapterRegistration::new(identifier, adapter)],
        )
        .unwrap();
        let first_target = logical_target("target-a");
        let second_target = logical_target("target-b");

        assert!(ptr::eq(
            router.resolve(&first_target).unwrap() as *const dyn TargetAdapter,
            expected,
        ));
        assert!(ptr::eq(
            router.resolve(&second_target).unwrap() as *const dyn TargetAdapter,
            expected,
        ));
    }

    #[test]
    fn rejects_duplicate_logical_targets_with_different_adapter_identifiers() {
        let result = TargetRouter::new(
            vec![
                TargetRoute::new(logical_target("target-a"), adapter_identifier("adapter-a")),
                TargetRoute::new(logical_target("target-a"), adapter_identifier("adapter-b")),
            ],
            Vec::new(),
        );

        let Err(TargetRouterBuildError::DuplicateLogicalTarget { target }) = result else {
            panic!("duplicate logical target unexpectedly succeeded");
        };

        assert_eq!(target.as_str(), "target-a");
    }

    #[test]
    fn rejects_duplicate_logical_targets_with_identical_adapter_identifiers() {
        let identifier = adapter_identifier("adapter-a");
        let result = TargetRouter::new(
            vec![
                TargetRoute::new(logical_target("target-a"), identifier.clone()),
                TargetRoute::new(logical_target("target-a"), identifier),
            ],
            Vec::new(),
        );

        let Err(TargetRouterBuildError::DuplicateLogicalTarget { target }) = result else {
            panic!("duplicate logical target unexpectedly succeeded");
        };

        assert_eq!(target.as_str(), "target-a");
    }

    #[test]
    fn rejects_duplicate_adapter_registrations() {
        let result = TargetRouter::new(
            Vec::new(),
            vec![
                AdapterRegistration::new(adapter_identifier("adapter-a"), test_adapter(1)),
                AdapterRegistration::new(adapter_identifier("adapter-a"), test_adapter(2)),
            ],
        );

        let Err(TargetRouterBuildError::DuplicateAdapterIdentifier { identifier }) = result else {
            panic!("duplicate adapter registration unexpectedly succeeded");
        };

        assert_eq!(identifier.as_str(), "adapter-a");
    }

    #[test]
    fn does_not_match_target_prefixes_or_suffixes() {
        let router = TargetRouter::new(
            vec![TargetRoute::new(
                logical_target("target-a"),
                adapter_identifier("adapter-a"),
            )],
            vec![AdapterRegistration::new(
                adapter_identifier("adapter-a"),
                test_adapter(1),
            )],
        )
        .unwrap();

        for value in ["target", "target-a-extra"] {
            let logical_target = logical_target(value);

            let Err(error) = router.resolve(&logical_target) else {
                panic!("{value:?} unexpectedly matched a route");
            };

            assert!(matches!(error, TargetResolutionError::UnknownLogicalTarget));
        }
    }

    #[test]
    fn matches_adapter_identifiers_exactly_and_separately_from_targets() {
        let router = TargetRouter::new(
            vec![TargetRoute::new(
                logical_target("logical-target"),
                adapter_identifier("Adapter-A"),
            )],
            vec![AdapterRegistration::new(
                adapter_identifier("adapter-a"),
                test_adapter(1),
            )],
        )
        .unwrap();
        let logical_target = logical_target("logical-target");

        let Err(error) = router.resolve(&logical_target) else {
            panic!("case-different adapter identifier unexpectedly matched");
        };

        let TargetResolutionError::UnavailableCompiledAdapter { identifier } = error else {
            panic!("case-different identifier returned the wrong error");
        };

        assert_eq!(identifier.as_str(), "Adapter-A");
    }

    #[test]
    fn errors_redact_logical_target_and_adapter_identifier_values() {
        let logical_target_value = "sensitive-target";
        let adapter_identifier_value = "sensitive-adapter-identifier";
        let duplicate_route_result = TargetRouter::new(
            vec![
                TargetRoute::new(
                    logical_target(logical_target_value),
                    adapter_identifier("adapter-a"),
                ),
                TargetRoute::new(
                    logical_target(logical_target_value),
                    adapter_identifier("adapter-b"),
                ),
            ],
            Vec::new(),
        );

        let Err(duplicate_route_error) = duplicate_route_result else {
            panic!("duplicate logical target unexpectedly succeeded");
        };

        for rendered in [
            duplicate_route_error.to_string(),
            format!("{duplicate_route_error:?}"),
        ] {
            assert!(!rendered.contains(logical_target_value));
        }

        let router = TargetRouter::new(
            vec![TargetRoute::new(
                logical_target("target-a"),
                adapter_identifier(adapter_identifier_value),
            )],
            Vec::new(),
        )
        .unwrap();
        let logical_target = logical_target("target-a");

        let Err(resolution_error) = router.resolve(&logical_target) else {
            panic!("target without an adapter unexpectedly resolved");
        };

        for rendered in [
            resolution_error.to_string(),
            format!("{resolution_error:?}"),
        ] {
            assert!(!rendered.contains(adapter_identifier_value));
        }
    }

    #[test]
    fn router_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<TargetRouter>();
    }
}
