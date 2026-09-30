//! The executable HTTP contract: outcome statuses, ADR 0001 precedence, the
//! fixed body bound, header multiplicity, and the operational endpoints.
//!
//! Requests go through the real Axum router with no socket involved, so the
//! transport adapter, the bounded body collection, and the existing inbound
//! boundary are all exercised together.

use std::{num::NonZeroUsize, time::Duration};

use axum::{
    body::Body,
    http::{Request, StatusCode, header::CONTENT_TYPE},
};
use permissionsync_inbound_http::HttpOutcome;

use crate::runtime::{
    tests::support::{
        GLPI, HttpsFixture, RefusingEndpoint, RuntimeFixture, RuntimeFixtureOptions,
        ScriptedResponse, SigningMaterial, authenticator, body_bytes, body_of_length,
        glpi_configuration, jwks_fixture, provider_configuration, target, unavailable_jwks_fixture,
        valid_body,
    },
    transport::{HEALTH_ROUTE, INBOUND_BODY_LIMIT_BYTES, METRICS_ROUTE, SYNCHRONIZATION_ROUTE},
};

/// A GLPI endpoint that is configured and locally valid, which is all that is
/// needed for a route to resolve: GLPI construction performs no remote I/O.
const UNREACHABLE_GLPI: &str = "https://127.0.0.1:1/apirest.php";

/// A Provider endpoint that is configured and locally valid.
const UNREACHABLE_PROVIDER: &str = "https://127.0.0.1:1/permissions";

struct Scenario {
    jwks: HttpsFixture,
    signing: SigningMaterial,
    fixture: RuntimeFixture,
}

impl Scenario {
    async fn build(options: impl FnOnce(&mut RuntimeFixtureOptions)) -> Self {
        Self::assemble(options, true).await
    }

    /// Builds a scenario whose metadata source answers `500` instead of a JWKS.
    async fn with_unavailable_verifier(options: impl FnOnce(&mut RuntimeFixtureOptions)) -> Self {
        Self::assemble(options, false).await
    }

    async fn assemble(
        options: impl FnOnce(&mut RuntimeFixtureOptions),
        metadata_available: bool,
    ) -> Self {
        let signing = SigningMaterial::new("runtime-test-key");
        let jwks = if metadata_available {
            jwks_fixture(&signing, 4).await
        } else {
            unavailable_jwks_fixture(4).await
        };
        let mut fixture_options = RuntimeFixtureOptions::default();
        options(&mut fixture_options);
        let fixture = RuntimeFixture::new(
            authenticator(jwks.endpoint("/keys"), jwks.trust_anchor_pem().to_vec()),
            fixture_options,
        );

        Self {
            jwks,
            signing,
            fixture,
        }
    }

    fn token(&self, scope: Option<&str>) -> String {
        self.signing.token(scope)
    }

    async fn finish(self) {
        self.jwks.shutdown().await;
    }
}

// ---------------------------------------------------------------------------
// Targetless requests
// ---------------------------------------------------------------------------

/// A valid targetless request must complete as a successful no-op without
/// touching target routing, selected-target capacity, the Provider, or GLPI.
#[tokio::test]
async fn a_valid_targetless_request_is_a_successful_no_op_without_selected_target_work() {
    let provider = HttpsFixture::start(Vec::new()).await;
    let scenario = Scenario::build(|options| {
        options.provider = Some(provider_configuration(
            &provider.endpoint("/permissions"),
            vec![provider.trust_anchor_pem().to_vec()],
        ));
        options.glpi = Some(glpi_configuration(UNREACHABLE_GLPI));
        options.targets = vec![target("glpi", GLPI)];
        options.synchronization_capacity = NonZeroUsize::new(3).unwrap();
    })
    .await;
    let token = scenario.token(Some("service_account"));

    let response = scenario
        .fixture
        .call(
            Request::builder()
                .method("POST")
                .uri(SYNCHRONIZATION_ROUTE)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(valid_body()))
                .unwrap(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(body_bytes(response).await.is_empty());
    assert_eq!(
        scenario.fixture.state.capacity().available_permits(),
        3,
        "a targetless request must not acquire selected-target capacity"
    );
    assert_eq!(
        provider.request_count(),
        0,
        "a targetless request must not invoke the Provider"
    );

    provider.shutdown().await;
    scenario.finish().await;
}

/// Absent and empty scopes, and scopes with no exact PermissionSync token, are
/// all targetless.
#[tokio::test]
async fn every_zero_token_scope_shape_is_targetless() {
    let scenario = Scenario::build(|_| {}).await;

    for scope in [
        None,
        Some(""),
        Some("service_account"),
        Some("Permissionsync:glpi"),
        Some("xpermissionsync:glpi permissionsyncx:glpi"),
    ] {
        let token = scenario.token(scope);
        assert_eq!(
            scenario
                .fixture
                .synchronize(Some(&token), Body::from(valid_body()))
                .await,
            StatusCode::NO_CONTENT,
            "{scope:?} must be targetless"
        );
    }

    scenario.finish().await;
}

// ---------------------------------------------------------------------------
// Client-side outcomes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_malformed_normal_size_body_is_a_bad_request() {
    let scenario = Scenario::build(|_| {}).await;
    let token = scenario.token(Some("service_account"));

    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&token), Body::from("{"))
            .await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        scenario
            .fixture
            .synchronize(
                Some(&token),
                Body::from(r#"{"event_type":"LOGIN","username":"u","groups":[],"extra":true}"#)
            )
            .await,
        StatusCode::BAD_REQUEST
    );

    scenario.finish().await;
}

#[tokio::test]
async fn an_unknown_logical_target_is_a_bad_request() {
    let scenario = Scenario::build(|options| {
        options.glpi = Some(glpi_configuration(UNREACHABLE_GLPI));
        options.targets = vec![target("glpi", GLPI)];
    })
    .await;
    let token = scenario.token(Some("permissionsync:absent-target"));

    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&token), Body::from(valid_body()))
            .await,
        StatusCode::BAD_REQUEST
    );

    scenario.finish().await;
}

#[tokio::test]
async fn a_missing_or_malformed_credential_is_unauthorized() {
    let scenario = Scenario::build(|_| {}).await;

    assert_eq!(
        scenario
            .fixture
            .synchronize(None, Body::from(valid_body()))
            .await,
        StatusCode::UNAUTHORIZED
    );
    for credential in ["Basic secret", "Bearer", "Bearer  ", "Bearer not.a.jwt!"] {
        let response = scenario
            .fixture
            .call(
                Request::builder()
                    .method("POST")
                    .uri(SYNCHRONIZATION_ROUTE)
                    .header("authorization", credential)
                    .body(Body::from(valid_body()))
                    .unwrap(),
            )
            .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{credential} must be rejected"
        );
    }

    scenario.finish().await;
}

/// Axum must not reduce duplicate credentials to one value: the inbound
/// boundary has to see the ambiguity and reject it.
#[tokio::test]
async fn duplicate_authorization_fields_are_rejected_through_the_transport() {
    let scenario = Scenario::build(|_| {}).await;
    let token = scenario.token(Some("service_account"));

    let response = scenario
        .fixture
        .call(
            Request::builder()
                .method("POST")
                .uri(SYNCHRONIZATION_ROUTE)
                .header("authorization", format!("Bearer {token}"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(valid_body()))
                .unwrap(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        scenario.jwks.request_count(),
        0,
        "an ambiguous credential must be rejected before any metadata retrieval"
    );

    scenario.finish().await;
}

#[tokio::test]
async fn more_than_one_permissionsync_scope_is_forbidden() {
    let scenario = Scenario::build(|options| {
        options.glpi = Some(glpi_configuration(UNREACHABLE_GLPI));
        options.targets = vec![target("glpi", GLPI)];
    })
    .await;

    for scope in [
        "permissionsync:glpi permissionsync:other",
        "permissionsync:glpi permissionsync:glpi",
        // Exactly one token with a grammar-invalid suffix is also forbidden.
        "permissionsync:",
        "permissionsync:-invalid",
    ] {
        let token = scenario.token(Some(scope));
        assert_eq!(
            scenario
                .fixture
                .synchronize(Some(&token), Body::from(valid_body()))
                .await,
            StatusCode::FORBIDDEN,
            "{scope} must be forbidden"
        );
    }

    scenario.finish().await;
}

// ---------------------------------------------------------------------------
// Server-side outcomes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_unavailable_verifier_is_a_server_side_failure() {
    let scenario = Scenario::with_unavailable_verifier(|_| {}).await;
    let token = scenario.token(Some("service_account"));

    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&token), Body::from(valid_body()))
            .await,
        StatusCode::INTERNAL_SERVER_ERROR
    );

    scenario.finish().await;
}

#[tokio::test]
async fn a_recognized_target_with_an_unavailable_adapter_is_a_server_side_failure() {
    let scenario = Scenario::build(|options| {
        // A configured route with no GLPI section: recognized, unavailable.
        options.targets = vec![target("glpi", GLPI)];
    })
    .await;
    let token = scenario.token(Some("permissionsync:glpi"));

    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&token), Body::from(valid_body()))
            .await,
        StatusCode::INTERNAL_SERVER_ERROR
    );

    scenario.finish().await;
}

#[tokio::test]
async fn an_unavailable_provider_is_a_server_side_failure_after_target_resolution() {
    let scenario = Scenario::build(|options| {
        options.glpi = Some(glpi_configuration(UNREACHABLE_GLPI));
        options.targets = vec![target("glpi", GLPI)];
        options.synchronization_capacity = NonZeroUsize::new(2).unwrap();
    })
    .await;
    let token = scenario.token(Some("permissionsync:glpi"));

    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&token), Body::from(valid_body()))
            .await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        scenario.fixture.state.capacity().available_permits(),
        2,
        "an unavailable Provider must fail before capacity is acquired"
    );

    scenario.finish().await;
}

/// Capacity is acquired for selected-target work and is independent of inbound
/// admission.
#[tokio::test]
async fn exhausted_selected_target_capacity_is_a_server_side_failure() {
    let scenario = Scenario::build(|options| {
        options.provider = Some(provider_configuration(UNREACHABLE_PROVIDER, Vec::new()));
        options.glpi = Some(glpi_configuration(UNREACHABLE_GLPI));
        options.targets = vec![target("glpi", GLPI)];
        options.synchronization_capacity = NonZeroUsize::new(1).unwrap();
        options.overall_request_deadline = Duration::from_millis(200);
    })
    .await;
    let token = scenario.token(Some("permissionsync:glpi"));

    // Hold the only permit for the duration of the request.
    let cancellation = NeverCancelled;
    let held_context = permissionsync_core::SynchronizationContext::new(
        std::time::Instant::now() + Duration::from_secs(60),
        &cancellation,
    );
    let held = permissionsync_orchestration::SynchronizationCapacity::acquire(
        scenario.fixture.state.capacity(),
        &held_context,
    )
    .await
    .expect("the test holds the only permit");
    assert_eq!(scenario.fixture.state.capacity().available_permits(), 0);

    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&token), Body::from(valid_body()))
            .await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        scenario.fixture.state.admission().available_permits(),
        scenario.fixture.state.admission().limit().get(),
        "inbound admission is released independently of selected-target capacity"
    );

    drop(held);
    assert_eq!(scenario.fixture.state.capacity().available_permits(), 1);
    scenario.finish().await;
}

struct NeverCancelled;
impl permissionsync_core::CancellationSignal for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

#[tokio::test]
async fn a_failing_provider_call_is_a_server_side_failure() {
    let refusing = RefusingEndpoint::start().await;
    let scenario = Scenario::build(|options| {
        options.provider = Some(provider_configuration(
            &refusing.endpoint("/permissions"),
            Vec::new(),
        ));
        options.glpi = Some(glpi_configuration(UNREACHABLE_GLPI));
        options.targets = vec![target("glpi", GLPI)];
        options.synchronization_capacity = NonZeroUsize::new(2).unwrap();
    })
    .await;
    let token = scenario.token(Some("permissionsync:glpi"));

    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&token), Body::from(valid_body()))
            .await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        scenario.fixture.state.capacity().available_permits(),
        2,
        "capacity is released after a Provider failure"
    );

    scenario.finish().await;
}

/// The whole selected-target chain runs through the executable: the Provider is
/// really called over local TLS, and the GLPI adapter then rejects the envelope
/// before making any GLPI request.
#[tokio::test]
async fn an_adapter_failure_after_a_successful_provider_call_is_a_server_side_failure() {
    let provider = HttpsFixture::start(vec![ScriptedResponse::json(
        200,
        br#"{"version":2,"payload":null}"#.to_vec(),
    )])
    .await;
    let scenario = Scenario::build(|options| {
        options.provider = Some(provider_configuration(
            &provider.endpoint("/permissions"),
            vec![provider.trust_anchor_pem().to_vec()],
        ));
        // Unreachable GLPI is fine: an unsupported envelope version fails
        // before any GLPI request starts.
        options.glpi = Some(glpi_configuration(UNREACHABLE_GLPI));
        options.targets = vec![target("glpi", GLPI)];
        options.synchronization_capacity = NonZeroUsize::new(2).unwrap();
    })
    .await;
    let token = scenario.token(Some("permissionsync:glpi"));

    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&token), Body::from(valid_body()))
            .await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        provider.request_count(),
        1,
        "exactly one Provider attempt, with no retry"
    );
    assert_eq!(
        scenario.fixture.state.capacity().available_permits(),
        2,
        "capacity is released after an Adapter failure"
    );

    provider.shutdown().await;
    scenario.finish().await;
}

/// An already-expired budget terminates through the existing server-side
/// deadline semantics, with no new caller-facing status.
#[tokio::test]
async fn an_expired_overall_deadline_is_a_server_side_failure() {
    let scenario = Scenario::build(|options| {
        options.overall_request_deadline = Duration::ZERO;
    })
    .await;
    let token = scenario.token(Some("service_account"));

    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&token), Body::from(valid_body()))
            .await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        scenario.jwks.request_count(),
        0,
        "an expired request must not reach authentication metadata retrieval"
    );

    scenario.finish().await;
}

// ---------------------------------------------------------------------------
// The fixed body bound and ADR 0001 precedence
// ---------------------------------------------------------------------------

/// Exactly the fixed bound is collected and validated normally.
#[tokio::test]
async fn a_body_of_exactly_the_fixed_bound_is_collected_and_validated() {
    let scenario = Scenario::build(|_| {}).await;
    let token = scenario.token(Some("service_account"));
    let body = body_of_length(INBOUND_BODY_LIMIT_BYTES);
    assert_eq!(body.len(), INBOUND_BODY_LIMIT_BYTES);

    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&token), Body::from(body))
            .await,
        StatusCode::NO_CONTENT,
        "a body of exactly the bound is permitted and validates normally"
    );

    scenario.finish().await;
}

#[tokio::test]
async fn a_body_one_byte_over_the_fixed_bound_is_a_body_validation_failure() {
    let scenario = Scenario::build(|_| {}).await;
    let token = scenario.token(Some("service_account"));

    assert_eq!(
        scenario
            .fixture
            .synchronize(
                Some(&token),
                Body::from(body_of_length(INBOUND_BODY_LIMIT_BYTES + 1))
            )
            .await,
        StatusCode::BAD_REQUEST
    );

    scenario.finish().await;
}

/// The oversized-body precedence matrix. Authentication and complete scope
/// processing resolve first and keep their outcomes; only a request that
/// reaches body validation sees `400`.
#[tokio::test]
async fn oversized_bodies_preserve_the_fixed_processing_order() {
    let scenario = Scenario::build(|options| {
        options.glpi = Some(glpi_configuration(UNREACHABLE_GLPI));
        options.targets = vec![target("glpi", GLPI)];
    })
    .await;
    let oversized = || Body::from(body_of_length(INBOUND_BODY_LIMIT_BYTES * 2));

    // An invalid credential with an oversized body is still 401.
    let response = scenario
        .fixture
        .call(
            Request::builder()
                .method("POST")
                .uri(SYNCHRONIZATION_ROUTE)
                .header("authorization", "Basic secret")
                .body(oversized())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // More than one PermissionSync scope with an oversized body is still 403.
    let ambiguous = scenario.token(Some("permissionsync:glpi permissionsync:other"));
    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&ambiguous), oversized())
            .await,
        StatusCode::FORBIDDEN
    );

    // Otherwise valid earlier stages with an oversized body are 400.
    let targetless = scenario.token(Some("service_account"));
    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&targetless), oversized())
            .await,
        StatusCode::BAD_REQUEST
    );
    let selected = scenario.token(Some("permissionsync:glpi"));
    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&selected), oversized())
            .await,
        StatusCode::BAD_REQUEST,
        "an oversized body is rejected before selected-target work"
    );

    scenario.finish().await;
}

/// The bound applies to what actually arrives, not to a declared length: a
/// misleading `Content-Length` cannot raise or lower it.
#[tokio::test]
async fn the_body_bound_does_not_depend_on_a_declared_content_length() {
    let scenario = Scenario::build(|_| {}).await;
    let token = scenario.token(Some("service_account"));

    // An understated length with an oversized body is still rejected.
    let response = scenario
        .fixture
        .call(
            Request::builder()
                .method("POST")
                .uri(SYNCHRONIZATION_ROUTE)
                .header("authorization", format!("Bearer {token}"))
                .header("content-length", "10")
                .body(Body::from(body_of_length(INBOUND_BODY_LIMIT_BYTES + 1)))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // An overstated length with a small valid body still succeeds.
    let response = scenario
        .fixture
        .call(
            Request::builder()
                .method("POST")
                .uri(SYNCHRONIZATION_ROUTE)
                .header("authorization", format!("Bearer {token}"))
                .header("content-length", "99999999")
                .body(Body::from(valid_body()))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    scenario.finish().await;
}

// ---------------------------------------------------------------------------
// Response shape and operational endpoints
// ---------------------------------------------------------------------------

/// Every outcome status in the contract is reachable from the transport, and
/// none of them carries a response body.
#[test]
fn the_contract_statuses_are_exactly_the_existing_outcome_mapping() {
    for (outcome, status) in [
        (HttpOutcome::Changed, 200),
        (HttpOutcome::TargetlessNoop, 204),
        (HttpOutcome::Unchanged, 204),
        (HttpOutcome::InvalidRequest, 400),
        (HttpOutcome::UnknownTarget, 400),
        (HttpOutcome::AuthenticationRejected, 401),
        (HttpOutcome::AuthorizationForbidden, 403),
        (HttpOutcome::VerifierUnavailable, 500),
        (HttpOutcome::CancelledOrExpired, 500),
        (HttpOutcome::TargetUnavailable, 500),
        (HttpOutcome::CapacityUnavailable, 500),
        (HttpOutcome::ProviderFailed, 500),
        (HttpOutcome::AdapterFailed, 500),
    ] {
        assert_eq!(outcome.status_code(), status);
        assert!(
            StatusCode::from_u16(outcome.status_code()).is_ok(),
            "the transport must be able to emit {status}"
        );
    }
}

#[tokio::test]
async fn synchronization_responses_never_carry_a_body() {
    let scenario = Scenario::build(|_| {}).await;
    let valid = scenario.token(Some("service_account"));
    let ambiguous = scenario.token(Some("permissionsync:a permissionsync:b"));

    for (bearer, body, expected) in [
        (Some(valid.as_str()), valid_body(), StatusCode::NO_CONTENT),
        (Some(valid.as_str()), b"{".to_vec(), StatusCode::BAD_REQUEST),
        (None, valid_body(), StatusCode::UNAUTHORIZED),
        (
            Some(ambiguous.as_str()),
            valid_body(),
            StatusCode::FORBIDDEN,
        ),
    ] {
        let mut request = Request::builder().method("POST").uri(SYNCHRONIZATION_ROUTE);
        if let Some(bearer) = bearer {
            request = request.header("authorization", format!("Bearer {bearer}"));
        }
        let response = scenario
            .fixture
            .call(request.body(Body::from(body)).unwrap())
            .await;

        assert_eq!(response.status(), expected);
        assert!(
            body_bytes(response).await.is_empty(),
            "the synchronization contract has an empty response body"
        );
    }

    scenario.finish().await;
}

#[tokio::test]
async fn health_reports_a_functioning_process_without_any_downstream_dependency() {
    // No Provider, no GLPI, and an unavailable metadata source.
    let scenario = Scenario::with_unavailable_verifier(|_| {}).await;

    let response = scenario.fixture.get(HEALTH_ROUTE).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        scenario.jwks.request_count(),
        0,
        "health must not consult the authentication metadata source"
    );

    scenario.finish().await;
}

#[tokio::test]
async fn metrics_are_exposed_in_the_prometheus_text_format() {
    let scenario = Scenario::build(|_| {}).await;

    let response = scenario.fixture.get(METRICS_ROUTE).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/plain; version=0.0.4; charset=utf-8")
    );

    scenario.finish().await;
}

#[tokio::test]
async fn unsupported_routes_and_methods_keep_normal_framework_behavior() {
    let scenario = Scenario::build(|_| {}).await;

    let unknown = scenario.fixture.get("/status").await;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

    let wrong_method = scenario.fixture.get(SYNCHRONIZATION_ROUTE).await;
    assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);

    scenario.finish().await;
}

/// The operational endpoints must not disclose configuration, credentials, or
/// internal detail.
#[tokio::test]
async fn operational_endpoints_disclose_nothing_sensitive() {
    let provider = HttpsFixture::start(Vec::new()).await;
    let scenario = Scenario::build(|options| {
        options.provider = Some(provider_configuration(
            &provider.endpoint("/permissions"),
            vec![provider.trust_anchor_pem().to_vec()],
        ));
        options.glpi = Some(glpi_configuration(UNREACHABLE_GLPI));
        options.targets = vec![target("glpi", GLPI)];
    })
    .await;

    let mut disclosed = String::new();
    for route in [HEALTH_ROUTE, METRICS_ROUTE] {
        let response = scenario.fixture.get(route).await;
        disclosed.push_str(&String::from_utf8_lossy(&body_bytes(response).await));
    }

    for sensitive in [
        "sentinel-app-token",
        "sentinel-user-token",
        provider.base_uri(),
        UNREACHABLE_GLPI,
        scenario.jwks.base_uri(),
        "BEGIN CERTIFICATE",
        "issuer.test",
    ] {
        assert!(
            !disclosed.contains(sensitive),
            "operational endpoints leaked {sensitive}"
        );
    }

    provider.shutdown().await;
    scenario.finish().await;
}
