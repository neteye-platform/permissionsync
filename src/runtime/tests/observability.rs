//! The rendered Prometheus exposition.
//!
//! Every assertion is made against real rendered text produced by a recorder
//! local to the test thread, so tests never interfere with each other through
//! global observability state.

use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use axum::{body::Body, http::Request, http::StatusCode};

use crate::runtime::{
    observability::{
        ADMISSION_ABANDONED_TOTAL, ADMISSION_REFUSED_TOTAL, ADMISSION_SATURATED_TOTAL,
        ADMISSION_WAITERS, CAPACITY_IN_USE, CAPACITY_SATURATED_TOTAL, CAPACITY_UNAVAILABLE_TOTAL,
        COMPONENT_AVAILABLE, READY, REQUEST_DURATION_SECONDS, REQUEST_STAGE_TOTAL,
        REQUESTS_IN_FLIGHT, REQUESTS_TOTAL,
    },
    tests::support::{
        GLPI, HttpsFixture, RuntimeFixture, RuntimeFixtureOptions, SigningMaterial, authenticator,
        glpi_configuration, jwks_fixture, provider_configuration, target, valid_body,
    },
    transport::{METRICS_ROUTE, READINESS_ROUTE, SYNCHRONIZATION_ROUTE, is_transport_refusal},
};

const UNREACHABLE_GLPI: &str = "https://127.0.0.1:1/apirest.php";
const UNREACHABLE_PROVIDER: &str = "https://127.0.0.1:1/permissions";

/// Sentinel values that must never appear anywhere in rendered metrics.
const SENTINELS: [&str; 6] = [
    "sentinel-username",
    "/sentinel/group/path",
    "sentinel-client-id",
    "sentinel-app-token",
    "sentinel-user-token",
    "127.0.0.1",
];

struct Scenario {
    jwks: HttpsFixture,
    signing: SigningMaterial,
    fixture: RuntimeFixture,
}

impl Scenario {
    async fn build(options: impl FnOnce(&mut RuntimeFixtureOptions)) -> Self {
        let signing = SigningMaterial::new("metrics-test-key");
        let jwks = jwks_fixture(&signing, 8).await;
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

    async fn finish(self) {
        self.jwks.shutdown().await;
    }
}

fn assert_contains(exposition: &str, expected: &str) {
    assert!(
        exposition.contains(expected),
        "missing {expected} in rendered metrics:\n{exposition}"
    );
}

fn assert_no_sentinels(exposition: &str) {
    for sentinel in SENTINELS {
        assert!(
            !exposition.contains(sentinel),
            "rendered metrics leaked {sentinel}:\n{exposition}"
        );
    }
}

// ---------------------------------------------------------------------------
// Request outcome evidence
// ---------------------------------------------------------------------------

/// Coarse request outcomes and their stages are counted, end-to-end duration is
/// recorded, and a targetless no-op stays distinguishable from every other
/// outcome.
#[tokio::test]
async fn request_outcomes_stages_and_duration_are_recorded() {
    let scenario = Scenario::build(|options| {
        options.glpi = Some(glpi_configuration(UNREACHABLE_GLPI));
        options.targets = vec![target("glpi", GLPI)];
    })
    .await;
    let guard = scenario.fixture.recorder_guard();

    // Targetless no-op.
    let targetless = scenario.signing.token(Some("service_account"));
    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&targetless), Body::from(valid_body()))
            .await,
        StatusCode::NO_CONTENT
    );
    // A validation failure.
    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&targetless), Body::from("{"))
            .await,
        StatusCode::BAD_REQUEST
    );
    // An authorization failure.
    let ambiguous = scenario
        .signing
        .token(Some("permissionsync:glpi permissionsync:other"));
    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&ambiguous), Body::from(valid_body()))
            .await,
        StatusCode::FORBIDDEN
    );
    // An unavailable Provider for a usable target.
    let selected = scenario.signing.token(Some("permissionsync:glpi"));
    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&selected), Body::from(valid_body()))
            .await,
        StatusCode::INTERNAL_SERVER_ERROR
    );

    drop(guard);
    let exposition = scenario.fixture.rendered_metrics();

    assert_contains(
        &exposition,
        &format!("{REQUESTS_TOTAL}{{outcome=\"targetless_noop\"}} 1"),
    );
    assert_contains(
        &exposition,
        &format!("{REQUESTS_TOTAL}{{outcome=\"invalid_request\"}} 1"),
    );
    assert_contains(
        &exposition,
        &format!("{REQUESTS_TOTAL}{{outcome=\"authorization_forbidden\"}} 1"),
    );
    assert_contains(
        &exposition,
        &format!("{REQUESTS_TOTAL}{{outcome=\"provider_failed\"}} 1"),
    );
    assert_contains(
        &exposition,
        &format!("{REQUEST_STAGE_TOTAL}{{stage=\"completed\"}} 1"),
    );
    assert_contains(
        &exposition,
        &format!("{REQUEST_STAGE_TOTAL}{{stage=\"validation\"}} 1"),
    );
    assert_contains(
        &exposition,
        &format!("{REQUEST_STAGE_TOTAL}{{stage=\"authorization\"}} 1"),
    );
    assert_contains(
        &exposition,
        &format!("{REQUEST_STAGE_TOTAL}{{stage=\"provider\"}} 1"),
    );
    assert_contains(&exposition, REQUEST_DURATION_SECONDS);
    assert_no_sentinels(&exposition);

    scenario.finish().await;
}

/// A targetless no-op and a selected-target result are separate coarse outcomes,
/// so an operator can tell them apart.
#[tokio::test]
async fn targetless_and_selected_target_outcomes_are_distinguishable() {
    let scenario = Scenario::build(|options| {
        options.glpi = Some(glpi_configuration(UNREACHABLE_GLPI));
        options.targets = vec![target("glpi", GLPI)];
    })
    .await;
    let guard = scenario.fixture.recorder_guard();

    let targetless = scenario.signing.token(Some("service_account"));
    let selected = scenario.signing.token(Some("permissionsync:glpi"));
    let _ = scenario
        .fixture
        .synchronize(Some(&targetless), Body::from(valid_body()))
        .await;
    let _ = scenario
        .fixture
        .synchronize(Some(&selected), Body::from(valid_body()))
        .await;

    drop(guard);
    let exposition = scenario.fixture.rendered_metrics();

    assert_contains(
        &exposition,
        &format!("{REQUESTS_TOTAL}{{outcome=\"targetless_noop\"}} 1"),
    );
    assert!(
        !exposition.contains(&format!("{REQUESTS_TOTAL}{{outcome=\"unchanged\"}}")),
        "a targetless no-op must never be counted as an Adapter-reported unchanged result"
    );

    scenario.finish().await;
}

/// The in-flight gauge tracks admitted requests and returns to zero.
#[tokio::test]
async fn the_in_flight_gauge_tracks_admitted_requests() {
    let scenario = Scenario::build(|_| {}).await;
    let guard = scenario.fixture.recorder_guard();

    // One held admission makes the gauge non-zero.
    let held = scenario.fixture.hold_admission().await;
    let during = scenario.fixture.rendered_metrics();
    assert_contains(&during, &format!("{REQUESTS_IN_FLIGHT} 1"));

    drop(held);
    let token = scenario.signing.token(Some("service_account"));
    let _ = scenario
        .fixture
        .synchronize(Some(&token), Body::from(valid_body()))
        .await;

    drop(guard);
    let after = scenario.fixture.rendered_metrics();
    assert_contains(&after, &format!("{REQUESTS_IN_FLIGHT} 0"));

    scenario.finish().await;
}

// ---------------------------------------------------------------------------
// Saturation evidence
// ---------------------------------------------------------------------------

/// Inbound admission saturation is visible, and so is the abandonment of a wait
/// that outlived its budget.
#[tokio::test(start_paused = true)]
async fn inbound_admission_saturation_is_represented() {
    let scenario = Scenario::build(|options| {
        options.inbound_admission_limit = NonZeroUsize::new(1).unwrap();
        options.overall_request_deadline = Duration::from_millis(100);
    })
    .await;
    let guard = scenario.fixture.recorder_guard();

    let held = scenario.fixture.hold_admission().await;
    let token = scenario.signing.token(Some("service_account"));
    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&token), Body::from(valid_body()))
            .await,
        StatusCode::INTERNAL_SERVER_ERROR
    );

    drop(guard);
    let exposition = scenario.fixture.rendered_metrics();

    assert_contains(&exposition, &format!("{ADMISSION_SATURATED_TOTAL} 1"));
    assert_contains(&exposition, &format!("{ADMISSION_ABANDONED_TOTAL} 1"));
    assert_contains(&exposition, &format!("{ADMISSION_WAITERS} 0"));
    // This waiter's own deadline really did expire, so the deadline outcome is
    // the truthful one to record for it.
    assert_contains(
        &exposition,
        &format!("{REQUESTS_TOTAL}{{outcome=\"cancelled_or_expired\"}} 1"),
    );
    assert_contains(
        &exposition,
        &format!("{REQUEST_STAGE_TOTAL}{{stage=\"admission\"}} 1"),
    );
    assert!(
        !exposition.contains(ADMISSION_REFUSED_TOTAL),
        "an expired waiter is not a refusal:\n{exposition}"
    );
    assert_no_sentinels(&exposition);

    drop(held);
    scenario.finish().await;
}

/// A transport-level admission refusal is observable through its own bounded
/// counter, and is never recorded as a synchronization outcome.
///
/// Nothing was cancelled, nothing expired, and nothing was processed, so no
/// request outcome, stage, or duration may be attributed to it.
#[tokio::test]
async fn a_transport_admission_refusal_is_counted_without_a_synchronization_outcome() {
    let scenario = Arc::new(
        Scenario::build(|options| {
            options.inbound_admission_limit = NonZeroUsize::new(1).unwrap();
            // Long enough that the parked waiter cannot expire during the test,
            // so any deadline outcome would have to come from the refusal.
            options.overall_request_deadline = Duration::from_secs(600);
        })
        .await,
    );
    let guard = scenario.fixture.recorder_guard();

    let held = scenario.fixture.saturate_admission().await;
    let token = scenario.signing.token(Some("service_account"));

    // Occupy the single waiter slot, proven through observed admission state.
    let parked = {
        let scenario = Arc::clone(&scenario);
        let token = token.clone();
        tokio::spawn(async move {
            scenario
                .fixture
                .synchronize(Some(&token), Body::from(valid_body()))
                .await
        })
    };
    scenario
        .fixture
        .await_admission(|observation| observation.waiting == 1)
        .await;

    // One request beyond both bounds.
    let refused = scenario
        .fixture
        .synchronize_response(Some(&token), Body::from(valid_body()))
        .await;
    assert!(is_transport_refusal(&refused));

    let exposition = scenario.fixture.rendered_metrics();

    assert_contains(&exposition, &format!("{ADMISSION_REFUSED_TOTAL} 1"));
    assert_contains(&exposition, &format!("{ADMISSION_SATURATED_TOTAL} 2"));
    assert!(
        !exposition.contains("outcome=\"cancelled_or_expired\""),
        "a refusal must not be recorded as cancelled or expired:\n{exposition}"
    );
    assert!(
        !exposition.contains("stage=\"admission\""),
        "a refusal must not be recorded as a request stage:\n{exposition}"
    );
    assert!(
        !exposition.contains(ADMISSION_ABANDONED_TOTAL),
        "a refusal abandoned no wait:\n{exposition}"
    );
    assert!(
        !exposition.contains(REQUESTS_TOTAL),
        "a refusal is not a synchronization request outcome:\n{exposition}"
    );
    assert_no_sentinels(&exposition);

    drop(guard);
    drop(held);
    let _ = tokio::time::timeout(Duration::from_secs(10), parked).await;
    Arc::try_unwrap(scenario)
        .map_err(|_| "scenario is still shared")
        .unwrap()
        .finish()
        .await;
}

/// Selected-target capacity use, saturation, and unavailability are visible and
/// separate from inbound admission.
#[tokio::test]
async fn selected_target_capacity_saturation_is_represented() {
    let scenario = Scenario::build(|options| {
        options.provider = Some(provider_configuration(UNREACHABLE_PROVIDER, Vec::new()));
        options.glpi = Some(glpi_configuration(UNREACHABLE_GLPI));
        options.targets = vec![target("glpi", GLPI)];
        options.synchronization_capacity = NonZeroUsize::new(1).unwrap();
        options.overall_request_deadline = Duration::from_millis(150);
    })
    .await;
    let guard = scenario.fixture.recorder_guard();

    struct NeverCancelled;
    impl permissionsync_core::CancellationSignal for NeverCancelled {
        fn is_cancelled(&self) -> bool {
            false
        }
    }
    let cancellation = NeverCancelled;
    let held_context = permissionsync_core::SynchronizationContext::new(
        std::time::Instant::now() + Duration::from_secs(600),
        &cancellation,
    );
    let held = permissionsync_orchestration::SynchronizationCapacity::acquire(
        scenario.fixture.state.capacity(),
        &held_context,
    )
    .await
    .expect("the test holds the only permit");

    let in_use = scenario.fixture.rendered_metrics();
    assert_contains(&in_use, &format!("{CAPACITY_IN_USE} 1"));

    let token = scenario.signing.token(Some("permissionsync:glpi"));
    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&token), Body::from(valid_body()))
            .await,
        StatusCode::INTERNAL_SERVER_ERROR
    );

    drop(guard);
    let exposition = scenario.fixture.rendered_metrics();

    assert_contains(&exposition, &format!("{CAPACITY_SATURATED_TOTAL} 1"));
    assert_contains(&exposition, &format!("{CAPACITY_UNAVAILABLE_TOTAL} 1"));
    assert_contains(
        &exposition,
        &format!("{REQUESTS_TOTAL}{{outcome=\"capacity_unavailable\"}} 1"),
    );
    assert_contains(
        &exposition,
        &format!("{REQUEST_STAGE_TOTAL}{{stage=\"capacity\"}} 1"),
    );
    assert_no_sentinels(&exposition);

    drop(held);
    scenario.finish().await;
}

// ---------------------------------------------------------------------------
// Provider and Adapter evidence
// ---------------------------------------------------------------------------

/// Provider outcome and latency evidence is produced by the composed Provider,
/// through a real local Provider call, and the Adapter failure that follows is
/// likewise recorded.
#[tokio::test]
async fn provider_and_adapter_outcome_and_latency_evidence_exists() {
    let provider = HttpsFixture::start(vec![
        crate::runtime::tests::support::ScriptedResponse::json(
            200,
            br#"{"version":2,"payload":null}"#.to_vec(),
        ),
    ])
    .await;
    let scenario = Scenario::build(|options| {
        options.provider = Some(provider_configuration(
            &provider.endpoint("/permissions"),
            vec![provider.trust_anchor_pem().to_vec()],
        ));
        options.glpi = Some(glpi_configuration(UNREACHABLE_GLPI));
        options.targets = vec![target("glpi", GLPI)];
    })
    .await;
    let guard = scenario.fixture.recorder_guard();

    let token = scenario.signing.token(Some("permissionsync:glpi"));
    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&token), Body::from(valid_body()))
            .await,
        StatusCode::INTERNAL_SERVER_ERROR
    );

    drop(guard);
    let exposition = scenario.fixture.rendered_metrics();

    assert_contains(
        &exposition,
        "permissionsync_provider_operations_total{outcome=\"success\"} 1",
    );
    assert_contains(&exposition, "permissionsync_provider_duration_seconds");
    assert_contains(
        &exposition,
        "permissionsync_adapter_reconciliations_total{outcome=\"failure\"} 1",
    );
    assert_contains(&exposition, "permissionsync_adapter_duration_seconds");
    assert_no_sentinels(&exposition);

    provider.shutdown().await;
    scenario.finish().await;
}

// ---------------------------------------------------------------------------
// Label cardinality and disclosure
// ---------------------------------------------------------------------------

/// Every emitted label key is one of the three closed keys, and every label
/// value is a fixed lowercase constant.
#[tokio::test]
async fn rendered_labels_stay_bounded_and_closed() {
    let scenario = Scenario::build(|options| {
        options.glpi = Some(glpi_configuration(UNREACHABLE_GLPI));
        options.targets = vec![
            target("sentinel-target-a", GLPI),
            target("sentinel-target-b", GLPI),
        ];
    })
    .await;
    let guard = scenario.fixture.recorder_guard();

    crate::runtime::transport::record_component_availability("provider", false);
    crate::runtime::transport::record_component_availability("glpi", true);
    let _ = scenario.fixture.get(READINESS_ROUTE).await;
    for scope in [
        Some("service_account"),
        Some("permissionsync:sentinel-target-a"),
        Some("permissionsync:sentinel-target-b"),
    ] {
        let token = scenario.signing.token(scope);
        let _ = scenario
            .fixture
            .synchronize(Some(&token), Body::from(valid_body()))
            .await;
    }

    drop(guard);
    let exposition = scenario.fixture.rendered_metrics();

    // Only the closed label keys may appear.
    for line in exposition
        .lines()
        .filter(|line| !line.starts_with('#') && line.contains('{'))
    {
        let labels = line
            .split_once('{')
            .and_then(|(_, rest)| rest.split_once('}'))
            .map(|(labels, _)| labels)
            .unwrap_or_default();
        for pair in labels.split(',').filter(|pair| !pair.is_empty()) {
            let (key, value) = pair.split_once('=').expect("a rendered label is key=value");
            assert!(
                matches!(key, "outcome" | "stage" | "component" | "le" | "quantile"),
                "unexpected metric label key {key} in {line}"
            );
            if matches!(key, "le" | "quantile") {
                continue;
            }
            let value = value.trim_matches('"');
            assert!(
                value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
                "label value {value} is not a fixed constant in {line}"
            );
        }
    }

    // A configured target identifier must never become a label.
    for target_name in ["sentinel-target-a", "sentinel-target-b"] {
        assert!(
            !exposition.contains(target_name),
            "a configured target identifier must not be a metric dimension"
        );
    }
    assert_contains(
        &exposition,
        &format!("{COMPONENT_AVAILABLE}{{component=\"glpi\"}} 1"),
    );
    assert_contains(
        &exposition,
        &format!("{COMPONENT_AVAILABLE}{{component=\"provider\"}} 0"),
    );
    assert_contains(&exposition, READY);
    assert_no_sentinels(&exposition);

    scenario.finish().await;
}

/// The `/metrics` endpoint itself must not disclose sentinel values either.
#[tokio::test]
async fn the_metrics_endpoint_exposes_no_sensitive_dimension() {
    let scenario = Scenario::build(|options| {
        options.glpi = Some(glpi_configuration(UNREACHABLE_GLPI));
        options.targets = vec![target("glpi", GLPI)];
    })
    .await;
    let guard = scenario.fixture.recorder_guard();

    let token = scenario.signing.token(Some("permissionsync:glpi"));
    let bearer_sentinel = token.clone();
    let _ = scenario
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

    drop(guard);
    let response = scenario.fixture.get(METRICS_ROUTE).await;
    assert_eq!(response.status(), StatusCode::OK);
    let rendered = String::from_utf8(crate::runtime::tests::support::body_bytes(response).await)
        .expect("the exposition is UTF-8");

    assert_no_sentinels(&rendered);
    assert!(
        !rendered.contains(&bearer_sentinel),
        "the bearer credential must never reach rendered metrics"
    );

    scenario.finish().await;
}
