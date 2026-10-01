//! `GET /readyz` behaviour.
//!
//! Readiness is evaluated against the real authenticator, never against a
//! separate readiness flag, and depends only on whether usable trusted verifier
//! state exists under ADR 0002.

use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use axum::{body::Body, http::StatusCode};
use tokio::time::timeout;

use crate::runtime::{
    observability::READY,
    tests::support::{
        FIXTURE_TIMEOUT, GLPI, GatedHttpsFixture, HttpsFixture, RefusingEndpoint, RuntimeFixture,
        RuntimeFixtureOptions, ScriptedResponse, SigningMaterial, authenticator, body_bytes,
        glpi_configuration, jwks_fixture, provider_configuration, target, unavailable_jwks_fixture,
        valid_body,
    },
    transport::READINESS_ROUTE,
};

const UNREACHABLE_GLPI: &str = "https://127.0.0.1:1/apirest.php";

struct Scenario {
    jwks: HttpsFixture,
    signing: SigningMaterial,
    fixture: RuntimeFixture,
}

impl Scenario {
    async fn with_metadata(
        jwks: HttpsFixture,
        signing: SigningMaterial,
        options: impl FnOnce(&mut RuntimeFixtureOptions),
    ) -> Self {
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

    async fn available(options: impl FnOnce(&mut RuntimeFixtureOptions)) -> Self {
        let signing = SigningMaterial::new("readiness-test-key");
        let jwks = jwks_fixture(&signing, 8).await;
        Self::with_metadata(jwks, signing, options).await
    }

    async fn unavailable(options: impl FnOnce(&mut RuntimeFixtureOptions)) -> Self {
        let signing = SigningMaterial::new("readiness-test-key");
        let jwks = unavailable_jwks_fixture(8).await;
        Self::with_metadata(jwks, signing, options).await
    }

    async fn readiness(&self) -> StatusCode {
        self.fixture.get(READINESS_ROUTE).await.status()
    }

    async fn finish(self) {
        self.jwks.shutdown().await;
    }
}

// ---------------------------------------------------------------------------
// Trusted verifier state
// ---------------------------------------------------------------------------

/// With no usable trusted state and an unavailable metadata source, readiness is
/// false. Exactly one bounded refresh is attempted per evaluation.
#[tokio::test]
async fn no_usable_trusted_state_is_not_ready() {
    let scenario = Scenario::unavailable(|_| {}).await;

    assert_eq!(scenario.readiness().await, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        scenario.jwks.request_count(),
        1,
        "readiness may initiate at most one bounded refresh"
    );

    scenario.finish().await;
}

/// A successful bounded warm-up through readiness makes the process ready, and
/// a subsequent evaluation needs no further retrieval while the state is fresh.
#[tokio::test]
async fn a_successful_warm_up_makes_the_process_ready() {
    let scenario = Scenario::available(|_| {}).await;

    assert_eq!(scenario.readiness().await, StatusCode::OK);
    assert_eq!(scenario.jwks.request_count(), 1);

    assert_eq!(scenario.readiness().await, StatusCode::OK);
    assert_eq!(
        scenario.jwks.request_count(),
        1,
        "usable trusted state needs no further metadata retrieval"
    );

    scenario.finish().await;
}

/// Once usable trusted state exists, a metadata outage does not make the
/// process unready: readiness means safe caller verification, not current
/// Keycloak connectivity.
#[tokio::test]
async fn a_metadata_outage_after_warm_up_keeps_usable_cached_state_ready() {
    let signing = SigningMaterial::new("readiness-test-key");
    // One successful JWKS response, then the source fails.
    let jwks = HttpsFixture::start(vec![
        ScriptedResponse::jwks(signing.jwks()),
        ScriptedResponse::empty(500),
        ScriptedResponse::empty(500),
    ])
    .await;
    let scenario = Scenario::with_metadata(jwks, signing, |_| {}).await;

    assert_eq!(scenario.readiness().await, StatusCode::OK);
    let after_warm_up = scenario.jwks.request_count();

    // The source is now failing, but the cached state is still fresh.
    assert_eq!(scenario.readiness().await, StatusCode::OK);
    assert_eq!(
        scenario.jwks.request_count(),
        after_warm_up,
        "a fresh cache is not refreshed just because a probe arrived"
    );

    scenario.finish().await;
}

/// Concurrent readiness evaluations reuse the authenticator's existing refresh
/// serialization instead of each consulting the trusted source.
#[tokio::test]
async fn concurrent_readiness_evaluations_do_not_create_a_metadata_herd() {
    let scenario = Arc::new(Scenario::available(|_| {}).await);
    let mut probes = Vec::new();
    for _ in 0..8 {
        let scenario = Arc::clone(&scenario);
        probes.push(tokio::spawn(async move { scenario.readiness().await }));
    }

    for probe in probes {
        let status = tokio::time::timeout(Duration::from_secs(10), probe)
            .await
            .expect("every probe must answer")
            .expect("probe task must not panic");
        assert_eq!(status, StatusCode::OK);
    }
    assert_eq!(
        scenario.jwks.request_count(),
        1,
        "concurrent evaluations must issue one metadata request"
    );

    Arc::try_unwrap(scenario)
        .map_err(|_| "scenario is still shared")
        .unwrap()
        .finish()
        .await;
}

// ---------------------------------------------------------------------------
// Independence from everything else
// ---------------------------------------------------------------------------

/// An unavailable Provider, an unavailable GLPI adapter, an unavailable target,
/// and no telemetry backend must all leave readiness untouched.
#[tokio::test]
async fn readiness_ignores_provider_glpi_target_and_telemetry_availability() {
    let refusing = RefusingEndpoint::start().await;
    let scenario = Scenario::available(|options| {
        // A Provider endpoint that cannot be reached, a GLPI endpoint that
        // cannot be reached, and a route whose adapter is unavailable.
        options.provider = Some(provider_configuration(
            &refusing.endpoint("/permissions"),
            Vec::new(),
        ));
        options.glpi = Some(glpi_configuration(UNREACHABLE_GLPI));
        options.targets = vec![target("glpi", GLPI), target("absent", "uncompiled-adapter")];
    })
    .await;

    assert_eq!(scenario.readiness().await, StatusCode::OK);

    // Drive a selected-target request that fails server-side, then confirm
    // readiness is still unaffected.
    let token = scenario.signing.token(Some("permissionsync:glpi"));
    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&token), Body::from(valid_body()))
            .await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(scenario.readiness().await, StatusCode::OK);

    scenario.finish().await;
}

/// Readiness is independent of synchronization saturation: it takes no
/// admission permit and no synchronization capacity.
#[tokio::test]
async fn readiness_answers_while_synchronization_is_saturated() {
    let scenario = Scenario::available(|options| {
        options.inbound_admission_limit = NonZeroUsize::new(1).unwrap();
        options.synchronization_capacity = NonZeroUsize::new(1).unwrap();
    })
    .await;

    let held = scenario.fixture.hold_admission().await;
    assert_eq!(scenario.fixture.state.admission().available_permits(), 0);

    assert_eq!(scenario.readiness().await, StatusCode::OK);
    assert_eq!(
        scenario.fixture.state.capacity().available_permits(),
        1,
        "readiness must not take selected-target capacity"
    );

    drop(held);
    scenario.finish().await;
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

/// Readiness turns false immediately when shutdown begins, before anything else
/// happens, and without consulting the metadata source again.
#[tokio::test]
async fn readiness_is_false_immediately_when_shutdown_begins() {
    let scenario = Scenario::available(|_| {}).await;
    assert_eq!(scenario.readiness().await, StatusCode::OK);
    let before_shutdown = scenario.jwks.request_count();

    scenario.fixture.lifecycle.begin_shutdown();

    assert_eq!(scenario.readiness().await, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        scenario.jwks.request_count(),
        before_shutdown,
        "a shutting-down process reports unready without any further retrieval"
    );

    scenario.finish().await;
}

/// The decisive readiness/shutdown race: a readiness evaluation that is already
/// waiting on the trusted metadata source must answer `503` as soon as shutdown
/// begins, even when the retrieval it was waiting for then *succeeds*.
///
/// Checking the shutdown flag only once, before awaiting, would let a probe that
/// started while the process was still serving answer `200` after shutdown had
/// already begun, because the refresh it was waiting for finally installed
/// usable trusted state. ADR 0011 requires readiness to be false from the start
/// of shutdown.
///
/// The race is established structurally, never by timing. The test itself
/// decides both when shutdown begins and when the retrieval would have
/// succeeded:
///
/// - the authenticator holds no usable cached state, so the evaluation *must*
///   consult the metadata source;
/// - the metadata source reports the arriving request and then answers nothing,
///   so receiving that report proves retrieval really started;
/// - shutdown begins next, and only then is a valid JWKS released, so the
///   refresh would succeed if anything still awaited it;
/// - the probe future is driven on this task rather than spawned, so no
///   scheduling order is assumed.
#[tokio::test]
async fn a_readiness_evaluation_already_awaiting_metadata_turns_false_at_shutdown() {
    let signing = SigningMaterial::new("readiness-race-key");
    let (jwks, mut arrivals) =
        GatedHttpsFixture::start(ScriptedResponse::jwks(signing.jwks())).await;
    let fixture = RuntimeFixture::new(
        authenticator(jwks.endpoint("/keys"), jwks.trust_anchor_pem().to_vec()),
        RuntimeFixtureOptions::default(),
    );
    let guard = fixture.recorder_guard();

    let mut probe = Box::pin(fixture.get(READINESS_ROUTE));

    // Driving the probe here is what makes it reach metadata retrieval; the
    // fixture's report is what proves it did.
    tokio::select! {
        _ = &mut probe => panic!("readiness must not answer while retrieval is still blocked"),
        arrived = arrivals.recv() => {
            arrived.expect("the metadata source must report the arriving request");
        }
    }
    assert_eq!(
        jwks.request_count(),
        1,
        "the evaluation must really be waiting on the trusted metadata source"
    );

    // Shutdown begins while that retrieval is still outstanding, and only then
    // is the retrieval allowed to succeed. Anything still awaiting it would now
    // observe usable trusted state.
    fixture.lifecycle.begin_shutdown();
    jwks.release();

    let readiness = timeout(FIXTURE_TIMEOUT, probe)
        .await
        .expect("readiness must answer at shutdown, not when the backend finally answers");
    assert_eq!(
        readiness.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "an in-flight readiness evaluation must become unready at shutdown, even though the \
         refresh it was waiting for succeeded"
    );

    drop(guard);
    let exposition = fixture.rendered_metrics();
    assert!(
        exposition.contains(&format!("{READY} 0")),
        "the readiness gauge must report unready:\n{exposition}"
    );
    assert!(
        !exposition.contains(&format!("{READY} 1")),
        "readiness must never briefly report ready while draining:\n{exposition}"
    );
}

/// The same probe, with shutdown never beginning, must still become ready once
/// the retrieval is released.
///
/// This proves the shutdown race is what ends the evaluation above, rather than
/// the gated fixture simply being unable to produce usable trusted state.
#[tokio::test]
async fn the_same_gated_evaluation_becomes_ready_when_shutdown_never_begins() {
    let signing = SigningMaterial::new("readiness-race-key");
    let (jwks, mut arrivals) =
        GatedHttpsFixture::start(ScriptedResponse::jwks(signing.jwks())).await;
    let fixture = RuntimeFixture::new(
        authenticator(jwks.endpoint("/keys"), jwks.trust_anchor_pem().to_vec()),
        RuntimeFixtureOptions::default(),
    );

    let mut probe = Box::pin(fixture.get(READINESS_ROUTE));
    tokio::select! {
        _ = &mut probe => panic!("readiness must not answer while retrieval is still blocked"),
        arrived = arrivals.recv() => {
            arrived.expect("the metadata source must report the arriving request");
        }
    }

    jwks.release();

    let readiness = timeout(FIXTURE_TIMEOUT, probe)
        .await
        .expect("readiness must answer once the metadata source does");
    assert_eq!(
        readiness.status(),
        StatusCode::OK,
        "a released retrieval installs usable trusted state and reports ready"
    );
}

/// Shutdown that begins before the probe arrives must likewise answer `503`
/// without any retrieval at all, even with no usable cached state.
#[tokio::test]
async fn a_readiness_probe_during_draining_consults_no_metadata_source() {
    let signing = SigningMaterial::new("readiness-draining-key");
    let (jwks, _arrivals) = GatedHttpsFixture::start(ScriptedResponse::jwks(signing.jwks())).await;
    let fixture = RuntimeFixture::new(
        authenticator(jwks.endpoint("/keys"), jwks.trust_anchor_pem().to_vec()),
        RuntimeFixtureOptions::default(),
    );

    fixture.lifecycle.begin_shutdown();

    let readiness = timeout(FIXTURE_TIMEOUT, fixture.get(READINESS_ROUTE))
        .await
        .expect("a draining process must answer readiness without any retrieval");
    assert_eq!(readiness.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        jwks.request_count(),
        0,
        "a shutting-down process must not consult the metadata source"
    );
}

// ---------------------------------------------------------------------------
// Disclosure
// ---------------------------------------------------------------------------

/// Readiness exposes no configuration, trust material, or internal detail.
#[tokio::test]
async fn readiness_responses_disclose_nothing() {
    let scenario = Scenario::available(|options| {
        options.glpi = Some(glpi_configuration(UNREACHABLE_GLPI));
        options.targets = vec![target("glpi", GLPI)];
    })
    .await;

    let ready = scenario.fixture.get(READINESS_ROUTE).await;
    assert_eq!(ready.status(), StatusCode::OK);
    let body = body_bytes(ready).await;

    assert!(
        body.is_empty(),
        "readiness answers with a status, not with detail"
    );

    scenario.finish().await;
}
