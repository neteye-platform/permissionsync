//! Inbound admission at the transport boundary.
//!
//! These tests prove the ordering and boundedness properties directly, rather
//! than inferring them from a permit count: the request body is instrumented so
//! the first poll is observable, and admission is saturated by holding real
//! permits.

use std::{
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body::{Body as HttpBody, Frame, SizeHint};

use crate::runtime::{
    admission::waiter_slots,
    tests::support::{
        FIXTURE_TIMEOUT, GLPI, HttpsFixture, RuntimeFixture, RuntimeFixtureOptions,
        SigningMaterial, authenticator, glpi_configuration, jwks_fixture, provider_configuration,
        target, valid_body,
    },
    transport::{
        HEALTH_ROUTE, METRICS_ROUTE, READINESS_ROUTE, SYNCHRONIZATION_ROUTE, is_transport_refusal,
    },
};

const UNREACHABLE_GLPI: &str = "https://127.0.0.1:1/apirest.php";
const UNREACHABLE_PROVIDER: &str = "https://127.0.0.1:1/permissions";

/// A request body that records whether it has ever been polled.
///
/// Body collection cannot begin without at least one poll, so an unset flag is
/// direct evidence that no body byte was buffered.
struct ObservedBody {
    polled: Arc<AtomicBool>,
    polls: Arc<AtomicUsize>,
    payload: Option<bytes::Bytes>,
}

impl ObservedBody {
    fn new(payload: Vec<u8>) -> (Self, Arc<AtomicBool>, Arc<AtomicUsize>) {
        let polled = Arc::new(AtomicBool::new(false));
        let polls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                polled: Arc::clone(&polled),
                polls: Arc::clone(&polls),
                payload: Some(bytes::Bytes::from(payload)),
            },
            polled,
            polls,
        )
    }
}

impl HttpBody for ObservedBody {
    type Data = bytes::Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.polled.store(true, Ordering::SeqCst);
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(self.payload.take().map(|data| Ok(Frame::data(data))))
    }

    fn size_hint(&self) -> SizeHint {
        match &self.payload {
            Some(payload) => SizeHint::with_exact(payload.len() as u64),
            None => SizeHint::with_exact(0),
        }
    }
}

struct Scenario {
    jwks: HttpsFixture,
    signing: SigningMaterial,
    fixture: RuntimeFixture,
}

impl Scenario {
    async fn build(options: impl FnOnce(&mut RuntimeFixtureOptions)) -> Self {
        let signing = SigningMaterial::new("admission-test-key");
        let jwks = jwks_fixture(&signing, 4).await;
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

    fn token(&self) -> String {
        self.signing.token(Some("service_account"))
    }

    async fn finish(self) {
        self.jwks.shutdown().await;
    }
}

// ---------------------------------------------------------------------------
// Ordering: admission precedes body collection
// ---------------------------------------------------------------------------

/// The decisive property: while admission is saturated, the request body is
/// never polled, so no body byte is buffered and no authentication happens.
#[tokio::test(start_paused = true)]
async fn the_body_is_not_collected_before_admission() {
    let scenario = Scenario::build(|options| {
        options.inbound_admission_limit = NonZeroUsize::new(1).unwrap();
        options.overall_request_deadline = Duration::from_millis(250);
    })
    .await;
    let token = scenario.token();
    let held = scenario.fixture.saturate_admission().await;
    let (body, polled, _) = ObservedBody::new(valid_body());

    let status = scenario
        .fixture
        .call(
            Request::builder()
                .method("POST")
                .uri(SYNCHRONIZATION_ROUTE)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::new(body))
                .unwrap(),
        )
        .await
        .status();

    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "an unadmitted request ends through the existing deadline semantics"
    );
    assert!(
        !polled.load(Ordering::SeqCst),
        "body collection must not begin before admission"
    );
    assert_eq!(
        scenario.jwks.request_count(),
        0,
        "authentication must not begin before admission"
    );

    drop(held);
    scenario.finish().await;
}

/// No Provider or Adapter work can start either, even when both are configured
/// and the token selects a usable target.
#[tokio::test(start_paused = true)]
async fn no_provider_or_adapter_work_begins_without_admission() {
    let provider = HttpsFixture::start(Vec::new()).await;
    let scenario = Scenario::build(|options| {
        options.inbound_admission_limit = NonZeroUsize::new(1).unwrap();
        options.overall_request_deadline = Duration::from_millis(250);
        options.provider = Some(provider_configuration(
            &provider.endpoint("/permissions"),
            vec![provider.trust_anchor_pem().to_vec()],
        ));
        options.glpi = Some(glpi_configuration(UNREACHABLE_GLPI));
        options.targets = vec![target("glpi", GLPI)];
        options.synchronization_capacity = NonZeroUsize::new(2).unwrap();
    })
    .await;
    let token = scenario.signing.token(Some("permissionsync:glpi"));
    let held = scenario.fixture.saturate_admission().await;

    let status = scenario
        .fixture
        .synchronize(Some(&token), Body::from(valid_body()))
        .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(provider.request_count(), 0, "no Provider attempt");
    assert_eq!(
        scenario.fixture.state.capacity().available_permits(),
        2,
        "no selected-target capacity acquired"
    );

    drop(held);
    provider.shutdown().await;
    scenario.finish().await;
}

/// Body collection happens exactly once, after admission, when a permit is
/// available.
#[tokio::test]
async fn an_admitted_request_collects_its_body_once() {
    let scenario = Scenario::build(|_| {}).await;
    let token = scenario.token();
    let (body, polled, _) = ObservedBody::new(valid_body());

    let status = scenario
        .fixture
        .call(
            Request::builder()
                .method("POST")
                .uri(SYNCHRONIZATION_ROUTE)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::new(body))
                .unwrap(),
        )
        .await
        .status();

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(polled.load(Ordering::SeqCst));

    scenario.finish().await;
}

// ---------------------------------------------------------------------------
// Concurrency bound
// ---------------------------------------------------------------------------

/// Admission is released when the request that owns it finishes, and never
/// exceeds the configured limit meanwhile.
#[tokio::test]
async fn admission_never_exceeds_the_configured_limit_and_is_always_released() {
    let scenario = Scenario::build(|options| {
        options.inbound_admission_limit = NonZeroUsize::new(2).unwrap();
    })
    .await;
    let token = scenario.token();
    let limit = scenario.fixture.state.admission().limit().get();

    for _ in 0..5 {
        assert_eq!(
            scenario
                .fixture
                .synchronize(Some(&token), Body::from(valid_body()))
                .await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            scenario.fixture.state.admission().available_permits(),
            limit,
            "the permit is released for every completed request"
        );
    }

    scenario.finish().await;
}

/// A permit released by its holder admits the waiting request, which proves the
/// wait is bounded by the request's own budget rather than by a separate, short
/// admission timeout.
#[tokio::test]
async fn a_released_permit_admits_a_waiting_request_within_its_own_budget() {
    let scenario = Arc::new(
        Scenario::build(|options| {
            options.inbound_admission_limit = NonZeroUsize::new(1).unwrap();
            options.overall_request_deadline = Duration::from_secs(60);
        })
        .await,
    );
    let token = scenario.token();
    let held = scenario.fixture.saturate_admission().await;

    let waiting = {
        let scenario = Arc::clone(&scenario);
        let token = token.clone();
        tokio::spawn(async move {
            scenario
                .fixture
                .synchronize(Some(&token), Body::from(valid_body()))
                .await
        })
    };
    // Observed admission state, not a scheduling assumption, establishes that
    // the request is really parked before the permit is released.
    scenario
        .fixture
        .await_admission(|observation| observation.waiting == 1)
        .await;

    drop(held);
    let status = tokio::time::timeout(Duration::from_secs(10), waiting)
        .await
        .expect("releasing the permit must admit the waiting request")
        .expect("request task must not panic");

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(scenario.fixture.state.admission().available_permits(), 1);

    Arc::try_unwrap(scenario)
        .map_err(|_| "scenario is still shared")
        .unwrap()
        .finish()
        .await;
}

// ---------------------------------------------------------------------------
// Operational endpoints
// ---------------------------------------------------------------------------

/// Operational endpoints stay observable while synchronization is saturated.
#[tokio::test]
async fn operational_endpoints_consume_no_admission_capacity() {
    let scenario = Scenario::build(|options| {
        options.inbound_admission_limit = NonZeroUsize::new(1).unwrap();
    })
    .await;
    let held = scenario.fixture.saturate_admission().await;

    assert_eq!(
        scenario.fixture.get(HEALTH_ROUTE).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        scenario.fixture.get(METRICS_ROUTE).await.status(),
        StatusCode::OK
    );
    // Readiness answers either way; what matters is that it answers at all.
    let readiness = scenario.fixture.get(READINESS_ROUTE).await.status();
    assert!(
        readiness == StatusCode::OK || readiness == StatusCode::SERVICE_UNAVAILABLE,
        "readiness must answer under saturation, got {readiness}"
    );
    assert_eq!(
        scenario.fixture.state.admission().available_permits(),
        0,
        "operational endpoints must not take or release a synchronization permit"
    );

    drop(held);
    scenario.finish().await;
}

// ---------------------------------------------------------------------------
// Abandonment, shutdown, and boundedness of waiter state
// ---------------------------------------------------------------------------

/// Dropping a request that is waiting for admission must leave no reservation.
///
/// This test uses real time because its final request performs real loopback
/// metadata retrieval; the negative assertion cannot race, because a request
/// can never be admitted while the only permit is held.
#[tokio::test]
async fn an_abandoned_request_releases_its_pending_admission_wait() {
    let scenario = Scenario::build(|options| {
        options.inbound_admission_limit = NonZeroUsize::new(1).unwrap();
        options.overall_request_deadline = Duration::from_secs(600);
    })
    .await;
    let token = scenario.token();
    let held = scenario.fixture.saturate_admission().await;

    let mut abandoned = Box::pin(
        scenario.fixture.call(
            Request::builder()
                .method("POST")
                .uri(SYNCHRONIZATION_ROUTE)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(valid_body()))
                .unwrap(),
        ),
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut abandoned)
            .await
            .is_err(),
        "a saturated request must still be waiting"
    );
    drop(abandoned);
    drop(held);

    assert_eq!(scenario.fixture.state.admission().available_permits(), 1);
    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&token), Body::from(valid_body()))
            .await,
        StatusCode::NO_CONTENT,
        "admission remains usable after an abandoned wait"
    );

    scenario.finish().await;
}

/// Shutdown releases pending admission waits instead of letting them run to
/// their own deadline, and those requests reach neither body collection nor
/// authentication.
#[tokio::test]
async fn shutdown_releases_pending_admission_without_body_or_authentication_work() {
    let scenario = Arc::new(
        Scenario::build(|options| {
            options.inbound_admission_limit = NonZeroUsize::new(1).unwrap();
            options.overall_request_deadline = Duration::from_secs(600);
        })
        .await,
    );
    let token = scenario.token();
    let held = scenario.fixture.saturate_admission().await;
    let (body, polled, _) = ObservedBody::new(valid_body());

    let waiting = {
        let scenario = Arc::clone(&scenario);
        let token = token.clone();
        tokio::spawn(async move {
            scenario
                .fixture
                .call(
                    Request::builder()
                        .method("POST")
                        .uri(SYNCHRONIZATION_ROUTE)
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::new(body))
                        .unwrap(),
                )
                .await
                .status()
        })
    };
    // Observed admission state establishes that the request is really parked
    // before shutdown begins.
    scenario
        .fixture
        .await_admission(|observation| observation.waiting == 1)
        .await;

    scenario.fixture.lifecycle.begin_shutdown();
    let status = tokio::time::timeout(Duration::from_secs(10), waiting)
        .await
        .expect("shutdown must release the pending admission wait")
        .expect("request task must not panic");

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        !polled.load(Ordering::SeqCst),
        "a request released by shutdown must not have collected its body"
    );
    assert_eq!(scenario.jwks.request_count(), 0);

    drop(held);
    assert_eq!(
        scenario.fixture.state.admission().available_permits(),
        1,
        "no admission permit survives shutdown"
    );

    Arc::try_unwrap(scenario)
        .map_err(|_| "scenario is still shared")
        .unwrap()
        .finish()
        .await;
}

/// Shutdown admits no further synchronization request at all.
#[tokio::test]
async fn no_synchronization_request_is_admitted_after_shutdown_begins() {
    let scenario = Scenario::build(|_| {}).await;
    let token = scenario.token();
    scenario.fixture.lifecycle.begin_shutdown();
    let (body, polled, _) = ObservedBody::new(valid_body());

    let status = scenario
        .fixture
        .call(
            Request::builder()
                .method("POST")
                .uri(SYNCHRONIZATION_ROUTE)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::new(body))
                .unwrap(),
        )
        .await
        .status();

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!polled.load(Ordering::SeqCst));
    assert_eq!(
        scenario.fixture.state.admission().available_permits(),
        scenario.fixture.state.admission().limit().get()
    );

    scenario.finish().await;
}

/// Saturation adds no caller-facing status: it is only the existing
/// server-side deadline path.
#[tokio::test(start_paused = true)]
async fn saturation_introduces_no_new_caller_facing_status() {
    let scenario = Scenario::build(|options| {
        options.inbound_admission_limit = NonZeroUsize::new(1).unwrap();
        options.overall_request_deadline = Duration::from_millis(100);
        options.provider = Some(provider_configuration(UNREACHABLE_PROVIDER, Vec::new()));
    })
    .await;
    let token = scenario.token();
    let held = scenario.fixture.saturate_admission().await;

    for _ in 0..4 {
        let status = scenario
            .fixture
            .synchronize(Some(&token), Body::from(valid_body()))
            .await;
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "saturation must never produce 429, 503, or another new status"
        );
    }

    drop(held);
    scenario.finish().await;
}

/// The complete invariant: the number of synchronization requests that are
/// admitted or waiting anywhere is bounded, and load beyond that bound does not
/// enlarge either population.
///
/// A request beyond the bound is refused immediately rather than parked, so no
/// second waiting area can appear outside the two bounded populations.
#[tokio::test]
async fn the_admitted_and_waiting_populations_cannot_grow_past_their_bound() {
    let limit = NonZeroUsize::new(2).unwrap();
    let slots = waiter_slots(limit).get();
    let scenario = Arc::new(
        Scenario::build(|options| {
            options.inbound_admission_limit = limit;
            options.overall_request_deadline = Duration::from_secs(600);
        })
        .await,
    );
    let token = scenario.token();
    let held = scenario.fixture.saturate_admission().await;

    // Park exactly as many requests as the bounded wait list allows, and prove
    // through observed admission state that each really reached admission.
    let mut parked = Vec::new();
    for expected in 1..=slots {
        parked.push({
            let scenario = Arc::clone(&scenario);
            let token = token.clone();
            tokio::spawn(async move {
                scenario
                    .fixture
                    .synchronize(Some(&token), Body::from(valid_body()))
                    .await
            })
        });
        scenario
            .fixture
            .await_admission(|observation| observation.waiting == expected)
            .await;
    }

    // Load beyond the bound is refused immediately: it neither parks nor
    // enlarges either population.
    const BEYOND: usize = 8;
    let mut refused = Vec::new();
    for _ in 0..BEYOND {
        refused.push(
            scenario
                .fixture
                .synchronize_response(Some(&token), Body::from(valid_body()))
                .await,
        );
    }
    let observation = scenario
        .fixture
        .await_admission(|observation| observation.refused_without_waiting == BEYOND)
        .await;

    assert!(
        refused.iter().all(is_transport_refusal),
        "a refusal is a transport refusal, never a PermissionSync outcome"
    );
    assert_eq!(
        observation.waiting, slots,
        "refused requests must not enlarge the waiting population"
    );
    assert_eq!(
        observation.admitted,
        limit.get(),
        "refused requests must not enlarge the admitted population"
    );
    assert_eq!(scenario.fixture.state.admission().available_permits(), 0);
    assert_eq!(
        scenario.fixture.state.admission().available_waiter_slots(),
        0
    );
    assert_eq!(
        scenario.jwks.request_count(),
        0,
        "no unadmitted request reached authentication"
    );

    // A legitimately waiting request still proceeds once capacity frees.
    drop(held);
    for waiting in parked {
        let status = tokio::time::timeout(FIXTURE_TIMEOUT, waiting)
            .await
            .expect("a waiting request must be woken by the freed permits")
            .expect("request task must not panic");
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "a waiting request completes normally once it is admitted"
        );
    }

    Arc::try_unwrap(scenario)
        .map_err(|_| "scenario is still shared")
        .unwrap()
        .finish()
        .await;
}

/// A request refused because the bounded population was full must not collect a
/// body and must produce no PermissionSync application response at all.
///
/// It is not `cancelled_or_expired`, `capacity_unavailable`, or any other
/// existing outcome: nothing was cancelled, nothing expired, and nothing was
/// processed. The route yields only the private placeholder that the connection
/// driver turns into a terminated connection.
#[tokio::test]
async fn a_refused_request_produces_no_application_response() {
    let scenario = Arc::new(
        Scenario::build(|options| {
            options.inbound_admission_limit = NonZeroUsize::new(1).unwrap();
            options.overall_request_deadline = Duration::from_secs(600);
        })
        .await,
    );
    let token = scenario.token();
    let held = scenario.fixture.saturate_admission().await;

    // Occupy the single waiter slot.
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

    let (body, polled, polls) = ObservedBody::new(valid_body());
    let response = scenario
        .fixture
        .call(
            Request::builder()
                .method("POST")
                .uri(SYNCHRONIZATION_ROUTE)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::new(body))
                .unwrap(),
        )
        .await;

    assert!(
        is_transport_refusal(&response),
        "a beyond-bound request must be refused at the transport boundary"
    );
    assert!(
        !polled.load(Ordering::SeqCst),
        "a refused request must not collect its body"
    );
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(
        scenario.jwks.request_count(),
        0,
        "a refused request must not start authentication"
    );

    drop(held);
    let _ = tokio::time::timeout(FIXTURE_TIMEOUT, parked).await;
    Arc::try_unwrap(scenario)
        .map_err(|_| "scenario is still shared")
        .unwrap()
        .finish()
        .await;
}

/// Saturation must not change the outcome ADR 0001 fixes for any request.
///
/// A missing credential, a malformed credential, and a malformed body each have
/// their own fixed outcome. While both bounded populations are full none of them
/// is produced, because the request is never processed: no `401`, `400`, `403`,
/// `429`, `500`, or `503` is invented for it.
#[tokio::test]
async fn saturation_never_invents_an_application_status() {
    let scenario = Arc::new(
        Scenario::build(|options| {
            options.inbound_admission_limit = NonZeroUsize::new(1).unwrap();
            options.overall_request_deadline = Duration::from_secs(600);
        })
        .await,
    );
    let token = scenario.token();
    let held = scenario.fixture.saturate_admission().await;

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

    for (credential, body) in [
        (None, valid_body()),
        (Some("Basic secret"), valid_body()),
        (Some("Bearer not.a.jwt!"), valid_body()),
        (Some(format!("Bearer {token}").as_str()), b"{".to_vec()),
    ] {
        let mut request = Request::builder().method("POST").uri(SYNCHRONIZATION_ROUTE);
        if let Some(credential) = credential {
            request = request.header("authorization", credential);
        }
        let response = scenario
            .fixture
            .call(request.body(Body::from(body)).unwrap())
            .await;

        assert!(
            is_transport_refusal(&response),
            "saturation must refuse at the transport boundary, not answer"
        );
    }
    assert_eq!(
        scenario.jwks.request_count(),
        0,
        "no refused request reached authentication"
    );

    drop(held);
    let _ = tokio::time::timeout(FIXTURE_TIMEOUT, parked).await;
    Arc::try_unwrap(scenario)
        .map_err(|_| "scenario is still shared")
        .unwrap()
        .finish()
        .await;
}
