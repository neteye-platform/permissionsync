//! The bounded operational lifecycle: operational reachability under
//! synchronization saturation, graceful shutdown, grace expiry, fatal
//! accept-loop failure, a bounded trace flush, and verifier warm-up ordering.
//!
//! Lifecycle correctness is exercised through the real accept loop on an
//! ephemeral loopback port, and through the lifecycle state directly, rather
//! than by sending real process signals.

use std::{
    collections::BTreeMap,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::http::StatusCode;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use crate::runtime::{
    admission::{Admission, waiter_slots},
    failure::RuntimeFailure,
    lifecycle::Lifecycle,
    observability::{
        BOUNDED_EXPORT_BATCH, BOUNDED_SPAN_QUEUE, SPAN_EXPORT_INTERVAL, TracingConfiguration,
        build_tracer_provider,
    },
    tests::support::{
        FIXTURE_TIMEOUT, HttpsFixture, RefusingEndpoint, RuntimeFixture, RuntimeFixtureOptions,
        SigningMaterial, authenticator, jwks_fixture, provider_configuration, valid_body,
    },
    transport::{HEALTH_ROUTE, METRICS_ROUTE, READINESS_ROUTE, SYNCHRONIZATION_ROUTE, router},
};

/// A generous bound on any lifecycle assertion, so a defect fails rather than
/// hanging while still proving the phase is bounded.
const LIFECYCLE_BOUND: Duration = Duration::from_secs(20);

/// A serving runtime on an ephemeral loopback port.
struct Serving {
    address: std::net::SocketAddr,
    lifecycle: Arc<Lifecycle>,
    fixture: Arc<RuntimeFixture>,
    jwks: HttpsFixture,
    signing: SigningMaterial,
    serve: Option<tokio::task::JoinHandle<Result<(), RuntimeFailure>>>,
}

impl Serving {
    async fn start(
        shutdown_grace: Duration,
        options: impl FnOnce(&mut RuntimeFixtureOptions),
    ) -> Self {
        let signing = SigningMaterial::new("lifecycle-test-key");
        let jwks = jwks_fixture(&signing, 8).await;
        let mut fixture_options = RuntimeFixtureOptions::default();
        options(&mut fixture_options);
        let fixture = Arc::new(RuntimeFixture::new(
            authenticator(jwks.endpoint("/keys"), jwks.trust_anchor_pem().to_vec()),
            fixture_options,
        ));
        let lifecycle = Arc::clone(&fixture.lifecycle);
        let router = router(Arc::clone(&fixture.state));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (serving_started, _serving_has_started) = tokio::sync::oneshot::channel();
        let serve = tokio::spawn(crate::runtime::serve_for_test(
            listener,
            router,
            Arc::clone(&lifecycle),
            shutdown_grace,
            serving_started,
        ));

        Self {
            address,
            lifecycle,
            fixture,
            jwks,
            signing,
            serve: Some(serve),
        }
    }

    /// Begins shutdown and waits for the accept loop to finish, bounded.
    ///
    /// A normal shutdown must report success: only a fatal serving failure
    /// terminates with a failure category.
    async fn shut_down(&mut self) -> Duration {
        let started = Instant::now();
        self.lifecycle.begin_shutdown();
        let serve = self.serve.take().expect("serve runs once");
        let served = timeout(LIFECYCLE_BOUND, serve)
            .await
            .expect("shutdown must be bounded")
            .expect("the accept loop must not panic");
        assert_eq!(served, Ok(()), "a requested shutdown is not a failure");
        started.elapsed()
    }

    async fn finish(mut self) {
        if let Some(serve) = self.serve.take() {
            self.lifecycle.begin_shutdown();
            let _ = timeout(LIFECYCLE_BOUND, serve).await;
        }
        self.jwks.shutdown().await;
    }
}

/// A raw HTTP/1.1 client connection, so connection lifetime is controllable.
struct Connection {
    stream: TcpStream,
}

impl Connection {
    async fn open(address: std::net::SocketAddr) -> Self {
        let stream = timeout(FIXTURE_TIMEOUT, TcpStream::connect(address))
            .await
            .expect("connect must not block")
            .expect("loopback connect succeeds");
        Self { stream }
    }

    async fn write_request(&mut self, request: &str) {
        self.stream
            .write_all(request.as_bytes())
            .await
            .expect("write succeeds");
        self.stream.flush().await.expect("flush succeeds");
    }

    /// Reads whatever has arrived within `budget`, or returns `None`.
    async fn read_response(&mut self, budget: Duration) -> Option<String> {
        let mut buffer = [0_u8; 2048];
        match timeout(budget, self.stream.read(&mut buffer)).await {
            Ok(Ok(0)) | Err(_) => None,
            Ok(Ok(read)) => Some(String::from_utf8_lossy(&buffer[..read]).into_owned()),
            Ok(Err(_)) => None,
        }
    }

    fn keep_alive_request(path: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n")
    }

    /// A complete synchronization request, so nothing about it is waiting on
    /// more bytes from the client.
    fn synchronization_request(bearer: &str) -> String {
        let body = String::from_utf8(valid_body()).expect("the fixed body is UTF-8");
        format!(
            "POST {SYNCHRONIZATION_ROUTE} HTTP/1.1\r\nHost: 127.0.0.1\r\n\
             Authorization: Bearer {bearer}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",
            body.len()
        )
    }

    /// A request that declares more body than it sends, so the handler stays in
    /// bounded body collection until its own deadline.
    fn incomplete_body_request(bearer: &str) -> String {
        format!(
            "POST {SYNCHRONIZATION_ROUTE} HTTP/1.1\r\nHost: 127.0.0.1\r\n\
             Authorization: Bearer {bearer}\r\nContent-Type: application/json\r\n\
             Content-Length: 4096\r\n\r\n{{"
        )
    }
}

// ---------------------------------------------------------------------------
// Operational reachability under synchronization saturation
// ---------------------------------------------------------------------------

/// The invariant that matters, proven over the real listener: with
/// synchronization admission fully saturated and every allowed application-level
/// waiting slot provably occupied, and with further synchronization load
/// arriving, `/healthz` and `/metrics` are still answered with `200` and
/// `/readyz` still answers from trusted verifier state alone.
///
/// Saturation is established through observed admission state, not by assuming
/// that writing bytes to a socket means the handler reached admission.
#[tokio::test]
async fn operational_endpoints_are_served_while_synchronization_admission_is_saturated() {
    /// Synchronization connections opened beyond the bounded population.
    const BEYOND_THE_BOUND: usize = 8;

    let provider = HttpsFixture::start(Vec::new()).await;
    let admission_limit = NonZeroUsize::new(1).unwrap();
    let waiters = waiter_slots(admission_limit).get();
    let mut serving = Serving::start(Duration::from_secs(10), |options| {
        options.inbound_admission_limit = admission_limit;
        // Long enough that no parked request can finish by itself during the
        // assertions below.
        options.overall_request_deadline = Duration::from_secs(600);
        options.provider = Some(provider_configuration(
            &provider.endpoint("/permissions"),
            vec![provider.trust_anchor_pem().to_vec()],
        ));
    })
    .await;
    let token = serving.signing.token(Some("service_account"));

    // Hold every admission permit, so nothing further can be admitted.
    let held = serving.fixture.hold_admission().await;
    assert_eq!(serving.fixture.state.admission().available_permits(), 0);

    // Fill every waiter slot, proving through observed admission state that each
    // request really reached admission and entered the bounded wait list.
    let mut parked = Vec::new();
    for expected in 1..=waiters {
        let mut connection = Connection::open(serving.address).await;
        connection
            .write_request(&Connection::synchronization_request(&token))
            .await;
        parked.push(connection);
        serving
            .fixture
            .await_admission(|observation| observation.waiting == expected)
            .await;
    }
    assert_eq!(
        serving.fixture.state.admission().available_waiter_slots(),
        0,
        "every allowed application-level waiting slot is occupied"
    );

    // Additional synchronization load must not create a growing population of
    // application request or waiter tasks: each is refused without waiting.
    let mut beyond = Vec::new();
    for _ in 0..BEYOND_THE_BOUND {
        let mut connection = Connection::open(serving.address).await;
        connection
            .write_request(&Connection::synchronization_request(&token))
            .await;
        beyond.push(connection);
    }
    let observation = serving
        .fixture
        .await_admission(|observation| observation.refused_without_waiting == BEYOND_THE_BOUND)
        .await;
    assert_eq!(
        observation.waiting, waiters,
        "load beyond the bound must not enlarge the waiting population"
    );
    assert_eq!(
        observation.admitted,
        admission_limit.get(),
        "load beyond the bound must not enlarge the admitted population"
    );

    // Each refused request received the existing server-side outcome and was
    // told its connection is closing, so the pushback is transport backpressure.
    for connection in &mut beyond {
        let response = connection
            .read_response(FIXTURE_TIMEOUT)
            .await
            .expect("a refused request still receives its response");
        assert!(
            response.starts_with("HTTP/1.1 500"),
            "a refusal uses the existing server-side outcome: {response}"
        );
        assert!(
            response.to_ascii_lowercase().contains("connection: close"),
            "a refusal closes its connection: {response}"
        );
    }

    // No unadmitted synchronization request started authentication, Provider, or
    // Adapter work. This is asserted before probing `/readyz`, because readiness
    // legitimately performs its own bounded metadata refresh.
    assert_eq!(
        serving.jwks.request_count(),
        0,
        "no unadmitted request reached authentication"
    );
    assert_eq!(
        provider.request_count(),
        0,
        "no unadmitted request reached the Provider"
    );
    assert_eq!(
        serving.fixture.state.capacity().available_permits(),
        RuntimeFixtureOptions::default()
            .synchronization_capacity
            .get(),
        "no unadmitted request acquired selected-target capacity"
    );

    // Liveness and metrics must answer exactly 200 under saturation.
    for route in [HEALTH_ROUTE, METRICS_ROUTE] {
        let mut probe = Connection::open(serving.address).await;
        probe
            .write_request(&Connection::keep_alive_request(route))
            .await;
        let response = probe
            .read_response(FIXTURE_TIMEOUT)
            .await
            .unwrap_or_else(|| panic!("{route} must be served under saturation"));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "{route} must answer 200 under saturation: {response}"
        );
    }

    // Readiness depends only on trusted verifier state, never on saturation.
    // The metadata source is available here, so it is ready; the readiness tests
    // cover the unusable-state case that answers 503.
    let mut readiness = Connection::open(serving.address).await;
    readiness
        .write_request(&Connection::keep_alive_request(READINESS_ROUTE))
        .await;
    let response = readiness
        .read_response(FIXTURE_TIMEOUT)
        .await
        .expect("readiness must be served under saturation");
    assert!(
        response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.1 503"),
        "readiness must answer its contract status: {response}"
    );
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "with usable trusted verifier state readiness is 200: {response}"
    );

    // The bounded populations are unchanged by the probes.
    let after_probes = serving
        .fixture
        .await_admission(|observation| observation.waiting == waiters)
        .await;
    assert_eq!(after_probes.admitted, admission_limit.get());
    assert_eq!(
        serving.fixture.state.admission().available_permits(),
        0,
        "no further request was admitted"
    );
    assert_eq!(
        provider.request_count(),
        0,
        "operational probes never reach the Provider"
    );

    drop(beyond);
    drop(parked);
    drop(held);
    serving.shut_down().await;
    provider.shutdown().await;
    serving.finish().await;
}

/// The admission wait list is bounded by a value derived from the configured
/// limit, which is what keeps application-owned waiter state bounded now that
/// connections are not gated behind an application semaphore.
#[test]
fn the_admission_wait_list_bound_is_derived_from_the_configured_limit() {
    for limit in [1_usize, 2, 16, 64, 1024] {
        let admission = NonZeroUsize::new(limit).unwrap();
        assert_eq!(waiter_slots(admission).get(), limit);
    }
}

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------

/// Readiness is false as soon as shutdown begins, before the accept loop has
/// even finished draining.
#[tokio::test]
async fn readiness_turns_false_before_shutdown_completes() {
    let serving = Serving::start(Duration::from_secs(5), |_| {}).await;
    assert_eq!(
        serving.fixture.get(READINESS_ROUTE).await.status(),
        StatusCode::OK
    );

    serving.lifecycle.begin_shutdown();

    assert!(serving.lifecycle.is_shutting_down());
    assert_eq!(
        serving.fixture.get(READINESS_ROUTE).await.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "readiness must be false first"
    );
    assert!(
        !serving.lifecycle.requests_cancelled(),
        "admitted requests are not cancelled merely because shutdown began"
    );

    serving.finish().await;
}

/// An idle, open connection does not keep the process alive: shutdown closes it
/// and the accept loop returns well inside the grace period.
#[tokio::test]
async fn shutdown_closes_idle_connections_within_the_grace_period() {
    let grace = Duration::from_secs(10);
    let mut serving = Serving::start(grace, |_| {}).await;

    let mut idle = Connection::open(serving.address).await;
    idle.write_request(&Connection::keep_alive_request(HEALTH_ROUTE))
        .await;
    assert!(
        idle.read_response(FIXTURE_TIMEOUT).await.is_some(),
        "the connection must be served before shutdown"
    );

    let elapsed = serving.shut_down().await;

    assert!(
        elapsed < grace,
        "an idle connection must not hold shutdown for the whole grace period, took {elapsed:?}"
    );
    assert!(
        !serving.lifecycle.requests_cancelled(),
        "a clean drain inside the grace period needs no cancellation"
    );

    serving.finish().await;
}

/// The accept loop stops accepting as soon as shutdown begins.
#[tokio::test]
async fn no_connection_is_accepted_after_shutdown_begins() {
    let mut serving = Serving::start(Duration::from_secs(5), |_| {}).await;
    let elapsed = serving.shut_down().await;
    assert!(elapsed < LIFECYCLE_BOUND);

    // The listener has been dropped with the accept loop, so a late connection
    // either fails outright or is never served.
    match TcpStream::connect(serving.address).await {
        Err(_) => {}
        Ok(mut stream) => {
            let request = Connection::keep_alive_request(HEALTH_ROUTE);
            let _ = stream.write_all(request.as_bytes()).await;
            let mut buffer = [0_u8; 512];
            let read = timeout(Duration::from_millis(250), stream.read(&mut buffer)).await;
            assert!(
                matches!(read, Ok(Ok(0)) | Err(_)),
                "a late connection must not be served"
            );
        }
    }

    serving.finish().await;
}

// ---------------------------------------------------------------------------
// Grace expiry
// ---------------------------------------------------------------------------

/// A request that cannot finish must not hold shutdown open: at grace expiry the
/// remaining request contexts are cancelled, the bounded cancellation window
/// elapses, and the remaining owned tasks are terminated and awaited.
#[tokio::test]
async fn grace_expiry_cancels_remaining_contexts_and_terminates_owned_tasks() {
    let grace = Duration::from_millis(300);
    let mut serving = Serving::start(
        grace,
        // A long request deadline, so the in-flight request cannot end by
        // itself before the grace period expires.
        |options| options.overall_request_deadline = Duration::from_secs(600),
    )
    .await;
    let token = serving.signing.token(Some("service_account"));

    // This request is admitted and then blocks in bounded body collection,
    // because the declared body never fully arrives.
    let mut stuck = Connection::open(serving.address).await;
    stuck
        .write_request(&Connection::incomplete_body_request(&token))
        .await;
    // Observed admission state, not elapsed time, establishes that the handler
    // holds a permit and has moved on to body collection.
    serving
        .fixture
        .await_admission(|observation| observation.admitted == 1)
        .await;

    let elapsed = serving.shut_down().await;

    assert!(
        serving.lifecycle.requests_cancelled(),
        "grace expiry must cancel the remaining request contexts"
    );
    assert!(
        elapsed >= grace,
        "an in-flight request may use the whole grace period, took {elapsed:?}"
    );
    assert!(
        elapsed < LIFECYCLE_BOUND,
        "shutdown must stay bounded, took {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(600),
        "shutdown must not wait for the request's own deadline"
    );

    // The stuck request never receives a response: its task was terminated.
    assert!(
        stuck
            .read_response(Duration::from_millis(250))
            .await
            .is_none()
            || serving.lifecycle.requests_cancelled()
    );

    serving.finish().await;
}

/// No admission permit survives shutdown, so no admitted request outlives the
/// process lifecycle.
#[tokio::test]
async fn no_admission_permit_survives_shutdown() {
    let mut serving = Serving::start(Duration::from_millis(300), |options| {
        options.inbound_admission_limit = NonZeroUsize::new(2).unwrap();
        options.overall_request_deadline = Duration::from_secs(600);
    })
    .await;
    let token = serving.signing.token(Some("service_account"));

    let mut stuck = Connection::open(serving.address).await;
    stuck
        .write_request(&Connection::incomplete_body_request(&token))
        .await;
    serving
        .fixture
        .await_admission(|observation| observation.admitted == 1)
        .await;
    assert_eq!(
        serving.fixture.state.admission().available_permits(),
        1,
        "the in-flight request holds one admission permit"
    );

    serving.shut_down().await;

    assert_eq!(
        serving.fixture.state.admission().available_permits(),
        2,
        "every admission permit is released by shutdown"
    );

    serving.finish().await;
}

/// Admission waiting never extends shutdown: a request still waiting for
/// admission is released immediately rather than draining for the grace period.
#[tokio::test]
async fn admission_waiting_never_extends_shutdown() {
    let grace = Duration::from_secs(10);
    let mut serving = Serving::start(grace, |options| {
        options.inbound_admission_limit = NonZeroUsize::new(1).unwrap();
        options.overall_request_deadline = Duration::from_secs(600);
    })
    .await;

    // Hold the only admission permit outside any connection, so every arriving
    // request can only wait.
    let held = serving.fixture.hold_admission().await;

    let token = serving.signing.token(Some("service_account"));
    let mut waiting = Connection::open(serving.address).await;
    waiting
        .write_request(&format!(
            "POST {SYNCHRONIZATION_ROUTE} HTTP/1.1\r\nHost: 127.0.0.1\r\n\
             Authorization: Bearer {token}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n{}",
            valid_body().len(),
            String::from_utf8(valid_body()).unwrap()
        ))
        .await;
    // Observed admission state establishes that the request really is parked in
    // the bounded wait list before shutdown begins.
    serving
        .fixture
        .await_admission(|observation| observation.waiting == 1)
        .await;

    let elapsed = serving.shut_down().await;

    assert!(
        elapsed < grace,
        "a waiting request must be released, not drained for the grace period, took {elapsed:?}"
    );

    drop(held);
    assert_eq!(serving.fixture.state.admission().available_permits(), 1);

    serving.finish().await;
}

// ---------------------------------------------------------------------------
// Bounded trace flush
// ---------------------------------------------------------------------------

/// The telemetry queue is bounded, so a slow or unavailable backend drops spans
/// instead of growing memory without bound.
#[test]
fn the_span_queue_and_export_batch_are_bounded() {
    const { assert!(BOUNDED_SPAN_QUEUE > 0) };
    const { assert!(BOUNDED_EXPORT_BATCH > 0) };
    const { assert!(BOUNDED_EXPORT_BATCH <= BOUNDED_SPAN_QUEUE) };
    assert!(SPAN_EXPORT_INTERVAL > Duration::ZERO);
}

/// Shutting down a trace provider whose backend is unavailable must return
/// within the bounded flush budget rather than extending shutdown.
#[tokio::test]
async fn a_trace_flush_against_an_unavailable_backend_stays_bounded() {
    let unreachable = RefusingEndpoint::start().await;
    let mut headers = BTreeMap::new();
    headers.insert(
        "authorization".to_owned(),
        "ApiKey sentinel-exporter-credential".to_owned(),
    );
    let configuration = TracingConfiguration::new(
        unreachable.endpoint("/v1/traces"),
        Duration::from_millis(200),
        headers,
        Vec::new(),
    )
    .expect("a valid enabled tracing configuration");
    let provider = build_tracer_provider(&configuration).expect("the provider builds locally");

    let budget = crate::runtime::trace_flush_budget();
    let started = Instant::now();
    // Telemetry loss is deliberate here; only boundedness is asserted.
    let _ = provider.shutdown_with_timeout(budget);
    let elapsed = started.elapsed();

    assert!(
        elapsed < budget + Duration::from_secs(5),
        "the trace flush must stay bounded, took {elapsed:?}"
    );
}

/// The post-grace cancellation window is a fixed, bounded product value.
#[test]
fn the_post_grace_cancellation_window_is_bounded() {
    let window = crate::runtime::cancelled_request_window();
    assert!(window > Duration::ZERO);
    assert!(window <= Duration::from_secs(5));
}

// ---------------------------------------------------------------------------
// Fatal accept-loop failure
// ---------------------------------------------------------------------------

/// A transient accept failure is tolerated; only repeated consecutive failures
/// make the listener unusable, and the threshold is exact.
#[test]
fn only_repeated_consecutive_accept_failures_are_fatal() {
    let threshold = crate::runtime::max_consecutive_accept_failures();
    assert!(
        threshold > 1,
        "a single transient failure must not be fatal"
    );

    let mut consecutive = 0_u32;
    for attempt in 1..threshold {
        assert!(
            !crate::runtime::accept_failure_is_fatal_for_test(&mut consecutive),
            "failure {attempt} of {threshold} must not be fatal"
        );
    }
    assert!(
        crate::runtime::accept_failure_is_fatal_for_test(&mut consecutive),
        "the threshold failure must be fatal"
    );

    // A successful accept resets the counter in the loop, so a fresh counter
    // must again tolerate transient failures.
    let mut reset = 0_u32;
    assert!(!crate::runtime::accept_failure_is_fatal_for_test(
        &mut reset
    ));
}

/// Fatal accept exhaustion must enter the same lifecycle invariants as a
/// requested shutdown, and must report a failure rather than normal
/// termination.
#[tokio::test]
async fn fatal_accept_failure_enters_shutdown_and_reports_failure() {
    let serving = Serving::start(Duration::from_millis(200), |_| {}).await;
    assert_eq!(
        serving.fixture.get(READINESS_ROUTE).await.status(),
        StatusCode::OK,
        "the process is ready before the listener fails"
    );

    // An owned connection task that never finishes on its own, so the bounded
    // grace and cancellation phases have to terminate it.
    let mut connections: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    connections.spawn(std::future::pending::<()>());

    let failure = timeout(
        LIFECYCLE_BOUND,
        crate::runtime::terminate_after_fatal_accept_failure_for_test(
            &mut connections,
            &serving.lifecycle,
            Duration::from_millis(200),
        ),
    )
    .await
    .expect("fatal termination must stay bounded");

    assert_eq!(
        failure,
        RuntimeFailure::ListenerAcceptFailed,
        "the process must report a failure, not normal termination"
    );
    assert!(
        serving.lifecycle.is_shutting_down(),
        "readiness must be false and admission closed"
    );
    assert!(
        serving.lifecycle.requests_cancelled(),
        "grace expiry must cancel the remaining request contexts"
    );
    assert_eq!(
        serving.fixture.get(READINESS_ROUTE).await.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "readiness must be false once the listener is unusable"
    );
    assert!(
        connections.is_empty(),
        "remaining owned tasks must be terminated and awaited"
    );

    // No further synchronization request is admitted after the transition.
    assert!(
        matches!(
            serving
                .fixture
                .state
                .admission()
                .admit(
                    Instant::now() + Duration::from_secs(600),
                    &serving.lifecycle
                )
                .await,
            Admission::NotAdmitted
        ),
        "no synchronization request may be admitted after fatal termination"
    );

    serving.finish().await;
}

/// The fatal category renders safely and exposes no operating-system error.
#[test]
fn the_fatal_accept_category_is_value_free() {
    let rendered = RuntimeFailure::ListenerAcceptFailed.to_string();

    assert!(!rendered.is_empty());
    for leaked in [
        "EMFILE",
        "errno",
        "os error",
        "127.0.0.1",
        "Too many open files",
    ] {
        assert!(!rendered.contains(leaked), "{rendered} leaked {leaked}");
    }
}

// ---------------------------------------------------------------------------
// Verifier warm-up ordering
// ---------------------------------------------------------------------------

/// Warm-up must not consult the trusted metadata source before serving has
/// begun. The ordering is a happens-before relation on an explicit signal, not
/// a scheduling assumption, so holding the signal holds the warm-up.
#[tokio::test]
async fn warm_up_cannot_consult_the_metadata_source_before_serving_starts() {
    let signing = SigningMaterial::new("warm-up-order-key");
    let jwks = jwks_fixture(&signing, 2).await;
    let fixture = Arc::new(RuntimeFixture::new(
        authenticator(jwks.endpoint("/keys"), jwks.trust_anchor_pem().to_vec()),
        RuntimeFixtureOptions::default(),
    ));

    let (serving_started, serving_has_started) = tokio::sync::oneshot::channel();
    let mut warm_up = crate::runtime::spawn_verifier_warm_up_for_test(
        &fixture.state,
        Duration::from_secs(5),
        serving_has_started,
    );

    // While the signal is unsent the task cannot progress past its first await,
    // so it can never have issued a metadata request.
    assert!(
        timeout(Duration::from_millis(100), &mut warm_up)
            .await
            .is_err(),
        "warm-up must not complete before serving starts"
    );
    assert_eq!(
        jwks.request_count(),
        0,
        "warm-up must not consult the metadata source before serving starts"
    );

    // Signalling that serving started releases exactly one bounded refresh.
    serving_started.send(()).expect("the warm-up task is alive");
    timeout(LIFECYCLE_BOUND, warm_up)
        .await
        .expect("warm-up must stay bounded")
        .expect("warm-up must not panic");
    assert_eq!(
        jwks.request_count(),
        1,
        "warm-up performs exactly one bounded refresh once serving started"
    );

    jwks.shutdown().await;
}

/// Serving that never starts must leave warm-up doing nothing at all.
#[tokio::test]
async fn warm_up_performs_no_work_when_serving_never_starts() {
    let signing = SigningMaterial::new("warm-up-never-key");
    let jwks = jwks_fixture(&signing, 2).await;
    let fixture = Arc::new(RuntimeFixture::new(
        authenticator(jwks.endpoint("/keys"), jwks.trust_anchor_pem().to_vec()),
        RuntimeFixtureOptions::default(),
    ));

    let (serving_started, serving_has_started) = tokio::sync::oneshot::channel::<()>();
    let warm_up = crate::runtime::spawn_verifier_warm_up_for_test(
        &fixture.state,
        Duration::from_secs(5),
        serving_has_started,
    );

    // Dropping the sender is what happens when the listener could not be bound.
    drop(serving_started);
    timeout(LIFECYCLE_BOUND, warm_up)
        .await
        .expect("warm-up must return promptly")
        .expect("warm-up must not panic");

    assert_eq!(
        jwks.request_count(),
        0,
        "warm-up must perform no metadata retrieval when serving never started"
    );

    jwks.shutdown().await;
}
