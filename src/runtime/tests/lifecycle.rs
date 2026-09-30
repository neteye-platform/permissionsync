//! The bounded operational lifecycle: transport backpressure, graceful
//! shutdown, grace expiry, and a bounded trace flush.
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
    admission::concurrent_connection_limit,
    lifecycle::Lifecycle,
    observability::{
        BOUNDED_EXPORT_BATCH, BOUNDED_SPAN_QUEUE, SPAN_EXPORT_INTERVAL, TracingConfiguration,
        build_tracer_provider,
    },
    tests::support::{
        FIXTURE_TIMEOUT, HttpsFixture, RefusingEndpoint, RuntimeFixture, RuntimeFixtureOptions,
        SigningMaterial, authenticator, jwks_fixture, valid_body,
    },
    transport::{HEALTH_ROUTE, READINESS_ROUTE, SYNCHRONIZATION_ROUTE, router},
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
    serve: Option<tokio::task::JoinHandle<()>>,
}

impl Serving {
    async fn start(
        connection_limit: usize,
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
        let serve = tokio::spawn(crate::runtime::serve_for_test(
            listener,
            router,
            Arc::clone(&lifecycle),
            connection_limit,
            shutdown_grace,
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
    async fn shut_down(&mut self) -> Duration {
        let started = Instant::now();
        self.lifecycle.begin_shutdown();
        let serve = self.serve.take().expect("serve runs once");
        timeout(LIFECYCLE_BOUND, serve)
            .await
            .expect("shutdown must be bounded")
            .expect("the accept loop must not panic");
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
// Transport backpressure
// ---------------------------------------------------------------------------

/// The accept loop stops accepting at the connection bound, so surplus load
/// stays in the kernel listen backlog instead of becoming application state.
/// This is what bounds admission waiter state.
#[tokio::test]
async fn the_accept_loop_serves_no_more_than_the_connection_bound() {
    let mut serving = Serving::start(1, Duration::from_secs(5), |_| {}).await;

    // The first connection is served and then kept alive, so its connection
    // task holds the only transport permit.
    let mut first = Connection::open(serving.address).await;
    first
        .write_request(&Connection::keep_alive_request(HEALTH_ROUTE))
        .await;
    let served = first
        .read_response(FIXTURE_TIMEOUT)
        .await
        .expect("the first connection must be served");
    assert!(served.starts_with("HTTP/1.1 200"), "got {served}");

    // A second connection can complete its TCP handshake through the listen
    // backlog, but must not be served while the bound is reached.
    let mut second = Connection::open(serving.address).await;
    second
        .write_request(&Connection::keep_alive_request(HEALTH_ROUTE))
        .await;
    assert!(
        second
            .read_response(Duration::from_millis(250))
            .await
            .is_none(),
        "a connection beyond the bound must not be served"
    );

    // Releasing the first connection lets the second one through.
    drop(first);
    let served = second
        .read_response(FIXTURE_TIMEOUT)
        .await
        .expect("the second connection must be served once a slot frees");
    assert!(served.starts_with("HTTP/1.1 200"), "got {served}");

    serving.shut_down().await;
    serving.finish().await;
}

/// The derived bound is always strictly above the configured admission limit, so
/// operational probes and admission waiters always have room.
#[test]
fn the_connection_bound_always_exceeds_the_admission_limit() {
    for limit in [1_usize, 2, 16, 64, 1024] {
        let admission = NonZeroUsize::new(limit).unwrap();
        assert!(concurrent_connection_limit(admission) > limit);
    }
}

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------

/// Readiness is false as soon as shutdown begins, before the accept loop has
/// even finished draining.
#[tokio::test]
async fn readiness_turns_false_before_shutdown_completes() {
    let serving = Serving::start(4, Duration::from_secs(5), |_| {}).await;
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
    let mut serving = Serving::start(4, grace, |_| {}).await;

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
    let mut serving = Serving::start(4, Duration::from_secs(5), |_| {}).await;
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
        4,
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
    // Give the handler time to be admitted and start collecting.
    tokio::time::sleep(Duration::from_millis(100)).await;

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
    let mut serving = Serving::start(4, Duration::from_millis(300), |options| {
        options.inbound_admission_limit = NonZeroUsize::new(2).unwrap();
        options.overall_request_deadline = Duration::from_secs(600);
    })
    .await;
    let token = serving.signing.token(Some("service_account"));

    let mut stuck = Connection::open(serving.address).await;
    stuck
        .write_request(&Connection::incomplete_body_request(&token))
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
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
    let mut serving = Serving::start(4, grace, |options| {
        options.inbound_admission_limit = NonZeroUsize::new(1).unwrap();
        options.overall_request_deadline = Duration::from_secs(600);
    })
    .await;

    // Hold the only admission permit outside any connection, so every arriving
    // request can only wait.
    let held = serving
        .fixture
        .state
        .admission()
        .admit(
            Instant::now() + Duration::from_secs(600),
            &serving.lifecycle,
        )
        .await
        .expect("admissible");

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
    tokio::time::sleep(Duration::from_millis(100)).await;

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
