//! Public authentication and cache-state regressions.

use std::{
    future::Future,
    sync::{
        Arc, Mutex,
        mpsc::{self},
    },
    task::Poll,
    time::{Duration, Instant},
};

use josekit::jws::JwsHeader;
use tokio::sync::oneshot;

use super::{
    super::{
        AuthenticationError, AuthenticationRequest, JwtAlgorithm, TargetSelection,
        TrustedVerificationSource, VerificationCachePolicy, clock::Clock,
    },
    support::{
        AlreadyCancelled, HttpsFixture, MutableCancellationSignal, NeverCancelled, SigningMaterial,
        TestClock, authenticator, build_snapshot, cache_generation, config, context, install_jwks,
    },
    transport::ScriptedResponse,
};

const FRESHNESS: Duration = Duration::from_secs(10);
const STALE_GRACE: Duration = Duration::from_secs(5);
const REQUEST_DEADLINE: Duration = Duration::from_secs(5);

fn token(material: &SigningMaterial) -> String {
    material.token(
        &SigningMaterial::bearer_payload(Some("permissionsync:cache-target")),
        &JwsHeader::new(),
    )
}

fn auth_for(
    fixture: &HttpsFixture,
    clock: TestClock,
    freshness: Duration,
    stale_grace: Duration,
) -> super::super::TechnicalCallerAuthenticator {
    authenticator(
        config(
            TrustedVerificationSource::DirectJwks {
                uri: fixture.endpoint("/jwks"),
            },
            fixture.trust_anchor_pem().to_vec(),
            vec![JwtAlgorithm::RS256],
            VerificationCachePolicy::new(freshness, stale_grace),
        ),
        clock,
    )
}

fn request_context<'a>(
    cancellation: &'a NeverCancelled,
) -> permissionsync_core::SynchronizationContext<'a> {
    context(Instant::now() + REQUEST_DEADLINE, cancellation)
}

#[tokio::test]
async fn missing_bearer_token_is_rejected_before_any_metadata_io() {
    let fixture = HttpsFixture::start(Vec::new()).await;
    let clock = TestClock::new(Instant::now(), Some(1_700_000_000.0));
    let auth = auth_for(&fixture, clock, FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;

    assert!(matches!(
        auth.authenticate(AuthenticationRequest::new(
            None,
            request_context(&cancellation)
        ))
        .await,
        Err(AuthenticationError::Rejected)
    ));
    assert_eq!(fixture.request_count(), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn oversized_bearer_token_is_rejected_before_any_metadata_io() {
    let fixture = HttpsFixture::start(Vec::new()).await;
    let clock = TestClock::new(Instant::now(), Some(1_700_000_000.0));
    let auth = auth_for(&fixture, clock, FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    let oversized = "a".repeat(super::super::MAX_TOKEN_BYTES + 1);

    assert!(matches!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&oversized),
            request_context(&cancellation)
        ))
        .await,
        Err(AuthenticationError::Rejected)
    ));
    assert_eq!(fixture.request_count(), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn cold_cache_fetches_then_authenticates_with_the_installed_verifier() {
    let material = SigningMaterial::new(JwtAlgorithm::RS256, "cold");
    let fixture = HttpsFixture::start(vec![ScriptedResponse::jwks(material.jwks())]).await;
    let clock = TestClock::new(Instant::now(), Some(1_700_000_000.0));
    let auth = auth_for(&fixture, clock, FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;

    let result = auth
        .authenticate(AuthenticationRequest::new(
            Some(&token(&material)),
            request_context(&cancellation),
        ))
        .await
        .unwrap();

    assert_eq!(result.client_id().as_str(), "test-caller");
    assert_eq!(result.bearer_token().as_str(), token(&material));
    assert!(
        matches!(result.target_selection(), TargetSelection::Selected(target) if target.as_str() == "cache-target")
    );
    assert_eq!(fixture.request_count(), 1);
    fixture.shutdown().await;
}

#[tokio::test]
async fn fresh_cache_reuses_verifier_without_metadata_io() {
    let material = SigningMaterial::new(JwtAlgorithm::RS256, "fresh");
    let fixture = HttpsFixture::start(Vec::new()).await;
    let clock = TestClock::new(Instant::now(), Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock, FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    install_jwks(&mut auth, &material.jwks(), &request_context(&cancellation))
        .await
        .unwrap();

    assert!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&token(&material)),
            request_context(&cancellation)
        ))
        .await
        .is_ok()
    );
    assert_eq!(fixture.request_count(), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn unknown_kid_refreshes_and_uses_rotated_key() {
    let old = SigningMaterial::new(JwtAlgorithm::RS256, "old");
    let rotated = SigningMaterial::new(JwtAlgorithm::RS256, "rotated");
    let fixture = HttpsFixture::start(vec![ScriptedResponse::jwks(rotated.jwks())]).await;
    let clock = TestClock::new(Instant::now(), Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock, FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    install_jwks(&mut auth, &old.jwks(), &request_context(&cancellation))
        .await
        .unwrap();

    assert!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&token(&rotated)),
            request_context(&cancellation)
        ))
        .await
        .is_ok()
    );
    assert_eq!(fixture.request_count(), 1);
    fixture.shutdown().await;
}

#[tokio::test]
async fn successful_rotation_removes_old_key_acceptance() {
    let old = SigningMaterial::new(JwtAlgorithm::RS256, "removed");
    let rotated = SigningMaterial::new(JwtAlgorithm::RS256, "current");
    let fixture = HttpsFixture::start(vec![
        ScriptedResponse::jwks(rotated.jwks()),
        ScriptedResponse::jwks(rotated.jwks()),
    ])
    .await;
    let clock = TestClock::new(Instant::now(), Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock, FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    install_jwks(&mut auth, &old.jwks(), &request_context(&cancellation))
        .await
        .unwrap();

    assert!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&token(&rotated)),
            request_context(&cancellation)
        ))
        .await
        .is_ok()
    );
    assert!(matches!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&token(&old)),
            request_context(&cancellation)
        ))
        .await,
        Err(AuthenticationError::Rejected)
    ));
    assert_eq!(fixture.request_count(), 2);
    fixture.shutdown().await;
}

#[tokio::test]
async fn stale_cache_refreshes_successfully_before_verification() {
    let material = SigningMaterial::new(JwtAlgorithm::RS256, "stale-refresh");
    let fixture = HttpsFixture::start(vec![ScriptedResponse::jwks(material.jwks())]).await;
    let now = Instant::now();
    let clock = TestClock::new(now, Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock.clone(), FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    install_jwks(&mut auth, &material.jwks(), &request_context(&cancellation))
        .await
        .unwrap();
    clock.advance(FRESHNESS + Duration::from_secs(1));

    assert!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&token(&material)),
            request_context(&cancellation)
        ))
        .await
        .is_ok()
    );
    assert_eq!(fixture.request_count(), 1);
    fixture.shutdown().await;
}

#[tokio::test]
async fn stale_outage_accepts_valid_cache_but_rejects_invalid_signature() {
    let trusted = SigningMaterial::new(JwtAlgorithm::RS256, "same-kid");
    let untrusted = SigningMaterial::new(JwtAlgorithm::RS256, "same-kid");
    let fixture = HttpsFixture::start(vec![
        ScriptedResponse::json(500, b"outage".to_vec()),
        ScriptedResponse::json(500, b"outage".to_vec()),
    ])
    .await;
    let clock = TestClock::new(Instant::now(), Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock.clone(), FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    install_jwks(&mut auth, &trusted.jwks(), &request_context(&cancellation))
        .await
        .unwrap();
    clock.advance(FRESHNESS + Duration::from_secs(1));

    assert!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&token(&trusted)),
            request_context(&cancellation)
        ))
        .await
        .is_ok()
    );
    assert!(matches!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&token(&untrusted)),
            request_context(&cancellation)
        ))
        .await,
        Err(AuthenticationError::Rejected)
    ));
    assert_eq!(fixture.request_count(), 2);
    fixture.shutdown().await;
}

#[tokio::test]
async fn stale_grace_boundary_is_inclusive_and_beyond_grace_fails_closed() {
    let material = SigningMaterial::new(JwtAlgorithm::RS256, "grace");
    let fixture = HttpsFixture::start(vec![
        ScriptedResponse::json(500, b"outage".to_vec()),
        ScriptedResponse::json(500, b"outage".to_vec()),
    ])
    .await;
    let now = Instant::now();
    let clock = TestClock::new(now, Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock.clone(), FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    install_jwks(&mut auth, &material.jwks(), &request_context(&cancellation))
        .await
        .unwrap();
    clock.advance(FRESHNESS + STALE_GRACE);

    assert!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&token(&material)),
            request_context(&cancellation)
        ))
        .await
        .is_ok()
    );
    clock.advance(Duration::from_nanos(1));
    assert!(matches!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&token(&material)),
            request_context(&cancellation)
        ))
        .await,
        Err(AuthenticationError::VerifierUnavailable)
    ));
    fixture.shutdown().await;
}

#[tokio::test]
async fn no_cache_outage_fails_closed() {
    let material = SigningMaterial::new(JwtAlgorithm::RS256, "cache-miss-outage");
    let fixture = HttpsFixture::start(vec![ScriptedResponse::json(500, b"outage".to_vec())]).await;
    let clock = TestClock::new(Instant::now(), Some(1_700_000_000.0));
    let auth = auth_for(&fixture, clock, FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;

    assert!(matches!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&token(&material)),
            request_context(&cancellation)
        ))
        .await,
        Err(AuthenticationError::VerifierUnavailable)
    ));
    fixture.shutdown().await;
}

#[tokio::test]
async fn failed_refresh_keeps_the_existing_fresh_cache() {
    let retained = SigningMaterial::new(JwtAlgorithm::RS256, "retained");
    let unknown = SigningMaterial::new(JwtAlgorithm::RS256, "unknown");
    let fixture = HttpsFixture::start(vec![ScriptedResponse::json(500, b"outage".to_vec())]).await;
    let clock = TestClock::new(Instant::now(), Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock, FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    let generation = install_jwks(&mut auth, &retained.jwks(), &request_context(&cancellation))
        .await
        .unwrap();

    assert!(matches!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&token(&unknown)),
            request_context(&cancellation)
        ))
        .await,
        Err(AuthenticationError::VerifierUnavailable)
    ));
    assert_eq!(cache_generation(&auth).await, Some(generation));
    assert!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&token(&retained)),
            request_context(&cancellation)
        ))
        .await
        .is_ok()
    );
    assert_eq!(fixture.request_count(), 1);
    fixture.shutdown().await;
}

#[tokio::test]
async fn cancellation_before_authentication_starts_no_metadata_io() {
    let material = SigningMaterial::new(JwtAlgorithm::RS256, "cancelled");
    let fixture = HttpsFixture::start(vec![ScriptedResponse::jwks(material.jwks())]).await;
    let clock = TestClock::new(Instant::now(), Some(1_700_000_000.0));
    let auth = auth_for(&fixture, clock, FRESHNESS, STALE_GRACE);
    let cancelled = AlreadyCancelled;

    assert!(matches!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&token(&material)),
            context(Instant::now() + REQUEST_DEADLINE, &cancelled),
        ))
        .await,
        Err(AuthenticationError::Cancelled)
    ));
    assert_eq!(fixture.request_count(), 0);
    fixture.shutdown().await;
}

/// Two concurrent callers needing a refresh (a fresh key-miss leader, and a
/// waiter whose cache has since aged past freshness) never cause more than
/// one metadata request and both authenticate successfully. `wait_for_request`
/// deterministically proves the leader is already mid-fetch (holding the
/// refresh mutex) before the waiter is spawned; `yield_now` only nudges
/// scheduling and does not itself guarantee the waiter has reached the
/// mutex before the leader's response is released. That distinction does not
/// weaken this test: whether the waiter reaches the mutex first (and then
/// observes the leader's fresh install without fetching again) or only
/// starts after the leader has already installed (and never calls refresh at
/// all), both interleavings deterministically yield exactly one HTTP request
/// and a single incremented generation, which is exactly what this test
/// asserts.
#[tokio::test]
async fn fresh_key_miss_and_stale_waiter_coalesce_on_the_leaders_generation() {
    let old = SigningMaterial::new(JwtAlgorithm::RS256, "coalesced-old");
    let rotated = SigningMaterial::new(JwtAlgorithm::RS256, "coalesced-new");
    let (release, held) = oneshot::channel();
    let fixture = HttpsFixture::start(vec![
        ScriptedResponse::jwks(rotated.jwks()).hold_until(held),
    ])
    .await;
    let now = Instant::now();
    let clock = TestClock::new(now, Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock.clone(), FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    let initial_generation = install_jwks(&mut auth, &old.jwks(), &request_context(&cancellation))
        .await
        .unwrap();

    let leader = {
        let auth = auth.clone();
        let bearer = token(&rotated);
        tokio::spawn(async move {
            let cancellation = NeverCancelled;
            auth.authenticate(AuthenticationRequest::new(
                Some(&bearer),
                request_context(&cancellation),
            ))
            .await
        })
    };
    fixture.wait_for_request(1).await;
    clock.advance(FRESHNESS + Duration::from_secs(1));

    let waiter = {
        let auth = auth.clone();
        let bearer = token(&rotated);
        tokio::spawn(async move {
            let cancellation = NeverCancelled;
            auth.authenticate(AuthenticationRequest::new(
                Some(&bearer),
                request_context(&cancellation),
            ))
            .await
        })
    };

    tokio::task::yield_now().await;
    release.send(()).unwrap();
    assert!(leader.await.unwrap().is_ok());
    assert!(waiter.await.unwrap().is_ok());
    assert_eq!(fixture.request_count(), 1);
    assert_eq!(cache_generation(&auth).await, Some(initial_generation + 1));
    fixture.shutdown().await;
}

#[tokio::test]
async fn cancellation_while_waiting_for_refresh_gate_takes_precedence() {
    let material = SigningMaterial::new(JwtAlgorithm::RS256, "gate-cancelled");
    let (release, held) = oneshot::channel();
    let fixture = HttpsFixture::start(vec![
        ScriptedResponse::jwks(material.jwks()).hold_until(held),
    ])
    .await;
    let clock = TestClock::new(Instant::now(), Some(1_700_000_000.0));
    let auth = auth_for(&fixture, clock, FRESHNESS, STALE_GRACE);

    let leader = {
        let auth = auth.clone();
        let bearer = token(&material);
        tokio::spawn(async move {
            let cancellation = NeverCancelled;
            auth.authenticate(AuthenticationRequest::new(
                Some(&bearer),
                request_context(&cancellation),
            ))
            .await
        })
    };
    fixture.wait_for_request(1).await;

    let waiter_cancellation = Arc::new(MutableCancellationSignal::new());
    let waiter = {
        let auth = auth.clone();
        let bearer = token(&material);
        let cancellation = Arc::clone(&waiter_cancellation);
        tokio::spawn(async move {
            auth.authenticate(AuthenticationRequest::new(
                Some(&bearer),
                context(Instant::now() + REQUEST_DEADLINE, cancellation.as_ref()),
            ))
            .await
        })
    };

    tokio::task::yield_now().await;
    waiter_cancellation.cancel();
    release.send(()).unwrap();

    assert!(leader.await.unwrap().is_ok());
    assert!(matches!(
        waiter.await.unwrap(),
        Err(AuthenticationError::Cancelled)
    ));
    assert_eq!(fixture.request_count(), 1);
    fixture.shutdown().await;
}

#[tokio::test]
async fn cancellation_during_held_refresh_response_takes_precedence() {
    let material = SigningMaterial::new(JwtAlgorithm::RS256, "response-cancelled");
    let (release, held) = oneshot::channel();
    let fixture = HttpsFixture::start(vec![ScriptedResponse::held_chunks(
        200,
        vec![(material.jwks(), held)],
    )])
    .await;
    let clock = TestClock::new(Instant::now(), Some(1_700_000_000.0));
    let auth = auth_for(&fixture, clock, FRESHNESS, STALE_GRACE);
    let cancellation = Arc::new(MutableCancellationSignal::new());
    let request = {
        let auth = auth.clone();
        let bearer = token(&material);
        let cancellation = Arc::clone(&cancellation);
        tokio::spawn(async move {
            auth.authenticate(AuthenticationRequest::new(
                Some(&bearer),
                context(Instant::now() + REQUEST_DEADLINE, cancellation.as_ref()),
            ))
            .await
        })
    };

    fixture.wait_for_request(1).await;
    fixture.wait_for_body_stage(1).await;
    cancellation.cancel();
    release.send(()).unwrap();

    assert!(matches!(
        request.await.unwrap(),
        Err(AuthenticationError::Cancelled)
    ));
    assert_eq!(fixture.request_count(), 1);
    assert_eq!(cache_generation(&auth).await, None);
    fixture.shutdown().await;
}

/// A test-only [`Clock`] whose synchronous `unix_seconds()` rendezvouses
/// with a concurrent rotation writer while the reader still holds its cache
/// read guard, then genuinely blocks (a real, synchronous `mpsc::recv`) until
/// told to proceed. This lets the test deterministically observe, via a
/// structural rendezvous rather than any timing assumption, that a
/// concurrent writer's `.write().await` cannot resolve while the reader's
/// guard is alive.
struct BlockingClock {
    tick: Instant,
    unix_seconds: f64,
    reached: Mutex<Option<oneshot::Sender<()>>>,
    proceed: Mutex<mpsc::Receiver<()>>,
}

impl BlockingClock {
    fn new(
        tick: Instant,
        unix_seconds: f64,
        reached: oneshot::Sender<()>,
        proceed: mpsc::Receiver<()>,
    ) -> Self {
        Self {
            tick,
            unix_seconds,
            reached: Mutex::new(Some(reached)),
            proceed: Mutex::new(proceed),
        }
    }
}

impl Clock for BlockingClock {
    fn tick(&self) -> Instant {
        self.tick
    }

    fn unix_seconds(&self) -> Option<f64> {
        // Only the first call rendezvous-and-blocks (announcing that the
        // read guard is held, then genuinely blocking until told to
        // proceed); any subsequent call (for example the final assertion's
        // authenticate calls, made after the rendezvous concluded) returns
        // immediately since `reached` has already been taken.
        if let Some(sender) = self.reached.lock().unwrap().take() {
            let _ = sender.send(());
            self.proceed
                .lock()
                .unwrap()
                .recv()
                .expect("proceed sender must remain live");
        }
        Some(self.unix_seconds)
    }
}

/// Blocks the first `tick()` call while the caller holds the cache read guard,
/// then delegates to the mutable test clock. This makes it possible to queue a
/// writer after the request has classified a fresh snapshot but before it can
/// make its authoritative verification decision.
struct BlockingTickClock {
    clock: TestClock,
    reached: Mutex<Option<oneshot::Sender<()>>>,
    proceed: Mutex<mpsc::Receiver<()>>,
}

impl BlockingTickClock {
    fn new(clock: TestClock, reached: oneshot::Sender<()>, proceed: mpsc::Receiver<()>) -> Self {
        Self {
            clock,
            reached: Mutex::new(Some(reached)),
            proceed: Mutex::new(proceed),
        }
    }
}

impl Clock for BlockingTickClock {
    fn tick(&self) -> Instant {
        if let Some(sender) = self.reached.lock().unwrap().take() {
            let _ = sender.send(());
            self.proceed
                .lock()
                .unwrap()
                .recv()
                .expect("proceed sender must remain live");
        }
        self.clock.tick()
    }

    fn unix_seconds(&self) -> Option<f64> {
        self.clock.unix_seconds()
    }
}

/// Blocks one selected clock tick while delegating all time values to the
/// mutable test clock. It lets a test age a freshly installed replacement
/// before the final guarded verification reads its age.
struct NthTickBlockingClock {
    clock: TestClock,
    block_on: usize,
    ticks: Mutex<usize>,
    reached: Mutex<Option<oneshot::Sender<()>>>,
    proceed: Mutex<mpsc::Receiver<()>>,
}

impl NthTickBlockingClock {
    fn new(
        clock: TestClock,
        block_on: usize,
        reached: oneshot::Sender<()>,
        proceed: mpsc::Receiver<()>,
    ) -> Self {
        Self {
            clock,
            block_on,
            ticks: Mutex::new(0),
            reached: Mutex::new(Some(reached)),
            proceed: Mutex::new(proceed),
        }
    }
}

impl Clock for NthTickBlockingClock {
    fn tick(&self) -> Instant {
        let should_block = {
            let mut ticks = self.ticks.lock().unwrap();
            *ticks += 1;
            *ticks == self.block_on
        };
        if should_block {
            let sender = self
                .reached
                .lock()
                .unwrap()
                .take()
                .expect("selected clock tick must signal once");
            let _ = sender.send(());
            self.proceed
                .lock()
                .unwrap()
                .recv()
                .expect("proceed sender must remain live");
        }
        self.clock.tick()
    }

    fn unix_seconds(&self) -> Option<f64> {
        self.clock.unix_seconds()
    }
}

/// A request that initially observes a fresh verifier must preserve a
/// definitive bad-claim rejection when the guarded verification decision sees
/// that verifier as stale. Claim shape is conclusive, so this path neither
/// authenticates nor consults metadata.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_initial_cache_and_stale_guarded_bad_claims_are_rejected_without_metadata_io() {
    let material = SigningMaterial::new(JwtAlgorithm::RS256, "guarded-bad-claims");
    let fixture = HttpsFixture::start(Vec::new()).await;
    let now = Instant::now();
    let clock = TestClock::new(now, Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock.clone(), FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    install_jwks(&mut auth, &material.jwks(), &request_context(&cancellation))
        .await
        .unwrap();

    let mut claims: serde_json::Value = serde_json::from_slice(&SigningMaterial::bearer_payload(
        Some("permissionsync:cache-target"),
    ))
    .unwrap();
    claims["client_id"] = serde_json::json!(["test-caller"]);
    let bad_claims_token = material.token(&serde_json::to_vec(&claims).unwrap(), &JwsHeader::new());

    let (reached_tx, reached_rx) = oneshot::channel();
    let (proceed_tx, proceed_rx) = mpsc::channel();
    Arc::get_mut(&mut auth.inner).unwrap().clock = Arc::new(NthTickBlockingClock::new(
        clock.clone(),
        2,
        reached_tx,
        proceed_rx,
    ));
    let request = {
        let auth = auth.clone();
        tokio::spawn(async move {
            let cancellation = NeverCancelled;
            auth.authenticate(AuthenticationRequest::new(
                Some(&bad_claims_token),
                request_context(&cancellation),
            ))
            .await
        })
    };
    reached_rx
        .await
        .expect("guarded verification must reach its cache-age check");
    clock.advance(FRESHNESS + Duration::from_secs(1));
    proceed_tx
        .send(())
        .expect("guarded verification must still await release");

    assert!(matches!(
        request.await.unwrap(),
        Err(AuthenticationError::Rejected)
    ));
    assert_eq!(fixture.request_count(), 0);
    fixture.shutdown().await;
}

/// A request may classify a snapshot as fresh only for refresh control flow;
/// it must not authorize that snapshot if it becomes expired while queued for
/// the verification read guard. The first clock tick blocks while
/// `classify_cache` holds its read guard. A writer queued at that point has
/// priority over the request's next read, so the test can advance the mutable
/// clock beyond stale grace before that authoritative decision gets its guard.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_verification_reclassifies_cache_age_under_its_read_guard() {
    let material = SigningMaterial::new(JwtAlgorithm::RS256, "queued-age");
    let fixture = HttpsFixture::start(vec![ScriptedResponse::json(500, b"outage".to_vec())]).await;
    let now = Instant::now();
    let clock = TestClock::new(now, Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock.clone(), FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    install_jwks(&mut auth, &material.jwks(), &request_context(&cancellation))
        .await
        .unwrap();

    let (classified_tx, classified_rx) = oneshot::channel();
    let (proceed_tx, proceed_rx) = mpsc::channel();
    Arc::get_mut(&mut auth.inner).unwrap().clock = Arc::new(BlockingTickClock::new(
        clock.clone(),
        classified_tx,
        proceed_rx,
    ));

    let request = {
        let auth = auth.clone();
        let bearer = token(&material);
        tokio::spawn(async move {
            let cancellation = NeverCancelled;
            auth.authenticate(AuthenticationRequest::new(
                Some(&bearer),
                request_context(&cancellation),
            ))
            .await
        })
    };
    classified_rx
        .await
        .expect("request must classify the cache while holding its read guard");

    let (writer_queued_tx, writer_queued_rx) = oneshot::channel();
    let (writer_acquired_tx, writer_acquired_rx) = oneshot::channel();
    let (release_writer_tx, release_writer_rx) = oneshot::channel();
    let writer = {
        let auth = auth.clone();
        tokio::spawn(async move {
            let mut acquisition = Box::pin(auth.test_only_cache().write());
            std::future::poll_fn(|context| match acquisition.as_mut().poll(context) {
                Poll::Pending => Poll::Ready(()),
                Poll::Ready(_) => panic!("classifier's held read guard must queue the writer"),
            })
            .await;
            writer_queued_tx
                .send(())
                .expect("test must observe the writer queued on the cache lock");
            let _guard = acquisition.await;
            let _ = writer_acquired_tx.send(());
            release_writer_rx
                .await
                .expect("test must release the queued writer");
        })
    };

    writer_queued_rx
        .await
        .expect("writer must be queued before the classifier releases its guard");

    proceed_tx
        .send(())
        .expect("classifier must still be waiting on the proceed signal");
    writer_acquired_rx
        .await
        .expect("queued writer must acquire before verification can re-read");
    clock.advance(FRESHNESS + STALE_GRACE + Duration::from_nanos(1));
    release_writer_tx
        .send(())
        .expect("queued writer must still be holding the lock");
    writer.await.unwrap();

    assert!(matches!(
        request.await.unwrap(),
        Err(AuthenticationError::VerifierUnavailable)
    ));
    assert_eq!(fixture.request_count(), 1);
    fixture.shutdown().await;
}

/// A signature failure found by the guarded stale decision is conclusive even
/// if the sole permitted refresh fails after the cache has subsequently
/// expired. The held response gives the test a structural point to advance the
/// cache age, without a wall-clock sleep.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_to_stale_signature_invalid_stays_rejected_after_expiring_during_refresh_failure() {
    let trusted = SigningMaterial::new(JwtAlgorithm::RS256, "stale-invalid");
    let attacker = SigningMaterial::new(JwtAlgorithm::RS256, "stale-invalid");
    let (release_response, held_response) = oneshot::channel();
    let fixture = HttpsFixture::start(vec![
        ScriptedResponse::json(500, b"outage".to_vec()).hold_until(held_response),
    ])
    .await;
    let now = Instant::now();
    let clock = TestClock::new(now, Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock.clone(), FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    install_jwks(&mut auth, &trusted.jwks(), &request_context(&cancellation))
        .await
        .unwrap();

    let (classified_tx, classified_rx) = oneshot::channel();
    let (proceed_tx, proceed_rx) = mpsc::channel();
    Arc::get_mut(&mut auth.inner).unwrap().clock = Arc::new(BlockingTickClock::new(
        clock.clone(),
        classified_tx,
        proceed_rx,
    ));
    let request = {
        let auth = auth.clone();
        let bearer = token(&attacker);
        tokio::spawn(async move {
            let cancellation = NeverCancelled;
            auth.authenticate(AuthenticationRequest::new(
                Some(&bearer),
                request_context(&cancellation),
            ))
            .await
        })
    };
    classified_rx
        .await
        .expect("request must classify the fresh cache under its read guard");

    let (writer_queued_tx, writer_queued_rx) = oneshot::channel();
    let (writer_acquired_tx, writer_acquired_rx) = oneshot::channel();
    let (release_writer_tx, release_writer_rx) = oneshot::channel();
    let writer = {
        let auth = auth.clone();
        tokio::spawn(async move {
            let mut acquisition = Box::pin(auth.test_only_cache().write());
            std::future::poll_fn(|context| match acquisition.as_mut().poll(context) {
                Poll::Pending => Poll::Ready(()),
                Poll::Ready(_) => panic!("classifier's held read guard must queue the writer"),
            })
            .await;
            writer_queued_tx.send(()).unwrap();
            let _guard = acquisition.await;
            writer_acquired_tx.send(()).unwrap();
            release_writer_rx.await.unwrap();
        })
    };
    writer_queued_rx.await.unwrap();
    proceed_tx.send(()).unwrap();
    writer_acquired_rx.await.unwrap();
    clock.advance(FRESHNESS + Duration::from_secs(1));
    release_writer_tx.send(()).unwrap();
    writer.await.unwrap();

    fixture.wait_for_request(1).await;
    clock.advance(STALE_GRACE);
    release_response.send(()).unwrap();
    assert!(matches!(
        request.await.unwrap(),
        Err(AuthenticationError::Rejected)
    ));
    assert_eq!(fixture.request_count(), 1);
    fixture.shutdown().await;
}

/// After a successful trusted refresh, a stale no-candidate outcome is a
/// conclusive rejection rather than verifier unavailability.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successful_refresh_stale_no_candidate_is_rejected() {
    let old = SigningMaterial::new(JwtAlgorithm::RS256, "stale-empty-old");
    let fixture =
        HttpsFixture::start(vec![ScriptedResponse::json(200, b"{\"keys\":[]}".to_vec())]).await;
    let now = Instant::now();
    let clock = TestClock::new(now, Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock.clone(), FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    install_jwks(&mut auth, &old.jwks(), &request_context(&cancellation))
        .await
        .unwrap();
    clock.advance(FRESHNESS + Duration::from_secs(1));

    let (reached_tx, reached_rx) = oneshot::channel();
    let (proceed_tx, proceed_rx) = mpsc::channel();
    Arc::get_mut(&mut auth.inner).unwrap().clock = Arc::new(NthTickBlockingClock::new(
        clock.clone(),
        4,
        reached_tx,
        proceed_rx,
    ));
    let request = {
        let auth = auth.clone();
        let bearer = token(&old);
        tokio::spawn(async move {
            let cancellation = NeverCancelled;
            auth.authenticate(AuthenticationRequest::new(
                Some(&bearer),
                request_context(&cancellation),
            ))
            .await
        })
    };
    reached_rx
        .await
        .expect("final verification must reach its guarded age check");
    clock.advance(FRESHNESS + Duration::from_secs(1));
    proceed_tx.send(()).unwrap();

    assert!(matches!(
        request.await.unwrap(),
        Err(AuthenticationError::Rejected)
    ));
    assert_eq!(fixture.request_count(), 1);
    fixture.shutdown().await;
}

/// A stale valid result from a successful refresh cannot authorize, even
/// though stale definitive rejection outcomes are retained.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successful_refresh_stale_valid_is_verifier_unavailable() {
    let material = SigningMaterial::new(JwtAlgorithm::RS256, "stale-valid");
    let fixture = HttpsFixture::start(vec![ScriptedResponse::jwks(material.jwks())]).await;
    let now = Instant::now();
    let clock = TestClock::new(now, Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock.clone(), FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    install_jwks(&mut auth, &material.jwks(), &request_context(&cancellation))
        .await
        .unwrap();
    clock.advance(FRESHNESS + Duration::from_secs(1));

    let (reached_tx, reached_rx) = oneshot::channel();
    let (proceed_tx, proceed_rx) = mpsc::channel();
    Arc::get_mut(&mut auth.inner).unwrap().clock = Arc::new(NthTickBlockingClock::new(
        clock.clone(),
        4,
        reached_tx,
        proceed_rx,
    ));
    let request = {
        let auth = auth.clone();
        let bearer = token(&material);
        tokio::spawn(async move {
            let cancellation = NeverCancelled;
            auth.authenticate(AuthenticationRequest::new(
                Some(&bearer),
                request_context(&cancellation),
            ))
            .await
        })
    };
    reached_rx
        .await
        .expect("final verification must reach its guarded age check");
    clock.advance(FRESHNESS + Duration::from_secs(1));
    proceed_tx.send(()).unwrap();

    assert!(matches!(
        request.await.unwrap(),
        Err(AuthenticationError::VerifierUnavailable)
    ));
    assert_eq!(fixture.request_count(), 1);
    fixture.shutdown().await;
}

/// A stale result cannot establish authentication and therefore cannot return
/// the authorization-only `Forbidden` outcome after a successful refresh.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successful_refresh_stale_forbidden_is_verifier_unavailable() {
    let material = SigningMaterial::new(JwtAlgorithm::RS256, "stale-forbidden");
    let fixture = HttpsFixture::start(vec![ScriptedResponse::jwks(material.jwks())]).await;
    let now = Instant::now();
    let clock = TestClock::new(now, Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock.clone(), FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    install_jwks(&mut auth, &material.jwks(), &request_context(&cancellation))
        .await
        .unwrap();
    clock.advance(FRESHNESS + Duration::from_secs(1));

    let (reached_tx, reached_rx) = oneshot::channel();
    let (proceed_tx, proceed_rx) = mpsc::channel();
    Arc::get_mut(&mut auth.inner).unwrap().clock = Arc::new(NthTickBlockingClock::new(
        clock.clone(),
        4,
        reached_tx,
        proceed_rx,
    ));
    let request = {
        let auth = auth.clone();
        let bearer = material.token(
            &SigningMaterial::bearer_payload(Some("permissionsync:first permissionsync:second")),
            &JwsHeader::new(),
        );
        tokio::spawn(async move {
            let cancellation = NeverCancelled;
            auth.authenticate(AuthenticationRequest::new(
                Some(&bearer),
                request_context(&cancellation),
            ))
            .await
        })
    };
    reached_rx
        .await
        .expect("final verification must reach its guarded age check");
    clock.advance(FRESHNESS + Duration::from_secs(1));
    proceed_tx.send(()).unwrap();

    assert!(matches!(
        request.await.unwrap(),
        Err(AuthenticationError::VerifierUnavailable)
    ));
    assert_eq!(fixture.request_count(), 1);
    fixture.shutdown().await;
}

/// The real asynchronous cache lock must consume the request's overall budget:
/// this manually polls the public authentication future until its initial cache
/// read is pending behind a held write guard, then advances Tokio's paused time
/// past the context deadline. No scheduler timing or wall-clock sleep is used.
#[tokio::test(start_paused = true)]
async fn cache_read_wait_is_bounded_by_the_overall_request_deadline() {
    let material = SigningMaterial::new(JwtAlgorithm::RS256, "read-deadline");
    let fixture = HttpsFixture::start(Vec::new()).await;
    let clock = TestClock::new(Instant::now(), Some(1_700_000_000.0));
    let auth = auth_for(&fixture, clock, FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    let deadline = Instant::now() + Duration::from_secs(1);
    let write_guard = auth.test_only_cache().write().await;
    let bearer = token(&material);
    let mut authentication = Box::pin(auth.authenticate(AuthenticationRequest::new(
        Some(&bearer),
        context(deadline, &cancellation),
    )));

    std::future::poll_fn(|context| match authentication.as_mut().poll(context) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(_) => panic!("held cache write guard must make authentication wait"),
    })
    .await;
    tokio::time::advance(Duration::from_secs(1)).await;

    assert!(matches!(
        authentication.await,
        Err(AuthenticationError::Cancelled)
    ));
    assert_eq!(fixture.request_count(), 0);
    drop(write_guard);
    fixture.shutdown().await;
}

/// Refresh coalescing must assess a newer generation's age after obtaining its
/// cache read guard. Manual polling proves the check is queued behind the real
/// write lock before the mutable clock crosses freshness.
#[tokio::test]
async fn refresh_coalescing_rechecks_newer_generation_age_after_lock_wait() {
    let material = SigningMaterial::new(JwtAlgorithm::RS256, "coalesced-age");
    let fixture = HttpsFixture::start(Vec::new()).await;
    let now = Instant::now();
    let clock = TestClock::new(now, Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock.clone(), FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    let generation = install_jwks(&mut auth, &material.jwks(), &request_context(&cancellation))
        .await
        .unwrap();
    let write_guard = auth.test_only_cache().write().await;
    let request_context = request_context(&cancellation);
    let mut coalesced =
        Box::pin(auth.newer_generation_is_currently_fresh(&request_context, generation - 1));

    std::future::poll_fn(|context| match coalesced.as_mut().poll(context) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(_) => panic!("held cache write guard must make coalescing wait"),
    })
    .await;
    clock.advance(FRESHNESS + Duration::from_secs(1));
    drop(write_guard);

    assert!(!coalesced.await.unwrap());
    fixture.shutdown().await;
}

/// Deterministic, structural regression: while
/// [`TechnicalCallerAuthenticator::verify_current`]'s read guard is held (its
/// synchronous decision calls `Clock::unix_seconds`, which this test blocks
/// inside), a concurrent successful rotation writer's `.write().await`
/// literally cannot have resolved yet. This is `tokio::sync::RwLock` mutual
/// exclusion linearized against the reader's guard lifetime, not a timing
/// coincidence: the writer task announces (via a second channel) only after
/// its write guard is acquired, and this test observes that announcement has
/// not occurred while the reader is still blocked mid-decision.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_read_guard_structurally_excludes_a_concurrent_rotation_write() {
    let key_a = SigningMaterial::new(JwtAlgorithm::RS256, "shared");
    let key_b = SigningMaterial::new(JwtAlgorithm::RS256, "shared");
    let fixture = HttpsFixture::start(vec![ScriptedResponse::json(500, b"outage".to_vec())]).await;
    let clock = TestClock::new(Instant::now(), Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock, FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    let generation_a = install_jwks(&mut auth, &key_a.jwks(), &request_context(&cancellation))
        .await
        .unwrap();
    let snapshot_b = build_snapshot(
        &auth,
        &key_b.jwks(),
        generation_a + 1,
        &request_context(&cancellation),
    )
    .unwrap();

    let (reached_tx, reached_rx) = oneshot::channel();
    let (proceed_tx, proceed_rx) = mpsc::channel::<()>();
    let blocking_clock =
        BlockingClock::new(Instant::now(), 1_700_000_000.0, reached_tx, proceed_rx);
    Arc::get_mut(&mut auth.inner).unwrap().clock = Arc::new(blocking_clock);

    let (write_acquired_tx, mut write_acquired_rx) = oneshot::channel();

    let reader = {
        let auth = auth.clone();
        let bearer = token(&key_a);
        tokio::spawn(async move {
            let cancellation = NeverCancelled;
            auth.authenticate(AuthenticationRequest::new(
                Some(&bearer),
                request_context(&cancellation),
            ))
            .await
        })
    };

    reached_rx
        .await
        .expect("reader must reach the clock decision point while holding its read guard");

    let writer = {
        let auth = auth.clone();
        tokio::spawn(async move {
            let mut guard = auth.test_only_cache().write().await;
            let _ = write_acquired_tx.send(());
            *guard = Some(snapshot_b);
        })
    };

    // Structural guarantee, not a timing race: the reader still holds its
    // read guard (blocked synchronously inside `unix_seconds()`), so the
    // writer's `.write().await` future cannot possibly have resolved yet,
    // regardless of scheduling. `try_recv` must observe the channel is still
    // empty.
    assert!(matches!(
        write_acquired_rx.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    proceed_tx
        .send(())
        .expect("reader task must still be waiting on the proceed signal");

    assert!(reader.await.unwrap().is_ok());
    write_acquired_rx
        .await
        .expect("writer must signal after acquiring the write lock");
    writer.await.unwrap();

    assert!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&token(&key_b)),
            request_context(&cancellation)
        ))
        .await
        .is_ok()
    );
    assert!(matches!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&token(&key_a)),
            request_context(&cancellation)
        ))
        .await,
        Err(AuthenticationError::Rejected)
    ));
    assert_eq!(fixture.request_count(), 1);
    fixture.shutdown().await;
}

#[tokio::test]
async fn fresh_same_kid_legitimate_rotation_succeeds_after_one_refresh() {
    let old = SigningMaterial::new(JwtAlgorithm::RS256, "shared");
    let rotated = SigningMaterial::new(JwtAlgorithm::RS256, "shared");
    let fixture = HttpsFixture::start(vec![ScriptedResponse::jwks(rotated.jwks())]).await;
    let clock = TestClock::new(Instant::now(), Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock, FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    install_jwks(&mut auth, &old.jwks(), &request_context(&cancellation))
        .await
        .unwrap();

    assert!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&token(&rotated)),
            request_context(&cancellation)
        ))
        .await
        .is_ok()
    );
    assert_eq!(fixture.request_count(), 1);
    fixture.shutdown().await;
}

#[tokio::test]
async fn fresh_same_kid_attacker_signature_rejected_after_refresh_serves_trusted_key() {
    let cache_key = SigningMaterial::new(JwtAlgorithm::RS256, "shared");
    let trusted_after_refresh = SigningMaterial::new(JwtAlgorithm::RS256, "shared");
    let attacker = SigningMaterial::new(JwtAlgorithm::RS256, "shared");
    let fixture =
        HttpsFixture::start(vec![ScriptedResponse::jwks(trusted_after_refresh.jwks())]).await;
    let clock = TestClock::new(Instant::now(), Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock, FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    install_jwks(
        &mut auth,
        &cache_key.jwks(),
        &request_context(&cancellation),
    )
    .await
    .unwrap();

    assert!(matches!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&token(&attacker)),
            request_context(&cancellation)
        ))
        .await,
        Err(AuthenticationError::Rejected)
    ));
    assert_eq!(fixture.request_count(), 1);
    fixture.shutdown().await;
}

#[tokio::test]
async fn fresh_signature_invalid_with_refresh_outage_rejects_not_verifier_unavailable() {
    let trusted = SigningMaterial::new(JwtAlgorithm::RS256, "outage-kid");
    let attacker = SigningMaterial::new(JwtAlgorithm::RS256, "outage-kid");
    let fixture = HttpsFixture::start(vec![ScriptedResponse::json(500, b"outage".to_vec())]).await;
    let clock = TestClock::new(Instant::now(), Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock, FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    install_jwks(&mut auth, &trusted.jwks(), &request_context(&cancellation))
        .await
        .unwrap();

    assert!(matches!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&token(&attacker)),
            request_context(&cancellation)
        ))
        .await,
        Err(AuthenticationError::Rejected)
    ));
    assert_eq!(fixture.request_count(), 1);
    fixture.shutdown().await;
}

#[tokio::test]
async fn stale_outage_with_unknown_kid_is_verifier_unavailable_not_rejected() {
    let cached = SigningMaterial::new(JwtAlgorithm::RS256, "stale-known");
    let unknown = SigningMaterial::new(JwtAlgorithm::RS256, "stale-unknown");
    let fixture = HttpsFixture::start(vec![ScriptedResponse::json(500, b"outage".to_vec())]).await;
    let now = Instant::now();
    let clock = TestClock::new(now, Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock.clone(), FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    install_jwks(&mut auth, &cached.jwks(), &request_context(&cancellation))
        .await
        .unwrap();
    clock.advance(FRESHNESS + Duration::from_secs(1));

    assert!(matches!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&token(&unknown)),
            request_context(&cancellation)
        ))
        .await,
        Err(AuthenticationError::VerifierUnavailable)
    ));
    assert_eq!(fixture.request_count(), 1);
    fixture.shutdown().await;
}

#[tokio::test]
async fn dropping_the_authentication_future_before_completion_never_mutates_the_cache() {
    let material = SigningMaterial::new(JwtAlgorithm::RS256, "dropped-refresh");
    let (release, held) = oneshot::channel();
    let fixture = HttpsFixture::start(vec![
        ScriptedResponse::jwks(material.jwks()).hold_until(held),
    ])
    .await;
    let clock = TestClock::new(Instant::now(), Some(1_700_000_000.0));
    let auth = auth_for(&fixture, clock, FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    let baseline_generation = cache_generation(&auth).await;

    {
        let bearer = token(&material);
        let authentication = auth.authenticate(AuthenticationRequest::new(
            Some(&bearer),
            request_context(&cancellation),
        ));
        tokio::pin!(authentication);

        tokio::select! {
            _ = fixture.wait_for_request(1) => {},
            _ = &mut authentication => panic!("authentication completed before its refresh response was released"),
        }
        // `authentication` is dropped here, before the held response is
        // ever released: the in-flight refresh future is discarded
        // mid-flight and must never install a cache write.
    }
    release
        .send(())
        .expect("held response must still accept release after the future was dropped");

    assert_eq!(cache_generation(&auth).await, baseline_generation);
    fixture.shutdown().await;
}

#[tokio::test]
async fn successful_empty_jwks_replacement_rejects_previously_trusted_key() {
    let key_a = SigningMaterial::new(JwtAlgorithm::RS256, "emptied");
    let fixture =
        HttpsFixture::start(vec![ScriptedResponse::json(200, b"{\"keys\":[]}".to_vec())]).await;
    let clock = TestClock::new(Instant::now(), Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock.clone(), FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    let generation = install_jwks(&mut auth, &key_a.jwks(), &request_context(&cancellation))
        .await
        .unwrap();
    clock.advance(FRESHNESS + Duration::from_secs(1));

    assert!(matches!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&token(&key_a)),
            request_context(&cancellation)
        ))
        .await,
        Err(AuthenticationError::Rejected)
    ));
    assert_eq!(fixture.request_count(), 1);
    assert_eq!(cache_generation(&auth).await, Some(generation + 1));
    fixture.shutdown().await;
}

fn unsupported_public_jwk() -> serde_json::Value {
    serde_json::json!({"kty": "AKP", "pub": "AA"})
}

#[tokio::test]
async fn future_only_public_jwks_replacement_rejects_previously_trusted_key() {
    let key_a = SigningMaterial::new(JwtAlgorithm::RS256, "future-only-old");
    let replacement = serde_json::json!({"keys": [unsupported_public_jwk()]});
    let fixture = HttpsFixture::start(vec![ScriptedResponse::json(
        200,
        serde_json::to_vec(&replacement).unwrap(),
    )])
    .await;
    let now = Instant::now();
    let clock = TestClock::new(now, Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock.clone(), FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    let generation = install_jwks(&mut auth, &key_a.jwks(), &request_context(&cancellation))
        .await
        .unwrap();
    clock.advance(FRESHNESS + Duration::from_secs(1));

    assert!(matches!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&token(&key_a)),
            request_context(&cancellation)
        ))
        .await,
        Err(AuthenticationError::Rejected)
    ));
    assert_eq!(fixture.request_count(), 1);
    assert_eq!(cache_generation(&auth).await, Some(generation + 1));
    fixture.shutdown().await;
}

fn encryption_only_jwk(material: &SigningMaterial) -> serde_json::Value {
    let jwks: serde_json::Value = serde_json::from_slice(&material.jwks()).unwrap();
    let mut key = jwks["keys"][0].clone();
    key.as_object_mut().unwrap().insert(
        "use".to_owned(),
        serde_json::Value::String("enc".to_owned()),
    );
    key
}

#[tokio::test]
async fn all_encryption_jwks_replacement_rejects_previously_trusted_key() {
    let key_a = SigningMaterial::new(JwtAlgorithm::RS256, "encrypted-out");
    let encryption_only = SigningMaterial::new(JwtAlgorithm::RS256, "enc-only");
    let replacement = serde_json::json!({"keys": [encryption_only_jwk(&encryption_only)]});
    let fixture = HttpsFixture::start(vec![ScriptedResponse::json(
        200,
        serde_json::to_vec(&replacement).unwrap(),
    )])
    .await;
    let clock = TestClock::new(Instant::now(), Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock.clone(), FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    let generation = install_jwks(&mut auth, &key_a.jwks(), &request_context(&cancellation))
        .await
        .unwrap();
    clock.advance(FRESHNESS + Duration::from_secs(1));

    assert!(matches!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&token(&key_a)),
            request_context(&cancellation)
        ))
        .await,
        Err(AuthenticationError::Rejected)
    ));
    assert_eq!(fixture.request_count(), 1);
    assert_eq!(cache_generation(&auth).await, Some(generation + 1));
    fixture.shutdown().await;
}

#[tokio::test]
async fn mixed_signing_and_encryption_jwks_authenticates_with_the_signing_key() {
    let key_a = SigningMaterial::new(JwtAlgorithm::RS256, "mixed-old");
    let signing_b = SigningMaterial::new(JwtAlgorithm::RS256, "mixed-signing");
    let encryption_only = SigningMaterial::new(JwtAlgorithm::RS256, "mixed-enc");
    let signing_b_jwks: serde_json::Value = serde_json::from_slice(&signing_b.jwks()).unwrap();
    let mixed = serde_json::json!({"keys": [
        signing_b_jwks["keys"][0].clone(),
        encryption_only_jwk(&encryption_only),
    ]});
    let fixture = HttpsFixture::start(vec![ScriptedResponse::json(
        200,
        serde_json::to_vec(&mixed).unwrap(),
    )])
    .await;
    let clock = TestClock::new(Instant::now(), Some(1_700_000_000.0));
    let mut auth = auth_for(&fixture, clock, FRESHNESS, STALE_GRACE);
    let cancellation = NeverCancelled;
    install_jwks(&mut auth, &key_a.jwks(), &request_context(&cancellation))
        .await
        .unwrap();

    assert!(
        auth.authenticate(AuthenticationRequest::new(
            Some(&token(&signing_b)),
            request_context(&cancellation)
        ))
        .await
        .is_ok()
    );
    assert_eq!(fixture.request_count(), 1);
    fixture.shutdown().await;
}
