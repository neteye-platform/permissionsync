//! Adversarial coverage for the trusted-verifier-state capability that the
//! executable runtime uses for readiness and bounded warm-up.
//!
//! These tests use only the crate's own local HTTPS fixture, deterministic
//! signing material, and a controlled clock. They assert the public capability
//! against the real authenticator cache, refresh serialization, and cache
//! policy; there is no separate readiness state and no synthetic token.

use std::time::{Duration, Instant};

use permissionsync_core::SynchronizationContext;

use super::{
    super::{
        JwtAlgorithm, TrustedVerifierState,
        config::{TrustedVerificationSource, VerificationCachePolicy},
    },
    support::{
        HttpsFixture, NeverCancelled, SigningMaterial, TestClock, authenticator, cache_generation,
        config, context, install_jwks,
    },
    transport::ScriptedResponse,
};

const FRESHNESS: Duration = Duration::from_secs(300);
const STALE_IF_ERROR: Duration = Duration::from_secs(600);

fn policy() -> VerificationCachePolicy {
    VerificationCachePolicy::new(FRESHNESS, STALE_IF_ERROR)
}

/// A readiness/warm-up budget is bounded and never the caller's budget.
fn probe_deadline(now: Instant) -> Instant {
    now + Duration::from_secs(5)
}

#[tokio::test]
async fn absent_trusted_state_is_unusable_without_any_metadata_request() {
    let fixture = HttpsFixture::start(Vec::new()).await;
    let now = Instant::now();
    let clock = TestClock::new(now, Some(1_700_000_000.0));
    let authenticator = authenticator(
        config(
            TrustedVerificationSource::DirectJwks {
                uri: fixture.endpoint("/keys"),
            },
            fixture.trust_anchor_pem().to_vec(),
            vec![JwtAlgorithm::RS256],
            policy(),
        ),
        clock,
    );
    let cancellation = NeverCancelled;
    let probe = context(probe_deadline(now), &cancellation);

    assert_eq!(
        authenticator.trusted_verifier_state(&probe).await,
        TrustedVerifierState::Unusable
    );
    assert_eq!(fixture.request_count(), 0);
    assert_eq!(cache_generation(&authenticator).await, None);

    fixture.shutdown().await;
}

#[tokio::test]
async fn bounded_warm_up_installs_usable_trusted_state() {
    let signing = SigningMaterial::new(JwtAlgorithm::RS256, "warm-up-key");
    let fixture = HttpsFixture::start(vec![ScriptedResponse::jwks(signing.jwks())]).await;
    let now = Instant::now();
    let authenticator = authenticator(
        config(
            TrustedVerificationSource::DirectJwks {
                uri: fixture.endpoint("/keys"),
            },
            fixture.trust_anchor_pem().to_vec(),
            vec![JwtAlgorithm::RS256],
            policy(),
        ),
        TestClock::new(now, Some(1_700_000_000.0)),
    );
    let cancellation = NeverCancelled;
    let probe = context(probe_deadline(now), &cancellation);

    assert_eq!(
        authenticator.ensure_trusted_verifier_state(&probe).await,
        TrustedVerifierState::Usable
    );
    assert_eq!(fixture.request_count(), 1);
    assert_eq!(cache_generation(&authenticator).await, Some(1));

    fixture.shutdown().await;
}

#[tokio::test]
async fn already_usable_trusted_state_performs_no_further_retrieval() {
    let signing = SigningMaterial::new(JwtAlgorithm::RS256, "reuse-key");
    let fixture = HttpsFixture::start(vec![ScriptedResponse::jwks(signing.jwks())]).await;
    let now = Instant::now();
    let authenticator = authenticator(
        config(
            TrustedVerificationSource::DirectJwks {
                uri: fixture.endpoint("/keys"),
            },
            fixture.trust_anchor_pem().to_vec(),
            vec![JwtAlgorithm::RS256],
            policy(),
        ),
        TestClock::new(now, Some(1_700_000_000.0)),
    );
    let cancellation = NeverCancelled;
    let probe = context(probe_deadline(now), &cancellation);

    assert_eq!(
        authenticator.ensure_trusted_verifier_state(&probe).await,
        TrustedVerifierState::Usable
    );
    assert_eq!(
        authenticator.ensure_trusted_verifier_state(&probe).await,
        TrustedVerifierState::Usable
    );
    assert_eq!(
        authenticator.trusted_verifier_state(&probe).await,
        TrustedVerifierState::Usable
    );

    assert_eq!(fixture.request_count(), 1);
    assert_eq!(cache_generation(&authenticator).await, Some(1));

    fixture.shutdown().await;
}

/// ADR 0002 keeps bounded stale-if-error material usable, so a temporary
/// metadata outage must not make the process unready and must not trigger a
/// refresh that readiness does not need.
#[tokio::test]
async fn bounded_stale_trusted_state_stays_usable_during_a_metadata_outage() {
    let signing = SigningMaterial::new(JwtAlgorithm::RS256, "stale-key");
    let fixture = HttpsFixture::start(vec![ScriptedResponse::json(500, Vec::new())]).await;
    let now = Instant::now();
    let clock = TestClock::new(now, Some(1_700_000_000.0));
    let mut authenticator = authenticator(
        config(
            TrustedVerificationSource::DirectJwks {
                uri: fixture.endpoint("/keys"),
            },
            fixture.trust_anchor_pem().to_vec(),
            vec![JwtAlgorithm::RS256],
            policy(),
        ),
        clock.clone(),
    );
    let cancellation = NeverCancelled;
    let seed = context(probe_deadline(now), &cancellation);
    install_jwks(&mut authenticator, &signing.jwks(), &seed)
        .await
        .unwrap();

    clock.advance(FRESHNESS + Duration::from_secs(1));
    let probe = context(probe_deadline(Instant::now()), &cancellation);

    assert_eq!(
        authenticator.trusted_verifier_state(&probe).await,
        TrustedVerifierState::Usable
    );
    assert_eq!(
        authenticator.ensure_trusted_verifier_state(&probe).await,
        TrustedVerifierState::Usable
    );
    assert_eq!(fixture.request_count(), 0);

    fixture.shutdown().await;
}

#[tokio::test]
async fn trusted_state_beyond_the_stale_grace_is_unusable() {
    let signing = SigningMaterial::new(JwtAlgorithm::RS256, "expired-key");
    let fixture = HttpsFixture::start(vec![ScriptedResponse::json(500, Vec::new())]).await;
    let now = Instant::now();
    let clock = TestClock::new(now, Some(1_700_000_000.0));
    let mut authenticator = authenticator(
        config(
            TrustedVerificationSource::DirectJwks {
                uri: fixture.endpoint("/keys"),
            },
            fixture.trust_anchor_pem().to_vec(),
            vec![JwtAlgorithm::RS256],
            policy(),
        ),
        clock.clone(),
    );
    let cancellation = NeverCancelled;
    let seed = context(probe_deadline(now), &cancellation);
    install_jwks(&mut authenticator, &signing.jwks(), &seed)
        .await
        .unwrap();

    clock.advance(FRESHNESS + STALE_IF_ERROR + Duration::from_secs(1));
    let probe = context(probe_deadline(Instant::now()), &cancellation);

    assert_eq!(
        authenticator.trusted_verifier_state(&probe).await,
        TrustedVerifierState::Unusable
    );
    assert_eq!(fixture.request_count(), 0);

    // The one permitted bounded refresh is attempted and fails, so the state
    // remains unusable rather than becoming ready on a source failure.
    assert_eq!(
        authenticator.ensure_trusted_verifier_state(&probe).await,
        TrustedVerifierState::Unusable
    );
    assert_eq!(fixture.request_count(), 1);

    fixture.shutdown().await;
}

/// The one metadata request is the property that matters: concurrent readiness
/// evaluations and warm-up must reuse the existing refresh serialization
/// instead of each consulting the trusted source.
#[tokio::test]
async fn concurrent_readiness_evaluations_issue_one_metadata_request() {
    const CONCURRENT_PROBES: usize = 8;

    let signing = SigningMaterial::new(JwtAlgorithm::RS256, "herd-key");
    let fixture = HttpsFixture::start(vec![ScriptedResponse::jwks(signing.jwks())]).await;
    let now = Instant::now();
    let authenticator = authenticator(
        config(
            TrustedVerificationSource::DirectJwks {
                uri: fixture.endpoint("/keys"),
            },
            fixture.trust_anchor_pem().to_vec(),
            vec![JwtAlgorithm::RS256],
            policy(),
        ),
        TestClock::new(now, Some(1_700_000_000.0)),
    );

    let mut probes = Vec::with_capacity(CONCURRENT_PROBES);
    for _ in 0..CONCURRENT_PROBES {
        let authenticator = authenticator.clone();
        probes.push(tokio::spawn(async move {
            let cancellation = NeverCancelled;
            let probe = context(probe_deadline(Instant::now()), &cancellation);
            authenticator.ensure_trusted_verifier_state(&probe).await
        }));
    }

    for probe in probes {
        assert_eq!(probe.await.unwrap(), TrustedVerifierState::Usable);
    }
    assert_eq!(fixture.request_count(), 1);
    assert_eq!(cache_generation(&authenticator).await, Some(1));

    fixture.shutdown().await;
}

#[tokio::test]
async fn an_expired_probe_context_reports_unusable_without_retrieval() {
    let signing = SigningMaterial::new(JwtAlgorithm::RS256, "expired-context-key");
    let fixture = HttpsFixture::start(vec![ScriptedResponse::jwks(signing.jwks())]).await;
    let now = Instant::now();
    let authenticator = authenticator(
        config(
            TrustedVerificationSource::DirectJwks {
                uri: fixture.endpoint("/keys"),
            },
            fixture.trust_anchor_pem().to_vec(),
            vec![JwtAlgorithm::RS256],
            policy(),
        ),
        TestClock::new(now, Some(1_700_000_000.0)),
    );
    let cancellation = NeverCancelled;
    let expired = SynchronizationContext::new(now - Duration::from_secs(1), &cancellation);

    assert_eq!(
        authenticator.trusted_verifier_state(&expired).await,
        TrustedVerifierState::Unusable
    );
    assert_eq!(
        authenticator.ensure_trusted_verifier_state(&expired).await,
        TrustedVerifierState::Unusable
    );
    assert_eq!(fixture.request_count(), 0);

    fixture.shutdown().await;
}

/// The capability is a closed category: it must not become a channel for
/// verification material, key identifiers, or the configured source URI.
#[tokio::test]
async fn trusted_verifier_state_renders_only_a_closed_category() {
    let signing = SigningMaterial::new(JwtAlgorithm::RS256, "sentinel-kid");
    let fixture = HttpsFixture::start(vec![ScriptedResponse::jwks(signing.jwks())]).await;
    let now = Instant::now();
    let authenticator = authenticator(
        config(
            TrustedVerificationSource::DirectJwks {
                uri: fixture.endpoint("/keys"),
            },
            fixture.trust_anchor_pem().to_vec(),
            vec![JwtAlgorithm::RS256],
            policy(),
        ),
        TestClock::new(now, Some(1_700_000_000.0)),
    );
    let cancellation = NeverCancelled;
    let probe = context(probe_deadline(now), &cancellation);

    let state = authenticator.ensure_trusted_verifier_state(&probe).await;
    let rendered = format!("{state:?}");

    assert_eq!(rendered, "Usable");
    for sentinel in ["sentinel-kid", fixture.base_uri(), "BEGIN", "keys"] {
        assert!(!rendered.contains(sentinel), "leaked {sentinel}");
    }

    fixture.shutdown().await;
}
