//! The reusable authenticator: bounded in-memory trusted-verification cache,
//! opportunistic/bounded refresh from the one configured trusted source, and
//! the linearized verification decision. A successful refresh replaces older
//! trusted state; there is no background refresh, only refresh performed
//! synchronously within an authentication attempt.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{
    Method, Request, StatusCode, Uri,
    body::{Body, Incoming},
    header::{ACCEPT, CONTENT_LENGTH},
};
use hyper_tls::HttpsConnector;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioTimer},
};
use josekit::jws::JwsContext;
use permissionsync_core::{SynchronizationContext, TechnicalCallerBearerToken};
use tokio::{
    sync::RwLock,
    time::{Instant as TokioInstant, timeout_at},
};

use crate::{
    MAX_DOCUMENT_BYTES, MAX_TOKEN_BYTES,
    claims::validate_claims,
    clock::{Clock, SystemClock},
    config::{Config, JwtAlgorithm, SourceUri, TechnicalCallerAuthenticatorConfig},
    context::{EffectiveDeadline, check_context, effective_deadline, timeout_error},
    error::AuthenticationError,
    jwks::{Candidate, DiscoveryDocument, parse_jwks, preflight_header},
    types::{AuthenticatedTechnicalCaller, AuthenticationRequest, TechnicalCallerClientId},
};

/// Reusable internal technical-caller authenticator.
#[derive(Clone)]
pub struct TechnicalCallerAuthenticator {
    pub(crate) inner: Arc<Inner>,
}

pub(crate) struct Inner {
    pub(crate) config: Config,
    client: MetadataClient,
    /// Authoritative trusted verification cache. `tokio::sync::RwLock` (not a
    /// blocking `std::sync::RwLock`) so request-path acquisition never blocks
    /// an executor thread, and so the wait itself can be bounded by the
    /// request's overall `SynchronizationContext` deadline via `timeout_at`.
    /// It still provides the linearization point between a verification
    /// decision and a successful trusted-cache replacement:
    /// [`TechnicalCallerAuthenticator::verify_current`] holds a read guard
    /// for the entire synchronous decision (no `.await` while it is held), so
    /// a concurrent successful rotation cannot be installed mid-decision, and
    /// a decision can never be returned against state already superseded by
    /// an installed write.
    pub(crate) cache: RwLock<Option<Snapshot>>,
    refresh: tokio::sync::Mutex<()>,
    pub(crate) clock: Arc<dyn Clock>,
}

type MetadataClient = Client<HttpsConnector<HttpConnector>, Empty<Bytes>>;

impl TechnicalCallerAuthenticator {
    /// Creates an authenticator without performing remote I/O.
    pub fn new(config: TechnicalCallerAuthenticatorConfig) -> Self {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let mut https = HttpsConnector::from((http, config.tls.into()));
        https.https_only(true);
        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(Some(Duration::from_secs(30)))
            .pool_max_idle_per_host(4)
            .retry_canceled_requests(false);
        let client = builder.build(https);
        Self {
            inner: Arc::new(Inner {
                config: Config {
                    issuer: config.issuer,
                    audience: config.audience,
                    source: config.source,
                    algorithms: config.algorithms,
                    metadata_timeout: config.metadata_timeout,
                    cache_policy: config.cache_policy,
                    clock_skew: config.clock_skew,
                },
                client,
                cache: RwLock::new(None),
                refresh: tokio::sync::Mutex::new(()),
                clock: Arc::new(SystemClock),
            }),
        }
    }

    /// Authenticates a compact bearer credential and derives only the required
    /// identity, exact bearer, and target selection.
    pub async fn authenticate(
        &self,
        request: AuthenticationRequest<'_>,
    ) -> Result<AuthenticatedTechnicalCaller, AuthenticationError> {
        check_context(&request.context)?;
        let token = request
            .raw_compact_token
            .ok_or(AuthenticationError::Rejected)?;
        if token.len() > MAX_TOKEN_BYTES {
            return Err(AuthenticationError::Rejected);
        }
        check_context(&request.context)?;
        let algorithm = preflight_header(token, &self.inner.config.algorithms)?;
        check_context(&request.context)?;

        let (observed_generation, classification) = self.classify_cache(&request.context).await?;

        match classification {
            CacheClassification::Fresh => {
                match self
                    .verify_current(token, algorithm, &request.context)
                    .await
                {
                    // Freshness is part of the linearized verification decision,
                    // not merely the earlier control-flow observation. A state
                    // that aged while this request waited for the read guard
                    // must follow the stale or expired path below.
                    CacheVerification::Cancelled => Err(AuthenticationError::Cancelled),
                    CacheVerification::Stale(Verification::Rejected) => {
                        Err(AuthenticationError::Rejected)
                    }
                    CacheVerification::Stale(Verification::VerifierUnavailable) => {
                        Err(AuthenticationError::VerifierUnavailable)
                    }
                    CacheVerification::Stale(Verification::SignatureInvalid) => {
                        self.refresh_after_proven_signature_invalid(
                            token,
                            algorithm,
                            &request.context,
                            observed_generation,
                        )
                        .await
                    }
                    CacheVerification::Stale(_) => {
                        self.refresh_or_stale_fallback(
                            token,
                            algorithm,
                            &request.context,
                            observed_generation,
                        )
                        .await
                    }
                    CacheVerification::ColdOrExpired => {
                        self.refresh_then_verify_fresh(
                            token,
                            algorithm,
                            &request.context,
                            observed_generation,
                        )
                        .await
                    }
                    CacheVerification::Fresh(verification) => match verification {
                        Verification::Valid(result) => Ok(result),
                        Verification::Rejected => Err(AuthenticationError::Rejected),
                        Verification::Forbidden => Err(AuthenticationError::Forbidden),
                        Verification::VerifierUnavailable => {
                            Err(AuthenticationError::VerifierUnavailable)
                        }
                        // No candidate at all matched this token: one opportunistic
                        // refresh is permitted. Its own outcome (success or
                        // failure) always finalizes the result; see
                        // `verification_result`.
                        Verification::NoCandidate => {
                            self.refresh_then_verify_fresh(
                                token,
                                algorithm,
                                &request.context,
                                observed_generation,
                            )
                            .await
                        }
                        // A candidate matched kid/algorithm but signature
                        // verification definitively failed. One opportunistic
                        // refresh is permitted to allow legitimate same-`kid`
                        // rotation. If that refresh cannot be completed, the
                        // already-proven-invalid signature still stands:
                        // `Rejected`, never `VerifierUnavailable`.
                        Verification::SignatureInvalid => {
                            self.refresh_after_proven_signature_invalid(
                                token,
                                algorithm,
                                &request.context,
                                observed_generation,
                            )
                            .await
                        }
                    },
                }
            }
            CacheClassification::Stale => {
                self.refresh_or_stale_fallback(
                    token,
                    algorithm,
                    &request.context,
                    observed_generation,
                )
                .await
            }
            CacheClassification::ColdOrExpired => {
                self.refresh_then_verify_fresh(
                    token,
                    algorithm,
                    &request.context,
                    observed_generation,
                )
                .await
            }
        }
    }

    /// Refreshes once, then applies the final guarded verification outcome.
    /// A valid outcome still requires a fresh snapshot, but a successful
    /// trusted refresh conclusively rejects a no-candidate or invalid-signature
    /// outcome even if that replacement has become stale before verification.
    async fn refresh_then_verify_fresh(
        &self,
        token: &str,
        algorithm: JwtAlgorithm,
        context: &SynchronizationContext<'_>,
        observed_generation: u64,
    ) -> Result<AuthenticatedTechnicalCaller, AuthenticationError> {
        self.refresh(context, observed_generation).await?;
        refreshed_verification_result(self.verify_current(token, algorithm, context).await)
    }

    /// Preserves stale-if-error semantics. The fallback's cache-age category
    /// and signature/claim decision are obtained together under one read
    /// guard, so a snapshot that expires while this request waits cannot be
    /// accepted based on the stale control-flow observation made earlier.
    async fn refresh_or_stale_fallback(
        &self,
        token: &str,
        algorithm: JwtAlgorithm,
        context: &SynchronizationContext<'_>,
        observed_generation: u64,
    ) -> Result<AuthenticatedTechnicalCaller, AuthenticationError> {
        match self.refresh(context, observed_generation).await {
            Ok(()) => {
                refreshed_verification_result(self.verify_current(token, algorithm, context).await)
            }
            Err(AuthenticationError::Cancelled) => Err(AuthenticationError::Cancelled),
            Err(_) => {
                stale_cache_fallback_result(self.verify_current(token, algorithm, context).await)
            }
        }
    }

    /// A signature-invalid decision made under the authoritative read guard
    /// remains conclusive if the one permitted refresh fails, including when
    /// the snapshot expires while that refresh is in flight.
    async fn refresh_after_proven_signature_invalid(
        &self,
        token: &str,
        algorithm: JwtAlgorithm,
        context: &SynchronizationContext<'_>,
        observed_generation: u64,
    ) -> Result<AuthenticatedTechnicalCaller, AuthenticationError> {
        match self.refresh(context, observed_generation).await {
            Ok(()) => {
                refreshed_verification_result(self.verify_current(token, algorithm, context).await)
            }
            Err(AuthenticationError::Cancelled) => Err(AuthenticationError::Cancelled),
            Err(_) => Err(AuthenticationError::Rejected),
        }
    }

    /// Classifies the current cache state for control-flow purposes only
    /// (whether an opportunistic refresh should be attempted). This is a
    /// brief, independent, deadline-bounded read; the authoritative
    /// verification decision, including its own cache-age check, is always
    /// made separately and linearly in [`Self::verify_current`].
    async fn classify_cache(
        &self,
        context: &SynchronizationContext<'_>,
    ) -> Result<(u64, CacheClassification), AuthenticationError> {
        check_context(context)?;
        let deadline = TokioInstant::from_std(context.deadline());
        let cache = timeout_at(deadline, self.inner.cache.read())
            .await
            .map_err(|_| AuthenticationError::Cancelled)?;
        check_context(context)?;
        let Some(snapshot) = cache.as_ref() else {
            return Ok((0, CacheClassification::ColdOrExpired));
        };
        let generation = snapshot.generation;
        let now = self.inner.clock.tick();
        let classification = match snapshot.age(now) {
            Some(age) if age <= self.inner.config.cache_policy.freshness => {
                CacheClassification::Fresh
            }
            Some(age) if within_stale(age, self.inner.config.cache_policy) => {
                CacheClassification::Stale
            }
            _ => CacheClassification::ColdOrExpired,
        };
        Ok((generation, classification))
    }

    /// Makes one authoritative verification decision against whatever
    /// trusted state is current *at this moment*, holding a read guard for
    /// the full synchronous decision. This is the linearization point
    /// required so a decision can never be returned against cache state
    /// already superseded by a successful concurrent trusted-cache
    /// replacement. Its cache-age classification is also obtained under that
    /// same guard, immediately before the synchronous signature and claim
    /// decision. The guard acquisition itself is the only `.await`; nothing
    /// awaits while the guard is held, and its wait is bounded by the overall
    /// request deadline.
    async fn verify_current(
        &self,
        token: &str,
        preflight_algorithm: JwtAlgorithm,
        context: &SynchronizationContext<'_>,
    ) -> CacheVerification {
        if check_context(context).is_err() {
            return CacheVerification::Cancelled;
        }
        let deadline = TokioInstant::from_std(context.deadline());
        let cache = match timeout_at(deadline, self.inner.cache.read()).await {
            Ok(guard) => guard,
            Err(_) => return CacheVerification::Cancelled,
        };
        if check_context(context).is_err() {
            return CacheVerification::Cancelled;
        }
        let Some(snapshot) = cache.as_ref() else {
            return CacheVerification::ColdOrExpired;
        };
        let cache_classification = match snapshot.age(self.inner.clock.tick()) {
            Some(age) if age <= self.inner.config.cache_policy.freshness => {
                CacheClassification::Fresh
            }
            Some(age) if within_stale(age, self.inner.config.cache_policy) => {
                CacheClassification::Stale
            }
            _ => return CacheVerification::ColdOrExpired,
        };
        let jws = JwsContext::new();
        let mut selected_any = false;
        let prohibited_header = std::cell::Cell::new(false);
        for candidate in &snapshot.candidates {
            if check_context(context).is_err() {
                return CacheVerification::Cancelled;
            }
            let selected = std::cell::Cell::new(false);
            let output = jws.deserialize_compact_with_selector(token, |header| {
                if header.claim("crit").is_some() || header.claim("b64").is_some() {
                    prohibited_header.set(true);
                    return Ok(None);
                }
                if candidate.algorithm != preflight_algorithm
                    || header.algorithm() != Some(preflight_algorithm.name())
                {
                    return Ok(None);
                }
                let verifier = match header.key_id() {
                    Some(kid) if candidate.kid.as_deref() == Some(kid) => {
                        candidate.with_kid.as_ref()
                    }
                    None => candidate.without_kid.as_ref(),
                    _ => return Ok(None),
                };
                selected.set(true);
                Ok(Some(verifier))
            });
            selected_any |= selected.get();
            // A failed verification is still synchronous work that may consume
            // the final request budget. Check before attempting another
            // candidate or converting this last failed attempt into a
            // definitive signature/no-candidate result.
            if check_context(context).is_err() {
                return CacheVerification::Cancelled;
            }
            if let Ok((payload, _)) = output {
                let verification = match validate_claims(
                    &payload,
                    &self.inner.config,
                    self.inner.clock.as_ref(),
                    context,
                ) {
                    Ok((client_id, target_selection)) => {
                        Verification::Valid(AuthenticatedTechnicalCaller {
                            client_id: TechnicalCallerClientId(client_id),
                            bearer_token: TechnicalCallerBearerToken::new(token.to_owned()),
                            target_selection,
                        })
                    }
                    Err(AuthenticationError::Cancelled) => return CacheVerification::Cancelled,
                    Err(AuthenticationError::VerifierUnavailable) => {
                        Verification::VerifierUnavailable
                    }
                    Err(AuthenticationError::Forbidden) => Verification::Forbidden,
                    Err(_) => Verification::Rejected,
                };
                return match cache_classification {
                    CacheClassification::Fresh => CacheVerification::Fresh(verification),
                    CacheClassification::Stale => CacheVerification::Stale(verification),
                    CacheClassification::ColdOrExpired => {
                        unreachable!("expired cache returned above")
                    }
                };
            }
        }
        let verification = if prohibited_header.get() {
            Verification::Rejected
        } else if selected_any {
            // At least one candidate matched kid/algorithm, but signature
            // verification failed for every attempted candidate: this token
            // is definitively invalid against currently-trusted material.
            Verification::SignatureInvalid
        } else {
            Verification::NoCandidate
        };
        match cache_classification {
            CacheClassification::Fresh => CacheVerification::Fresh(verification),
            CacheClassification::Stale => CacheVerification::Stale(verification),
            CacheClassification::ColdOrExpired => unreachable!("expired cache returned above"),
        }
    }

    /// Performs at most one bounded trusted-source refresh consultation for
    /// this authentication attempt, serialized against concurrent refreshes.
    /// Returns `Ok(())` once *some* generation newer than `observed_generation`
    /// (this request's own successful fetch, or a fresh generation already
    /// installed by a concurrent leader) is current; the caller must then
    /// re-verify against current state via [`Self::verify_current`], which is
    /// itself always linearized with cache replacement.
    async fn refresh(
        &self,
        context: &SynchronizationContext<'_>,
        observed_generation: u64,
    ) -> Result<(), AuthenticationError> {
        check_context(context)?;
        let deadline = TokioInstant::from_std(context.deadline());
        let guard = timeout_at(deadline, self.inner.refresh.lock())
            .await
            .map_err(|_| AuthenticationError::Cancelled)?;
        check_context(context)?;

        // A preceding leader's successful replacement, including an empty
        // replacement, is this request's one refresh consultation, provided
        // it is still fresh right now.
        if self
            .newer_generation_is_currently_fresh(context, observed_generation)
            .await?
        {
            drop(guard);
            return Ok(());
        }

        let result = self.fetch_snapshot(context).await;
        let outcome = match result {
            Ok(snapshot) => self.install_snapshot(context, snapshot).await,
            Err(AuthenticationError::Cancelled) => Err(AuthenticationError::Cancelled),
            Err(_) => Err(AuthenticationError::VerifierUnavailable),
        };
        drop(guard);
        outcome
    }

    /// Installs a successfully fetched snapshot as the new authoritative
    /// generation, under a deadline-bounded write guard.
    async fn install_snapshot(
        &self,
        context: &SynchronizationContext<'_>,
        mut snapshot: Snapshot,
    ) -> Result<(), AuthenticationError> {
        check_context(context)?;
        let deadline = TokioInstant::from_std(context.deadline());
        let mut cache = timeout_at(deadline, self.inner.cache.write())
            .await
            .map_err(|_| AuthenticationError::Cancelled)?;
        check_context(context)?;
        snapshot.generation = cache
            .as_ref()
            .map_or(0, |current| current.generation)
            .saturating_add(1);
        *cache = Some(snapshot);
        Ok(())
    }

    pub(crate) async fn newer_generation_is_currently_fresh(
        &self,
        context: &SynchronizationContext<'_>,
        observed_generation: u64,
    ) -> Result<bool, AuthenticationError> {
        check_context(context)?;
        let deadline = TokioInstant::from_std(context.deadline());
        let cache = timeout_at(deadline, self.inner.cache.read())
            .await
            .map_err(|_| AuthenticationError::Cancelled)?;
        check_context(context)?;
        let now = self.inner.clock.tick();
        Ok(cache.as_ref().is_some_and(|snapshot| {
            snapshot.generation != observed_generation
                && snapshot
                    .age(now)
                    .is_some_and(|age| age <= self.inner.config.cache_policy.freshness)
        }))
    }

    async fn fetch_snapshot(
        &self,
        context: &SynchronizationContext<'_>,
    ) -> Result<Snapshot, AuthenticationError> {
        let jwks = match &self.inner.config.source {
            SourceUri::Direct(uri) => self.get_document(uri, context).await?,
            SourceUri::Discovery(uri) => {
                let bytes = self.get_document(uri, context).await?;
                check_context(context)?;
                let document: DiscoveryDocument = serde_json::from_slice(&bytes)
                    .map_err(|_| AuthenticationError::VerifierUnavailable)?;
                if document.issuer != self.inner.config.issuer {
                    return Err(AuthenticationError::VerifierUnavailable);
                }
                let jwks_uri = crate::config::parse_metadata_uri(&document.jwks_uri)
                    .map_err(|_| AuthenticationError::VerifierUnavailable)?;
                self.get_document(&jwks_uri, context).await?
            }
        };
        check_context(context)?;
        let candidates = parse_jwks(&jwks, &self.inner.config.algorithms, context)?;
        check_context(context)?;
        Ok(Snapshot {
            candidates,
            acquired: self.inner.clock.tick(),
            generation: 0,
        })
    }

    async fn get_document(
        &self,
        uri: &Uri,
        context: &SynchronizationContext<'_>,
    ) -> Result<Vec<u8>, AuthenticationError> {
        check_context(context)?;
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri.clone())
            .header(ACCEPT, "application/json")
            .body(Empty::<Bytes>::new())
            .map_err(|_| AuthenticationError::VerifierUnavailable)?;
        let deadline = effective_deadline(context, self.inner.config.metadata_timeout)?;
        let response = timeout_at(
            TokioInstant::from_std(deadline.instant),
            self.inner.client.request(request),
        )
        .await
        .map_err(|_| timeout_error(context, deadline.cause))?;
        check_context(context)?;
        let response = response.map_err(|_| AuthenticationError::VerifierUnavailable)?;
        if response.status() != StatusCode::OK {
            return Err(AuthenticationError::VerifierUnavailable);
        }
        let declared = response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());
        if declared.is_some_and(|value| value > MAX_DOCUMENT_BYTES) {
            return Err(AuthenticationError::VerifierUnavailable);
        }
        read_document(response.into_body(), declared, context, deadline).await
    }

    /// Test-only accessor to the authoritative cache lock, compiled only for
    /// `#[cfg(test)]` builds. Never present in a production/release artifact;
    /// not a public API. Used to prove the linearization property directly
    /// against the real lock type.
    #[cfg(test)]
    pub(crate) fn test_only_cache(&self) -> &RwLock<Option<Snapshot>> {
        &self.inner.cache
    }
}

enum CacheClassification {
    Fresh,
    Stale,
    ColdOrExpired,
}

/// The cache-age eligibility and synchronous verification result are coupled:
/// both were read while one authoritative cache read guard was held.
enum CacheVerification {
    Fresh(Verification),
    Stale(Verification),
    ColdOrExpired,
    Cancelled,
}

enum Verification {
    Valid(AuthenticatedTechnicalCaller),
    Rejected,
    Forbidden,
    VerifierUnavailable,
    NoCandidate,
    SignatureInvalid,
}

fn verification_result(
    verification: Verification,
) -> Result<AuthenticatedTechnicalCaller, AuthenticationError> {
    match verification {
        Verification::Valid(value) => Ok(value),
        Verification::Forbidden => Err(AuthenticationError::Forbidden),
        Verification::VerifierUnavailable => Err(AuthenticationError::VerifierUnavailable),
        // Both are finalized after at most one refresh consultation: no
        // applicable candidate, or a candidate whose signature was
        // definitively invalid. Neither can be repaired by a second refresh.
        Verification::Rejected | Verification::NoCandidate | Verification::SignatureInvalid => {
            Err(AuthenticationError::Rejected)
        }
    }
}

/// A successful trusted refresh may authorize only a fresh valid snapshot.
/// Other definitive verification outcomes remain definitive even when the
/// final snapshot crossed into stale age before its guarded decision.
fn refreshed_verification_result(
    verification: CacheVerification,
) -> Result<AuthenticatedTechnicalCaller, AuthenticationError> {
    match verification {
        CacheVerification::Fresh(verification) => verification_result(verification),
        // A stale snapshot cannot establish successful authentication or the
        // authorization outcome that depends on it.
        CacheVerification::Stale(Verification::Valid(_) | Verification::Forbidden) => {
            Err(AuthenticationError::VerifierUnavailable)
        }
        CacheVerification::Stale(verification) => verification_result(verification),
        CacheVerification::ColdOrExpired => Err(AuthenticationError::VerifierUnavailable),
        CacheVerification::Cancelled => Err(AuthenticationError::Cancelled),
    }
}

/// After refresh failure, retain the stale-if-error fallback only when the
/// same guarded decision proves the currently authoritative snapshot is still
/// stale (or a concurrent replacement made it fresh).
fn stale_cache_fallback_result(
    verification: CacheVerification,
) -> Result<AuthenticatedTechnicalCaller, AuthenticationError> {
    match verification {
        CacheVerification::Fresh(verification) => verification_result(verification),
        CacheVerification::Stale(verification) => stale_fallback_result(verification),
        CacheVerification::ColdOrExpired => Err(AuthenticationError::VerifierUnavailable),
        CacheVerification::Cancelled => Err(AuthenticationError::Cancelled),
    }
}

fn stale_fallback_result(
    verification: Verification,
) -> Result<AuthenticatedTechnicalCaller, AuthenticationError> {
    match verification {
        // An unknown key during a source outage is genuine infrastructure
        // uncertainty, not a proven-invalid credential.
        Verification::NoCandidate => Err(AuthenticationError::VerifierUnavailable),
        verification => verification_result(verification),
    }
}

#[derive(Clone)]
pub(crate) struct Snapshot {
    pub(crate) candidates: Vec<Candidate>,
    pub(crate) acquired: Instant,
    pub(crate) generation: u64,
}

impl Snapshot {
    fn age(&self, now: Instant) -> Option<Duration> {
        now.checked_duration_since(self.acquired)
    }
}

fn within_stale(age: Duration, policy: crate::config::VerificationCachePolicy) -> bool {
    policy
        .freshness()
        .checked_add(policy.stale_if_error())
        .is_some_and(|limit| age > policy.freshness() && age <= limit)
}

async fn read_document(
    mut body: Incoming,
    declared: Option<usize>,
    context: &SynchronizationContext<'_>,
    deadline: EffectiveDeadline,
) -> Result<Vec<u8>, AuthenticationError> {
    let declared = declared.or_else(|| {
        body.size_hint()
            .exact()
            .and_then(|value| usize::try_from(value).ok())
    });
    if declared.is_some_and(|value| value > MAX_DOCUMENT_BYTES) {
        return Err(AuthenticationError::VerifierUnavailable);
    }
    let mut document = Vec::with_capacity(declared.unwrap_or_default());
    while let Some(frame) = timeout_at(TokioInstant::from_std(deadline.instant), body.frame())
        .await
        .map_err(|_| timeout_error(context, deadline.cause))?
    {
        check_context(context)?;
        let frame = frame.map_err(|_| AuthenticationError::VerifierUnavailable)?;
        if let Ok(data) = frame.into_data() {
            let new_len = document
                .len()
                .checked_add(data.len())
                .ok_or(AuthenticationError::VerifierUnavailable)?;
            if new_len > MAX_DOCUMENT_BYTES {
                return Err(AuthenticationError::VerifierUnavailable);
            }
            document.extend_from_slice(&data);
        }
    }
    check_context(context)?;
    Ok(document)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        future::Future,
        sync::Arc,
        task::Poll,
        time::{Duration, Instant},
    };

    use josekit::{
        jwk::Jwk,
        jws::{self, JwsContext, JwsHeader},
    };
    use permissionsync_core::{CancellationSignal, SynchronizationContext};
    use serde_json::json;

    use super::{
        CacheVerification, Snapshot, TechnicalCallerAuthenticator, Verification,
        refreshed_verification_result, within_stale,
    };
    use crate::{
        clock::Clock,
        config::{
            JwtAlgorithm, TechnicalCallerAuthenticatorConfig, TrustedVerificationSource,
            VerificationCachePolicy,
        },
        error::AuthenticationError,
        jwks::parse_jwks,
        types::AuthenticationRequest,
    };

    struct NotCancelled;

    impl CancellationSignal for NotCancelled {
        fn is_cancelled(&self) -> bool {
            false
        }
    }

    struct TestClock {
        tick: Instant,
        unix_seconds: f64,
    }

    impl Clock for TestClock {
        fn tick(&self) -> Instant {
            self.tick
        }

        fn unix_seconds(&self) -> Option<f64> {
            Some(self.unix_seconds)
        }
    }

    struct UnavailableClock {
        tick: Instant,
    }

    impl Clock for UnavailableClock {
        fn tick(&self) -> Instant {
            self.tick
        }

        fn unix_seconds(&self) -> Option<f64> {
            None
        }
    }

    #[test]
    fn cache_boundaries_are_inclusive() {
        let policy = VerificationCachePolicy::new(Duration::from_secs(10), Duration::from_secs(5));
        assert!(!within_stale(Duration::from_secs(10), policy));
        assert!(within_stale(Duration::from_secs(11), policy));
        assert!(within_stale(Duration::from_secs(15), policy));
        assert!(!within_stale(Duration::from_secs(16), policy));
    }

    #[test]
    fn successful_refresh_keeps_stale_definitive_failures_rejected() {
        assert!(matches!(
            refreshed_verification_result(CacheVerification::Stale(Verification::NoCandidate)),
            Err(AuthenticationError::Rejected)
        ));
        assert!(matches!(
            refreshed_verification_result(CacheVerification::Stale(Verification::SignatureInvalid)),
            Err(AuthenticationError::Rejected)
        ));
    }

    #[tokio::test]
    async fn newer_generation_is_reused_only_while_currently_fresh() {
        let now = Instant::now();
        let cancellation = NotCancelled;
        let context = SynchronizationContext::new(now + Duration::from_secs(5), &cancellation);
        let policy = VerificationCachePolicy::new(Duration::from_millis(1), Duration::ZERO);
        let config = TechnicalCallerAuthenticatorConfig::new(
            "https://issuer.test".to_owned(),
            "permissionsync".to_owned(),
            TrustedVerificationSource::DirectJwks {
                uri: "https://issuer.test/keys".to_owned(),
            },
            vec![JwtAlgorithm::RS256],
            Duration::from_secs(1),
            policy,
            Duration::ZERO,
            Vec::new(),
        )
        .unwrap();
        let mut authenticator = TechnicalCallerAuthenticator::new(config);
        let inner = Arc::get_mut(&mut authenticator.inner).unwrap();
        inner.clock = Arc::new(TestClock {
            tick: now,
            unix_seconds: 0.0,
        });
        *inner.cache.write().await = Some(Snapshot {
            candidates: Vec::new(),
            acquired: now,
            generation: 2,
        });

        assert!(
            authenticator
                .newer_generation_is_currently_fresh(&context, 1)
                .await
                .unwrap()
        );
        Arc::get_mut(&mut authenticator.inner).unwrap().clock = Arc::new(TestClock {
            tick: now + Duration::from_millis(2),
            unix_seconds: 0.0,
        });
        assert!(
            !authenticator
                .newer_generation_is_currently_fresh(&context, 1)
                .await
                .unwrap()
        );
        assert!(
            !authenticator
                .newer_generation_is_currently_fresh(&context, 2)
                .await
                .unwrap()
        );
    }

    /// A timed-out cache write must release its queued writer future without
    /// altering the authoritative snapshot or retaining a lock waiter.
    #[tokio::test(start_paused = true)]
    async fn install_snapshot_write_wait_obeys_deadline_without_lock_leak() {
        let cancellation = NotCancelled;
        let config = TechnicalCallerAuthenticatorConfig::new(
            "https://issuer.test".to_owned(),
            "permissionsync".to_owned(),
            TrustedVerificationSource::DirectJwks {
                uri: "https://issuer.test/keys".to_owned(),
            },
            vec![JwtAlgorithm::RS256],
            Duration::from_secs(1),
            VerificationCachePolicy::new(Duration::from_secs(30), Duration::ZERO),
            Duration::ZERO,
            Vec::new(),
        )
        .unwrap();
        let authenticator = TechnicalCallerAuthenticator::new(config);
        let now = Instant::now();
        let original = Snapshot {
            candidates: Vec::new(),
            acquired: now,
            generation: 7,
        };
        *authenticator.test_only_cache().write().await = Some(original.clone());

        let read_guard = authenticator.test_only_cache().read().await;
        let context =
            SynchronizationContext::new(Instant::now() + Duration::from_secs(1), &cancellation);
        let replacement = Snapshot {
            candidates: Vec::new(),
            acquired: now + Duration::from_secs(1),
            generation: 0,
        };
        let mut installation = Box::pin(authenticator.install_snapshot(&context, replacement));
        std::future::poll_fn(|context| match installation.as_mut().poll(context) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("held cache read guard must make installation wait"),
        })
        .await;
        tokio::time::advance(Duration::from_secs(2)).await;

        assert!(matches!(
            installation.await,
            Err(AuthenticationError::Cancelled)
        ));
        assert_eq!(
            read_guard
                .as_ref()
                .map(|snapshot| (snapshot.acquired, snapshot.generation)),
            Some((original.acquired, original.generation))
        );
        drop(read_guard);
        assert_eq!(
            authenticator
                .test_only_cache()
                .read()
                .await
                .as_ref()
                .map(|snapshot| (snapshot.acquired, snapshot.generation)),
            Some((original.acquired, original.generation))
        );
        drop(authenticator.test_only_cache().write().await);
    }

    #[tokio::test]
    async fn public_authentication_preserves_valid_signed_bearer_and_target() {
        let cancellation = NotCancelled;
        let mut key = Jwk::generate_rsa_key(2048).unwrap();
        key.set_key_id("test-key");
        let mut public_key = key.to_public_key().unwrap();
        public_key.set_key_id("test-key");
        let jwks = serde_json::to_vec(&json!({"keys": [public_key]})).unwrap();
        let allowed = BTreeSet::from([JwtAlgorithm::RS256]);
        let now = Instant::now();
        let context = SynchronizationContext::new(now + Duration::from_secs(5), &cancellation);
        let candidates = parse_jwks(&jwks, &allowed, &context).unwrap();

        let config = TechnicalCallerAuthenticatorConfig::new(
            "https://issuer.test".to_owned(),
            "permissionsync".to_owned(),
            TrustedVerificationSource::DirectJwks {
                uri: "https://issuer.test/keys".to_owned(),
            },
            vec![JwtAlgorithm::RS256],
            Duration::from_secs(1),
            VerificationCachePolicy::new(Duration::from_secs(30), Duration::ZERO),
            Duration::ZERO,
            Vec::new(),
        )
        .unwrap();
        let mut authenticator = TechnicalCallerAuthenticator::new(config);
        let inner = Arc::get_mut(&mut authenticator.inner).unwrap();
        inner.clock = Arc::new(TestClock {
            tick: now,
            unix_seconds: 100.0,
        });
        *inner.cache.write().await = Some(Snapshot {
            candidates,
            acquired: now,
            generation: 1,
        });

        let payload = serde_json::to_vec(&json!({
            "iss": "https://issuer.test",
            "aud": "permissionsync",
            "exp": 101.0,
            "iat": 100.0,
            "client_id": "test-caller",
            "scope": "other permissionsync:target-a",
        }))
        .unwrap();
        let signer = jws::RS256.signer_from_jwk(&key).unwrap();
        let token = JwsContext::new()
            .serialize_compact(&payload, &JwsHeader::new(), &signer)
            .unwrap();

        let result = authenticator
            .authenticate(AuthenticationRequest::new(Some(&token), context))
            .await
            .unwrap();
        assert_eq!(result.bearer_token().as_str(), token);
        assert_eq!(result.client_id().as_str(), "test-caller");
        assert_eq!(
            result.target_selection().selected().unwrap().as_str(),
            "target-a"
        );

        Arc::get_mut(&mut authenticator.inner).unwrap().clock =
            Arc::new(UnavailableClock { tick: now });
        let unavailable_context =
            SynchronizationContext::new(now + Duration::from_secs(5), &cancellation);
        assert!(matches!(
            authenticator
                .authenticate(AuthenticationRequest::new(
                    Some(&token),
                    unavailable_context
                ))
                .await,
            Err(AuthenticationError::VerifierUnavailable)
        ));
    }
}
