//! Scriptable local HTTPS response types for transport adversarial scenarios.

use tokio::sync::oneshot;

/// One operation-owned scripted HTTP response.
pub(super) struct ScriptedResponse {
    pub(super) status: u16,
    pub(super) headers: Vec<(String, String)>,
    pub(super) body: ResponseBody,
    pub(super) release: Option<oneshot::Receiver<()>>,
    pub(super) chunk_releases: Vec<oneshot::Receiver<()>>,
}

pub(super) enum ResponseBody {
    Complete(Vec<u8>),
    Chunks(Vec<Vec<u8>>),
}

impl ScriptedResponse {
    pub(super) fn json(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: ResponseBody::Complete(body),
            release: None,
            chunk_releases: Vec::new(),
        }
    }

    pub(super) fn jwks(body: Vec<u8>) -> Self {
        Self::json(200, body)
    }

    pub(super) fn discovery(issuer: &str, jwks_uri: &str) -> Self {
        Self::json(
            200,
            serde_json::to_vec(&serde_json::json!({
                "issuer": issuer,
                "jwks_uri": jwks_uri,
            }))
            .unwrap(),
        )
    }

    pub(super) fn chunks(status: u16, chunks: Vec<Vec<u8>>) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: ResponseBody::Chunks(chunks),
            release: None,
            chunk_releases: Vec::new(),
        }
    }

    pub(super) fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub(super) fn hold_until(mut self, release: oneshot::Receiver<()>) -> Self {
        self.release = Some(release);
        self
    }

    /// Writes response headers, then waits for one release per body chunk.
    pub(super) fn held_chunks(status: u16, chunks: Vec<(Vec<u8>, oneshot::Receiver<()>)>) -> Self {
        let (chunks, chunk_releases) = chunks.into_iter().unzip();
        Self {
            status,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: ResponseBody::Chunks(chunks),
            release: None,
            chunk_releases,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::{Duration, Instant},
    };

    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        nid::Nid,
        pkey::PKey,
        x509::{
            X509,
            extension::{BasicConstraints, KeyUsage},
        },
    };
    use permissionsync_core::SynchronizationContext;
    use tokio::sync::oneshot;
    use tokio::time::Instant as TokioInstant;

    use super::ScriptedResponse;
    use crate::{
        AuthenticationError, AuthenticationRequest, JwtAlgorithm, MAX_DOCUMENT_BYTES,
        TechnicalCallerAuthenticator, TechnicalCallerAuthenticatorConfig,
        TrustedVerificationSource, VerificationCachePolicy,
        adversarial_tests::support::{
            AlreadyCancelled, HttpsFixture, MutableCancellationSignal, NeverCancelled,
            SigningMaterial, TestClock, authenticator, config, context,
        },
    };

    const METADATA_TOKEN: &str = "eyJhbGciOiJSUzI1NiJ9.e30.AA";

    fn configured_authenticator(
        source: TrustedVerificationSource,
        trust_anchor_pem: Vec<u8>,
    ) -> TechnicalCallerAuthenticator {
        authenticator(
            config(
                source,
                trust_anchor_pem,
                vec![JwtAlgorithm::RS256],
                VerificationCachePolicy::new(Duration::from_secs(30), Duration::ZERO),
            ),
            TestClock::new(Instant::now(), Some(1_700_000_000.0)),
        )
    }

    fn configured_authenticator_with_metadata_timeout(
        source: TrustedVerificationSource,
        trust_anchor_pem: Vec<u8>,
        metadata_timeout: Duration,
    ) -> TechnicalCallerAuthenticator {
        let config = TechnicalCallerAuthenticatorConfig::new(
            "https://issuer.test".to_owned(),
            "permissionsync".to_owned(),
            source,
            vec![JwtAlgorithm::RS256],
            metadata_timeout,
            VerificationCachePolicy::new(Duration::from_secs(30), Duration::ZERO),
            Duration::from_secs(5),
            vec![trust_anchor_pem],
        )
        .unwrap();
        authenticator(
            config,
            TestClock::new(Instant::now(), Some(1_700_000_000.0)),
        )
    }

    fn direct_source(fixture: &HttpsFixture) -> TrustedVerificationSource {
        TrustedVerificationSource::DirectJwks {
            uri: fixture.endpoint("/jwks"),
        }
    }

    fn unrelated_private_ca_trust_anchor() -> Vec<u8> {
        let key = PKey::generate_ed25519().unwrap();
        let mut name = openssl::x509::X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, "unrelated-test-root")
            .unwrap();
        let name = name.build();
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(&key).unwrap();
        let serial = BigNum::from_u32(99).unwrap();
        certificate
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        certificate
            .set_not_before(&Asn1Time::from_unix(1_700_000_000).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::from_unix(4_100_000_000).unwrap())
            .unwrap();
        certificate
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        certificate
            .append_extension(KeyUsage::new().critical().key_cert_sign().build().unwrap())
            .unwrap();
        certificate.sign(&key, MessageDigest::null()).unwrap();
        certificate.build().to_pem().unwrap()
    }

    fn request_context<'a>(
        cancellation: &'a dyn permissionsync_core::CancellationSignal,
    ) -> SynchronizationContext<'a> {
        context(Instant::now() + Duration::from_secs(5), cancellation)
    }

    fn non_controlling_context<'a>(
        cancellation: &'a dyn permissionsync_core::CancellationSignal,
    ) -> SynchronizationContext<'a> {
        context(Instant::now() + Duration::from_secs(60), cancellation)
    }

    struct PausedTimeGuard {
        shutdown: Arc<AtomicBool>,
        stopped: oneshot::Receiver<()>,
        task: tokio::task::JoinHandle<()>,
    }

    impl PausedTimeGuard {
        async fn start() -> Self {
            let (started, ready) = oneshot::channel();
            let shutdown = Arc::new(AtomicBool::new(false));
            let task_shutdown = Arc::clone(&shutdown);
            let (stopped, joined) = oneshot::channel();
            let task = tokio::task::spawn_blocking(move || {
                let _ = started.send(());
                while !task_shutdown.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                let _ = stopped.send(());
            });
            ready
                .await
                .expect("paused-time guard must signal that its yield loop is runnable");
            Self {
                shutdown,
                stopped: joined,
                task,
            }
        }

        async fn shutdown(self) {
            self.shutdown.store(true, Ordering::Release);
            self.stopped
                .await
                .expect("paused-time guard must acknowledge shutdown");
            self.task
                .await
                .expect("paused-time guard task must stop cleanly");
        }
    }

    fn metadata_timeout_horizon(metadata_timeout: Duration) -> TokioInstant {
        TokioInstant::from_std(
            Instant::now()
                .checked_add(metadata_timeout)
                .expect("test metadata timeout horizon must be representable"),
        )
    }

    #[tokio::test]
    async fn direct_jwks_accepts_a_private_ca_and_authenticates_a_valid_caller() {
        let signing = SigningMaterial::new(JwtAlgorithm::RS256, "direct-key");
        let fixture = HttpsFixture::start(vec![ScriptedResponse::jwks(signing.jwks())]).await;
        let authenticator =
            configured_authenticator(direct_source(&fixture), fixture.trust_anchor_pem().to_vec());
        let token = signing.token(
            &SigningMaterial::bearer_payload(Some("permissionsync:transport")),
            &josekit::jws::JwsHeader::new(),
        );
        let cancellation = NeverCancelled;

        let result = authenticator
            .authenticate(AuthenticationRequest::new(
                Some(&token),
                request_context(&cancellation),
            ))
            .await;

        let result = result.expect("a trusted private CA JWKS must authenticate");
        assert_eq!(result.client_id().as_str(), "test-caller");
        assert_eq!(
            result.target_selection().selected().unwrap().as_str(),
            "transport"
        );
        assert_eq!(fixture.request_count(), 1);
        fixture.shutdown().await;
    }

    #[tokio::test]
    async fn discovery_uses_a_dynamically_scripted_local_jwks_uri() {
        let signing = SigningMaterial::new(JwtAlgorithm::RS256, "discovery-key");
        let jwks = signing.jwks();
        let fixture = HttpsFixture::start_with_script(move |base_uri| {
            vec![
                ScriptedResponse::discovery("https://issuer.test", &format!("{base_uri}/jwks")),
                ScriptedResponse::jwks(jwks),
            ]
        })
        .await;
        let authenticator = configured_authenticator(
            TrustedVerificationSource::OidcDiscovery {
                uri: fixture.endpoint("/.well-known/openid-configuration"),
            },
            fixture.trust_anchor_pem().to_vec(),
        );
        let token = signing.token(
            &SigningMaterial::bearer_payload(Some("permissionsync:discovery")),
            &josekit::jws::JwsHeader::new(),
        );
        let cancellation = NeverCancelled;

        let result = authenticator
            .authenticate(AuthenticationRequest::new(
                Some(&token),
                request_context(&cancellation),
            ))
            .await;

        let result = result.expect("the local discovery JWKS must authenticate");
        assert_eq!(result.client_id().as_str(), "test-caller");
        assert_eq!(
            result.target_selection().selected().unwrap().as_str(),
            "discovery"
        );
        assert_eq!(fixture.request_count(), 2);
        fixture.shutdown().await;
    }

    #[tokio::test]
    async fn cancellation_after_metadata_arrival_before_release_is_cancelled() {
        let (release, held) = oneshot::channel();
        let fixture = HttpsFixture::start(vec![
            ScriptedResponse::jwks(br#"{"keys":[]}"#.to_vec()).hold_until(held),
        ])
        .await;
        let authenticator =
            configured_authenticator(direct_source(&fixture), fixture.trust_anchor_pem().to_vec());
        let cancellation = MutableCancellationSignal::new();
        let authentication = authenticator.authenticate(AuthenticationRequest::new(
            Some(METADATA_TOKEN),
            request_context(&cancellation),
        ));
        tokio::pin!(authentication);

        tokio::select! {
            _ = fixture.wait_for_request(1) => {},
            _ = &mut authentication => panic!("authentication completed before the held response released"),
        }
        cancellation.cancel();
        release.send(()).unwrap();
        let result = authentication.await;

        assert!(matches!(result, Err(AuthenticationError::Cancelled)));
        assert_eq!(fixture.request_count(), 1);
        fixture.shutdown().await;
    }

    #[tokio::test]
    async fn cancellation_during_a_held_streamed_body_is_cancelled() {
        let (first_release, first_chunk) = oneshot::channel();
        drop(first_release);
        let (release, held) = oneshot::channel();
        let fixture = HttpsFixture::start(vec![ScriptedResponse::held_chunks(
            200,
            vec![
                (br#"{"keys":"#.to_vec(), first_chunk),
                (br#"[]}"#.to_vec(), held),
            ],
        )])
        .await;
        let authenticator =
            configured_authenticator(direct_source(&fixture), fixture.trust_anchor_pem().to_vec());
        let cancellation = MutableCancellationSignal::new();
        let authentication = authenticator.authenticate(AuthenticationRequest::new(
            Some(METADATA_TOKEN),
            request_context(&cancellation),
        ));
        tokio::pin!(authentication);

        tokio::select! {
            _ = fixture.wait_for_request(1) => {},
            _ = &mut authentication => panic!("authentication completed before response headers arrived"),
        }
        fixture.wait_for_body_stage(2).await;
        cancellation.cancel();
        release.send(()).unwrap();
        let result = authentication.await;

        assert!(matches!(result, Err(AuthenticationError::Cancelled)));
        assert_eq!(fixture.request_count(), 1);
        fixture.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn held_metadata_response_times_out_as_verifier_unavailable() {
        let metadata_timeout = Duration::from_secs(1);
        let (release, held) = oneshot::channel();
        let fixture = HttpsFixture::start(vec![
            ScriptedResponse::jwks(br#"{"keys":[]}"#.to_vec()).hold_until(held),
        ])
        .await;
        let authenticator = configured_authenticator_with_metadata_timeout(
            direct_source(&fixture),
            fixture.trust_anchor_pem().to_vec(),
            metadata_timeout,
        );
        let cancellation = NeverCancelled;
        let guard = PausedTimeGuard::start().await;
        let authentication = authenticator.authenticate(AuthenticationRequest::new(
            Some(METADATA_TOKEN),
            non_controlling_context(&cancellation),
        ));
        tokio::pin!(authentication);

        tokio::select! {
            _ = fixture.wait_for_request(1) => {},
            _ = &mut authentication => panic!("authentication completed before the held response timed out"),
        }
        let timeout_horizon = metadata_timeout_horizon(metadata_timeout);
        tokio::time::advance(timeout_horizon.duration_since(TokioInstant::now())).await;
        let result = authentication.await;
        release.send(()).unwrap();
        guard.shutdown().await;

        assert!(matches!(
            result,
            Err(AuthenticationError::VerifierUnavailable)
        ));
        assert_eq!(fixture.request_count(), 1);
        fixture.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn held_streamed_body_times_out_as_verifier_unavailable() {
        let metadata_timeout = Duration::from_secs(1);
        let (first_release, first_chunk) = oneshot::channel();
        drop(first_release);
        let (release, held) = oneshot::channel();
        let fixture = HttpsFixture::start(vec![ScriptedResponse::held_chunks(
            200,
            vec![
                (br#"{"keys":"#.to_vec(), first_chunk),
                (br#"[]}"#.to_vec(), held),
            ],
        )])
        .await;
        let authenticator = configured_authenticator_with_metadata_timeout(
            direct_source(&fixture),
            fixture.trust_anchor_pem().to_vec(),
            metadata_timeout,
        );
        let cancellation = NeverCancelled;
        let guard = PausedTimeGuard::start().await;
        let authentication = authenticator.authenticate(AuthenticationRequest::new(
            Some(METADATA_TOKEN),
            non_controlling_context(&cancellation),
        ));
        tokio::pin!(authentication);

        tokio::select! {
            _ = fixture.wait_for_request(1) => {},
            _ = &mut authentication => panic!("authentication completed before streamed response headers arrived"),
        }
        tokio::select! {
            _ = fixture.wait_for_body_stage(2) => {},
            _ = &mut authentication => panic!("authentication completed before the held streamed body timed out"),
        }
        let timeout_horizon = metadata_timeout_horizon(metadata_timeout);
        tokio::time::advance(timeout_horizon.duration_since(TokioInstant::now())).await;
        let result = authentication.await;
        release.send(()).unwrap();
        guard.shutdown().await;

        assert!(matches!(
            result,
            Err(AuthenticationError::VerifierUnavailable)
        ));
        assert_eq!(fixture.request_count(), 1);
        fixture.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn held_metadata_response_is_limited_by_the_overall_context_deadline_not_the_metadata_timeout()
     {
        let metadata_timeout = Duration::from_secs(60);
        let overall_deadline = Duration::from_secs(1);
        let (release, held) = oneshot::channel();
        let fixture = HttpsFixture::start(vec![
            ScriptedResponse::jwks(br#"{"keys":[]}"#.to_vec()).hold_until(held),
        ])
        .await;
        let authenticator = configured_authenticator_with_metadata_timeout(
            direct_source(&fixture),
            fixture.trust_anchor_pem().to_vec(),
            metadata_timeout,
        );
        let cancellation = NeverCancelled;
        let guard = PausedTimeGuard::start().await;
        let authentication = authenticator.authenticate(AuthenticationRequest::new(
            Some(METADATA_TOKEN),
            context(Instant::now() + overall_deadline, &cancellation),
        ));
        tokio::pin!(authentication);

        tokio::select! {
            _ = fixture.wait_for_request(1) => {},
            _ = &mut authentication => panic!("authentication completed before the overall deadline elapsed"),
        }
        let deadline_horizon = metadata_timeout_horizon(overall_deadline);
        tokio::time::advance(deadline_horizon.duration_since(TokioInstant::now())).await;
        let result = authentication.await;
        release.send(()).unwrap();
        guard.shutdown().await;

        assert!(matches!(result, Err(AuthenticationError::Cancelled)));
        assert_eq!(fixture.request_count(), 1);
        fixture.shutdown().await;
    }

    #[tokio::test]
    async fn untrusted_root_refuses_metadata_before_an_http_request() {
        let fixture =
            HttpsFixture::start(vec![ScriptedResponse::jwks(br#"{"keys":[]}"#.to_vec())]).await;
        let authenticator =
            configured_authenticator(direct_source(&fixture), unrelated_private_ca_trust_anchor());
        let cancellation = NeverCancelled;

        let result = authenticator
            .authenticate(AuthenticationRequest::new(
                Some(METADATA_TOKEN),
                request_context(&cancellation),
            ))
            .await;

        assert!(matches!(
            result,
            Err(AuthenticationError::VerifierUnavailable)
        ));
        assert_eq!(fixture.request_count(), 0);
        fixture.shutdown().await;
    }

    #[tokio::test]
    async fn hostname_mismatch_refuses_metadata_before_an_http_request() {
        let fixture =
            HttpsFixture::start(vec![ScriptedResponse::jwks(br#"{"keys":[]}"#.to_vec())]).await;
        let authenticator = configured_authenticator(
            TrustedVerificationSource::DirectJwks {
                uri: format!("https://localhost:{}/jwks", fixture.address().port()),
            },
            fixture.trust_anchor_pem().to_vec(),
        );
        let cancellation = NeverCancelled;

        let result = authenticator
            .authenticate(AuthenticationRequest::new(
                Some(METADATA_TOKEN),
                request_context(&cancellation),
            ))
            .await;

        assert!(matches!(
            result,
            Err(AuthenticationError::VerifierUnavailable)
        ));
        assert_eq!(fixture.request_count(), 0);
        fixture.shutdown().await;
    }

    #[tokio::test]
    async fn discovery_issuer_mismatch_never_follows_the_document_jwks_uri() {
        let fixture = HttpsFixture::start(vec![ScriptedResponse::discovery(
            "https://other-issuer.test",
            "https://unintended-metadata.test/jwks",
        )])
        .await;
        let authenticator = configured_authenticator(
            TrustedVerificationSource::OidcDiscovery {
                uri: fixture.endpoint("/.well-known/openid-configuration"),
            },
            fixture.trust_anchor_pem().to_vec(),
        );
        let cancellation = NeverCancelled;

        let result = authenticator
            .authenticate(AuthenticationRequest::new(
                Some(METADATA_TOKEN),
                request_context(&cancellation),
            ))
            .await;

        assert!(matches!(
            result,
            Err(AuthenticationError::VerifierUnavailable)
        ));
        assert_eq!(fixture.request_count(), 1);
        fixture.shutdown().await;
    }

    #[tokio::test]
    async fn discovery_rejects_an_invalid_jwks_uri_without_following_it() {
        for invalid_jwks_uri in [
            "http://unintended-metadata.test/jwks",
            "https://user@unintended-metadata.test/jwks",
            "https://unintended-metadata.test/jwks#fragment",
        ] {
            let fixture = HttpsFixture::start(vec![ScriptedResponse::discovery(
                "https://issuer.test",
                invalid_jwks_uri,
            )])
            .await;
            let authenticator = configured_authenticator(
                TrustedVerificationSource::OidcDiscovery {
                    uri: fixture.endpoint("/.well-known/openid-configuration"),
                },
                fixture.trust_anchor_pem().to_vec(),
            );
            let cancellation = NeverCancelled;

            let result = authenticator
                .authenticate(AuthenticationRequest::new(
                    Some(METADATA_TOKEN),
                    request_context(&cancellation),
                ))
                .await;

            assert!(
                matches!(result, Err(AuthenticationError::VerifierUnavailable)),
                "jwks_uri {invalid_jwks_uri}"
            );
            assert_eq!(fixture.request_count(), 1, "jwks_uri {invalid_jwks_uri}");
            fixture.shutdown().await;
        }
    }

    #[tokio::test]
    async fn discovery_follows_a_discovered_jwks_uri_that_carries_a_query_string() {
        let signing = SigningMaterial::new(JwtAlgorithm::RS256, "discovery-query-key");
        let jwks = signing.jwks();
        let fixture = HttpsFixture::start_with_script(move |base_uri| {
            vec![
                ScriptedResponse::discovery(
                    "https://issuer.test",
                    &format!("{base_uri}/jwks?realm=main"),
                ),
                ScriptedResponse::jwks(jwks),
            ]
        })
        .await;
        let authenticator = configured_authenticator(
            TrustedVerificationSource::OidcDiscovery {
                uri: fixture.endpoint("/.well-known/openid-configuration"),
            },
            fixture.trust_anchor_pem().to_vec(),
        );
        let token = signing.token(
            &SigningMaterial::bearer_payload(Some("permissionsync:discovery")),
            &josekit::jws::JwsHeader::new(),
        );
        let cancellation = NeverCancelled;

        let result = authenticator
            .authenticate(AuthenticationRequest::new(
                Some(&token),
                request_context(&cancellation),
            ))
            .await;

        let result = result.expect("a discovered jwks_uri with a query string must be followed");
        assert_eq!(result.client_id().as_str(), "test-caller");
        assert_eq!(fixture.request_count(), 2);
        fixture.shutdown().await;
    }

    #[tokio::test]
    async fn direct_jwks_uri_with_a_query_string_authenticates_successfully() {
        let signing = SigningMaterial::new(JwtAlgorithm::RS256, "direct-query-key");
        let fixture = HttpsFixture::start(vec![ScriptedResponse::jwks(signing.jwks())]).await;
        let authenticator = configured_authenticator(
            TrustedVerificationSource::DirectJwks {
                uri: format!("{}?realm=main", fixture.endpoint("/jwks")),
            },
            fixture.trust_anchor_pem().to_vec(),
        );
        let token = signing.token(
            &SigningMaterial::bearer_payload(Some("permissionsync:transport")),
            &josekit::jws::JwsHeader::new(),
        );
        let cancellation = NeverCancelled;

        let result = authenticator
            .authenticate(AuthenticationRequest::new(
                Some(&token),
                request_context(&cancellation),
            ))
            .await;

        let result =
            result.expect("a configured direct JWKS URI with a query string must be followed");
        assert_eq!(result.client_id().as_str(), "test-caller");
        assert_eq!(fixture.request_count(), 1);
        fixture.shutdown().await;
    }

    #[tokio::test]
    async fn malformed_discovery_json_is_a_safe_verifier_failure() {
        let fixture =
            HttpsFixture::start(vec![ScriptedResponse::json(200, b"{not-json".to_vec())]).await;
        let authenticator = configured_authenticator(
            TrustedVerificationSource::OidcDiscovery {
                uri: fixture.endpoint("/.well-known/openid-configuration"),
            },
            fixture.trust_anchor_pem().to_vec(),
        );
        let cancellation = NeverCancelled;

        let result = authenticator
            .authenticate(AuthenticationRequest::new(
                Some(METADATA_TOKEN),
                request_context(&cancellation),
            ))
            .await;

        assert!(matches!(
            result,
            Err(AuthenticationError::VerifierUnavailable)
        ));
        assert_eq!(fixture.request_count(), 1);
        fixture.shutdown().await;
    }

    #[tokio::test]
    async fn oversized_discovery_documents_are_refused() {
        let fixture = HttpsFixture::start(vec![ScriptedResponse::json(
            200,
            vec![b' '; MAX_DOCUMENT_BYTES + 1],
        )])
        .await;
        let authenticator = configured_authenticator(
            TrustedVerificationSource::OidcDiscovery {
                uri: fixture.endpoint("/.well-known/openid-configuration"),
            },
            fixture.trust_anchor_pem().to_vec(),
        );
        let cancellation = NeverCancelled;

        let result = authenticator
            .authenticate(AuthenticationRequest::new(
                Some(METADATA_TOKEN),
                request_context(&cancellation),
            ))
            .await;

        assert!(matches!(
            result,
            Err(AuthenticationError::VerifierUnavailable)
        ));
        assert_eq!(fixture.request_count(), 1);
        fixture.shutdown().await;
    }

    #[tokio::test]
    async fn redirects_and_non_success_responses_are_refused() {
        for status in [302, 503] {
            let response = ScriptedResponse::json(status, br#"{"keys":[]}"#.to_vec());
            let response = if status == 302 {
                response.with_header("Location", "https://unintended-metadata.test/jwks")
            } else {
                response
            };
            let fixture = HttpsFixture::start(vec![response]).await;
            let authenticator = configured_authenticator(
                direct_source(&fixture),
                fixture.trust_anchor_pem().to_vec(),
            );
            let cancellation = NeverCancelled;

            let result = authenticator
                .authenticate(AuthenticationRequest::new(
                    Some(METADATA_TOKEN),
                    request_context(&cancellation),
                ))
                .await;

            assert!(matches!(
                result,
                Err(AuthenticationError::VerifierUnavailable)
            ));
            assert_eq!(fixture.request_count(), 1, "status {status}");
            fixture.shutdown().await;
        }
    }

    #[tokio::test]
    async fn malformed_jwks_json_is_a_safe_verifier_failure() {
        let fixture =
            HttpsFixture::start(vec![ScriptedResponse::jwks(b"{not-json".to_vec())]).await;
        let authenticator =
            configured_authenticator(direct_source(&fixture), fixture.trust_anchor_pem().to_vec());
        let cancellation = NeverCancelled;

        let result = authenticator
            .authenticate(AuthenticationRequest::new(
                Some(METADATA_TOKEN),
                request_context(&cancellation),
            ))
            .await;

        assert!(matches!(
            result,
            Err(AuthenticationError::VerifierUnavailable)
        ));
        assert_eq!(fixture.request_count(), 1);
        fixture.shutdown().await;
    }

    #[tokio::test]
    async fn declared_documents_larger_than_one_mib_are_refused() {
        let fixture = HttpsFixture::start(vec![ScriptedResponse::jwks(vec![
            b' ';
            MAX_DOCUMENT_BYTES + 1
        ])])
        .await;
        let authenticator =
            configured_authenticator(direct_source(&fixture), fixture.trust_anchor_pem().to_vec());
        let cancellation = NeverCancelled;

        let result = authenticator
            .authenticate(AuthenticationRequest::new(
                Some(METADATA_TOKEN),
                request_context(&cancellation),
            ))
            .await;

        assert!(matches!(
            result,
            Err(AuthenticationError::VerifierUnavailable)
        ));
        assert_eq!(fixture.request_count(), 1);
        fixture.shutdown().await;
    }

    #[tokio::test]
    async fn a_declared_jwks_document_of_exactly_max_document_bytes_is_accepted() {
        let signing = SigningMaterial::new(JwtAlgorithm::RS256, "declared-limit-key");
        let mut body = signing.jwks();
        body.resize(MAX_DOCUMENT_BYTES, b' ');
        assert_eq!(body.len(), MAX_DOCUMENT_BYTES);
        let fixture = HttpsFixture::start(vec![ScriptedResponse::jwks(body)]).await;
        let authenticator =
            configured_authenticator(direct_source(&fixture), fixture.trust_anchor_pem().to_vec());
        let token = signing.token(
            &SigningMaterial::bearer_payload(Some("permissionsync:transport")),
            &josekit::jws::JwsHeader::new(),
        );
        let cancellation = NeverCancelled;

        let result = authenticator
            .authenticate(AuthenticationRequest::new(
                Some(&token),
                request_context(&cancellation),
            ))
            .await;

        assert!(result.is_ok());
        assert_eq!(fixture.request_count(), 1);
        fixture.shutdown().await;
    }

    #[tokio::test]
    async fn a_streamed_jwks_document_of_exactly_max_document_bytes_is_accepted() {
        let signing = SigningMaterial::new(JwtAlgorithm::RS256, "streamed-limit-key");
        let mut body = signing.jwks();
        body.resize(MAX_DOCUMENT_BYTES, b' ');
        assert_eq!(body.len(), MAX_DOCUMENT_BYTES);
        let split = body.len() - 1;
        let fixture = HttpsFixture::start(vec![ScriptedResponse::chunks(
            200,
            vec![body[..split].to_vec(), body[split..].to_vec()],
        )])
        .await;
        let authenticator =
            configured_authenticator(direct_source(&fixture), fixture.trust_anchor_pem().to_vec());
        let token = signing.token(
            &SigningMaterial::bearer_payload(Some("permissionsync:transport")),
            &josekit::jws::JwsHeader::new(),
        );
        let cancellation = NeverCancelled;

        let result = authenticator
            .authenticate(AuthenticationRequest::new(
                Some(&token),
                request_context(&cancellation),
            ))
            .await;

        assert!(result.is_ok());
        assert_eq!(fixture.request_count(), 1);
        fixture.shutdown().await;
    }

    #[tokio::test]
    async fn streamed_documents_larger_than_one_mib_are_refused() {
        let fixture = HttpsFixture::start(vec![ScriptedResponse::chunks(
            200,
            vec![vec![b' '; MAX_DOCUMENT_BYTES], vec![b' ']],
        )])
        .await;
        let authenticator =
            configured_authenticator(direct_source(&fixture), fixture.trust_anchor_pem().to_vec());
        let cancellation = NeverCancelled;

        let result = authenticator
            .authenticate(AuthenticationRequest::new(
                Some(METADATA_TOKEN),
                request_context(&cancellation),
            ))
            .await;

        assert!(matches!(
            result,
            Err(AuthenticationError::VerifierUnavailable)
        ));
        assert_eq!(fixture.request_count(), 1);
        fixture.shutdown().await;
    }

    #[tokio::test]
    async fn an_already_cancelled_request_does_not_fetch_metadata() {
        let fixture =
            HttpsFixture::start(vec![ScriptedResponse::jwks(br#"{"keys":[]}"#.to_vec())]).await;
        let authenticator =
            configured_authenticator(direct_source(&fixture), fixture.trust_anchor_pem().to_vec());
        let cancellation = AlreadyCancelled;

        let result = authenticator
            .authenticate(AuthenticationRequest::new(
                Some(METADATA_TOKEN),
                request_context(&cancellation),
            ))
            .await;

        assert!(matches!(result, Err(AuthenticationError::Cancelled)));
        assert_eq!(fixture.request_count(), 0);
        fixture.shutdown().await;
    }
}
