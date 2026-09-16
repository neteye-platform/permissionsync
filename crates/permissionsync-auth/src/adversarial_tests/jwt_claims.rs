//! Signed-token and verified-claims adversarial scenarios.

use std::{
    error::Error,
    time::{Duration, Instant},
};

use josekit::{
    jwk::{Jwk, alg::ed::EdCurve},
    jws::{self, JwsContext, JwsHeader},
};
use permissionsync_core::LogicalTarget;
use serde_json::{Value, json};

use super::{
    super::{
        AuthenticatedTechnicalCaller, AuthenticationError, AuthenticationRequest,
        AuthenticatorConfigurationError, JwtAlgorithm, TechnicalCallerAuthenticator,
        TechnicalCallerAuthenticatorConfig, TrustedVerificationSource, VerificationCachePolicy,
    },
    support::{
        HttpsFixture, NeverCancelled, SigningMaterial, TestClock, authenticator, config, context,
        install_jwks,
    },
    transport::ScriptedResponse,
};

#[derive(Clone, Copy, Debug)]
enum ScopeExpectation {
    NoTarget,
    Target(&'static str),
    Error(AuthenticationError),
}

fn claims(scope: Option<Value>) -> Value {
    let mut claims = json!({
        "iss": "https://issuer.test",
        "aud": "permissionsync",
        "exp": 4_000_000_000_f64,
        "iat": 1_700_000_000_f64,
        "client_id": "test-caller",
    });
    if let Some(scope) = scope {
        claims["scope"] = scope;
    }
    claims
}

fn token(material: &SigningMaterial, claims: Value, header: &JwsHeader) -> String {
    material.token(&serde_json::to_vec(&claims).unwrap(), header)
}

fn header_with_kid(kid: &str) -> JwsHeader {
    let mut header = JwsHeader::new();
    header.set_key_id(kid);
    header
}

async fn cached_authenticator(
    jwks: &[u8],
    algorithms: Vec<JwtAlgorithm>,
) -> TechnicalCallerAuthenticator {
    cached_authenticator_with_clock(
        jwks,
        algorithms,
        TestClock::new(Instant::now(), Some(1_700_000_000_f64)),
    )
    .await
}

/// Same fixed-issuer/audience direct-JWKS authenticator as
/// [`cached_authenticator`], but with a caller-controlled clock so tests can
/// exercise an unavailable wall clock (`unix_seconds() == None`) without
/// affecting the monotonic `tick()` used for cache aging/install.
async fn cached_authenticator_with_clock(
    jwks: &[u8],
    algorithms: Vec<JwtAlgorithm>,
    clock: TestClock,
) -> TechnicalCallerAuthenticator {
    let now = Instant::now();
    let mut authenticator = authenticator(
        TechnicalCallerAuthenticatorConfig::new(
            "https://issuer.test".to_owned(),
            "permissionsync".to_owned(),
            TrustedVerificationSource::DirectJwks {
                uri: "https://issuer.test/jwks".to_owned(),
            },
            algorithms,
            Duration::from_secs(1),
            VerificationCachePolicy::new(Duration::from_secs(60), Duration::ZERO),
            Duration::from_secs(5),
            Vec::new(),
        )
        .unwrap(),
        clock,
    );
    let never_cancelled = NeverCancelled;
    let install_context = context(now + Duration::from_secs(5), &never_cancelled);
    install_jwks(&mut authenticator, jwks, &install_context)
        .await
        .unwrap();
    authenticator
}

async fn authenticate_token(
    authenticator: &TechnicalCallerAuthenticator,
    token: &str,
) -> Result<AuthenticatedTechnicalCaller, AuthenticationError> {
    let never_cancelled = NeverCancelled;
    let request_context = context(Instant::now() + Duration::from_secs(5), &never_cancelled);
    authenticator
        .authenticate(AuthenticationRequest::new(Some(token), request_context))
        .await
}

fn assert_error(
    result: Result<AuthenticatedTechnicalCaller, AuthenticationError>,
    expected: AuthenticationError,
    case: &str,
) {
    assert_eq!(result.err(), Some(expected), "{case}");
}

#[tokio::test]
async fn valid_signed_result_preserves_exact_bearer_client_and_target() {
    let signing = SigningMaterial::new(JwtAlgorithm::RS256, "valid-key");
    let authenticator = cached_authenticator(&signing.jwks(), vec![JwtAlgorithm::RS256]).await;
    let token = token(
        &signing,
        claims(Some(json!("openid permissionsync:target-a service"))),
        &header_with_kid("valid-key"),
    );

    let result = authenticate_token(&authenticator, &token).await.unwrap();
    assert_eq!(result.bearer_token().as_str(), token);
    assert_eq!(result.client_id().as_str(), "test-caller");
    assert_eq!(
        result
            .target_selection()
            .selected()
            .map(LogicalTarget::as_str),
        Some("target-a")
    );
}

#[tokio::test]
async fn invalid_signature_is_rejected_even_when_kid_matches() {
    let trusted = SigningMaterial::new(JwtAlgorithm::RS256, "shared-kid");
    let attacker = SigningMaterial::new(JwtAlgorithm::RS256, "shared-kid");
    let authenticator = cached_authenticator(&trusted.jwks(), vec![JwtAlgorithm::RS256]).await;
    let token = token(
        &attacker,
        claims(Some(json!("permissionsync:target-a"))),
        &header_with_kid("shared-kid"),
    );

    assert_error(
        authenticate_token(&authenticator, &token).await,
        AuthenticationError::Rejected,
        "invalid signature",
    );
}

#[tokio::test]
async fn every_supported_asymmetric_algorithm_family_verifies() {
    for algorithm in [
        JwtAlgorithm::RS256,
        JwtAlgorithm::PS256,
        JwtAlgorithm::ES256,
        JwtAlgorithm::EdDSA,
    ] {
        let signing = SigningMaterial::new(algorithm, "family-key");
        let authenticator = cached_authenticator(&signing.jwks(), vec![algorithm]).await;
        let token = token(
            &signing,
            claims(Some(json!("permissionsync:family-target"))),
            &header_with_kid("family-key"),
        );

        let result = authenticate_token(&authenticator, &token)
            .await
            .unwrap_or_else(|error| panic!("{algorithm:?}: {error}"));
        assert_eq!(result.client_id().as_str(), "test-caller", "{algorithm:?}");
        assert_eq!(
            result
                .target_selection()
                .selected()
                .map(LogicalTarget::as_str),
            Some("family-target"),
            "{algorithm:?}"
        );
    }
}

#[tokio::test]
async fn kid_selection_handles_present_absent_duplicate_and_no_candidates() {
    let present = SigningMaterial::new(JwtAlgorithm::RS256, "present-kid");
    let present_authenticator =
        cached_authenticator(&present.jwks(), vec![JwtAlgorithm::RS256]).await;
    let present_token = token(
        &present,
        claims(Some(json!("permissionsync:present"))),
        &header_with_kid("present-kid"),
    );
    assert!(
        authenticate_token(&present_authenticator, &present_token)
            .await
            .is_ok()
    );

    // SigningMaterial assigns a kid and josekit copies a signer's kid into the
    // protected header. Build the no-kid key directly so both the trusted JWK
    // and the compact token are genuinely without kid.
    let without_kid = Jwk::generate_rsa_key(2048).unwrap();
    let without_kid_public = without_kid.to_public_key().unwrap();
    let without_kid_jwks = serde_json::to_vec(&json!({
        "keys": [without_kid_public.clone()],
    }))
    .unwrap();
    let without_kid_authenticator =
        cached_authenticator(&without_kid_jwks, vec![JwtAlgorithm::RS256]).await;
    let without_kid_token = JwsContext::new()
        .serialize_compact(
            &serde_json::to_vec(&claims(Some(json!("permissionsync:no-kid")))).unwrap(),
            &JwsHeader::new(),
            &jws::RS256.signer_from_jwk(&without_kid).unwrap(),
        )
        .unwrap();
    let (_, signed_header) = JwsContext::new()
        .deserialize_compact(
            &without_kid_token,
            &jws::RS256.verifier_from_jwk(&without_kid_public).unwrap(),
        )
        .unwrap();
    assert!(signed_header.key_id().is_none());
    assert!(
        authenticate_token(&without_kid_authenticator, &without_kid_token)
            .await
            .is_ok()
    );

    let first_duplicate = SigningMaterial::new(JwtAlgorithm::RS256, "duplicate-kid");
    let second_duplicate = SigningMaterial::new(JwtAlgorithm::RS256, "duplicate-kid");
    let mut duplicate_jwks: Value = serde_json::from_slice(&first_duplicate.jwks()).unwrap();
    let second_jwks: Value = serde_json::from_slice(&second_duplicate.jwks()).unwrap();
    duplicate_jwks["keys"]
        .as_array_mut()
        .unwrap()
        .push(second_jwks["keys"][0].clone());
    let duplicate_authenticator = cached_authenticator(
        &serde_json::to_vec(&duplicate_jwks).unwrap(),
        vec![JwtAlgorithm::RS256],
    )
    .await;
    let duplicate_token = token(
        &second_duplicate,
        claims(Some(json!("permissionsync:duplicate"))),
        &header_with_kid("duplicate-kid"),
    );
    assert!(
        authenticate_token(&duplicate_authenticator, &duplicate_token)
            .await
            .is_ok()
    );

    let fixture = HttpsFixture::start(vec![ScriptedResponse::jwks(present.jwks())]).await;
    let authenticator = authenticator(
        config(
            TrustedVerificationSource::DirectJwks {
                uri: fixture.endpoint("/jwks"),
            },
            fixture.trust_anchor_pem().to_vec(),
            vec![JwtAlgorithm::RS256],
            VerificationCachePolicy::new(Duration::from_secs(60), Duration::ZERO),
        ),
        TestClock::new(Instant::now(), Some(1_700_000_000_f64)),
    );
    let unknown_kid_token = JwsContext::new()
        .serialize_compact(
            &serde_json::to_vec(&claims(Some(json!("permissionsync:unknown")))).unwrap(),
            &header_with_kid("unknown-kid"),
            &jws::RS256.signer_from_jwk(&without_kid).unwrap(),
        )
        .unwrap();
    assert_error(
        authenticate_token(&authenticator, &unknown_kid_token).await,
        AuthenticationError::Rejected,
        "no kid candidate after trusted refresh",
    );
    assert_eq!(fixture.request_count(), 1);
    fixture.shutdown().await;
}

#[tokio::test]
async fn malformed_or_prohibited_headers_reject_before_metadata_io() {
    let signing = SigningMaterial::new(JwtAlgorithm::RS256, "header-key");
    let fixture = HttpsFixture::start(Vec::new()).await;
    let authenticator = authenticator(
        config(
            TrustedVerificationSource::DirectJwks {
                uri: fixture.endpoint("/jwks"),
            },
            fixture.trust_anchor_pem().to_vec(),
            vec![JwtAlgorithm::RS256],
            VerificationCachePolicy::new(Duration::from_secs(60), Duration::ZERO),
        ),
        TestClock::new(Instant::now(), Some(1_700_000_000_f64)),
    );
    let mut crit_header = header_with_kid("header-key");
    crit_header.set_critical(&vec!["sentinel-extension"]);
    let mut b64_header = header_with_kid("header-key");
    b64_header.set_claim("b64", Some(json!(true))).unwrap();
    let tokens = [
        "not-a-compact-jwt".to_owned(),
        "eyJraWQiOiJoZWFkZXIta2V5In0.e30.signature".to_owned(),
        "eyJhbGciOiJIUzI1NiJ9.e30.signature".to_owned(),
        token(&signing, claims(None), &crit_header),
        token(&signing, claims(None), &b64_header),
    ];

    for token in tokens {
        assert_error(
            authenticate_token(&authenticator, &token).await,
            AuthenticationError::Rejected,
            "preflight rejection",
        );
    }
    assert_eq!(fixture.request_count(), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn token_controlled_key_locations_do_not_expand_trust() {
    let trusted = SigningMaterial::new(JwtAlgorithm::RS256, "trusted-kid");
    let attacker = SigningMaterial::new(JwtAlgorithm::RS256, "trusted-kid");
    let authenticator = cached_authenticator(&trusted.jwks(), vec![JwtAlgorithm::RS256]).await;
    let attacker_jwks: Value = serde_json::from_slice(&attacker.jwks()).unwrap();
    let embedded_jwk =
        Jwk::from_bytes(serde_json::to_vec(&attacker_jwks["keys"][0]).unwrap()).unwrap();
    let mut header = header_with_kid("trusted-kid");
    header.set_jwk_set_url("https://attacker.invalid/jwks");
    header.set_x509_url("https://attacker.invalid/certificate");
    header.set_jwk(embedded_jwk);

    let trusted_token = token(
        &trusted,
        claims(Some(json!("permissionsync:trusted"))),
        &header,
    );
    assert!(
        authenticate_token(&authenticator, &trusted_token)
            .await
            .is_ok()
    );

    let attacker_token = token(
        &attacker,
        claims(Some(json!("permissionsync:attacker"))),
        &header,
    );
    assert_error(
        authenticate_token(&authenticator, &attacker_token).await,
        AuthenticationError::Rejected,
        "embedded JWK, jku, and x5u cannot replace the configured verifier",
    );
}

#[tokio::test]
async fn required_claim_shapes_and_temporal_values_are_enforced() {
    let signing = SigningMaterial::new(JwtAlgorithm::RS256, "claims-key");
    let authenticator = cached_authenticator(&signing.jwks(), vec![JwtAlgorithm::RS256]).await;
    let header = header_with_kid("claims-key");

    for claim in ["iss", "aud", "exp", "iat", "client_id"] {
        let mut missing = claims(None);
        missing.as_object_mut().unwrap().remove(claim);
        assert_error(
            authenticate_token(&authenticator, &token(&signing, missing, &header)).await,
            AuthenticationError::Rejected,
            claim,
        );
    }

    for (claim, value) in [
        ("iss", json!(null)),
        ("iss", json!("https://other-issuer.test")),
        ("aud", json!(null)),
        ("aud", json!([])),
        ("aud", json!(["other", 1])),
        ("aud", json!(["other"])),
        ("exp", json!(null)),
        ("exp", json!("4000000000")),
        ("exp", json!(1_700_000_000_f64)),
        ("iat", json!(null)),
        ("iat", json!("1700000000")),
        ("iat", json!(1_700_000_301_f64)),
        ("client_id", json!(null)),
        ("client_id", json!(["caller"])),
        ("client_id", json!({"id": "caller"})),
    ] {
        let mut malformed = claims(None);
        malformed[claim] = value;
        assert_error(
            authenticate_token(&authenticator, &token(&signing, malformed, &header)).await,
            AuthenticationError::Rejected,
            claim,
        );
    }

    let mut multiple_audiences = claims(None);
    multiple_audiences["aud"] = json!(["other", "permissionsync"]);
    assert!(
        authenticate_token(
            &authenticator,
            &token(&signing, multiple_audiences, &header),
        )
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn scope_target_matrix_preserves_rejected_and_forbidden_precedence() {
    let signing = SigningMaterial::new(JwtAlgorithm::RS256, "scope-key");
    let authenticator = cached_authenticator(&signing.jwks(), vec![JwtAlgorithm::RS256]).await;
    let header = header_with_kid("scope-key");
    let cases = [
        ("absent", None, ScopeExpectation::NoTarget),
        ("empty", Some(json!("")), ScopeExpectation::NoTarget),
        (
            "unrelated and lookalikes",
            Some(json!(
                "service Permissionsync:glpi xpermissionsync:glpi permissionsyncx:glpi other:permissionsync:glpi"
            )),
            ScopeExpectation::NoTarget,
        ),
        (
            "single selected target",
            Some(json!("service permissionsync:glpi")),
            ScopeExpectation::Target("glpi"),
        ),
        (
            "multiple targets",
            Some(json!("permissionsync:glpi permissionsync:grafana")),
            ScopeExpectation::Error(AuthenticationError::Forbidden),
        ),
        (
            "duplicate targets",
            Some(json!("permissionsync:glpi permissionsync:glpi")),
            ScopeExpectation::Error(AuthenticationError::Forbidden),
        ),
        (
            "empty selected suffix",
            Some(json!("permissionsync:")),
            ScopeExpectation::Error(AuthenticationError::Forbidden),
        ),
        (
            "uppercase selected suffix",
            Some(json!("permissionsync:GLPI")),
            ScopeExpectation::Error(AuthenticationError::Forbidden),
        ),
        (
            "leading separator selected suffix",
            Some(json!("permissionsync:-glpi")),
            ScopeExpectation::Error(AuthenticationError::Forbidden),
        ),
        (
            "trailing separator selected suffix",
            Some(json!("permissionsync:glpi-")),
            ScopeExpectation::Error(AuthenticationError::Forbidden),
        ),
        (
            "colon in selected suffix",
            Some(json!("permissionsync:glpi:admin")),
            ScopeExpectation::Error(AuthenticationError::Forbidden),
        ),
        (
            "invalid suffix does not hide a duplicate target",
            Some(json!("permissionsync: permissionsync:glpi")),
            ScopeExpectation::Error(AuthenticationError::Forbidden),
        ),
        (
            "null scope shape",
            Some(json!(null)),
            ScopeExpectation::Error(AuthenticationError::Rejected),
        ),
        (
            "array scope shape",
            Some(json!(["permissionsync:glpi"])),
            ScopeExpectation::Error(AuthenticationError::Rejected),
        ),
        (
            "object scope shape",
            Some(json!({"scope": "permissionsync:glpi"})),
            ScopeExpectation::Error(AuthenticationError::Rejected),
        ),
        (
            "number scope shape",
            Some(json!(1)),
            ScopeExpectation::Error(AuthenticationError::Rejected),
        ),
        (
            "boolean scope shape",
            Some(json!(true)),
            ScopeExpectation::Error(AuthenticationError::Rejected),
        ),
        (
            "double space is malformed",
            Some(json!("permissionsync:glpi  service")),
            ScopeExpectation::Error(AuthenticationError::Rejected),
        ),
        (
            "tab is malformed",
            Some(json!("permissionsync:glpi\tservice")),
            ScopeExpectation::Error(AuthenticationError::Rejected),
        ),
        (
            "control character precedes suffix validation",
            Some(json!("permissionsync:GLPI\u{7f}")),
            ScopeExpectation::Error(AuthenticationError::Rejected),
        ),
        (
            "non-ASCII scope byte is malformed",
            Some(json!("permissionsync:glpié")),
            ScopeExpectation::Error(AuthenticationError::Rejected),
        ),
    ];

    for (name, scope, expected) in cases {
        let result =
            authenticate_token(&authenticator, &token(&signing, claims(scope), &header)).await;
        match expected {
            ScopeExpectation::NoTarget => {
                assert!(
                    result.unwrap().target_selection().selected().is_none(),
                    "{name}"
                );
            }
            ScopeExpectation::Target(target) => {
                assert_eq!(
                    result
                        .unwrap()
                        .target_selection()
                        .selected()
                        .map(LogicalTarget::as_str),
                    Some(target),
                    "{name}"
                );
            }
            ScopeExpectation::Error(error) => assert_error(result, error, name),
        }
    }
}

#[tokio::test]
async fn public_errors_redact_sentinel_bearers_and_claims_without_sources() {
    let trusted = SigningMaterial::new(JwtAlgorithm::RS256, "redaction-key");
    let attacker = SigningMaterial::new(JwtAlgorithm::RS256, "redaction-key");
    let authenticator = cached_authenticator(&trusted.jwks(), vec![JwtAlgorithm::RS256]).await;
    let mut sensitive_claims = claims(Some(json!("permissionsync:claims-sentinel")));
    sensitive_claims["client_id"] = json!("claims-sentinel");
    let sensitive_token = token(
        &attacker,
        sensitive_claims,
        &header_with_kid("redaction-key"),
    );

    for token in ["token-sentinel".to_owned(), sensitive_token] {
        let error = authenticate_token(&authenticator, &token)
            .await
            .err()
            .unwrap();
        assert_eq!(error, AuthenticationError::Rejected);
        assert!(!error.to_string().contains("token-sentinel"));
        assert!(!error.to_string().contains("claims-sentinel"));
        assert!(!format!("{error:?}").contains("token-sentinel"));
        assert!(!format!("{error:?}").contains("claims-sentinel"));
        assert!(Error::source(&error).is_none());
    }
}

#[tokio::test]
async fn unavailable_clock_follows_authentication_shape_before_scope_validation() {
    let signing = SigningMaterial::new(JwtAlgorithm::RS256, "precedence-key");
    let authenticator = cached_authenticator_with_clock(
        &signing.jwks(),
        vec![JwtAlgorithm::RS256],
        TestClock::new(Instant::now(), None),
    )
    .await;
    let header = header_with_kid("precedence-key");

    for (name, malformed_authentication_claim) in [
        ("invalid iss", {
            let mut claims = claims(None);
            claims["iss"] = json!("https://other-issuer.test");
            claims
        }),
        ("invalid aud", {
            let mut claims = claims(None);
            claims["aud"] = json!(["other"]);
            claims
        }),
        ("malformed exp", {
            let mut claims = claims(None);
            claims["exp"] = json!("4000000000");
            claims
        }),
        ("malformed iat", {
            let mut claims = claims(None);
            claims["iat"] = json!("1700000000");
            claims
        }),
        ("malformed client_id", {
            let mut claims = claims(None);
            claims["client_id"] = json!(["test-caller"]);
            claims
        }),
    ] {
        assert_error(
            authenticate_token(
                &authenticator,
                &token(&signing, malformed_authentication_claim, &header),
            )
            .await,
            AuthenticationError::Rejected,
            name,
        );
    }

    for (name, malformed_scope) in [
        (
            "wrong-shaped scope",
            claims(Some(json!(["permissionsync:glpi"]))),
        ),
        (
            "malformed scope syntax",
            claims(Some(json!("permissionsync:glpi  service"))),
        ),
    ] {
        assert_error(
            authenticate_token(&authenticator, &token(&signing, malformed_scope, &header)).await,
            AuthenticationError::VerifierUnavailable,
            name,
        );
    }

    assert_error(
        authenticate_token(&authenticator, &token(&signing, claims(None), &header)).await,
        AuthenticationError::VerifierUnavailable,
        "otherwise-valid claims with no clock",
    );

    assert_error(
        authenticate_token(
            &authenticator,
            &token(
                &signing,
                claims(Some(json!("permissionsync:glpi permissionsync:grafana"))),
                &header,
            ),
        )
        .await,
        AuthenticationError::VerifierUnavailable,
        "otherwise-valid claims, two distinct scopes, no clock: unavailable, not forbidden",
    );
}

#[tokio::test]
async fn available_clock_orders_authentication_then_scope_authorization() {
    let signing = SigningMaterial::new(JwtAlgorithm::RS256, "precedence-clocked-key");
    let authenticator = cached_authenticator(&signing.jwks(), vec![JwtAlgorithm::RS256]).await;
    let header = header_with_kid("precedence-clocked-key");

    let mut missing_client_id_multiple_scopes =
        claims(Some(json!("permissionsync:glpi permissionsync:grafana")));
    missing_client_id_multiple_scopes
        .as_object_mut()
        .unwrap()
        .remove("client_id");
    assert_error(
        authenticate_token(
            &authenticator,
            &token(&signing, missing_client_id_multiple_scopes, &header),
        )
        .await,
        AuthenticationError::Rejected,
        "missing client_id with multiple scopes: shape failure precedes authorization",
    );

    for (name, claim, value) in [
        ("expired exp", "exp", json!(1_699_999_999_f64)),
        ("future-issued iat", "iat", json!(1_700_000_006_f64)),
    ] {
        let mut temporally_invalid =
            claims(Some(json!("permissionsync:glpi permissionsync:grafana")));
        temporally_invalid[claim] = value;
        assert_error(
            authenticate_token(
                &authenticator,
                &token(&signing, temporally_invalid, &header),
            )
            .await,
            AuthenticationError::Rejected,
            name,
        );
    }

    assert_error(
        authenticate_token(
            &authenticator,
            &token(
                &signing,
                claims(Some(json!("permissionsync:glpi permissionsync:grafana"))),
                &header,
            ),
        )
        .await,
        AuthenticationError::Forbidden,
        "fully valid claims with multiple scopes",
    );

    let result = authenticate_token(
        &authenticator,
        &token(&signing, claims(Some(json!(""))), &header),
    )
    .await
    .unwrap();
    assert!(result.target_selection().selected().is_none());
    assert_eq!(result.client_id().as_str(), "test-caller");
}

#[tokio::test]
async fn ignored_claims_do_not_affect_identity_or_the_authentication_outcome() {
    let signing = SigningMaterial::new(JwtAlgorithm::RS256, "ignored-claims-key");
    let authenticator = cached_authenticator(&signing.jwks(), vec![JwtAlgorithm::RS256]).await;
    let mut ignored_claims = claims(Some(json!("permissionsync:glpi")));
    ignored_claims["nbf"] = json!(9_000_000_000_f64);
    ignored_claims["sub"] = json!("someone-else");
    ignored_claims["azp"] = json!("some-authorized-party");
    ignored_claims["jti"] = json!("11111111-1111-1111-1111-111111111111");
    ignored_claims["acr"] = json!("urn:mace:incommon:iap:silver");

    let result = authenticate_token(
        &authenticator,
        &token(
            &signing,
            ignored_claims,
            &header_with_kid("ignored-claims-key"),
        ),
    )
    .await
    .unwrap();

    assert_eq!(result.client_id().as_str(), "test-caller");
    assert_eq!(
        result
            .target_selection()
            .selected()
            .map(LogicalTarget::as_str),
        Some("glpi")
    );
}

#[tokio::test]
async fn scope_grammar_edge_bytes_are_rejected() {
    let signing = SigningMaterial::new(JwtAlgorithm::RS256, "scope-edge-key");
    let authenticator = cached_authenticator(&signing.jwks(), vec![JwtAlgorithm::RS256]).await;
    let header = header_with_kid("scope-edge-key");

    for (name, scope) in [
        ("leading space", " permissionsync:glpi"),
        ("trailing space", "permissionsync:glpi "),
        ("newline", "permissionsync:glpi\nservice"),
        ("embedded quote", "permissionsync:gl\"pi"),
        ("embedded backslash", "permissionsync:gl\\pi"),
        ("DEL control byte", "permissionsync:glpi\u{7f}"),
    ] {
        assert_error(
            authenticate_token(
                &authenticator,
                &token(&signing, claims(Some(json!(scope))), &header),
            )
            .await,
            AuthenticationError::Rejected,
            name,
        );
    }
}

#[tokio::test]
async fn every_configured_algorithm_family_signs_and_verifies_through_authenticate() {
    for algorithm in [
        JwtAlgorithm::RS256,
        JwtAlgorithm::RS384,
        JwtAlgorithm::RS512,
        JwtAlgorithm::PS256,
        JwtAlgorithm::PS384,
        JwtAlgorithm::PS512,
        JwtAlgorithm::ES256,
        JwtAlgorithm::ES384,
        JwtAlgorithm::ES512,
        JwtAlgorithm::EdDSA,
    ] {
        let signing = SigningMaterial::new(algorithm, "algorithm-matrix-key");
        let authenticator = cached_authenticator(&signing.jwks(), vec![algorithm]).await;
        let token = token(
            &signing,
            claims(Some(json!("permissionsync:algorithm-target"))),
            &header_with_kid("algorithm-matrix-key"),
        );

        let result = authenticate_token(&authenticator, &token)
            .await
            .unwrap_or_else(|error| panic!("{algorithm:?}: {error}"));
        assert_eq!(result.client_id().as_str(), "test-caller", "{algorithm:?}");
        assert_eq!(
            result
                .target_selection()
                .selected()
                .map(LogicalTarget::as_str),
            Some("algorithm-target"),
            "{algorithm:?}"
        );
    }
}

/// `SigningMaterial` always generates `Ed25519` for `JwtAlgorithm::EdDSA`
/// (already covered above); this test independently confirms this
/// josekit+OpenSSL stack also verifies `Ed448` EdDSA tokens through
/// `authenticate`, since the trusted-verification path accepts either curve
/// for `EdDSA` (see `jwks::compatible`).
#[tokio::test]
async fn ed448_eddsa_tokens_also_verify_through_authenticate() {
    let mut key = Jwk::generate_ed_key(EdCurve::Ed448).unwrap();
    key.set_key_id("ed448-key");
    let mut public = key.to_public_key().unwrap();
    public.set_key_id("ed448-key");
    let jwks = serde_json::to_vec(&json!({"keys": [public]})).unwrap();
    let authenticator = cached_authenticator(&jwks, vec![JwtAlgorithm::EdDSA]).await;
    let payload = serde_json::to_vec(&claims(Some(json!("permissionsync:ed448-target")))).unwrap();
    let token = JwsContext::new()
        .serialize_compact(
            &payload,
            &header_with_kid("ed448-key"),
            &jws::EdDSA.signer_from_jwk(&key).unwrap(),
        )
        .unwrap();

    let result = authenticate_token(&authenticator, &token).await.unwrap();
    assert_eq!(result.client_id().as_str(), "test-caller");
    assert_eq!(
        result
            .target_selection()
            .selected()
            .map(LogicalTarget::as_str),
        Some("ed448-target")
    );
}

#[test]
fn authenticator_configuration_constructor_rejects_each_invalid_input_with_the_exact_variant() {
    use AuthenticatorConfigurationError as Error;

    #[allow(clippy::too_many_arguments)]
    fn build(
        issuer: &str,
        audience: &str,
        source: TrustedVerificationSource,
        algorithms: Vec<JwtAlgorithm>,
        metadata_timeout: Duration,
        cache_policy: VerificationCachePolicy,
        clock_skew: Duration,
        trust_anchors_pem: Vec<Vec<u8>>,
    ) -> Result<TechnicalCallerAuthenticatorConfig, AuthenticatorConfigurationError> {
        TechnicalCallerAuthenticatorConfig::new(
            issuer.to_owned(),
            audience.to_owned(),
            source,
            algorithms,
            metadata_timeout,
            cache_policy,
            clock_skew,
            trust_anchors_pem,
        )
    }

    fn direct(uri: &str) -> TrustedVerificationSource {
        TrustedVerificationSource::DirectJwks {
            uri: uri.to_owned(),
        }
    }

    let valid_source = || direct("https://issuer.test/jwks");
    let valid_algorithms = || vec![JwtAlgorithm::RS256];
    let valid_metadata_timeout = Duration::from_secs(1);
    let valid_cache_policy = VerificationCachePolicy::new(Duration::from_secs(60), Duration::ZERO);
    let valid_clock_skew = Duration::from_secs(5);

    let cases: Vec<(
        &str,
        Result<TechnicalCallerAuthenticatorConfig, AuthenticatorConfigurationError>,
        Error,
    )> = vec![
        (
            "empty issuer",
            build(
                "",
                "permissionsync",
                valid_source(),
                valid_algorithms(),
                valid_metadata_timeout,
                valid_cache_policy,
                valid_clock_skew,
                Vec::new(),
            ),
            Error::InvalidIssuer,
        ),
        (
            "invalid issuer",
            build(
                "not-a-uri",
                "permissionsync",
                valid_source(),
                valid_algorithms(),
                valid_metadata_timeout,
                valid_cache_policy,
                valid_clock_skew,
                Vec::new(),
            ),
            Error::InvalidIssuer,
        ),
        (
            "issuer with a query",
            build(
                "https://issuer.test?realm=main",
                "permissionsync",
                valid_source(),
                valid_algorithms(),
                valid_metadata_timeout,
                valid_cache_policy,
                valid_clock_skew,
                Vec::new(),
            ),
            Error::InvalidIssuer,
        ),
        (
            "issuer with a fragment",
            build(
                "https://issuer.test#fragment",
                "permissionsync",
                valid_source(),
                valid_algorithms(),
                valid_metadata_timeout,
                valid_cache_policy,
                valid_clock_skew,
                Vec::new(),
            ),
            Error::InvalidIssuer,
        ),
        (
            "empty audience",
            build(
                "https://issuer.test",
                "",
                valid_source(),
                valid_algorithms(),
                valid_metadata_timeout,
                valid_cache_policy,
                valid_clock_skew,
                Vec::new(),
            ),
            Error::InvalidAudience,
        ),
        (
            "HTTP metadata source",
            build(
                "https://issuer.test",
                "permissionsync",
                direct("http://issuer.test/jwks"),
                valid_algorithms(),
                valid_metadata_timeout,
                valid_cache_policy,
                valid_clock_skew,
                Vec::new(),
            ),
            Error::InvalidSource,
        ),
        (
            "userinfo metadata source",
            build(
                "https://issuer.test",
                "permissionsync",
                direct("https://user@issuer.test/jwks"),
                valid_algorithms(),
                valid_metadata_timeout,
                valid_cache_policy,
                valid_clock_skew,
                Vec::new(),
            ),
            Error::InvalidSource,
        ),
        (
            "empty algorithm allowlist",
            build(
                "https://issuer.test",
                "permissionsync",
                valid_source(),
                Vec::new(),
                valid_metadata_timeout,
                valid_cache_policy,
                valid_clock_skew,
                Vec::new(),
            ),
            Error::InvalidAlgorithms,
        ),
        (
            "duplicate algorithm allowlist",
            build(
                "https://issuer.test",
                "permissionsync",
                valid_source(),
                vec![JwtAlgorithm::RS256, JwtAlgorithm::RS256],
                valid_metadata_timeout,
                valid_cache_policy,
                valid_clock_skew,
                Vec::new(),
            ),
            Error::InvalidAlgorithms,
        ),
        (
            "zero metadata timeout",
            build(
                "https://issuer.test",
                "permissionsync",
                valid_source(),
                valid_algorithms(),
                Duration::ZERO,
                valid_cache_policy,
                valid_clock_skew,
                Vec::new(),
            ),
            Error::InvalidMetadataTimeout,
        ),
        (
            "zero cache freshness",
            build(
                "https://issuer.test",
                "permissionsync",
                valid_source(),
                valid_algorithms(),
                valid_metadata_timeout,
                VerificationCachePolicy::new(Duration::ZERO, Duration::ZERO),
                valid_clock_skew,
                Vec::new(),
            ),
            Error::InvalidCachePolicy,
        ),
        (
            "overflowing freshness plus stale_if_error",
            build(
                "https://issuer.test",
                "permissionsync",
                valid_source(),
                valid_algorithms(),
                valid_metadata_timeout,
                VerificationCachePolicy::new(Duration::MAX, Duration::from_secs(1)),
                valid_clock_skew,
                Vec::new(),
            ),
            Error::InvalidCachePolicy,
        ),
        (
            "clock skew above the maximum",
            build(
                "https://issuer.test",
                "permissionsync",
                valid_source(),
                valid_algorithms(),
                valid_metadata_timeout,
                valid_cache_policy,
                Duration::from_secs(5 * 60 + 1),
                Vec::new(),
            ),
            Error::InvalidClockSkew,
        ),
        (
            "malformed trust-anchor PEM",
            build(
                "https://issuer.test",
                "permissionsync",
                valid_source(),
                valid_algorithms(),
                valid_metadata_timeout,
                valid_cache_policy,
                valid_clock_skew,
                vec![b"not a certificate".to_vec()],
            ),
            Error::InvalidTrustAnchor,
        ),
    ];

    for (name, result, expected) in cases {
        assert_eq!(result.err(), Some(expected), "{name}");
    }
}

#[test]
fn a_fully_valid_configuration_constructs_without_any_remote_io() {
    let config = TechnicalCallerAuthenticatorConfig::new(
        "https://issuer.test".to_owned(),
        "permissionsync".to_owned(),
        TrustedVerificationSource::DirectJwks {
            uri: "https://issuer.test/jwks".to_owned(),
        },
        vec![JwtAlgorithm::RS256],
        Duration::from_secs(1),
        VerificationCachePolicy::new(Duration::from_secs(60), Duration::ZERO),
        Duration::from_secs(5),
        Vec::new(),
    );

    // Constructing a valid configuration performs only local, synchronous
    // validation and TLS-connector construction: no network fixture is
    // started here, and this test does not `.await` anything.
    assert!(config.is_ok());
}
