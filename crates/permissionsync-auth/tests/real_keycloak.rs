//! Real supported-Keycloak deployment contract suite.
//!
//! These ignored tests prove that the one supported Keycloak release this
//! repository exercises actually satisfies the external deployment contract
//! [ADR-0002](../../../docs/adr/0002-receiver-side-jwt-verification.md)
//! depends on. They run the production authentication code against real
//! Keycloak-issued tokens over real HTTPS; they never reimplement JWT
//! validation, and they are not a second copy of the hermetic adversarial
//! suite, which keeps owning parser, cryptographic, and cache-timing edge
//! cases.
//!
//! Invoke them explicitly after sourcing the runtime environment the
//! disposable bootstrap prints, and tear the environment down afterward
//! regardless of the test outcome:
//!
//! ```sh
//! source <(crates/permissionsync-auth/integration/keycloak/bootstrap.sh)
//! set -a
//! source "$KEYCLOAK_TEST_RUNTIME_ENV"
//! set +a
//! cargo test -p permissionsync-auth --test real_keycloak --locked -- --ignored
//! crates/permissionsync-auth/integration/keycloak/teardown.sh
//! ```
//!
//! Every test hard-fails when the bootstrap environment is absent or
//! incomplete; an ignored test that silently returned would be
//! indistinguishable from success. No access token, client secret, admin
//! password, or complete JWT is ever printed: assertions compare outcomes and
//! claim-derived identities only, and the one assertion that inspects the
//! preserved credential compares it without formatting either value.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, StatusCode,
    header::{ACCEPT, CONTENT_TYPE},
};
use hyper_tls::HttpsConnector;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioTimer},
};
use permissionsync_auth::{
    AuthenticationError, AuthenticationRequest, JwtAlgorithm, TargetSelection,
    TechnicalCallerAuthenticator, TechnicalCallerAuthenticatorConfig, TrustedVerificationSource,
    TrustedVerifierState, VerificationCachePolicy,
};
use permissionsync_core::{CancellationSignal, SynchronizationContext};

/// The logical target the provisioned `permissionsync:<target>` scope selects.
const SELECTED_LOGICAL_TARGET: &str = "glpi";

/// The disposable forwarder the metadata-outage test stops. Only that test
/// configures a trusted source through it, so stopping it cannot disturb any
/// other test in this suite.
const OUTAGE_PROXY_SERVICE: &str = "outage-proxy";

/// Generous per-attempt budget: these tests assert authentication outcomes,
/// never latency, so a budget this size cannot be mistaken for a timing
/// assertion.
const CONTRACT_DEADLINE: Duration = Duration::from_secs(30);

/// Bounded budget for one real JWKS or discovery retrieval.
const METADATA_TIMEOUT: Duration = Duration::from_secs(10);

/// Long enough that no assertion below races a cache freshness boundary.
const LONG_FRESHNESS: Duration = Duration::from_secs(300);

/// Short enough that the stale-if-error case can wait for a known instant
/// instead of an arbitrary interval.
const SHORT_FRESHNESS: Duration = Duration::from_secs(1);

const STALE_IF_ERROR: Duration = Duration::from_secs(600);

const CLOCK_SKEW: Duration = Duration::from_secs(30);

/// Deterministic allowance added after a short-lived token's reported lifetime
/// has elapsed, so the expiry assertion never races the boundary it is testing.
const EXPIRY_MARGIN: Duration = Duration::from_secs(2);

struct NeverCancelled;

impl CancellationSignal for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

fn context(cancellation: &NeverCancelled) -> SynchronizationContext<'_> {
    SynchronizationContext::new(Instant::now() + CONTRACT_DEADLINE, cancellation)
}

struct RealKeycloakEnvironment {
    release: String,
    issuer: String,
    discovery_uri: String,
    jwks_uri: String,
    outage_jwks_uri: String,
    token_endpoint: String,
    foreign_token_endpoint: String,
    audience: String,
    ca_pem: Vec<u8>,
    compose_project: String,
    runtime_env: String,
    caller_client_id: String,
    caller_client_secret: String,
    minimal_client_id: String,
    minimal_client_secret: String,
    disallowed_algorithm_client_id: String,
    disallowed_algorithm_client_secret: String,
    shortlived_client_id: String,
    shortlived_client_secret: String,
    wrong_audience_client_id: String,
    wrong_audience_client_secret: String,
    foreign_client_id: String,
    foreign_client_secret: String,
    target_scope: String,
    second_target_scope: String,
    invalid_target_scope: String,
    noise_scope: String,
    case_different_scope: String,
    lookalike_prefix_scope: String,
    lookalike_suffix_scope: String,
}

/// Loads the disposable environment the bootstrap emitted. This deliberately
/// panics instead of skipping: `--ignored` is the CI invocation for this suite.
fn real_environment() -> RealKeycloakEnvironment {
    fn required(name: &str) -> String {
        env::var(name).unwrap_or_else(|_| {
            panic!(
                "required real-Keycloak configuration is not set. Run `source <(crates/permissionsync-auth/integration/keycloak/bootstrap.sh)` first; missing configuration is a hard failure."
            )
        })
    }

    let ca_pem_path = required("KEYCLOAK_TEST_CA_PEM_PATH");
    let ca_pem =
        fs::read(&ca_pem_path).unwrap_or_else(|_| panic!("test CA certificate could not be read"));

    RealKeycloakEnvironment {
        release: required("KEYCLOAK_TEST_RELEASE"),
        issuer: required("KEYCLOAK_TEST_ISSUER"),
        discovery_uri: required("KEYCLOAK_TEST_DISCOVERY_URI"),
        jwks_uri: required("KEYCLOAK_TEST_JWKS_URI"),
        outage_jwks_uri: required("KEYCLOAK_TEST_OUTAGE_JWKS_URI"),
        token_endpoint: required("KEYCLOAK_TEST_TOKEN_ENDPOINT"),
        foreign_token_endpoint: required("KEYCLOAK_TEST_FOREIGN_TOKEN_ENDPOINT"),
        audience: required("KEYCLOAK_TEST_AUDIENCE"),
        ca_pem,
        compose_project: required("KEYCLOAK_TEST_COMPOSE_PROJECT"),
        runtime_env: required("KEYCLOAK_TEST_RUNTIME_ENV"),
        caller_client_id: required("KEYCLOAK_TEST_CALLER_CLIENT_ID"),
        caller_client_secret: required("KEYCLOAK_TEST_CALLER_CLIENT_SECRET"),
        minimal_client_id: required("KEYCLOAK_TEST_MINIMAL_CLIENT_ID"),
        minimal_client_secret: required("KEYCLOAK_TEST_MINIMAL_CLIENT_SECRET"),
        disallowed_algorithm_client_id: required("KEYCLOAK_TEST_DISALLOWED_ALGORITHM_CLIENT_ID"),
        disallowed_algorithm_client_secret: required(
            "KEYCLOAK_TEST_DISALLOWED_ALGORITHM_CLIENT_SECRET",
        ),
        shortlived_client_id: required("KEYCLOAK_TEST_SHORTLIVED_CLIENT_ID"),
        shortlived_client_secret: required("KEYCLOAK_TEST_SHORTLIVED_CLIENT_SECRET"),
        wrong_audience_client_id: required("KEYCLOAK_TEST_WRONG_AUDIENCE_CLIENT_ID"),
        wrong_audience_client_secret: required("KEYCLOAK_TEST_WRONG_AUDIENCE_CLIENT_SECRET"),
        foreign_client_id: required("KEYCLOAK_TEST_FOREIGN_CLIENT_ID"),
        foreign_client_secret: required("KEYCLOAK_TEST_FOREIGN_CLIENT_SECRET"),
        target_scope: required("KEYCLOAK_TEST_TARGET_SCOPE"),
        second_target_scope: required("KEYCLOAK_TEST_SECOND_TARGET_SCOPE"),
        invalid_target_scope: required("KEYCLOAK_TEST_INVALID_TARGET_SCOPE"),
        noise_scope: required("KEYCLOAK_TEST_NOISE_SCOPE"),
        case_different_scope: required("KEYCLOAK_TEST_CASE_DIFFERENT_SCOPE"),
        lookalike_prefix_scope: required("KEYCLOAK_TEST_LOOKALIKE_PREFIX_SCOPE"),
        lookalike_suffix_scope: required("KEYCLOAK_TEST_LOOKALIKE_SUFFIX_SCOPE"),
    }
}

/// Builds the production authenticator exactly as the executable does, with
/// the disposable CA supplied through the existing additional trust-anchor
/// configuration. Certificate and hostname validation are never relaxed: the
/// authenticator's own TLS construction forbids disabling either.
fn build_authenticator(
    environment: &RealKeycloakEnvironment,
    source: TrustedVerificationSource,
    algorithms: Vec<JwtAlgorithm>,
    freshness: Duration,
) -> TechnicalCallerAuthenticator {
    let config = TechnicalCallerAuthenticatorConfig::new(
        environment.issuer.clone(),
        environment.audience.clone(),
        source,
        algorithms,
        METADATA_TIMEOUT,
        VerificationCachePolicy::new(freshness, STALE_IF_ERROR),
        CLOCK_SKEW,
        vec![environment.ca_pem.clone()],
    )
    .expect("the disposable Keycloak environment produced valid authenticator configuration");
    TechnicalCallerAuthenticator::new(config)
}

/// The deployment's normal configuration: OIDC discovery and the ADR-0002
/// baseline algorithm.
fn baseline_authenticator(environment: &RealKeycloakEnvironment) -> TechnicalCallerAuthenticator {
    build_authenticator(
        environment,
        TrustedVerificationSource::OidcDiscovery {
            uri: environment.discovery_uri.clone(),
        },
        vec![JwtAlgorithm::RS256],
        LONG_FRESHNESS,
    )
}

type HttpsClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Test-support HTTPS client for the Keycloak endpoints PermissionSync itself
/// never calls: the token endpoint, and the discovery document this suite
/// inspects directly to assert the wire contract.
fn https_client(environment: &RealKeycloakEnvironment) -> HttpsClient {
    let certificate = hyper_tls::native_tls::Certificate::from_pem(&environment.ca_pem)
        .expect("the disposable CA certificate is valid PEM");
    let tls = hyper_tls::native_tls::TlsConnector::builder()
        .add_root_certificate(certificate)
        .build()
        .expect("a strict TLS client could be built from the disposable CA");
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    let mut https = HttpsConnector::from((http, tls.into()));
    https.https_only(true);
    Client::builder(TokioExecutor::new())
        .pool_timer(TokioTimer::new())
        .build(https)
}

/// Percent-encodes one `application/x-www-form-urlencoded` component. Scope
/// strings legitimately contain `:` and spaces, and a client secret must never
/// be altered, so nothing passes through unencoded except unreserved
/// characters.
fn form_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(char::from(*byte));
            }
            other => encoded.push_str(&format!("%{other:02X}")),
        }
    }
    encoded
}

struct IssuedToken {
    compact: String,
    lifetime: Duration,
}

/// Obtains one real Client Credentials access token. The client secret travels
/// in the request body, never on a command line, and neither the request nor
/// the response is logged.
async fn issue_token(
    environment: &RealKeycloakEnvironment,
    token_endpoint: &str,
    client_id: &str,
    client_secret: &str,
    scope: Option<&str>,
) -> IssuedToken {
    let mut form = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}",
        form_encode(client_id),
        form_encode(client_secret)
    );
    if let Some(scope) = scope {
        form.push('&');
        form.push_str("scope=");
        form.push_str(&form_encode(scope));
    }

    let request = Request::builder()
        .method("POST")
        .uri(token_endpoint)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(ACCEPT, "application/json")
        .body(Full::new(Bytes::from(form)))
        .expect("the token request is well formed");

    let response = https_client(environment)
        .request(request)
        .await
        .expect("the disposable Keycloak token endpoint answered over HTTPS");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the provisioned client could not obtain a Client Credentials token"
    );
    let body = response
        .into_body()
        .collect()
        .await
        .expect("the token response body was readable")
        .to_bytes();
    let document: serde_json::Value =
        serde_json::from_slice(&body).expect("the token response is JSON");
    let compact = document
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .expect("the token response carries an access token")
        .to_owned();
    let lifetime = Duration::from_secs(
        document
            .get("expires_in")
            .and_then(serde_json::Value::as_u64)
            .expect("the token response carries expires_in"),
    );
    IssuedToken { compact, lifetime }
}

async fn caller_token(environment: &RealKeycloakEnvironment, scope: Option<&str>) -> IssuedToken {
    issue_token(
        environment,
        &environment.token_endpoint,
        &environment.caller_client_id,
        &environment.caller_client_secret,
        scope,
    )
    .await
}

/// Fetches the realm's OIDC discovery document for direct wire assertions.
async fn discovery_document(environment: &RealKeycloakEnvironment) -> serde_json::Value {
    let request = Request::builder()
        .method("GET")
        .uri(&environment.discovery_uri)
        .header(ACCEPT, "application/json")
        .body(Full::new(Bytes::new()))
        .expect("the discovery request is well formed");
    let response = https_client(environment)
        .request(request)
        .await
        .expect("the disposable Keycloak discovery endpoint answered over HTTPS");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("the discovery response body was readable")
        .to_bytes();
    serde_json::from_slice(&body).expect("the discovery response is JSON")
}

fn compose_file() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("integration/keycloak/docker-compose.yml")
}

/// The supported Keycloak release, read from the compose file that pins it.
/// That file is the single declaration of the release, so Renovate can update
/// it without a second edit anywhere.
fn pinned_keycloak_release() -> String {
    let compose = fs::read_to_string(compose_file()).expect("the compose file could be read");
    compose
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("image: quay.io/keycloak/keycloak:")
        })
        .filter_map(|reference| reference.split_once('@'))
        .map(|(tag, _)| tag.to_owned())
        .next()
        .expect("the compose file pins the Keycloak image by tag and digest")
}

/// Runs one `docker compose` subcommand against this run's disposable project.
///
/// The compose file is addressed explicitly so the command does not depend on
/// the test process's working directory, or on a particular compose
/// implementation resolving a project by name alone.
fn compose(environment: &RealKeycloakEnvironment, arguments: &[&str]) {
    let compose_file = compose_file();
    let output = Command::new("docker")
        .args([
            "compose",
            "-f",
            &compose_file.to_string_lossy(),
            "--env-file",
            &environment.runtime_env,
            "-p",
            &environment.compose_project,
        ])
        .args(arguments)
        .output()
        .expect("docker compose could be executed");
    assert!(
        output.status.success(),
        "docker compose {arguments:?} did not succeed"
    );
}

async fn selected_target(subject: &TechnicalCallerAuthenticator, token: &str) -> Option<String> {
    let cancellation = NeverCancelled;
    let caller = subject
        .authenticate(AuthenticationRequest::new(
            Some(token),
            context(&cancellation),
        ))
        .await
        .expect("a real Keycloak token satisfying the contract authenticates");
    match caller.target_selection() {
        TargetSelection::NoTarget => None,
        TargetSelection::Selected(target) => Some(target.as_str().to_owned()),
    }
}

/// Returns the refusal category, never the token or any claim value.
async fn authentication_error(
    subject: &TechnicalCallerAuthenticator,
    token: &str,
) -> AuthenticationError {
    let cancellation = NeverCancelled;
    match subject
        .authenticate(AuthenticationRequest::new(
            Some(token),
            context(&cancellation),
        ))
        .await
    {
        Ok(_) => panic!("the token was expected to be refused"),
        Err(error) => error,
    }
}

#[tokio::test]
#[ignore = "requires a disposable real Keycloak environment; see integration/keycloak/bootstrap.sh"]
async fn oidc_discovery_establishes_trusted_state_and_verifies_a_real_token() {
    let environment = real_environment();
    assert_eq!(
        environment.release,
        pinned_keycloak_release(),
        "the bootstrap must report the Keycloak release the compose file pins"
    );

    // The wire contract the production discovery path depends on: the
    // document's issuer is exactly the configured trusted issuer, and the
    // JWKS URI it advertises is HTTPS.
    let document = discovery_document(&environment).await;
    assert_eq!(
        document.get("issuer").and_then(serde_json::Value::as_str),
        Some(environment.issuer.as_str()),
        "the discovered issuer must equal the configured trusted issuer exactly"
    );
    let jwks_uri = document
        .get("jwks_uri")
        .and_then(serde_json::Value::as_str)
        .expect("the discovery document advertises a JWKS URI");
    assert!(
        jwks_uri.starts_with("https://"),
        "the discovered JWKS URI must be HTTPS"
    );

    let subject = baseline_authenticator(&environment);
    let cancellation = NeverCancelled;
    assert_eq!(
        subject
            .ensure_trusted_verifier_state(&context(&cancellation))
            .await,
        TrustedVerifierState::Usable,
        "discovery followed by JWKS retrieval must establish usable trusted state"
    );

    let token = caller_token(&environment, Some(&environment.target_scope)).await;
    let caller = subject
        .authenticate(AuthenticationRequest::new(
            Some(&token.compact),
            context(&cancellation),
        ))
        .await
        .expect("a real Keycloak Client Credentials token authenticates");
    assert_eq!(
        caller.client_id().as_str(),
        environment.caller_client_id,
        "Keycloak's built-in service-account provisioning must emit client_id"
    );
    assert_eq!(
        caller
            .target_selection()
            .selected()
            .map(|target| target.as_str()),
        Some(SELECTED_LOGICAL_TARGET)
    );
    // Compared without formatting either side: a failure must not print the
    // credential.
    assert!(
        caller.bearer_token().as_str() == token.compact,
        "the exact inbound credential is preserved for the Provider boundary"
    );
}

#[tokio::test]
#[ignore = "requires a disposable real Keycloak environment; see integration/keycloak/bootstrap.sh"]
async fn direct_jwks_source_verifies_a_real_token() {
    let environment = real_environment();
    let subject = build_authenticator(
        &environment,
        TrustedVerificationSource::DirectJwks {
            uri: environment.jwks_uri.clone(),
        },
        vec![JwtAlgorithm::RS256],
        LONG_FRESHNESS,
    );
    let cancellation = NeverCancelled;
    assert_eq!(
        subject
            .ensure_trusted_verifier_state(&context(&cancellation))
            .await,
        TrustedVerifierState::Usable,
        "the first-class direct-JWKS deployment mode must establish usable trusted state"
    );

    let token = caller_token(&environment, Some(&environment.target_scope)).await;
    assert_eq!(
        selected_target(&subject, &token.compact).await.as_deref(),
        Some(SELECTED_LOGICAL_TARGET)
    );
}

#[tokio::test]
#[ignore = "requires a disposable real Keycloak environment; see integration/keycloak/bootstrap.sh"]
async fn real_scope_provisioning_matches_the_target_selection_convention() {
    let environment = real_environment();
    let subject = baseline_authenticator(&environment);

    // Exactly one PermissionSync token selects that target, and unrelated
    // OAuth scopes in either order do not change the outcome.
    for scope in [
        environment.target_scope.clone(),
        format!("{} {}", environment.noise_scope, environment.target_scope),
        format!("{} {}", environment.target_scope, environment.noise_scope),
    ] {
        let token = caller_token(&environment, Some(&scope)).await;
        assert_eq!(
            selected_target(&subject, &token.compact).await.as_deref(),
            Some(SELECTED_LOGICAL_TARGET),
            "exactly one permissionsync:<target> scope must select that target"
        );
    }

    // Zero PermissionSync tokens select no target: the client's default scopes
    // only, a case-different prefix, and both lookalikes.
    let zero_token_scopes: [Option<String>; 3] = [
        None,
        Some(environment.case_different_scope.clone()),
        Some(format!(
            "{} {}",
            environment.lookalike_prefix_scope, environment.lookalike_suffix_scope
        )),
    ];
    for scope in zero_token_scopes {
        let token = caller_token(&environment, scope.as_deref()).await;
        assert_eq!(
            selected_target(&subject, &token.compact).await,
            None,
            "a token with no exact permissionsync: scope token selects no target"
        );
    }

    // A real token whose `scope` claim is the empty string, issued by a client
    // with every optional default scope removed. Its `aud` is also a single
    // JSON string rather than an array, which the audience assertion must
    // still accept.
    let minimal = issue_token(
        &environment,
        &environment.token_endpoint,
        &environment.minimal_client_id,
        &environment.minimal_client_secret,
        None,
    )
    .await;
    assert_eq!(
        selected_target(&subject, &minimal.compact).await,
        None,
        "an empty scope claim selects no target"
    );
}

#[tokio::test]
#[ignore = "requires a disposable real Keycloak environment; see integration/keycloak/bootstrap.sh"]
async fn more_than_one_real_target_scope_is_forbidden() {
    let environment = real_environment();
    let subject = baseline_authenticator(&environment);
    let scope = format!(
        "{} {}",
        environment.target_scope, environment.second_target_scope
    );
    let token = caller_token(&environment, Some(&scope)).await;
    assert_eq!(
        authentication_error(&subject, &token.compact).await,
        AuthenticationError::Forbidden,
        "two distinct permissionsync:<target> scopes are an ambiguous selection"
    );
}

#[tokio::test]
#[ignore = "requires a disposable real Keycloak environment; see integration/keycloak/bootstrap.sh"]
async fn a_real_grammar_invalid_target_suffix_is_forbidden() {
    let environment = real_environment();
    let subject = baseline_authenticator(&environment);
    let token = caller_token(&environment, Some(&environment.invalid_target_scope)).await;
    assert_eq!(
        authentication_error(&subject, &token.compact).await,
        AuthenticationError::Forbidden,
        "one permissionsync: token with a grammar-invalid suffix is an unusable grant"
    );
}

#[tokio::test]
#[ignore = "requires a disposable real Keycloak environment; see integration/keycloak/bootstrap.sh"]
async fn a_real_token_for_another_audience_is_rejected() {
    let environment = real_environment();
    let subject = baseline_authenticator(&environment);
    let token = issue_token(
        &environment,
        &environment.token_endpoint,
        &environment.wrong_audience_client_id,
        &environment.wrong_audience_client_secret,
        None,
    )
    .await;
    assert_eq!(
        authentication_error(&subject, &token.compact).await,
        AuthenticationError::Rejected,
        "a token whose aud omits the configured PermissionSync audience is rejected"
    );
}

#[tokio::test]
#[ignore = "requires a disposable real Keycloak environment; see integration/keycloak/bootstrap.sh"]
async fn a_real_token_from_another_realm_is_rejected() {
    let environment = real_environment();
    let subject = baseline_authenticator(&environment);
    let token = issue_token(
        &environment,
        &environment.foreign_token_endpoint,
        &environment.foreign_client_id,
        &environment.foreign_client_secret,
        None,
    )
    .await;
    assert_eq!(
        authentication_error(&subject, &token.compact).await,
        AuthenticationError::Rejected,
        "a token issued by a different realm, with different signing keys, is rejected"
    );
}

#[tokio::test]
#[ignore = "requires a disposable real Keycloak environment; see integration/keycloak/bootstrap.sh"]
async fn a_real_expired_token_is_rejected() {
    let environment = real_environment();
    let subject = baseline_authenticator(&environment);
    let cancellation = NeverCancelled;
    assert_eq!(
        subject
            .ensure_trusted_verifier_state(&context(&cancellation))
            .await,
        TrustedVerifierState::Usable
    );

    // A dedicated client with a one-second access-token lifespan, so expiry is
    // a known instant derived from the issuing response rather than an
    // arbitrary interval. `exp` is evaluated without clock skew, so waiting out
    // the reported lifetime is sufficient.
    let token = issue_token(
        &environment,
        &environment.token_endpoint,
        &environment.shortlived_client_id,
        &environment.shortlived_client_secret,
        None,
    )
    .await;
    // Taken after the response arrived. Keycloak set `exp` no later than this
    // instant plus the reported lifetime, so waiting from here cannot
    // under-wait however long issuance itself took.
    let received_at = Instant::now();
    assert!(
        token.lifetime <= Duration::from_secs(5),
        "the short-lived client must issue a short-lived token"
    );
    tokio::time::sleep_until(tokio::time::Instant::from_std(
        received_at + token.lifetime + EXPIRY_MARGIN,
    ))
    .await;

    assert_eq!(
        authentication_error(&subject, &token.compact).await,
        AuthenticationError::Rejected,
        "an expired real token is rejected"
    );
}

#[tokio::test]
#[ignore = "requires a disposable real Keycloak environment; see integration/keycloak/bootstrap.sh"]
async fn a_real_token_signed_with_a_disallowed_algorithm_is_rejected() {
    let environment = real_environment();
    // The realm really does publish an RS512 signing key and really does sign
    // this client's tokens with it, so the allowlist is tested against a token
    // Keycloak itself produced rather than a synthetic fixture.
    let subject = baseline_authenticator(&environment);
    let token = issue_token(
        &environment,
        &environment.token_endpoint,
        &environment.disallowed_algorithm_client_id,
        &environment.disallowed_algorithm_client_secret,
        None,
    )
    .await;
    assert_eq!(
        authentication_error(&subject, &token.compact).await,
        AuthenticationError::Rejected,
        "an algorithm outside the configured allowlist is rejected"
    );

    // The same token verifies once RS512 is actually allowed, which proves the
    // rejection above was the allowlist rather than a broken fixture.
    let permissive = build_authenticator(
        &environment,
        TrustedVerificationSource::OidcDiscovery {
            uri: environment.discovery_uri.clone(),
        },
        vec![JwtAlgorithm::RS512],
        LONG_FRESHNESS,
    );
    assert_eq!(
        selected_target(&permissive, &token.compact).await,
        None,
        "the RS512 fixture is a valid token under an allowlist that permits it"
    );
}

#[tokio::test]
#[ignore = "requires a disposable real Keycloak environment; see integration/keycloak/bootstrap.sh"]
async fn cached_trusted_state_survives_a_real_metadata_source_outage() {
    let environment = real_environment();
    let cancellation = NeverCancelled;

    // Both authenticators read their trusted JWKS through the disposable
    // forwarder, which is the only service stopped below. Keycloak itself
    // keeps running for every other test in this suite.
    let outage_source = || TrustedVerificationSource::DirectJwks {
        uri: environment.outage_jwks_uri.clone(),
    };
    let fresh = build_authenticator(
        &environment,
        outage_source(),
        vec![JwtAlgorithm::RS256],
        LONG_FRESHNESS,
    );
    let stale_if_error = build_authenticator(
        &environment,
        outage_source(),
        vec![JwtAlgorithm::RS256],
        SHORT_FRESHNESS,
    );
    for established in [&fresh, &stale_if_error] {
        assert_eq!(
            established
                .ensure_trusted_verifier_state(&context(&cancellation))
                .await,
            TrustedVerifierState::Usable
        );
    }

    let token = caller_token(&environment, Some(&environment.target_scope)).await;
    let established_at = Instant::now();

    // Explicit process control, not a timing coincidence: the configured
    // trusted source becomes unreachable at a point this test chooses.
    compose(&environment, &["stop", OUTAGE_PROXY_SERVICE]);

    assert_eq!(
        selected_target(&fresh, &token.compact).await.as_deref(),
        Some(SELECTED_LOGICAL_TARGET),
        "still-fresh trusted material keeps verifying while the source is unavailable"
    );
    assert_eq!(
        fresh.trusted_verifier_state(&context(&cancellation)).await,
        TrustedVerifierState::Usable,
        "readiness stays true while trusted material is still usable"
    );

    // Past the short freshness boundary the second authenticator must attempt
    // a refresh, fail, and then fall back to its still-usable material inside
    // the configured stale-if-error grace.
    tokio::time::sleep_until(tokio::time::Instant::from_std(
        established_at + SHORT_FRESHNESS + Duration::from_millis(500),
    ))
    .await;
    assert_eq!(
        selected_target(&stale_if_error, &token.compact)
            .await
            .as_deref(),
        Some(SELECTED_LOGICAL_TARGET),
        "stale-but-usable trusted material verifies during a bounded source outage"
    );

    // A failing source never accepts a token by itself: an authenticator with
    // no retained trusted state cannot establish validity at all.
    let without_cached_state = build_authenticator(
        &environment,
        outage_source(),
        vec![JwtAlgorithm::RS256],
        LONG_FRESHNESS,
    );
    assert_eq!(
        authentication_error(&without_cached_state, &token.compact).await,
        AuthenticationError::VerifierUnavailable,
        "with no usable cached trusted state, an unavailable source fails closed"
    );
    assert_eq!(
        without_cached_state
            .trusted_verifier_state(&context(&cancellation))
            .await,
        TrustedVerifierState::Unusable
    );
}
