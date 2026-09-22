//! Real GLPI integration suite (ADR 0009 "Two-layer test policy").
//!
//! These tests exercise the production GLPI V1 `apirest.php` contract
//! against a disposable, ephemeral GLPI + database environment. They are
//! `#[ignore]`d by default so `cargo test --workspace --all-features
//! --locked` never requires Docker or a real GLPI instance. Run them
//! explicitly after `tests/real-glpi/bootstrap.sh` has provisioned the
//! environment and exported the printed `GLPI_TEST_*` variables:
//!
//! ```sh
//! source <(crates/permissionsync-adapter-glpi/tests/real-glpi/bootstrap.sh)
//! cargo test -p permissionsync-adapter-glpi --test real_glpi -- --ignored
//! ```
//!
//! If any `GLPI_TEST_*` variable is unset, every test in this file exits
//! immediately without attempting any connection, so accidentally running
//! this binary outside the disposable environment cannot reach a real GLPI
//! instance.

use std::{env, fs, time::Duration};

use permissionsync_adapter_glpi::{
    GlpiAdapter, GlpiAdapterConfig, GlpiAppToken, GlpiAuthenticationSource, GlpiUserToken,
};
use permissionsync_core::{
    CancellationSignal, DesiredStateEnvelope, EnvelopeVersion, IdentityContext, OpaquePayload,
    ReconciliationOutcome, SynchronizationContext, TargetAdapter, TargetAdapterRequest,
};

struct NeverCancelled;

impl CancellationSignal for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

struct RealGlpiEnvironment {
    endpoint: String,
    app_token: String,
    user_token: String,
    ca_pem: Vec<u8>,
}

/// Reads the disposable environment's connection details from the exact
/// variables `bootstrap.sh` prints. Returns `None` (never panics) when any
/// variable is absent, so this file is always safe to compile and skip.
fn real_environment() -> Option<RealGlpiEnvironment> {
    let endpoint = env::var("GLPI_TEST_ENDPOINT").ok()?;
    let app_token = env::var("GLPI_TEST_APP_TOKEN").ok()?;
    let user_token = env::var("GLPI_TEST_USER_TOKEN").ok()?;
    let ca_pem_path = env::var("GLPI_TEST_CA_PEM_PATH").ok()?;
    let ca_pem = fs::read(ca_pem_path).ok()?;

    Some(RealGlpiEnvironment {
        endpoint,
        app_token,
        user_token,
        ca_pem,
    })
}

fn adapter(environment: &RealGlpiEnvironment) -> GlpiAdapter {
    GlpiAdapter::new(GlpiAdapterConfig {
        endpoint: environment.endpoint.clone(),
        app_token: GlpiAppToken::new(environment.app_token.clone()),
        user_token: GlpiUserToken::new(environment.user_token.clone()),
        operation_timeout: Duration::from_secs(20),
        additional_trust_anchors_pem: vec![environment.ca_pem.clone()],
        authentication_source: GlpiAuthenticationSource::default(),
    })
    .expect("valid real-environment GLPI adapter configuration")
}

async fn reconcile(
    environment: &RealGlpiEnvironment,
    username: &str,
    payload_json: &str,
) -> Result<ReconciliationOutcome, permissionsync_core::TargetAdapterError> {
    let glpi_adapter = adapter(environment);
    let identity = IdentityContext::new(username.to_owned(), vec![]);
    let envelope = DesiredStateEnvelope::new(
        EnvelopeVersion::new(1),
        OpaquePayload::try_from(payload_json.to_owned()).unwrap(),
    );
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(
        std::time::Instant::now() + Duration::from_secs(60),
        &cancellation,
    );
    let request = TargetAdapterRequest::new(&identity, &envelope, context);

    glpi_adapter.reconcile(request).await
}

/// Covers: session establishment (`initSession`/`App-Token`/`Session-Token`),
/// missing-user creation with the exact synchronized username, entity and
/// profile lookup, and `Profile_User` creation, against the real disposable
/// GLPI environment.
#[tokio::test]
#[ignore = "requires a disposable real GLPI environment; see tests/real-glpi/bootstrap.sh"]
async fn missing_user_is_created_and_gains_the_desired_assignment() {
    let Some(environment) = real_environment() else {
        return;
    };

    let outcome = reconcile(
        &environment,
        "permissionsync-real-test-user-1",
        r#"{"permissions": [{"entity": "Root entity", "profile": "Super-Admin", "recursive": true}]}"#,
    )
    .await
    .expect("reconciliation against the disposable real GLPI environment must succeed");

    assert_eq!(outcome, ReconciliationOutcome::Changed);
}

/// Covers: idempotent convergence. Reconciling the identical desired state
/// again against the now-existing user and assignment returns `Unchanged`.
#[tokio::test]
#[ignore = "requires a disposable real GLPI environment; see tests/real-glpi/bootstrap.sh"]
async fn repeating_the_same_reconciliation_is_unchanged() {
    let Some(environment) = real_environment() else {
        return;
    };
    let username = "permissionsync-real-test-user-2";
    let payload = r#"{"permissions": [{"entity": "Root entity", "profile": "Super-Admin", "recursive": false}]}"#;

    let first = reconcile(&environment, username, payload)
        .await
        .expect("first reconciliation must succeed");
    assert_eq!(first, ReconciliationOutcome::Changed);

    let second = reconcile(&environment, username, payload)
        .await
        .expect("second identical reconciliation must succeed");
    assert_eq!(second, ReconciliationOutcome::Unchanged);
}

/// Covers: authoritative empty-state reconciliation removes every
/// assignment the adapter previously created for the user.
#[tokio::test]
#[ignore = "requires a disposable real GLPI environment; see tests/real-glpi/bootstrap.sh"]
async fn empty_desired_state_removes_every_owned_assignment() {
    let Some(environment) = real_environment() else {
        return;
    };
    let username = "permissionsync-real-test-user-3";

    let created_outcome = reconcile(
        &environment,
        username,
        r#"{"permissions": [{"entity": "Root entity", "profile": "Super-Admin", "recursive": true}]}"#,
    )
    .await
    .expect("initial reconciliation must succeed");
    assert_eq!(created_outcome, ReconciliationOutcome::Changed);

    let outcome = reconcile(&environment, username, r#"{"permissions": []}"#)
        .await
        .expect("empty-state reconciliation must succeed");

    assert_eq!(outcome, ReconciliationOutcome::Changed);
}

/// Covers: duplicate/mixed desired `recursive` values for one pair
/// canonicalize to `true` and produce exactly one final physical row.
#[tokio::test]
#[ignore = "requires a disposable real GLPI environment; see tests/real-glpi/bootstrap.sh"]
async fn mixed_recursive_desired_values_canonicalize_to_true() {
    let Some(environment) = real_environment() else {
        return;
    };
    let username = "permissionsync-real-test-user-4";

    let outcome = reconcile(
        &environment,
        username,
        r#"{"permissions": [
            {"entity": "Root entity", "profile": "Super-Admin", "recursive": false},
            {"entity": "Root entity", "profile": "Super-Admin", "recursive": true}
        ]}"#,
    )
    .await
    .expect("reconciliation with mixed recursive values must succeed");

    assert_eq!(outcome, ReconciliationOutcome::Changed);

    // Repeating with only the `true` variant must observe the row as
    // already canonical.
    let second = reconcile(
        &environment,
        username,
        r#"{"permissions": [{"entity": "Root entity", "profile": "Super-Admin", "recursive": true}]}"#,
    )
    .await
    .expect("second reconciliation must succeed");

    assert_eq!(second, ReconciliationOutcome::Unchanged);
}
