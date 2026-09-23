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
//! Every test in this file is `#[ignore]`d, so `cargo test --workspace
//! --all-features --locked` never runs them and never requires Docker.
//! When this binary is explicitly invoked with `--ignored` (the dedicated
//! real-GLPI workflow's only supported invocation), a missing or
//! unreadable `GLPI_TEST_*` variable is a hard test failure for every test
//! in this file, not a silent skip: a silently skipped real test would be
//! indistinguishable from a passing one in CI, defeating the entire point
//! of the real-GLPI suite.

use std::{env, fs, process::Command, time::Duration};

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
    compose_project: String,
    db_root_password: String,
}

/// Reads the disposable environment's connection details from the exact
/// variables `bootstrap.sh` prints. This is a hard failure (never a silent
/// skip) when explicitly run with `--ignored` and any variable is missing,
/// unreadable, or the CA file cannot be read: a silently skipped real test
/// is indistinguishable from a passing one and would defeat the purpose of
/// this suite (ADR 0009 "Two-layer test policy", finding: real tests must
/// never false-pass).
fn real_environment() -> RealGlpiEnvironment {
    fn required(name: &str) -> String {
        env::var(name).unwrap_or_else(|_| {
            panic!(
                "{name} is not set. The real-GLPI suite must be run via \
                 `source <(tests/real-glpi/bootstrap.sh)` first; a missing \
                 environment variable is a hard failure, not a skipped test."
            )
        })
    }

    let endpoint = required("GLPI_TEST_ENDPOINT");
    let app_token = required("GLPI_TEST_APP_TOKEN");
    let user_token = required("GLPI_TEST_USER_TOKEN");
    let ca_pem_path = required("GLPI_TEST_CA_PEM_PATH");
    let compose_project = required("GLPI_TEST_COMPOSE_PROJECT");
    let db_root_password = required("GLPI_TEST_DB_ROOT_PASSWORD");
    let ca_pem = fs::read(&ca_pem_path).unwrap_or_else(|error| {
        panic!("GLPI_TEST_CA_PEM_PATH={ca_pem_path} could not be read: {error}")
    });

    RealGlpiEnvironment {
        endpoint,
        app_token,
        user_token,
        ca_pem,
        compose_project,
        db_root_password,
    }
}

/// Runs a read-only SQL query against the disposable environment's
/// database directly (administrative test-fixture access, never used by
/// production adapter code) to prove the *physical* state GLPI's own V1
/// API reconciled, rather than trusting the adapter's own
/// `ReconciliationOutcome`.
fn query_physical_row_count(environment: &RealGlpiEnvironment, sql: &str) -> u64 {
    let output = Command::new("docker")
        .args([
            "compose",
            "-p",
            &environment.compose_project,
            "exec",
            "-T",
            "db",
            "mariadb",
            "-uroot",
            &format!("-p{}", environment.db_root_password),
            "--skip-column-names",
            "--batch",
            "glpi",
            "-e",
            sql,
        ])
        .output()
        .expect("docker compose exec must be invocable against the disposable database");

    assert!(
        output.status.success(),
        "physical-state verification query failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u64>()
        .unwrap_or_else(|error| {
            panic!(
                "physical-state verification query returned a non-numeric result: {error}; \
                 stdout={:?}",
                String::from_utf8_lossy(&output.stdout)
            )
        })
}

/// Proves, by direct database read, that exactly one physical
/// `glpi_profile_user` row exists for `(username, entity, profile)` with
/// the expected `is_recursive` raw value. This never trusts the adapter's
/// own `ReconciliationOutcome`.
fn assert_exactly_one_physical_assignment(
    environment: &RealGlpiEnvironment,
    username: &str,
    entity_completename: &str,
    profile_name: &str,
    expected_is_recursive: u8,
) {
    let sql = format!(
        "SELECT COUNT(*) FROM glpi_profiles_users pu \
         JOIN glpi_users u ON u.id = pu.users_id \
         JOIN glpi_entities e ON e.id = pu.entities_id \
         JOIN glpi_profiles p ON p.id = pu.profiles_id \
         WHERE u.name = '{username}' AND e.completename = '{entity_completename}' \
         AND p.name = '{profile_name}' AND pu.is_recursive = {expected_is_recursive}"
    );
    assert_eq!(
        query_physical_row_count(environment, &sql),
        1,
        "expected exactly one physical Profile_User row for user={username} \
         entity={entity_completename} profile={profile_name} is_recursive={expected_is_recursive}"
    );
}

/// Proves, by direct database read, that a user has no physical
/// `glpi_profile_user` rows at all.
fn assert_no_physical_assignments(environment: &RealGlpiEnvironment, username: &str) {
    let sql = format!(
        "SELECT COUNT(*) FROM glpi_profiles_users pu \
         JOIN glpi_users u ON u.id = pu.users_id \
         WHERE u.name = '{username}'"
    );
    assert_eq!(
        query_physical_row_count(environment, &sql),
        0,
        "expected zero physical Profile_User rows for user={username}"
    );
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
    let environment = real_environment();

    let outcome = reconcile(
        &environment,
        "permissionsync-real-test-user-1",
        r#"{"permissions": [{"entity": "Root entity", "profile": "Super-Admin", "recursive": true}]}"#,
    )
    .await
    .expect("reconciliation against the disposable real GLPI environment must succeed");

    assert_eq!(outcome, ReconciliationOutcome::Changed);
    assert_exactly_one_physical_assignment(
        &environment,
        "permissionsync-real-test-user-1",
        "Root entity",
        "Super-Admin",
        1,
    );
}

/// Covers: idempotent convergence. Reconciling the identical desired state
/// again against the now-existing user and assignment returns `Unchanged`.
#[tokio::test]
#[ignore = "requires a disposable real GLPI environment; see tests/real-glpi/bootstrap.sh"]
async fn repeating_the_same_reconciliation_is_unchanged() {
    let environment = real_environment();
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
    assert_exactly_one_physical_assignment(&environment, username, "Root entity", "Super-Admin", 0);
}

/// Covers: authoritative empty-state reconciliation removes every
/// assignment the adapter previously created for the user.
#[tokio::test]
#[ignore = "requires a disposable real GLPI environment; see tests/real-glpi/bootstrap.sh"]
async fn empty_desired_state_removes_every_owned_assignment() {
    let environment = real_environment();
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
    assert_no_physical_assignments(&environment, username);
}

/// Covers: duplicate/mixed desired `recursive` values for one pair
/// canonicalize to `true` and produce exactly one final physical row.
#[tokio::test]
#[ignore = "requires a disposable real GLPI environment; see tests/real-glpi/bootstrap.sh"]
async fn mixed_recursive_desired_values_canonicalize_to_true() {
    let environment = real_environment();
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
    assert_exactly_one_physical_assignment(&environment, username, "Root entity", "Super-Admin", 1);

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
    assert_exactly_one_physical_assignment(&environment, username, "Root entity", "Super-Admin", 1);
}

/// Covers: desired `false` then `true` for the same pair also
/// canonicalizes to `true` (order independence of true-wins semantics).
#[tokio::test]
#[ignore = "requires a disposable real GLPI environment; see tests/real-glpi/bootstrap.sh"]
async fn desired_false_then_true_canonicalizes_to_true() {
    let environment = real_environment();
    let username = "permissionsync-real-test-user-5";

    let outcome = reconcile(
        &environment,
        username,
        r#"{"permissions": [
            {"entity": "Root entity", "profile": "Super-Admin", "recursive": true},
            {"entity": "Root entity", "profile": "Super-Admin", "recursive": false}
        ]}"#,
    )
    .await
    .expect("reconciliation must succeed");

    assert_eq!(outcome, ReconciliationOutcome::Changed);
    assert_exactly_one_physical_assignment(&environment, username, "Root entity", "Super-Admin", 1);
}

/// Covers: three-or-more mixed desired values for one pair still
/// canonicalize to exactly one physical row.
#[tokio::test]
#[ignore = "requires a disposable real GLPI environment; see tests/real-glpi/bootstrap.sh"]
async fn three_or_more_mixed_desired_values_canonicalize_to_one_row() {
    let environment = real_environment();
    let username = "permissionsync-real-test-user-6";

    let outcome = reconcile(
        &environment,
        username,
        r#"{"permissions": [
            {"entity": "Root entity", "profile": "Super-Admin", "recursive": false},
            {"entity": "Root entity", "profile": "Super-Admin", "recursive": false},
            {"entity": "Root entity", "profile": "Super-Admin", "recursive": true}
        ]}"#,
    )
    .await
    .expect("reconciliation must succeed");

    assert_eq!(outcome, ReconciliationOutcome::Changed);
    assert_exactly_one_physical_assignment(&environment, username, "Root entity", "Super-Admin", 1);
}

/// Covers: several independent assignments for one user converge and
/// stale, undesired assignments are removed on a later reconciliation.
#[tokio::test]
#[ignore = "requires a disposable real GLPI environment; see tests/real-glpi/bootstrap.sh"]
async fn stale_assignments_are_removed_on_a_later_reconciliation() {
    let environment = real_environment();
    let username = "permissionsync-real-test-user-7";

    let first = reconcile(
        &environment,
        username,
        r#"{"permissions": [
            {"entity": "Root entity", "profile": "Super-Admin", "recursive": true},
            {"entity": "Root entity", "profile": "Self-Service", "recursive": false}
        ]}"#,
    )
    .await
    .expect("first reconciliation must succeed");
    assert_eq!(first, ReconciliationOutcome::Changed);
    assert_exactly_one_physical_assignment(&environment, username, "Root entity", "Super-Admin", 1);

    let second = reconcile(
        &environment,
        username,
        r#"{"permissions": [{"entity": "Root entity", "profile": "Self-Service", "recursive": false}]}"#,
    )
    .await
    .expect("second reconciliation must succeed");
    assert_eq!(second, ReconciliationOutcome::Changed);

    let sql = format!(
        "SELECT COUNT(*) FROM glpi_profiles_users pu \
         JOIN glpi_users u ON u.id = pu.users_id \
         JOIN glpi_profiles p ON p.id = pu.profiles_id \
         WHERE u.name = '{username}' AND p.name = 'Super-Admin'"
    );
    assert_eq!(
        query_physical_row_count(&environment, &sql),
        0,
        "the stale Super-Admin assignment must have been removed"
    );
}

/// Covers: recursive `false -> true` transition for an already-existing
/// canonical row uses delete-then-add and results in exactly one physical
/// row with the new raw `is_recursive` value.
#[tokio::test]
#[ignore = "requires a disposable real GLPI environment; see tests/real-glpi/bootstrap.sh"]
async fn recursive_false_transitions_to_true() {
    let environment = real_environment();
    let username = "permissionsync-real-test-user-8";

    let first = reconcile(
        &environment,
        username,
        r#"{"permissions": [{"entity": "Root entity", "profile": "Self-Service", "recursive": false}]}"#,
    )
    .await
    .expect("first reconciliation must succeed");
    assert_eq!(first, ReconciliationOutcome::Changed);
    assert_exactly_one_physical_assignment(
        &environment,
        username,
        "Root entity",
        "Self-Service",
        0,
    );

    let second = reconcile(
        &environment,
        username,
        r#"{"permissions": [{"entity": "Root entity", "profile": "Self-Service", "recursive": true}]}"#,
    )
    .await
    .expect("second reconciliation must succeed");
    assert_eq!(second, ReconciliationOutcome::Changed);
    assert_exactly_one_physical_assignment(
        &environment,
        username,
        "Root entity",
        "Self-Service",
        1,
    );
}

/// Covers: recursive `true -> false` transition, the reverse of the
/// previous scenario.
#[tokio::test]
#[ignore = "requires a disposable real GLPI environment; see tests/real-glpi/bootstrap.sh"]
async fn recursive_true_transitions_to_false() {
    let environment = real_environment();
    let username = "permissionsync-real-test-user-9";

    let first = reconcile(
        &environment,
        username,
        r#"{"permissions": [{"entity": "Root entity", "profile": "Self-Service", "recursive": true}]}"#,
    )
    .await
    .expect("first reconciliation must succeed");
    assert_eq!(first, ReconciliationOutcome::Changed);
    assert_exactly_one_physical_assignment(
        &environment,
        username,
        "Root entity",
        "Self-Service",
        1,
    );

    let second = reconcile(
        &environment,
        username,
        r#"{"permissions": [{"entity": "Root entity", "profile": "Self-Service", "recursive": false}]}"#,
    )
    .await
    .expect("second reconciliation must succeed");
    assert_eq!(second, ReconciliationOutcome::Changed);
    assert_exactly_one_physical_assignment(
        &environment,
        username,
        "Root entity",
        "Self-Service",
        0,
    );
}

/// Covers: pre-existing exact duplicate `Profile_User` rows for the same
/// `(entity, profile, recursive)` tuple are cleaned up to exactly one
/// canonical row, and the cleanup itself is observed as `Changed`;
/// repeating the identical reconciliation afterwards is `Unchanged`. The
/// duplicate is created directly via the database as a disposable
/// fixture (ADR 0009 permits local administrative mechanisms for
/// fixtures), never through the adapter itself.
#[tokio::test]
#[ignore = "requires a disposable real GLPI environment; see tests/real-glpi/bootstrap.sh"]
async fn pre_existing_duplicate_current_rows_are_cleaned_up() {
    let environment = real_environment();
    let username = "permissionsync-real-test-user-10";

    let first = reconcile(
        &environment,
        username,
        r#"{"permissions": [{"entity": "Root entity", "profile": "Self-Service", "recursive": true}]}"#,
    )
    .await
    .expect("first reconciliation must succeed");
    assert_eq!(first, ReconciliationOutcome::Changed);

    // Fixture: duplicate the now-canonical row directly in the database.
    let duplicate_sql = format!(
        "INSERT INTO glpi_profiles_users (users_id, profiles_id, entities_id, is_recursive) \
         SELECT users_id, profiles_id, entities_id, is_recursive FROM glpi_profiles_users pu \
         JOIN glpi_users u ON u.id = pu.users_id WHERE u.name = '{username}'"
    );
    let output = Command::new("docker")
        .args([
            "compose",
            "-p",
            &environment.compose_project,
            "exec",
            "-T",
            "db",
            "mariadb",
            "-uroot",
            &format!("-p{}", environment.db_root_password),
            "glpi",
            "-e",
            &duplicate_sql,
        ])
        .output()
        .expect("docker compose exec must be invocable to insert the duplicate fixture row");
    assert!(
        output.status.success(),
        "failed to insert the duplicate current-row fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cleanup = reconcile(
        &environment,
        username,
        r#"{"permissions": [{"entity": "Root entity", "profile": "Self-Service", "recursive": true}]}"#,
    )
    .await
    .expect("cleanup reconciliation must succeed");
    assert_eq!(
        cleanup,
        ReconciliationOutcome::Changed,
        "cleaning up a duplicate physical row must be observed as Changed"
    );
    assert_exactly_one_physical_assignment(
        &environment,
        username,
        "Root entity",
        "Self-Service",
        1,
    );

    let repeated = reconcile(
        &environment,
        username,
        r#"{"permissions": [{"entity": "Root entity", "profile": "Self-Service", "recursive": true}]}"#,
    )
    .await
    .expect("repeating the identical reconciliation must succeed");
    assert_eq!(repeated, ReconciliationOutcome::Unchanged);
}

// NOTE: a real-GLPI pagination-boundary scenario (forcing more than
// `PAGE_SIZE` = 50 physical Profile_User rows for one user, per ADR 0009's
// pagination coverage requirement) is intentionally NOT included here yet.
// It requires bootstrap.php to provision at least 51 distinct entities (or
// profiles) as fixtures, which it does not currently do; adding a test
// that merely asserts two or three rows would not actually prove
// pagination correctness and would be a placeholder passing test, which is
// explicitly disallowed. This is a known, honestly-reported gap: extend
// bootstrap.php's fixture set with >= 51 distinct entities before adding
// this scenario.
