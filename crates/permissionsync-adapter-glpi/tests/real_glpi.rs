//! Real GLPI integration suite (ADR 0009 "Two-layer test policy").
//!
//! These ignored tests exercise the production GLPI V1 `apirest.php` contract
//! against the disposable environment created by `tests/real-glpi/bootstrap.sh`.
//! Invoke them explicitly after sourcing the runtime environment it prints:
//!
//! ```sh
//! source <(crates/permissionsync-adapter-glpi/tests/real-glpi/bootstrap.sh)
//! set -a
//! source "$GLPI_TEST_RUNTIME_ENV"
//! set +a
//! cargo test -p permissionsync-adapter-glpi --test real_glpi --locked -- --ignored
//! ```
//!
//! Every test hard-fails when the bootstrap environment is absent or incomplete;
//! an ignored test that silently returns would be indistinguishable from success.

use std::{env, fs, process::Command, time::Duration};

use permissionsync_adapter_glpi::{
    GlpiAdapter, GlpiAdapterConfig, GlpiAppToken, GlpiAuthenticationSource, GlpiUserToken,
};
use permissionsync_core::{
    CancellationSignal, DesiredStateEnvelope, EnvelopeVersion, IdentityContext, OpaquePayload,
    ReconciliationOutcome, SynchronizationContext, TargetAdapter, TargetAdapterRequest,
};

const ROOT_ENTITY: &str = "Root entity";
const PAGE_SIZE: u64 = 50;
const PAGINATION_PROFILE_COUNT: u64 = 60;

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
    runtime_env: String,
    db_root_password: String,
    target_profile_a: String,
    target_profile_b: String,
    target_profile_c: String,
}

/// Loads the credentials emitted by the disposable bootstrap. This deliberately
/// panics instead of skipping: `--ignored` is the CI invocation for this suite.
fn real_environment() -> RealGlpiEnvironment {
    fn required(name: &str) -> String {
        env::var(name).unwrap_or_else(|_| {
            panic!(
                "{name} is not set. Run `source <(crates/permissionsync-adapter-glpi/tests/real-glpi/bootstrap.sh)` first; missing real-GLPI configuration is a hard failure."
            )
        })
    }

    let ca_pem_path = required("GLPI_TEST_CA_PEM_PATH");
    let ca_pem = fs::read(&ca_pem_path).unwrap_or_else(|error| {
        panic!("GLPI_TEST_CA_PEM_PATH={ca_pem_path} could not be read: {error}")
    });

    RealGlpiEnvironment {
        endpoint: required("GLPI_TEST_ENDPOINT"),
        app_token: required("GLPI_TEST_APP_TOKEN"),
        user_token: required("GLPI_TEST_USER_TOKEN"),
        ca_pem,
        compose_project: required("GLPI_TEST_COMPOSE_PROJECT"),
        runtime_env: required("GLPI_TEST_RUNTIME_ENV"),
        db_root_password: required("GLPI_TEST_DB_ROOT_PASSWORD"),
        target_profile_a: required("GLPI_TEST_TARGET_PROFILE_A"),
        target_profile_b: required("GLPI_TEST_TARGET_PROFILE_B"),
        target_profile_c: required("GLPI_TEST_TARGET_PROFILE_C"),
    }
}

fn quote_sql_string(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Executes fixture-only SQL against the disposable database. All values used
/// below are fixed test identifiers or bootstrap-provided names and are quoted
/// with `quote_sql_string`; provider payload values are never interpolated.
fn run_fixture_sql(environment: &RealGlpiEnvironment, sql: &str) {
    let output = Command::new("docker")
        .args([
            "compose",
            "--env-file",
            &environment.runtime_env,
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
            sql,
        ])
        .output()
        .expect("docker compose exec must be invocable against the disposable database");
    assert!(
        output.status.success(),
        "fixture SQL failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Runs a fixture-only read query to prove GLPI's physical state independently
/// from the adapter's `ReconciliationOutcome`.
fn query_physical_row_count(environment: &RealGlpiEnvironment, sql: &str) -> u64 {
    let output = Command::new("docker")
        .args([
            "compose",
            "--env-file",
            &environment.runtime_env,
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
                "physical-state query returned a non-numeric result: {error}; stdout={:?}",
                String::from_utf8_lossy(&output.stdout)
            )
        })
}

fn assignment_pair_where(username: &str, entity: &str, profile: &str) -> String {
    format!(
        "u.name = {} AND e.completename = {} AND p.name = {}",
        quote_sql_string(username),
        quote_sql_string(entity),
        quote_sql_string(profile),
    )
}

fn physical_assignment_count(
    environment: &RealGlpiEnvironment,
    username: &str,
    entity: &str,
    profile: &str,
    recursive: Option<u8>,
) -> u64 {
    assert!(
        matches!(recursive, None | Some(0 | 1)),
        "test fixture recursive values are constrained to GLPI's raw 0/1 domain"
    );
    let recursive_where = recursive.map_or(String::new(), |value| {
        format!(" AND pu.is_recursive = {value}")
    });
    let sql = format!(
        "SELECT COUNT(*) FROM glpi_profiles_users pu \
         JOIN glpi_users u ON u.id = pu.users_id \
         JOIN glpi_entities e ON e.id = pu.entities_id \
         JOIN glpi_profiles p ON p.id = pu.profiles_id \
         WHERE {}{}",
        assignment_pair_where(username, entity, profile),
        recursive_where,
    );
    query_physical_row_count(environment, &sql)
}

/// Asserts the complete canonical physical invariant, including both recursive
/// values. Counting only the expected value could conceal an opposite duplicate.
fn assert_exactly_one_physical_assignment(
    environment: &RealGlpiEnvironment,
    username: &str,
    entity: &str,
    profile: &str,
    expected_recursive: u8,
) {
    let opposite_recursive = 1 - expected_recursive;
    assert_eq!(
        physical_assignment_count(environment, username, entity, profile, None),
        1,
        "expected one total Profile_User row for user={username}, entity={entity}, profile={profile}"
    );
    assert_eq!(
        physical_assignment_count(
            environment,
            username,
            entity,
            profile,
            Some(expected_recursive),
        ),
        1,
        "expected one is_recursive={expected_recursive} row for user={username}, entity={entity}, profile={profile}"
    );
    assert_eq!(
        physical_assignment_count(
            environment,
            username,
            entity,
            profile,
            Some(opposite_recursive),
        ),
        0,
        "expected no opposite is_recursive={opposite_recursive} row for user={username}, entity={entity}, profile={profile}"
    );
}

fn assert_no_physical_assignment(
    environment: &RealGlpiEnvironment,
    username: &str,
    entity: &str,
    profile: &str,
) {
    assert_eq!(
        physical_assignment_count(environment, username, entity, profile, None),
        0,
        "expected no Profile_User row for user={username}, entity={entity}, profile={profile}"
    );
}

fn assert_no_physical_assignments(environment: &RealGlpiEnvironment, username: &str) {
    let sql = format!(
        "SELECT COUNT(*) FROM glpi_profiles_users pu \
         JOIN glpi_users u ON u.id = pu.users_id WHERE u.name = {}",
        quote_sql_string(username),
    );
    assert_eq!(
        query_physical_row_count(environment, &sql),
        0,
        "expected no Profile_User rows for user={username}"
    );
}

fn assert_exactly_one_physical_user(environment: &RealGlpiEnvironment, username: &str) {
    let sql = format!(
        "SELECT COUNT(*) FROM glpi_users WHERE name = {}",
        quote_sql_string(username),
    );
    assert_eq!(
        query_physical_row_count(environment, &sql),
        1,
        "expected exactly one User row for username={username}"
    );
}

fn root_permissions_payload(permissions: &[(&str, bool)]) -> String {
    serde_json::json!({
        "permissions": permissions
            .iter()
            .map(|(profile, recursive)| serde_json::json!({
                "entity": ROOT_ENTITY,
                "profile": profile,
                "recursive": recursive,
            }))
            .collect::<Vec<_>>(),
    })
    .to_string()
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
    .expect("valid disposable real-GLPI adapter configuration")
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
        OpaquePayload::try_from(payload_json.to_owned()).expect("valid test JSON payload"),
    );
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(
        std::time::Instant::now() + Duration::from_secs(60),
        &cancellation,
    );
    glpi_adapter
        .reconcile(TargetAdapterRequest::new(&identity, &envelope, context))
        .await
}

/// Inserts one fixture row by copying the known canonical row and changing only
/// `is_recursive`. The source tuple is narrowed to the exact controlled pair.
fn insert_fixture_recursive_variant(
    environment: &RealGlpiEnvironment,
    username: &str,
    entity: &str,
    profile: &str,
    source_recursive: u8,
    inserted_recursive: u8,
) {
    assert!(
        source_recursive <= 1 && inserted_recursive <= 1,
        "test fixture recursive values are constrained to GLPI's raw 0/1 domain"
    );
    let sql = format!(
        "INSERT INTO glpi_profiles_users (users_id, profiles_id, entities_id, is_recursive) \
         SELECT pu.users_id, pu.profiles_id, pu.entities_id, {inserted_recursive} \
         FROM glpi_profiles_users pu \
         JOIN glpi_users u ON u.id = pu.users_id \
         JOIN glpi_entities e ON e.id = pu.entities_id \
         JOIN glpi_profiles p ON p.id = pu.profiles_id \
         WHERE {} AND pu.is_recursive = {source_recursive} LIMIT 1",
        assignment_pair_where(username, entity, profile),
    );
    run_fixture_sql(environment, &sql);
}

/// A successful reconciliation necessarily proves `initSession`, App-Token,
/// user-token, Session-Token authenticated V1 requests, and `Profile_User`
/// REST CRUD. The adapter intentionally does not expose its session token, and
/// GLPI exposes no V1 endpoint to query a particular opaque session after it is
/// killed, so a test cannot identify and inspect that session without adding a
/// production hook or relying on GLPI's non-portable session storage. The fake
/// conformance suite retains the request-level `killSession` proof; this real
/// suite does not falsely claim that final assignment state proves cleanup.
#[tokio::test]
#[ignore = "requires a disposable real GLPI environment; see tests/real-glpi/bootstrap.sh"]
async fn missing_user_is_created_through_v1_and_gains_a_canonical_assignment() {
    let environment = real_environment();
    let username = "permissionsync-real-missing-user";
    let profile = environment.target_profile_a.as_str();

    assert_eq!(
        reconcile(
            &environment,
            username,
            &root_permissions_payload(&[(profile, true)]),
        )
        .await
        .expect("V1 reconciliation must succeed"),
        ReconciliationOutcome::Changed
    );
    assert_exactly_one_physical_user(&environment, username);
    assert_exactly_one_physical_assignment(&environment, username, ROOT_ENTITY, profile, 1);
}

/// Empty desired state is authoritative and exercises real `Profile_User`
/// deletion after a real V1 user/assignment creation.
#[tokio::test]
#[ignore = "requires a disposable real GLPI environment; see tests/real-glpi/bootstrap.sh"]
async fn empty_desired_state_removes_all_assignments() {
    let environment = real_environment();
    let username = "permissionsync-real-empty-state";
    let profile = environment.target_profile_a.as_str();
    let populated = root_permissions_payload(&[(profile, true)]);

    assert_eq!(
        reconcile(&environment, username, &populated)
            .await
            .expect("initial V1 reconciliation must succeed"),
        ReconciliationOutcome::Changed
    );
    assert_eq!(
        reconcile(&environment, username, r#"{"permissions":[]}"#)
            .await
            .expect("empty V1 reconciliation must succeed"),
        ReconciliationOutcome::Changed
    );
    assert_exactly_one_physical_user(&environment, username);
    assert_no_physical_assignments(&environment, username);
}

/// Ordinary true and false assignments each converge to one physical row and
/// an identical repeat performs no REST mutation.
#[tokio::test]
#[ignore = "requires a disposable real GLPI environment; see tests/real-glpi/bootstrap.sh"]
async fn ordinary_recursive_values_are_idempotent() {
    let environment = real_environment();
    let profile = environment.target_profile_b.as_str();
    for (username, recursive) in [
        ("permissionsync-real-ordinary-false", false),
        ("permissionsync-real-ordinary-true", true),
    ] {
        let payload = root_permissions_payload(&[(profile, recursive)]);
        assert_eq!(
            reconcile(&environment, username, &payload)
                .await
                .expect("initial V1 reconciliation must succeed"),
            ReconciliationOutcome::Changed,
            "initial result for {username}"
        );
        assert_exactly_one_physical_assignment(
            &environment,
            username,
            ROOT_ENTITY,
            profile,
            u8::from(recursive),
        );
        assert_eq!(
            reconcile(&environment, username, &payload)
                .await
                .expect("repeated V1 reconciliation must succeed"),
            ReconciliationOutcome::Unchanged,
            "repeat result for {username}"
        );
    }
}

/// All ADR-0009 desired duplicate forms are accepted and normalize by OR. Each
/// case has an independent deterministic user, so test execution is concurrent
/// safe and no case depends on another case's rows. The bootstrap's Root entity
/// and dedicated target profiles are immutable shared lookup fixtures; every
/// test mutates only its own user and that user's Profile_User rows.
#[tokio::test]
#[ignore = "requires a disposable real GLPI environment; see tests/real-glpi/bootstrap.sh"]
async fn desired_duplicate_matrix_canonicalizes_and_is_idempotent() {
    let environment = real_environment();
    let profile = environment.target_profile_a.as_str();
    let cases: [(&str, &[bool], bool); 8] = [
        ("permissionsync-real-desired-false", &[false], false),
        ("permissionsync-real-desired-true", &[true], true),
        (
            "permissionsync-real-desired-false-false",
            &[false, false],
            false,
        ),
        ("permissionsync-real-desired-true-true", &[true, true], true),
        (
            "permissionsync-real-desired-false-true",
            &[false, true],
            true,
        ),
        (
            "permissionsync-real-desired-true-false",
            &[true, false],
            true,
        ),
        (
            "permissionsync-real-desired-false-false-true",
            &[false, false, true],
            true,
        ),
        (
            "permissionsync-real-desired-true-false-true",
            &[true, false, true],
            true,
        ),
    ];

    for (username, values, expected) in cases {
        let permissions = values
            .iter()
            .copied()
            .map(|value| (profile, value))
            .collect::<Vec<_>>();
        let payload = root_permissions_payload(&permissions);
        assert_eq!(
            reconcile(&environment, username, &payload)
                .await
                .expect("initial duplicate-input reconciliation must succeed"),
            ReconciliationOutcome::Changed,
            "initial result for {username}"
        );
        assert_exactly_one_physical_assignment(
            &environment,
            username,
            ROOT_ENTITY,
            profile,
            u8::from(expected),
        );
        assert_eq!(
            reconcile(&environment, username, &payload)
                .await
                .expect("repeated duplicate-input reconciliation must succeed"),
            ReconciliationOutcome::Unchanged,
            "provider multiplicity alone must not change canonical state for {username}"
        );
    }
}

/// Both actual mixed-current forms are created in the disposable DB, then
/// reconciled solely through production V1 REST. This proves physical duplicate
/// cleanup for desired true and false, rather than merely desired normalization.
#[tokio::test]
#[ignore = "requires a disposable real GLPI environment; see tests/real-glpi/bootstrap.sh"]
async fn mixed_current_rows_are_cleaned_to_the_desired_canonical_value() {
    let environment = real_environment();
    let profile = environment.target_profile_b.as_str();
    for (username, desired) in [
        ("permissionsync-real-mixed-current-true", true),
        ("permissionsync-real-mixed-current-false", false),
    ] {
        let payload = root_permissions_payload(&[(profile, desired)]);
        assert_eq!(
            reconcile(&environment, username, &payload)
                .await
                .expect("initial reconciliation must create canonical fixture source"),
            ReconciliationOutcome::Changed
        );
        insert_fixture_recursive_variant(
            &environment,
            username,
            ROOT_ENTITY,
            profile,
            u8::from(desired),
            u8::from(!desired),
        );
        assert_eq!(
            physical_assignment_count(&environment, username, ROOT_ENTITY, profile, None),
            2,
            "fixture must contain false+true rows for {username}"
        );
        assert_eq!(
            physical_assignment_count(&environment, username, ROOT_ENTITY, profile, Some(0)),
            1
        );
        assert_eq!(
            physical_assignment_count(&environment, username, ROOT_ENTITY, profile, Some(1)),
            1
        );

        assert_eq!(
            reconcile(&environment, username, &payload)
                .await
                .expect("mixed-current cleanup must succeed"),
            ReconciliationOutcome::Changed
        );
        assert_exactly_one_physical_assignment(
            &environment,
            username,
            ROOT_ENTITY,
            profile,
            u8::from(desired),
        );
        assert_eq!(
            reconcile(&environment, username, &payload)
                .await
                .expect("repeated mixed-current cleanup must succeed"),
            ReconciliationOutcome::Unchanged
        );
    }
}

/// Exact duplicate current rows are a separate physical cleanup case from the
/// mixed-current matrix: both rows already hold the desired recursive value.
#[tokio::test]
#[ignore = "requires a disposable real GLPI environment; see tests/real-glpi/bootstrap.sh"]
async fn duplicate_current_rows_are_cleaned_and_then_unchanged() {
    let environment = real_environment();
    let username = "permissionsync-real-duplicate-current";
    let profile = environment.target_profile_c.as_str();
    let payload = root_permissions_payload(&[(profile, true)]);

    assert_eq!(
        reconcile(&environment, username, &payload)
            .await
            .expect("initial reconciliation must succeed"),
        ReconciliationOutcome::Changed
    );
    insert_fixture_recursive_variant(&environment, username, ROOT_ENTITY, profile, 1, 1);
    assert_eq!(
        physical_assignment_count(&environment, username, ROOT_ENTITY, profile, None),
        2
    );
    assert_eq!(
        reconcile(&environment, username, &payload)
            .await
            .expect("duplicate cleanup must succeed"),
        ReconciliationOutcome::Changed
    );
    assert_exactly_one_physical_assignment(&environment, username, ROOT_ENTITY, profile, 1);
    assert_eq!(
        reconcile(&environment, username, &payload)
            .await
            .expect("repeated duplicate cleanup must succeed"),
        ReconciliationOutcome::Unchanged
    );
}

/// Independent assignments remain canonical while an undesired assignment is
/// removed, exercising an authoritative multi-pair plan through V1 REST.
#[tokio::test]
#[ignore = "requires a disposable real GLPI environment; see tests/real-glpi/bootstrap.sh"]
async fn several_assignments_converge_and_stale_assignment_is_removed() {
    let environment = real_environment();
    let username = "permissionsync-real-several-and-stale";
    let profile_a = environment.target_profile_a.as_str();
    let profile_c = environment.target_profile_c.as_str();

    assert_eq!(
        reconcile(
            &environment,
            username,
            &root_permissions_payload(&[(profile_a, true), (profile_c, false)]),
        )
        .await
        .expect("initial multiple-assignment reconciliation must succeed"),
        ReconciliationOutcome::Changed
    );
    assert_eq!(
        reconcile(
            &environment,
            username,
            &root_permissions_payload(&[(profile_c, false)]),
        )
        .await
        .expect("stale-assignment reconciliation must succeed"),
        ReconciliationOutcome::Changed
    );
    assert_no_physical_assignment(&environment, username, ROOT_ENTITY, profile_a);
    assert_exactly_one_physical_assignment(&environment, username, ROOT_ENTITY, profile_c, 0);
}

/// Recursive flips must delete the old physical row before creating its opposite
/// value; both directions finish with exactly one row of the requested value.
#[tokio::test]
#[ignore = "requires a disposable real GLPI environment; see tests/real-glpi/bootstrap.sh"]
async fn recursive_flips_converge_in_both_directions() {
    let environment = real_environment();
    let profile = environment.target_profile_c.as_str();
    for (username, initial, desired) in [
        ("permissionsync-real-flip-false-true", false, true),
        ("permissionsync-real-flip-true-false", true, false),
    ] {
        assert_eq!(
            reconcile(
                &environment,
                username,
                &root_permissions_payload(&[(profile, initial)]),
            )
            .await
            .expect("initial flip fixture reconciliation must succeed"),
            ReconciliationOutcome::Changed
        );
        assert_eq!(
            reconcile(
                &environment,
                username,
                &root_permissions_payload(&[(profile, desired)]),
            )
            .await
            .expect("recursive flip reconciliation must succeed"),
            ReconciliationOutcome::Changed
        );
        assert_exactly_one_physical_assignment(
            &environment,
            username,
            ROOT_ENTITY,
            profile,
            u8::from(desired),
        );
    }
}

/// Prepares 60 fixture rows (strictly more than production `PAGE_SIZE = 50`)
/// for one user. `permissionsync-pagination-target-60` is proved to have more
/// than fifty earlier physical candidates before V1 reconciliation, so its
/// removal proves the adapter consumed a later real search page.
#[tokio::test]
#[ignore = "requires a disposable real GLPI environment; see tests/real-glpi/bootstrap.sh"]
async fn current_assignment_pagination_removes_a_stale_row_from_a_later_page() {
    let environment = real_environment();
    let username = "permissionsync-real-pagination";
    let desired_profile = environment.target_profile_a.as_str();
    let late_profile = "permissionsync-pagination-target-60";

    assert_eq!(
        reconcile(&environment, username, r#"{"permissions":[]}"#)
            .await
            .expect("empty reconciliation must create the pagination user"),
        ReconciliationOutcome::Changed
    );
    let fixture_sql = format!(
        "INSERT INTO glpi_profiles_users (users_id, profiles_id, entities_id, is_recursive) \
         SELECT u.id, p.id, e.id, 0 \
         FROM glpi_users u CROSS JOIN glpi_profiles p CROSS JOIN glpi_entities e \
         WHERE u.name = {} AND e.completename = {} \
         AND p.name LIKE 'permissionsync-pagination-target-%' \
         ORDER BY p.id ASC",
        quote_sql_string(username),
        quote_sql_string(ROOT_ENTITY),
    );
    run_fixture_sql(&environment, &fixture_sql);
    assert_eq!(
        query_physical_row_count(
            &environment,
            &format!(
                "SELECT COUNT(*) FROM glpi_profiles_users pu \
                 JOIN glpi_users u ON u.id = pu.users_id \
                 JOIN glpi_entities e ON e.id = pu.entities_id \
                 JOIN glpi_profiles p ON p.id = pu.profiles_id \
                 WHERE u.name = {} AND e.completename = {} \
                 AND p.name LIKE 'permissionsync-pagination-target-%'",
                quote_sql_string(username),
                quote_sql_string(ROOT_ENTITY),
            ),
        ),
        PAGINATION_PROFILE_COUNT,
        "fixture preparation must create more than one full page of candidates"
    );
    assert_eq!(
        physical_assignment_count(&environment, username, ROOT_ENTITY, late_profile, None),
        1,
        "the later-page fixture row must exist"
    );
    let earlier_rows_sql = format!(
        "SELECT COUNT(*) FROM glpi_profiles_users earlier \
         WHERE earlier.users_id = (SELECT id FROM glpi_users WHERE name = {}) \
         AND earlier.id < (SELECT pu.id FROM glpi_profiles_users pu \
             JOIN glpi_profiles p ON p.id = pu.profiles_id \
             WHERE pu.users_id = (SELECT id FROM glpi_users WHERE name = {}) \
             AND p.name = {} LIMIT 1)",
        quote_sql_string(username),
        quote_sql_string(username),
        quote_sql_string(late_profile),
    );
    assert!(
        query_physical_row_count(&environment, &earlier_rows_sql) > PAGE_SIZE,
        "the stale fixture row must be beyond the first PAGE_SIZE=50 candidates"
    );

    let desired = root_permissions_payload(&[(desired_profile, true)]);
    assert_eq!(
        reconcile(&environment, username, &desired)
            .await
            .expect("pagination reconciliation through V1 REST must succeed"),
        ReconciliationOutcome::Changed
    );
    assert_no_physical_assignment(&environment, username, ROOT_ENTITY, late_profile);
    assert_exactly_one_physical_assignment(&environment, username, ROOT_ENTITY, desired_profile, 1);
    assert_eq!(
        query_physical_row_count(
            &environment,
            &format!(
                "SELECT COUNT(*) FROM glpi_profiles_users pu \
                 JOIN glpi_users u ON u.id = pu.users_id WHERE u.name = {}",
                quote_sql_string(username),
            ),
        ),
        1,
        "pagination reconciliation must leave only the desired canonical row"
    );
    assert_eq!(
        reconcile(&environment, username, &desired)
            .await
            .expect("repeated pagination reconciliation must succeed"),
        ReconciliationOutcome::Unchanged
    );
}
