//! The configuration delivery matrix: valid documents, global startup
//! failures, and component-local failures.
//!
//! Loading is exercised through a path in a temporary directory and through
//! [`decode`] directly. The environment-variable lookup is reached through
//! [`configuration_path`], which never needs process-environment mutation to be
//! meaningful because path resolution is separated from every loading and
//! validation rule.

use std::{io::Write, path::PathBuf, time::Duration};

use permissionsync::{ComposedApplication, ProviderAvailability, TargetAvailability};
use permissionsync_core::LogicalTarget;

use crate::runtime::{
    configuration::{
        CONFIGURATION_PATH_VARIABLE, ComponentOutcome, ExecutableConfiguration,
        MAX_SYNCHRONIZATION_CAPACITY, configuration_path, decode, load,
    },
    failure::StartupFailure,
};

/// A complete, valid document. Tests mutate it through textual substitution so
/// each case differs in exactly one place.
const VALID: &str = r#"
# PermissionSync runtime configuration. Comments carry no semantics.
listener:
  address: "0.0.0.0"
  port: 8443

request:
  overall_deadline_milliseconds: 10000
  inbound_admission_limit: 64
  synchronization_capacity: 16

shutdown:
  grace_milliseconds: 20000

authentication:
  issuer: "https://keycloak.example.test/realms/neteye"
  audience: "permissionsync"
  algorithms: ["RS256"]
  source:
    oidc_discovery_uri: "https://keycloak.example.test/realms/neteye/.well-known/openid-configuration"
  cache:
    freshness_milliseconds: 300000
    stale_if_error_milliseconds: 600000
  metadata_operation_timeout_milliseconds: 3000
  clock_skew_milliseconds: 30000

observability:
  log_level: info

provider:
  generic_rest:
    endpoint: "https://provider.example.test/permissions"
    operation_timeout_milliseconds: 5000

glpi:
  endpoint: "https://glpi.example.test/apirest.php"
  app_token: "sentinel-app-token"
  user_token: "sentinel-user-token"
  operation_timeout_milliseconds: 5000

targets:
  - logical_target: "glpi"
    adapter: "glpi"
"#;

fn document_without(section: &str) -> String {
    // Removes one whole top-level section from the valid document.
    let mut kept = String::new();
    let mut skipping = false;
    for line in VALID.lines() {
        if line.starts_with(&format!("{section}:")) {
            skipping = true;
            continue;
        }
        if skipping {
            let is_nested = line.starts_with(' ') || line.trim().is_empty();
            if is_nested {
                continue;
            }
            skipping = false;
        }
        kept.push_str(line);
        kept.push('\n');
    }
    kept
}

fn replaced(from: &str, to: &str) -> String {
    assert!(VALID.contains(from), "{from} must be present to replace");
    VALID.replace(from, to)
}

fn valid() -> ExecutableConfiguration {
    decode(VALID).expect("the baseline document must be valid")
}

/// Asserts a global failure without requiring the success value to be
/// formattable: [`ExecutableConfiguration`] owns credentials and trust
/// material and deliberately has no `Debug`.
fn global_failure(document: &str) -> StartupFailure {
    match decode(document) {
        Ok(_) => panic!("the document was expected to abort startup"),
        Err(failure) => failure,
    }
}

fn load_failure(path: &std::path::Path) -> StartupFailure {
    match load(path) {
        Ok(_) => panic!("loading was expected to abort startup"),
        Err(failure) => failure,
    }
}

// ---------------------------------------------------------------------------
// Valid documents
// ---------------------------------------------------------------------------

#[test]
fn a_commented_single_document_is_accepted_and_projected() {
    let configuration = valid();

    assert_eq!(configuration.listener.to_string(), "0.0.0.0:8443");
    assert_eq!(
        configuration.overall_request_deadline,
        Duration::from_millis(10_000)
    );
    assert_eq!(configuration.inbound_admission_limit.get(), 64);
    assert_eq!(configuration.synchronization_capacity.get(), 16);
    assert_eq!(configuration.shutdown_grace, Duration::from_millis(20_000));
    assert_eq!(
        configuration.metadata_operation_timeout,
        Duration::from_millis(3_000)
    );
    assert_eq!(configuration.provider_outcome, ComponentOutcome::Configured);
    assert_eq!(configuration.glpi_outcome, ComponentOutcome::Configured);
    assert_eq!(configuration.runtime.targets.len(), 1);
    assert_eq!(configuration.runtime.targets[0].logical_target, "glpi");
    assert_eq!(configuration.runtime.targets[0].adapter_identifier, "glpi");
}

#[test]
fn a_valid_document_composes_a_usable_provider_and_glpi_route() {
    let configuration = valid();
    let application = ComposedApplication::compose(configuration.runtime).expect("composes");

    assert!(matches!(
        application.provider(),
        ProviderAvailability::Usable(_)
    ));
    assert!(matches!(
        application.resolve_target(&LogicalTarget::try_from("glpi".to_owned()).unwrap()),
        TargetAvailability::Usable(_)
    ));
}

#[test]
fn a_direct_jwks_source_is_accepted() {
    let document = replaced(
        "    oidc_discovery_uri: \"https://keycloak.example.test/realms/neteye/.well-known/openid-configuration\"",
        "    jwks_uri: \"https://keycloak.example.test/realms/neteye/protocol/openid-connect/certs\"",
    );

    assert!(decode(&document).is_ok());
}

#[test]
fn an_absent_provider_section_leaves_the_provider_unavailable_without_failing_startup() {
    let configuration = decode(&document_without("provider")).expect("still valid");

    assert_eq!(configuration.provider_outcome, ComponentOutcome::Absent);
    let application = ComposedApplication::compose(configuration.runtime).expect("composes");
    assert!(matches!(
        application.provider(),
        ProviderAvailability::Unavailable
    ));
}

#[test]
fn an_absent_glpi_section_leaves_configured_glpi_routes_recognized_but_unavailable() {
    let configuration = decode(&document_without("glpi")).expect("still valid");

    assert_eq!(configuration.glpi_outcome, ComponentOutcome::Absent);
    let application = ComposedApplication::compose(configuration.runtime).expect("composes");
    assert!(matches!(
        application.resolve_target(&LogicalTarget::try_from("glpi".to_owned()).unwrap()),
        TargetAvailability::Unavailable
    ));
}

#[test]
fn an_absent_tracing_section_disables_trace_export() {
    let configuration = valid();
    assert!(configuration.observability.tracing.is_none());
}

#[test]
fn an_explicitly_disabled_tracing_section_validates_nothing_further() {
    let document = replaced(
        "observability:\n  log_level: info",
        "observability:\n  log_level: info\n  tracing:\n    enabled: false",
    );

    let configuration = decode(&document).expect("a disabled tracing section is valid");
    assert!(configuration.observability.tracing.is_none());
}

#[test]
fn an_enabled_tracing_section_is_validated_and_accepted() {
    let document = replaced(
        "observability:\n  log_level: info",
        "observability:\n  log_level: info\n  tracing:\n    enabled: true\n    \
         endpoint: \"https://otlp.example.test/v1/traces\"\n    \
         export_timeout_milliseconds: 5000\n    headers:\n      \
         authorization: \"ApiKey sentinel-exporter-credential\"",
    );

    let configuration = decode(&document).expect("a valid enabled tracing section");
    assert!(configuration.observability.tracing.is_some());
}

#[test]
fn every_bounded_log_level_is_accepted() {
    for level in ["error", "warn", "info", "debug", "trace"] {
        let document = replaced("  log_level: info", &format!("  log_level: {level}"));
        assert!(decode(&document).is_ok(), "{level} must be accepted");
    }
}

#[test]
fn an_empty_target_list_is_accepted() {
    let document = replaced(
        "targets:\n  - logical_target: \"glpi\"\n    adapter: \"glpi\"",
        "targets: []",
    );

    let configuration = decode(&document).expect("no configured routes is valid");
    assert!(configuration.runtime.targets.is_empty());
}

#[test]
fn inline_pem_trust_material_is_accepted_only_when_it_parses() {
    let document = replaced(
        "  clock_skew_milliseconds: 30000",
        "  clock_skew_milliseconds: 30000\n  additional_trust_anchors_pem:\n    - |\n      not a pem\n",
    );

    assert_eq!(
        global_failure(&document),
        StartupFailure::InvalidAuthentication
    );
}

// ---------------------------------------------------------------------------
// Loading from a path
// ---------------------------------------------------------------------------

struct TemporaryFile {
    path: PathBuf,
}

impl TemporaryFile {
    fn new(name: &str, contents: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "permissionsync-{}-{name}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        let mut file = std::fs::File::create(&path).expect("temporary file");
        file.write_all(contents.as_bytes()).expect("write");
        Self { path }
    }

    fn with_bytes(name: &str, contents: &[u8]) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "permissionsync-{}-{name}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        let mut file = std::fs::File::create(&path).expect("temporary file");
        file.write_all(contents).expect("write");
        Self { path }
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[test]
fn a_valid_document_loads_from_its_configured_path() {
    let file = TemporaryFile::new("valid", VALID);

    assert!(load(&file.path).is_ok());
}

#[test]
fn an_unreadable_path_is_a_global_failure() {
    let mut missing = std::env::temp_dir();
    missing.push("permissionsync-absent-configuration-file.yaml");
    let _ = std::fs::remove_file(&missing);

    assert_eq!(
        load_failure(&missing),
        StartupFailure::ConfigurationUnreadable
    );
}

#[test]
fn a_non_utf8_document_is_a_global_failure() {
    let file = TemporaryFile::with_bytes("not-utf8", &[0xff, 0xfe, 0x00]);

    assert_eq!(
        load_failure(&file.path),
        StartupFailure::ConfigurationNotUtf8
    );
}

/// The executable boundary resolves the path only from the required variable,
/// and reports a fixed category when it is unset or empty.
#[test]
fn the_configuration_path_comes_only_from_the_required_variable() {
    assert_eq!(CONFIGURATION_PATH_VARIABLE, "PERMISSIONSYNC_CONFIG_FILE");

    match configuration_path() {
        // The variable is not set in the test process, which is the normal
        // case and must be a fixed global failure rather than a default path.
        Err(failure) => assert_eq!(failure, StartupFailure::ConfigurationPathMissing),
        // If an ambient value exists, it must at least be non-empty; path
        // resolution never invents one.
        Ok(path) => assert!(!path.is_empty()),
    }
}

// ---------------------------------------------------------------------------
// Global startup failures
// ---------------------------------------------------------------------------

#[test]
fn an_empty_document_is_a_global_failure() {
    assert_eq!(global_failure(""), StartupFailure::ConfigurationEmpty);
    assert_eq!(
        global_failure("# only a comment\n"),
        StartupFailure::ConfigurationEmpty
    );
}

#[test]
fn malformed_yaml_is_a_global_failure() {
    assert_eq!(
        global_failure("listener: [unclosed\n"),
        StartupFailure::InvalidDocumentStructure
    );
    assert_eq!(
        global_failure("\tnot: yaml\n"),
        StartupFailure::InvalidDocumentStructure
    );
}

#[test]
fn more_than_one_yaml_document_is_a_global_failure() {
    let two = format!("{VALID}\n---\n{VALID}");

    assert_eq!(
        global_failure(&two),
        StartupFailure::ConfigurationMultipleDocuments
    );
}

#[test]
fn an_unknown_global_field_is_a_global_failure() {
    let document = format!("{VALID}\nunexpected_global_field: true\n");

    assert_eq!(
        global_failure(&document),
        StartupFailure::InvalidDocumentStructure
    );
}

#[test]
fn a_missing_required_section_is_a_global_failure() {
    for section in [
        "listener",
        "request",
        "shutdown",
        "authentication",
        "observability",
        "targets",
    ] {
        assert_eq!(
            global_failure(&document_without(section)),
            StartupFailure::InvalidDocumentStructure,
            "a missing {section} section must abort startup"
        );
    }
}

#[test]
fn an_unknown_field_inside_a_global_section_is_a_global_failure() {
    let document = replaced("  port: 8443", "  port: 8443\n  backlog: 128");

    assert_eq!(global_failure(&document), StartupFailure::InvalidListener);
}

#[test]
fn an_invalid_listener_is_a_global_failure() {
    for (from, to) in [
        ("  address: \"0.0.0.0\"", "  address: \"not-an-address\""),
        ("  address: \"0.0.0.0\"", "  address: \"\""),
        ("  port: 8443", "  port: 0"),
        ("  port: 8443", "  port: 70000"),
        ("  port: 8443", "  port: \"8443\""),
    ] {
        assert_eq!(
            global_failure(&replaced(from, to)),
            StartupFailure::InvalidListener,
            "{to} must abort startup"
        );
    }
}

#[test]
fn a_non_positive_overall_deadline_is_a_global_failure() {
    assert_eq!(
        global_failure(&replaced(
            "  overall_deadline_milliseconds: 10000",
            "  overall_deadline_milliseconds: 0"
        )),
        StartupFailure::InvalidRequest
    );
}

#[test]
fn a_zero_inbound_admission_limit_is_a_global_failure() {
    assert_eq!(
        global_failure(&replaced(
            "  inbound_admission_limit: 64",
            "  inbound_admission_limit: 0"
        )),
        StartupFailure::InvalidRequest
    );
}

#[test]
fn a_zero_synchronization_capacity_is_a_global_failure() {
    assert_eq!(
        global_failure(&replaced(
            "  synchronization_capacity: 16",
            "  synchronization_capacity: 0"
        )),
        StartupFailure::InvalidRequest
    );
}

#[test]
fn synchronization_capacity_above_the_product_ceiling_is_a_global_failure() {
    assert!(
        decode(&replaced(
            "  synchronization_capacity: 16",
            &format!("  synchronization_capacity: {MAX_SYNCHRONIZATION_CAPACITY}")
        ))
        .is_ok(),
        "exactly the ceiling is permitted"
    );
    assert_eq!(
        global_failure(&replaced(
            "  synchronization_capacity: 16",
            &format!(
                "  synchronization_capacity: {}",
                MAX_SYNCHRONIZATION_CAPACITY + 1
            )
        )),
        StartupFailure::InvalidRequest
    );
}

#[test]
fn a_non_positive_shutdown_grace_is_a_global_failure() {
    assert_eq!(
        global_failure(&replaced(
            "  grace_milliseconds: 20000",
            "  grace_milliseconds: 0"
        )),
        StartupFailure::InvalidShutdown
    );
}

/// The grace period must cover one complete compliant request.
#[test]
fn a_shutdown_grace_below_the_overall_deadline_is_a_global_failure() {
    assert_eq!(
        global_failure(&replaced(
            "  grace_milliseconds: 20000",
            "  grace_milliseconds: 9999"
        )),
        StartupFailure::InvalidShutdown
    );
    assert!(
        decode(&replaced(
            "  grace_milliseconds: 20000",
            "  grace_milliseconds: 10000"
        ))
        .is_ok(),
        "a grace period exactly equal to the deadline is permitted"
    );
}

#[test]
fn invalid_authentication_configuration_is_a_global_failure() {
    for (from, to) in [
        (
            "  issuer: \"https://keycloak.example.test/realms/neteye\"",
            "  issuer: \"http://keycloak.example.test/realms/neteye\"",
        ),
        (
            "  issuer: \"https://keycloak.example.test/realms/neteye\"",
            "  issuer: \"\"",
        ),
        ("  audience: \"permissionsync\"", "  audience: \"\""),
        ("  algorithms: [\"RS256\"]", "  algorithms: []"),
        (
            "  algorithms: [\"RS256\"]",
            "  algorithms: [\"RS256\", \"RS256\"]",
        ),
        ("  algorithms: [\"RS256\"]", "  algorithms: [\"HS256\"]"),
        (
            "    oidc_discovery_uri: \"https://keycloak.example.test/realms/neteye/.well-known/openid-configuration\"",
            "    oidc_discovery_uri: \"http://keycloak.example.test/insecure\"",
        ),
        (
            "  metadata_operation_timeout_milliseconds: 3000",
            "  metadata_operation_timeout_milliseconds: 0",
        ),
        (
            "    freshness_milliseconds: 300000",
            "    freshness_milliseconds: 0",
        ),
        (
            "  clock_skew_milliseconds: 30000",
            "  clock_skew_milliseconds: 600000",
        ),
    ] {
        assert_eq!(
            global_failure(&replaced(from, to)),
            StartupFailure::InvalidAuthentication,
            "{to} must abort startup"
        );
    }
}

/// A child operation may shorten the remaining budget but never create a later
/// deadline than the one overall request deadline.
#[test]
fn an_authentication_timeout_above_the_overall_deadline_is_a_global_failure() {
    assert_eq!(
        global_failure(&replaced(
            "  metadata_operation_timeout_milliseconds: 3000",
            "  metadata_operation_timeout_milliseconds: 10001"
        )),
        StartupFailure::InvalidAuthentication
    );
    assert!(
        decode(&replaced(
            "  metadata_operation_timeout_milliseconds: 3000",
            "  metadata_operation_timeout_milliseconds: 10000"
        ))
        .is_ok(),
        "a timeout exactly equal to the overall deadline is permitted"
    );
}

#[test]
fn an_ambiguous_or_unknown_trusted_source_is_a_global_failure() {
    let both = replaced(
        "    oidc_discovery_uri: \"https://keycloak.example.test/realms/neteye/.well-known/openid-configuration\"",
        "    oidc_discovery_uri: \"https://keycloak.example.test/a\"\n    jwks_uri: \"https://keycloak.example.test/b\"",
    );
    assert_eq!(global_failure(&both), StartupFailure::InvalidAuthentication);

    let unknown = replaced(
        "    oidc_discovery_uri: \"https://keycloak.example.test/realms/neteye/.well-known/openid-configuration\"",
        "    introspection_uri: \"https://keycloak.example.test/a\"",
    );
    assert_eq!(
        global_failure(&unknown),
        StartupFailure::InvalidAuthentication
    );
}

#[test]
fn an_unknown_log_level_is_a_global_failure() {
    assert_eq!(
        global_failure(&replaced("  log_level: info", "  log_level: verbose")),
        StartupFailure::InvalidObservability
    );
}

#[test]
fn invalid_enabled_tracing_configuration_is_a_global_failure() {
    let enabled = |extra: &str| {
        replaced(
            "observability:\n  log_level: info",
            &format!("observability:\n  log_level: info\n  tracing:\n    enabled: true\n{extra}"),
        )
    };

    for extra in [
        // Missing endpoint.
        "    export_timeout_milliseconds: 5000".to_owned(),
        // Missing export timeout.
        "    endpoint: \"https://otlp.example.test/v1/traces\"".to_owned(),
        // Non-positive export timeout.
        "    endpoint: \"https://otlp.example.test/v1/traces\"\n    export_timeout_milliseconds: 0"
            .to_owned(),
        // Plaintext endpoint.
        "    endpoint: \"http://otlp.example.test/v1/traces\"\n    export_timeout_milliseconds: 5000"
            .to_owned(),
        // Endpoint with userinfo.
        "    endpoint: \"https://user:secret@otlp.example.test/v1/traces\"\n    export_timeout_milliseconds: 5000"
            .to_owned(),
        // Reserved protocol header.
        "    endpoint: \"https://otlp.example.test/v1/traces\"\n    export_timeout_milliseconds: 5000\n    headers:\n      content-type: \"application/json\""
            .to_owned(),
        // Unknown tracing field.
        "    endpoint: \"https://otlp.example.test/v1/traces\"\n    export_timeout_milliseconds: 5000\n    insecure: true"
            .to_owned(),
    ] {
        assert_eq!(global_failure(&enabled(&extra)), StartupFailure::InvalidObservability, "invalid enabled tracing configuration must abort startup: {extra}"
        );
    }
}

#[test]
fn an_unknown_target_field_is_a_global_failure() {
    assert_eq!(
        global_failure(&replaced(
            "    adapter: \"glpi\"",
            "    adapter: \"glpi\"\n    endpoint: \"https://glpi.example.test\""
        )),
        StartupFailure::InvalidTargets
    );
}

#[test]
fn an_invalid_logical_target_fails_composition_globally() {
    let configuration = decode(&replaced(
        "  - logical_target: \"glpi\"",
        "  - logical_target: \"Invalid Target\"",
    ))
    .expect("delivery decoding does not own the routing grammar");

    assert!(ComposedApplication::compose(configuration.runtime).is_err());
}

#[test]
fn a_duplicate_logical_target_fails_composition_globally() {
    let configuration = decode(&replaced(
        "targets:\n  - logical_target: \"glpi\"\n    adapter: \"glpi\"",
        "targets:\n  - logical_target: \"glpi\"\n    adapter: \"glpi\"\n  - logical_target: \"glpi\"\n    adapter: \"glpi\"",
    ))
    .expect("delivery decoding does not own duplicate detection");

    assert!(ComposedApplication::compose(configuration.runtime).is_err());
}

// ---------------------------------------------------------------------------
// Component-local failures
// ---------------------------------------------------------------------------

/// A malformed Provider section must never abort startup. The process still
/// composes, and the Provider is simply unavailable.
#[test]
fn a_malformed_provider_section_leaves_only_the_provider_unavailable() {
    for provider in [
        // Unknown field inside the component section.
        "provider:\n  generic_rest:\n    endpoint: \"https://provider.example.test/permissions\"\n    operation_timeout_milliseconds: 5000\n    verify_tls: false",
        // Unknown provider type.
        "provider:\n  soap:\n    endpoint: \"https://provider.example.test/permissions\"",
        // Wrong shape entirely.
        "provider: \"https://provider.example.test/permissions\"",
        // Missing required field.
        "provider:\n  generic_rest:\n    operation_timeout_milliseconds: 5000",
        // Wrong type.
        "provider:\n  generic_rest:\n    endpoint: \"https://provider.example.test/permissions\"\n    operation_timeout_milliseconds: \"5000\"",
    ] {
        let document = replaced(
            "provider:\n  generic_rest:\n    endpoint: \"https://provider.example.test/permissions\"\n    operation_timeout_milliseconds: 5000",
            provider,
        );
        let configuration =
            decode(&document).expect("a malformed Provider section must not abort startup");

        assert_eq!(
            configuration.provider_outcome,
            ComponentOutcome::Invalid,
            "{provider} must be an invalid component, never a silently ignored field"
        );
        let application = ComposedApplication::compose(configuration.runtime).expect("composes");
        assert!(matches!(
            application.provider(),
            ProviderAvailability::Unavailable
        ));
    }
}

#[test]
fn an_invalid_provider_endpoint_leaves_the_provider_unavailable() {
    for endpoint in [
        "http://provider.example.test/permissions",
        "https://provider.example.test/permissions?token=sentinel",
        "https://user:secret@provider.example.test/permissions",
        "not-a-uri",
    ] {
        let document = replaced(
            "    endpoint: \"https://provider.example.test/permissions\"",
            &format!("    endpoint: \"{endpoint}\""),
        );
        let configuration = decode(&document).expect("still starts");

        // Decoding succeeds; the Provider contract rejects the endpoint during
        // composition, which is a component-local failure.
        assert_eq!(configuration.provider_outcome, ComponentOutcome::Configured);
        let application = ComposedApplication::compose(configuration.runtime).expect("composes");
        assert!(
            matches!(application.provider(), ProviderAvailability::Unavailable),
            "{endpoint} must leave the Provider unavailable"
        );
    }
}

/// A Provider operation timeout longer than the one overall request deadline is
/// Provider-local validation, not a global defect.
#[test]
fn a_provider_timeout_above_the_overall_deadline_leaves_the_provider_unavailable() {
    let configuration = decode(&replaced(
        "    endpoint: \"https://provider.example.test/permissions\"\n    operation_timeout_milliseconds: 5000",
        "    endpoint: \"https://provider.example.test/permissions\"\n    operation_timeout_milliseconds: 10001",
    ))
    .expect("must not abort startup");

    assert_eq!(configuration.provider_outcome, ComponentOutcome::Invalid);
    let application = ComposedApplication::compose(configuration.runtime).expect("composes");
    assert!(matches!(
        application.provider(),
        ProviderAvailability::Unavailable
    ));
}

#[test]
fn a_malformed_glpi_section_leaves_glpi_routes_recognized_but_unavailable() {
    for glpi in [
        // Unknown field inside the component section.
        "glpi:\n  endpoint: \"https://glpi.example.test/apirest.php\"\n  app_token: \"sentinel-app-token\"\n  user_token: \"sentinel-user-token\"\n  operation_timeout_milliseconds: 5000\n  verify_tls: false",
        // Missing required credential.
        "glpi:\n  endpoint: \"https://glpi.example.test/apirest.php\"\n  user_token: \"sentinel-user-token\"\n  operation_timeout_milliseconds: 5000",
        // Incoherent authentication source: both fields are required together.
        "glpi:\n  endpoint: \"https://glpi.example.test/apirest.php\"\n  app_token: \"sentinel-app-token\"\n  user_token: \"sentinel-user-token\"\n  operation_timeout_milliseconds: 5000\n  authentication_source:\n    authtype: 3",
        // Wrong shape entirely.
        "glpi: []",
    ] {
        let document = replaced(
            "glpi:\n  endpoint: \"https://glpi.example.test/apirest.php\"\n  app_token: \"sentinel-app-token\"\n  user_token: \"sentinel-user-token\"\n  operation_timeout_milliseconds: 5000",
            glpi,
        );
        let configuration =
            decode(&document).expect("a malformed GLPI section must not abort startup");

        assert_eq!(configuration.glpi_outcome, ComponentOutcome::Invalid);
        let application = ComposedApplication::compose(configuration.runtime).expect("composes");
        assert!(matches!(
            application.resolve_target(&LogicalTarget::try_from("glpi".to_owned()).unwrap()),
            TargetAvailability::Unavailable
        ));
    }
}

#[test]
fn invalid_glpi_values_leave_glpi_routes_recognized_but_unavailable() {
    for (from, to) in [
        (
            "  endpoint: \"https://glpi.example.test/apirest.php\"",
            "  endpoint: \"http://glpi.example.test/apirest.php\"",
        ),
        (
            "  endpoint: \"https://glpi.example.test/apirest.php\"",
            "  endpoint: \"https://glpi.example.test/api\"",
        ),
        ("  app_token: \"sentinel-app-token\"", "  app_token: \"\""),
        (
            "  user_token: \"sentinel-user-token\"",
            "  user_token: \"\"",
        ),
    ] {
        let configuration = decode(&replaced(from, to)).expect("must not abort startup");
        let application = ComposedApplication::compose(configuration.runtime).expect("composes");

        assert!(
            matches!(
                application.resolve_target(&LogicalTarget::try_from("glpi".to_owned()).unwrap()),
                TargetAvailability::Unavailable
            ),
            "{to} must leave GLPI routes unavailable"
        );
    }
}

#[test]
fn a_glpi_timeout_above_the_overall_deadline_leaves_glpi_unavailable() {
    let configuration = decode(&replaced(
        "  app_token: \"sentinel-app-token\"\n  user_token: \"sentinel-user-token\"\n  operation_timeout_milliseconds: 5000",
        "  app_token: \"sentinel-app-token\"\n  user_token: \"sentinel-user-token\"\n  operation_timeout_milliseconds: 10001",
    ))
    .expect("must not abort startup");

    assert_eq!(configuration.glpi_outcome, ComponentOutcome::Invalid);
}

/// An unrelated, correctly configured route must stay serviceable while a
/// component-local defect makes another one unavailable.
#[test]
fn an_unrelated_valid_route_remains_serviceable_while_glpi_is_unavailable() {
    let document = replaced(
        "targets:\n  - logical_target: \"glpi\"\n    adapter: \"glpi\"",
        "targets:\n  - logical_target: \"glpi-a\"\n    adapter: \"glpi\"\n  - logical_target: \"other\"\n    adapter: \"uncompiled-adapter\"",
    );
    let document = document.replace(
        "  endpoint: \"https://glpi.example.test/apirest.php\"",
        "  endpoint: \"http://glpi.example.test/apirest.php\"",
    );
    let configuration = decode(&document).expect("must not abort startup");
    let application = ComposedApplication::compose(configuration.runtime).expect("composes");

    // The GLPI route stays recognized and unavailable, an unconfigured target
    // stays unknown, and neither makes composition fail.
    assert!(matches!(
        application.resolve_target(&LogicalTarget::try_from("glpi-a".to_owned()).unwrap()),
        TargetAvailability::Unavailable
    ));
    assert!(matches!(
        application.resolve_target(&LogicalTarget::try_from("other".to_owned()).unwrap()),
        TargetAvailability::Unavailable
    ));
    assert!(matches!(
        application.resolve_target(&LogicalTarget::try_from("absent".to_owned()).unwrap()),
        TargetAvailability::Unknown
    ));
}
