//! Environment-variable overrides and environment-only secrets (ADR 0012).
//!
//! Every test injects its environment. No test reads or mutates the real
//! process environment.

use std::{
    ffi::OsString,
    io,
    os::unix::ffi::OsStringExt,
    sync::{Arc, Mutex},
    time::Duration,
};

use permissionsync::{ComposedApplication, TargetAvailability};
use permissionsync_core::LogicalTarget;
use yaml_serde::Value;

use crate::runtime::{
    configuration::{ComponentOutcome, ExecutableConfiguration, decode, delivery_sections},
    environment::{
        CONFIGURATION_PATH_VARIABLE, ENVIRONMENT_VARIABLES, Environment, PREFIX,
        TRACING_HEADER_PREFIX, UnknownVariableReport, ValueType, documentation_table, header_name,
        unknown_variables,
    },
    failure::RuntimeFailure,
    observability::LogLevel,
    tests::configuration::{
        GLPI_SECRETS, VALID, baseline_environment, environment_with, global_failure_with,
    },
};

/// A document that sets every scalar key the delivery model accepts, except
/// the secrets, which come only from the environment.
const FULL: &str = r#"
listener:
  address: "127.0.0.1"
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
  additional_trust_anchors_pem: []
observability:
  log_level: info
  tracing:
    enabled: true
    endpoint: "https://otlp.example.test/v1/traces"
    export_timeout_milliseconds: 5000
    additional_trust_anchors_pem: []
provider:
  generic_rest:
    endpoint: "https://provider.example.test/permissions"
    operation_timeout_milliseconds: 5000
    additional_trust_anchors_pem: []
glpi:
  endpoint: "https://glpi.example.test/apirest.php"
  operation_timeout_milliseconds: 5000
  additional_trust_anchors_pem: []
  authentication_source:
    authtype: 3
    auths_id: 2
targets:
  - logical_target: "glpi"
    adapter: "glpi"
"#;

/// The keys the table lists that a valid document cannot set together.
///
/// The trusted source accepts exactly one of its two keys, and the file never
/// carries a secret.
const NOT_IN_FULL: [&str; 4] = [
    "authentication.source.jwks_uri",
    "observability.tracing.headers.<name>",
    "glpi.app_token",
    "glpi.user_token",
];

const BEGIN_MARKER: &str = "<!-- BEGIN GENERATED ENVIRONMENT VARIABLE TABLE -->";
const END_MARKER: &str = "<!-- END GENERATED ENVIRONMENT VARIABLE TABLE -->";

fn decoded(document: &str, environment: &Environment) -> ExecutableConfiguration {
    match decode(document, environment) {
        Ok(configuration) => configuration,
        Err(failure) => panic!("the document was expected to be valid: {failure}"),
    }
}

fn file_key(path: &[&str], value_type: ValueType) -> String {
    let mut key = path.join(".");
    if value_type == ValueType::HeaderMap {
        key.push_str(".<name>");
    }
    key
}

fn scalar_keys(value: &Value, prefix: &str, keys: &mut Vec<String>) {
    match value {
        Value::Mapping(mapping) => {
            for (key, child) in mapping {
                let key = key.as_str().expect("every key is a string");
                let path = if prefix.is_empty() {
                    key.to_owned()
                } else {
                    format!("{prefix}.{key}")
                };
                scalar_keys(child, &path, keys);
            }
        }
        // Lists stay in the file only.
        Value::Sequence(_) => {}
        _ => keys.push(prefix.to_owned()),
    }
}

fn non_utf8() -> OsString {
    OsString::from_vec(vec![0xff, 0xfe])
}

// ---------------------------------------------------------------------------
// The schema
// ---------------------------------------------------------------------------

/// Pattern A: `PERMISSIONSYNC_` and the file key path in uppercase, with `__`
/// between levels.
#[test]
fn every_variable_name_follows_the_file_key_path() {
    let mut names = Vec::new();
    for variable in ENVIRONMENT_VARIABLES {
        let mut expected = format!(
            "{PREFIX}{}",
            variable
                .path
                .iter()
                .map(|segment| segment.to_ascii_uppercase())
                .collect::<Vec<_>>()
                .join("__")
        );
        if variable.value_type == ValueType::HeaderMap {
            expected.push_str("__<NAME>");
            assert_eq!(format!("{TRACING_HEADER_PREFIX}<NAME>"), variable.name);
        }
        assert_eq!(variable.name, expected);
        assert_ne!(variable.name, CONFIGURATION_PATH_VARIABLE);
        names.push(variable.name);
    }

    let count = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), count, "every variable name is unique");
}

/// The table lists exactly the scalar keys of the delivery model.
#[test]
fn the_schema_lists_every_scalar_key_of_the_file() {
    let document: Value = yaml_serde::from_str(FULL).unwrap();
    let mut from_document = Vec::new();
    scalar_keys(&document, "", &mut from_document);
    from_document.extend(NOT_IN_FULL.map(str::to_owned));
    from_document.sort();

    let mut from_schema: Vec<String> = ENVIRONMENT_VARIABLES
        .iter()
        .map(|variable| file_key(variable.path, variable.value_type))
        .collect();
    from_schema.sort();

    assert_eq!(from_schema, from_document);

    // The full document is valid, so it names only real keys.
    let configuration = decoded(FULL, &baseline_environment());
    assert!(configuration.observability.tracing.is_some());
    assert_eq!(configuration.glpi_outcome, ComponentOutcome::Configured);
    assert_eq!(configuration.provider_outcome, ComponentOutcome::Configured);
}

/// The delivery fields that are lists. Lists stay in the file only, so they
/// have no variable.
const LIST_FIELDS: [&str; 6] = [
    "targets",
    "authentication.algorithms",
    "authentication.additional_trust_anchors_pem",
    "observability.tracing.additional_trust_anchors_pem",
    "provider.generic_rest.additional_trust_anchors_pem",
    "glpi.additional_trust_anchors_pem",
];

/// The schema is complete by structure: every field of every delivery struct
/// is a nested section, a list, the exporter header map, or a schema entry,
/// and every schema entry is such a field.
///
/// The field names come from the derived `Deserialize` implementations, so a
/// new delivery field fails this test until it gets a variable, or is listed
/// as a list or a nested section.
#[test]
fn the_schema_covers_every_field_of_the_delivery_structs() {
    let sections = delivery_sections();
    let prefixes: Vec<&str> = sections.iter().map(|(prefix, _)| *prefix).collect();

    let mut from_structs = Vec::new();
    for (prefix, fields) in &sections {
        // The fields of one list element belong to that list.
        if prefix.ends_with("[]") {
            continue;
        }
        for field in *fields {
            let path = if prefix.is_empty() {
                (*field).to_owned()
            } else {
                format!("{prefix}.{field}")
            };
            if prefixes.contains(&path.as_str()) || LIST_FIELDS.contains(&path.as_str()) {
                continue;
            }
            if path == "observability.tracing.headers" {
                from_structs.push(format!("{path}.<name>"));
            } else {
                from_structs.push(path);
            }
        }
    }
    from_structs.sort();

    let mut from_schema: Vec<String> = ENVIRONMENT_VARIABLES
        .iter()
        .map(|variable| file_key(variable.path, variable.value_type))
        .collect();
    from_schema.sort();

    assert_eq!(from_schema, from_structs);

    // Every nested section and every list is a real field of its parent, so
    // the two lists above cannot hide a field.
    for path in prefixes
        .iter()
        .filter(|prefix| !prefix.is_empty())
        .map(|prefix| prefix.trim_end_matches("[]"))
        .chain(LIST_FIELDS)
    {
        let (parent, field) = path.rsplit_once('.').unwrap_or(("", path));
        let parent_fields = sections
            .iter()
            .find(|(prefix, _)| *prefix == parent)
            .map(|(_, fields)| *fields)
            .unwrap_or_else(|| panic!("{parent} is a delivery section"));
        assert!(
            parent_fields.contains(&field),
            "{path} is a field of {parent:?}"
        );
    }
}

#[test]
fn exactly_the_glpi_tokens_and_the_tracing_headers_are_secrets() {
    let secrets: Vec<&str> = ENVIRONMENT_VARIABLES
        .iter()
        .filter(|variable| variable.secret)
        .map(|variable| variable.name)
        .collect();

    assert_eq!(
        secrets,
        [
            "PERMISSIONSYNC_OBSERVABILITY__TRACING__HEADERS__<NAME>",
            "PERMISSIONSYNC_GLPI__APP_TOKEN",
            "PERMISSIONSYNC_GLPI__USER_TOKEN",
        ]
    );
}

/// The documentation is generated from the schema, so it is always complete.
/// When this fails, replace the table in `docs/environment-variables.md` with
/// the generated table that the failure prints.
#[test]
fn the_documentation_table_is_the_generated_table() {
    let documentation = include_str!("../../../docs/environment-variables.md");
    let table = documentation_table();
    let expected = format!("{BEGIN_MARKER}\n\n{table}\n{END_MARKER}");

    assert!(
        documentation.contains(&expected),
        "docs/environment-variables.md must contain exactly this generated table:\n\n{table}"
    );
    assert_eq!(documentation.matches(BEGIN_MARKER).count(), 1);
}

#[test]
fn header_names_are_derived_from_the_variable_suffix() {
    assert_eq!(
        header_name("AUTHORIZATION").as_deref(),
        Some("authorization")
    );
    assert_eq!(header_name("X_API_KEY").as_deref(), Some("x-api-key"));
    assert_eq!(header_name("X_TENANT_2").as_deref(), Some("x-tenant-2"));

    for invalid in [
        "",
        "authorization",
        "Authorization",
        "X__API",
        "_X",
        "X_",
        "X-API",
        "X API",
    ] {
        assert_eq!(
            header_name(invalid),
            None,
            "{invalid:?} is not a header suffix"
        );
    }
}

// ---------------------------------------------------------------------------
// Merge semantics
// ---------------------------------------------------------------------------

/// One variable replaces exactly one value, and every other value stays the
/// file value.
#[test]
fn one_variable_replaces_exactly_one_file_value() {
    let file = decoded(VALID, &baseline_environment());
    let overridden = decoded(
        VALID,
        &environment_with(&[
            ("PERMISSIONSYNC_LISTENER__PORT", "9443"),
            (
                "PERMISSIONSYNC_REQUEST__OVERALL_DEADLINE_MILLISECONDS",
                "15000",
            ),
            ("PERMISSIONSYNC_OBSERVABILITY__LOG_LEVEL", "debug"),
        ]),
    );

    assert_eq!(file.listener.to_string(), "0.0.0.0:8443");
    assert_eq!(overridden.listener.to_string(), "0.0.0.0:9443");
    assert_eq!(
        overridden.overall_request_deadline,
        Duration::from_millis(15_000)
    );
    assert_eq!(overridden.observability.log_level, LogLevel::Debug);
    assert_eq!(overridden.shutdown_grace, file.shutdown_grace);
    assert_eq!(
        overridden.inbound_admission_limit,
        file.inbound_admission_limit
    );
    assert_eq!(
        overridden.synchronization_capacity,
        file.synchronization_capacity
    );
    assert_eq!(
        overridden.metadata_operation_timeout,
        file.metadata_operation_timeout
    );
}

/// Validation runs after the merge with the same rules as file values.
#[test]
fn an_environment_value_is_validated_like_a_file_value() {
    // The grace period must be at least the overall deadline. The file value
    // is valid, and the environment value makes it invalid.
    assert_eq!(
        global_failure_with(
            VALID,
            &environment_with(&[(
                "PERMISSIONSYNC_REQUEST__OVERALL_DEADLINE_MILLISECONDS",
                "30000"
            )])
        ),
        RuntimeFailure::InvalidShutdown
    );

    // A Provider timeout above the overall deadline leaves only the Provider
    // unavailable.
    let configuration = decoded(
        VALID,
        &environment_with(&[(
            "PERMISSIONSYNC_PROVIDER__GENERIC_REST__OPERATION_TIMEOUT_MILLISECONDS",
            "10001",
        )]),
    );
    assert_eq!(configuration.provider_outcome, ComponentOutcome::Invalid);
    assert_eq!(configuration.glpi_outcome, ComponentOutcome::Configured);
}

/// Missing mappings are created, and a null mapping counts as missing.
#[test]
fn the_merge_creates_missing_mappings() {
    let configuration = decoded(
        VALID,
        &environment_with(&[
            ("PERMISSIONSYNC_OBSERVABILITY__TRACING__ENABLED", "true"),
            (
                "PERMISSIONSYNC_OBSERVABILITY__TRACING__ENDPOINT",
                "https://otlp.example.test/v1/traces",
            ),
            (
                "PERMISSIONSYNC_OBSERVABILITY__TRACING__EXPORT_TIMEOUT_MILLISECONDS",
                "5000",
            ),
            (
                "PERMISSIONSYNC_OBSERVABILITY__TRACING__HEADERS__AUTHORIZATION",
                "ApiKey sentinel-exporter-credential",
            ),
            ("PERMISSIONSYNC_GLPI__AUTHENTICATION_SOURCE__AUTHTYPE", "-3"),
            ("PERMISSIONSYNC_GLPI__AUTHENTICATION_SOURCE__AUTHS_ID", "2"),
        ]),
    );
    assert!(configuration.observability.tracing.is_some());
    assert_eq!(configuration.glpi_outcome, ComponentOutcome::Configured);

    let null_tracing = VALID.replace(
        "observability:\n  log_level: info",
        "observability:\n  log_level: info\n  tracing:",
    );
    let configuration = decoded(
        &null_tracing,
        &environment_with(&[("PERMISSIONSYNC_OBSERVABILITY__TRACING__ENABLED", "false")]),
    );
    assert!(configuration.observability.tracing.is_none());
}

/// A node that exists and is not a mapping is never replaced, so the file
/// defect stays visible.
#[test]
fn the_merge_never_repairs_a_non_mapping_node() {
    let listener = VALID.replace(
        "listener:\n  address: \"0.0.0.0\"\n  port: 8443",
        "listener: \"0.0.0.0:8443\"",
    );
    assert_eq!(
        global_failure_with(
            &listener,
            &environment_with(&[
                ("PERMISSIONSYNC_LISTENER__ADDRESS", "0.0.0.0"),
                ("PERMISSIONSYNC_LISTENER__PORT", "8443"),
            ])
        ),
        RuntimeFailure::InvalidListener
    );

    assert_eq!(
        global_failure_with("just a scalar document", &baseline_environment()),
        RuntimeFailure::InvalidDocumentStructure
    );
}

/// The environment cannot replace a missing file, an empty file, or a list.
#[test]
fn the_file_stays_the_base_document() {
    let all_required: Vec<(&str, &str)> = vec![
        ("PERMISSIONSYNC_LISTENER__ADDRESS", "0.0.0.0"),
        ("PERMISSIONSYNC_LISTENER__PORT", "8443"),
    ];
    assert_eq!(
        global_failure_with("", &environment_with(&all_required)),
        RuntimeFailure::ConfigurationEmpty
    );

    // There is no variable for a list, so the name is unknown.
    let environment = environment_with(&[("PERMISSIONSYNC_TARGETS", "[]")]);
    let configuration = decoded(VALID, &environment);
    assert_eq!(configuration.runtime.targets.len(), 1);
    assert_eq!(unknown_variables(&environment), ["PERMISSIONSYNC_TARGETS"]);
}

// ---------------------------------------------------------------------------
// YAML tags
// ---------------------------------------------------------------------------

/// No configuration value uses a YAML tag. A tagged key would hide from the
/// secret check and from the merge while typed decoding still accepts it, so a
/// tag anywhere makes the document structure invalid.
#[test]
fn a_yaml_tag_anywhere_in_the_file_is_a_global_failure() {
    let glpi = "  endpoint: \"https://glpi.example.test/apirest.php\"";
    let tracing = "observability:\n  log_level: info";
    for document in [
        // A tagged secret key.
        VALID.replace(glpi, &format!("{glpi}\n  !foo app_token: \"s3cret\"")),
        VALID.replace(glpi, &format!("{glpi}\n  !foo user_token: \"s3cret\"")),
        VALID.replace(
            tracing,
            &format!(
                "{tracing}\n  tracing:\n    enabled: false\n    !x headers:\n      \
                 authorization: \"s3cret\""
            ),
        ),
        // A tagged parent mapping.
        VALID.replace("glpi:\n", "glpi: !section\n"),
        VALID.replace("listener:\n", "listener: !section\n"),
        // A tagged scalar.
        VALID.replace("  port: 8443", "  port: !port 8443"),
        VALID.replace("  log_level: info", "  log_level: !level info"),
        // A tagged list element.
        VALID.replace("[\"RS256\"]", "[!alg \"RS256\"]"),
    ] {
        assert_ne!(document, VALID);
        assert_eq!(
            global_failure_with(&document, &baseline_environment()),
            RuntimeFailure::InvalidDocumentStructure,
            "a tag must be rejected:\n{document}"
        );
    }
}

/// A tagged parent cannot silently drop an environment override, because the
/// tagged document is rejected before the merge.
#[test]
fn a_tagged_parent_cannot_drop_an_environment_override() {
    let tagged = VALID.replace("listener:\n", "listener: !section\n");
    assert_eq!(
        global_failure_with(
            &tagged,
            &environment_with(&[("PERMISSIONSYNC_LISTENER__PORT", "9443")])
        ),
        RuntimeFailure::InvalidDocumentStructure
    );
}

// ---------------------------------------------------------------------------
// Typed decoding
// ---------------------------------------------------------------------------

/// The failure a defect in the section of `path` causes.
#[derive(Debug, Eq, PartialEq)]
enum SectionFailure {
    Global(RuntimeFailure),
    Component(&'static str),
}

fn expected_failure(path: &[&str]) -> SectionFailure {
    match path[0] {
        "listener" => SectionFailure::Global(RuntimeFailure::InvalidListener),
        "request" => SectionFailure::Global(RuntimeFailure::InvalidRequest),
        "shutdown" => SectionFailure::Global(RuntimeFailure::InvalidShutdown),
        "authentication" => SectionFailure::Global(RuntimeFailure::InvalidAuthentication),
        "observability" => SectionFailure::Global(RuntimeFailure::InvalidObservability),
        "provider" => SectionFailure::Component("provider"),
        "glpi" => SectionFailure::Component("glpi"),
        other => panic!("the schema names an unexpected section {other}"),
    }
}

fn observed_failure(environment: &Environment) -> Option<SectionFailure> {
    match decode(VALID, environment) {
        Err(failure) => Some(SectionFailure::Global(failure)),
        Ok(configuration) if configuration.provider_outcome == ComponentOutcome::Invalid => {
            Some(SectionFailure::Component("provider"))
        }
        Ok(configuration) if configuration.glpi_outcome == ComponentOutcome::Invalid => {
            Some(SectionFailure::Component("glpi"))
        }
        Ok(_) => None,
    }
}

/// A value that cannot be decoded with its declared type fails its section
/// exactly as a wrongly typed file value does: a global section stops startup,
/// and a component section leaves only that component unavailable.
#[test]
fn an_undecodable_value_fails_exactly_its_own_section() {
    for variable in ENVIRONMENT_VARIABLES {
        let name = if variable.value_type == ValueType::HeaderMap {
            format!("{TRACING_HEADER_PREFIX}AUTHORIZATION")
        } else {
            variable.name.to_owned()
        };
        let mut variables: Vec<(OsString, OsString)> = GLPI_SECRETS
            .into_iter()
            .map(|(name, value)| (name.into(), value.into()))
            .collect();
        variables.push((name.clone().into(), non_utf8()));
        let environment: Environment = variables.into_iter().collect();

        assert_eq!(
            observed_failure(&environment),
            Some(expected_failure(variable.path)),
            "a non-UTF-8 {name} must fail its own section"
        );
    }
}

#[test]
fn numbers_and_booleans_are_decoded_with_their_declared_type() {
    for value in ["abc", "", " 64", "64 ", "+64", "-1", "6.4", "1e3", "0x40"] {
        assert_eq!(
            observed_failure(&environment_with(&[(
                "PERMISSIONSYNC_REQUEST__INBOUND_ADMISSION_LIMIT",
                value
            )])),
            Some(SectionFailure::Global(RuntimeFailure::InvalidRequest)),
            "{value:?} is not an unsigned integer"
        );
    }
    assert_eq!(
        observed_failure(&environment_with(&[(
            "PERMISSIONSYNC_REQUEST__INBOUND_ADMISSION_LIMIT",
            "18446744073709551616"
        )])),
        Some(SectionFailure::Global(RuntimeFailure::InvalidRequest)),
        "a value above u64::MAX is not decodable"
    );
    assert_eq!(
        observed_failure(&environment_with(&[(
            "PERMISSIONSYNC_LISTENER__PORT",
            "70000"
        )])),
        Some(SectionFailure::Global(RuntimeFailure::InvalidListener)),
        "the strict decoding still applies the narrower port range"
    );

    for value in ["yes", "1", "True", ""] {
        assert_eq!(
            observed_failure(&environment_with(&[(
                "PERMISSIONSYNC_OBSERVABILITY__TRACING__ENABLED",
                value
            )])),
            Some(SectionFailure::Global(RuntimeFailure::InvalidObservability)),
            "{value:?} is not a boolean"
        );
    }

    assert_eq!(
        observed_failure(&environment_with(&[(
            "PERMISSIONSYNC_OBSERVABILITY__LOG_LEVEL",
            "verbose"
        )])),
        Some(SectionFailure::Global(RuntimeFailure::InvalidObservability))
    );

    for value in ["x", "--3", "3-"] {
        assert_eq!(
            observed_failure(&environment_with(&[
                (
                    "PERMISSIONSYNC_GLPI__AUTHENTICATION_SOURCE__AUTHTYPE",
                    value
                ),
                ("PERMISSIONSYNC_GLPI__AUTHENTICATION_SOURCE__AUTHS_ID", "2"),
            ])),
            Some(SectionFailure::Component("glpi")),
            "{value:?} is not a signed integer"
        );
    }

    // A leading zero is rejected, as the file rejects it, unless the value is
    // exactly zero.
    for (name, value, failure) in [
        (
            "PERMISSIONSYNC_LISTENER__PORT",
            "08080",
            RuntimeFailure::InvalidListener,
        ),
        (
            "PERMISSIONSYNC_REQUEST__INBOUND_ADMISSION_LIMIT",
            "064",
            RuntimeFailure::InvalidRequest,
        ),
        (
            "PERMISSIONSYNC_REQUEST__INBOUND_ADMISSION_LIMIT",
            "00",
            RuntimeFailure::InvalidRequest,
        ),
    ] {
        assert_eq!(
            observed_failure(&environment_with(&[(name, value)])),
            Some(SectionFailure::Global(failure)),
            "{value:?} has a leading zero"
        );
    }
    assert_eq!(
        observed_failure(&environment_with(&[(
            "PERMISSIONSYNC_LISTENER__PORT",
            "8080"
        )])),
        None
    );
    assert_eq!(
        observed_failure(&environment_with(&[(
            "PERMISSIONSYNC_AUTHENTICATION__CACHE__STALE_IF_ERROR_MILLISECONDS",
            "0"
        )])),
        None,
        "exactly 0 is a valid unsigned integer"
    );
    assert_eq!(
        observed_failure(&environment_with(&[(
            "PERMISSIONSYNC_AUTHENTICATION__CACHE__STALE_IF_ERROR_MILLISECONDS",
            "0600000"
        )])),
        Some(SectionFailure::Global(
            RuntimeFailure::InvalidAuthentication
        )),
    );
    for (value, expected) in [
        ("-007", Some(SectionFailure::Component("glpi"))),
        ("007", Some(SectionFailure::Component("glpi"))),
        ("-0", None),
        ("0", None),
        ("-7", None),
    ] {
        assert_eq!(
            observed_failure(&environment_with(&[
                (
                    "PERMISSIONSYNC_GLPI__AUTHENTICATION_SOURCE__AUTHTYPE",
                    value
                ),
                ("PERMISSIONSYNC_GLPI__AUTHENTICATION_SOURCE__AUTHS_ID", "2"),
            ])),
            expected,
            "signed integer {value:?}"
        );
    }

    // A wrongly typed GLPI value leaves GLPI unavailable and startup continues.
    assert_eq!(
        observed_failure(&environment_with(&[(
            "PERMISSIONSYNC_GLPI__OPERATION_TIMEOUT_MILLISECONDS",
            "five seconds"
        )])),
        Some(SectionFailure::Component("glpi"))
    );
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

#[test]
fn a_secret_key_in_the_file_stops_startup() {
    let glpi = "  endpoint: \"https://glpi.example.test/apirest.php\"";
    let tracing = "observability:\n  log_level: info";
    for document in [
        VALID.replace(
            glpi,
            &format!("{glpi}\n  app_token: \"sentinel-app-token\""),
        ),
        VALID.replace(
            glpi,
            &format!("{glpi}\n  user_token: \"sentinel-user-token\""),
        ),
        VALID.replace(glpi, &format!("{glpi}\n  app_token: \"\"")),
        VALID.replace(glpi, &format!("{glpi}\n  user_token:")),
        VALID.replace(
            tracing,
            &format!(
                "{tracing}\n  tracing:\n    enabled: false\n    headers:\n      \
                 authorization: \"ApiKey sentinel-exporter-credential\""
            ),
        ),
        VALID.replace(
            tracing,
            &format!("{tracing}\n  tracing:\n    enabled: false\n    headers: {{}}"),
        ),
    ] {
        assert_ne!(document, VALID);
        let failure = global_failure_with(&document, &baseline_environment());
        assert_eq!(failure, RuntimeFailure::SecretInConfigurationFile);
        for rendered in [failure.to_string(), format!("{failure:?}")] {
            assert!(!rendered.contains("sentinel"), "{rendered} leaked a value");
        }
    }
}

/// The GLPI secrets come from the environment and reach the GLPI adapter.
#[test]
fn the_glpi_secrets_come_from_the_environment() {
    let configuration = decoded(VALID, &baseline_environment());
    assert_eq!(configuration.glpi_outcome, ComponentOutcome::Configured);

    let application = ComposedApplication::compose(configuration.runtime).expect("composes");
    assert!(matches!(
        application.resolve_target(&LogicalTarget::try_from("glpi".to_owned()).unwrap()),
        TargetAvailability::Usable(_)
    ));

    let without_secrets: Environment = std::iter::empty::<(&str, &str)>().collect();
    let configuration = decoded(VALID, &without_secrets);
    assert_eq!(configuration.glpi_outcome, ComponentOutcome::Invalid);
}

/// The documented example has no secret and is valid with the secrets in the
/// environment.
#[test]
fn the_documented_example_is_valid_with_secrets_from_the_environment() {
    let example = include_str!("../../../docs/permissionsync.example.yaml");
    let configuration = decoded(example, &baseline_environment());

    assert_eq!(configuration.glpi_outcome, ComponentOutcome::Configured);
    assert_eq!(configuration.provider_outcome, ComponentOutcome::Configured);
}

// ---------------------------------------------------------------------------
// Unknown variables
// ---------------------------------------------------------------------------

#[test]
fn unknown_permissionsync_variables_are_reported_by_name_only() {
    let mut variables: Vec<(OsString, OsString)> = [
        ("PERMISSIONSYNC_LISTENER_PORT", "sentinel-value-1"),
        ("PERMISSIONSYNC_GLPI__APP_TOKN", "sentinel-value-2"),
        (
            "PERMISSIONSYNC_OBSERVABILITY__TRACING__HEADERS__x_api_key",
            "sentinel-value-3",
        ),
        (
            "PERMISSIONSYNC_OBSERVABILITY__TRACING__HEADERS__X__API",
            "sentinel-value-4",
        ),
        (
            CONFIGURATION_PATH_VARIABLE,
            "/etc/permissionsync/permissionsync.yaml",
        ),
        ("PATH", "/usr/bin"),
        ("permissionsync_listener__port", "1"),
    ]
    .into_iter()
    .chain(GLPI_SECRETS)
    .map(|(name, value)| (name.into(), value.into()))
    .collect();
    let mut non_utf8_name = b"PERMISSIONSYNC_".to_vec();
    non_utf8_name.push(0xff);
    variables.push((OsString::from_vec(non_utf8_name), "sentinel-value-5".into()));

    let environment: Environment = variables.into_iter().collect();
    let configuration = decoded(VALID, &environment);

    // Startup continues with the file values.
    assert_eq!(configuration.listener.to_string(), "0.0.0.0:8443");
    assert_eq!(configuration.glpi_outcome, ComponentOutcome::Configured);
    assert_eq!(
        unknown_variables(&environment),
        [
            "PERMISSIONSYNC_GLPI__APP_TOKN",
            "PERMISSIONSYNC_LISTENER_PORT",
            "PERMISSIONSYNC_OBSERVABILITY__TRACING__HEADERS__X__API",
            "PERMISSIONSYNC_OBSERVABILITY__TRACING__HEADERS__x_api_key",
            "PERMISSIONSYNC_\u{fffd}",
        ]
    );
}

#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl io::Write for CapturedLogs {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn captured_logs(action: impl FnOnce()) -> String {
    let logs = CapturedLogs::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, action);
    let captured = logs.0.lock().unwrap().clone();
    String::from_utf8(captured).unwrap()
}

fn captured_text(captured: &CapturedLogs) -> String {
    String::from_utf8(captured.0.lock().unwrap().clone()).unwrap()
}

/// The warning goes through the structured log and carries only the name.
/// While warnings are visible, nothing goes to the fallback writer.
#[test]
fn the_unknown_variable_warning_carries_only_the_name() {
    let environment =
        environment_with(&[("PERMISSIONSYNC_LISTENER_PORT", "sentinel-unknown-value")]);
    let fallback = CapturedLogs::default();
    let report = UnknownVariableReport::new(unknown_variables(&environment), fallback.clone());

    let captured = captured_logs(|| report.log(true));

    assert_eq!(captured.lines().count(), 1, "one warning per unknown name");
    let event: serde_json::Value = serde_json::from_str(captured.trim()).unwrap();
    assert_eq!(event["level"], "WARN");
    assert_eq!(event["fields"]["variable"], "PERMISSIONSYNC_LISTENER_PORT");
    assert!(!captured.contains("sentinel"), "the warning leaked a value");
    assert!(captured_text(&fallback).is_empty());
}

/// A global failure stops startup before logging exists. The names still reach
/// the fallback writer, one line per name, and never a value.
#[test]
fn a_global_failure_with_an_unknown_name_reports_the_name_never_the_value() {
    let environment = environment_with(&[
        ("PERMISSIONSYNC_LISTENER_PORT", "sentinel-unknown-value"),
        ("PERMISSIONSYNC_GLPI__APP_TOKN", "sentinel-unknown-token"),
        ("PERMISSIONSYNC_LISTENER__PORT", "sentinel-invalid-port"),
    ]);
    let fallback = CapturedLogs::default();
    let report = UnknownVariableReport::new(unknown_variables(&environment), fallback.clone());

    let failure = global_failure_with(VALID, &environment);
    assert_eq!(failure, RuntimeFailure::InvalidListener);
    // Startup stops here, so the report is dropped without logging.
    drop(report);

    let written = captured_text(&fallback);
    assert_eq!(
        written,
        "permissionsync: unknown PermissionSync environment variable was ignored: \
         PERMISSIONSYNC_GLPI__APP_TOKN\n\
         permissionsync: unknown PermissionSync environment variable was ignored: \
         PERMISSIONSYNC_LISTENER_PORT\n"
    );
    assert!(
        !written.contains("sentinel"),
        "a value reached standard error"
    );
    assert!(!failure.to_string().contains("sentinel"));
}

/// The `error` log level filters warnings, so the names also reach the
/// fallback writer.
#[test]
fn unknown_names_reach_the_fallback_when_warnings_are_filtered() {
    let environment =
        environment_with(&[("PERMISSIONSYNC_LISTENER_PORT", "sentinel-unknown-value")]);
    let fallback = CapturedLogs::default();
    let report = UnknownVariableReport::new(unknown_variables(&environment), fallback.clone());

    let _ = captured_logs(|| report.log(false));

    let written = captured_text(&fallback);
    assert_eq!(written.lines().count(), 1);
    assert!(written.ends_with(": PERMISSIONSYNC_LISTENER_PORT\n"));
    assert!(!written.contains("sentinel"));
}

/// Without unknown names, the report writes nothing at all.
#[test]
fn no_unknown_name_writes_nothing() {
    let fallback = CapturedLogs::default();
    drop(UnknownVariableReport::new(
        unknown_variables(&baseline_environment()),
        fallback.clone(),
    ));

    assert!(captured_text(&fallback).is_empty());
}
