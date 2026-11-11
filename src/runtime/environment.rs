//! Environment-variable overrides of the configuration file (ADR 0011).
//!
//! The configuration file stays the base document. One environment variable
//! replaces exactly one scalar value of that document, and secrets come only
//! from the environment. Lists stay in the file only.
//!
//! [`ENVIRONMENT_VARIABLES`] is the single schema of every variable. The merge
//! uses it, the startup check for secrets in the file uses it, and the
//! documentation table in `docs/environment-variables.md` is generated from it
//! and checked by a test.
//!
//! # Merge
//!
//! [`merge`] decodes each recognized value with the declared type of its key
//! and inserts it into the parsed YAML tree, creating missing mappings. The
//! existing strict decoding and validation then run on the merged tree, so an
//! environment value follows exactly the same rules as a file value. A value
//! that cannot be decoded with its declared type is inserted as a marker that
//! no typed decoding accepts, so its section fails exactly as a wrongly typed
//! file value does.
//!
//! # Values are never exposed
//!
//! [`Environment`] owns raw values, which can be credentials, so it implements
//! neither `Debug` nor `Display`. Only variable names ever leave this module,
//! and only for unknown `PERMISSIONSYNC_*` variables.

use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    io::Write,
};

use yaml_serde::{Mapping, Value};

pub(crate) const PREFIX: &str = "PERMISSIONSYNC_";

/// The environment variable that supplies the single configuration file path.
///
/// It selects the base document and is not an override of a value in it.
pub(crate) const CONFIGURATION_PATH_VARIABLE: &str = "PERMISSIONSYNC_CONFIG_FILE";

/// The name prefix of the tracing exporter header variables.
///
/// One variable `PERMISSIONSYNC_OBSERVABILITY__TRACING__HEADERS__<NAME>`
/// supplies one exporter header. See [`header_name`] for how `<NAME>` becomes
/// the header name.
pub(crate) const TRACING_HEADER_PREFIX: &str = "PERMISSIONSYNC_OBSERVABILITY__TRACING__HEADERS__";

/// The declared type of one configuration value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ValueType {
    /// Any UTF-8 text.
    Text,
    /// Decimal ASCII digits only, with no leading `0` unless the value is `0`,
    /// at most `u64::MAX`.
    UnsignedInteger,
    /// Decimal ASCII digits with an optional leading `-` and no leading `0`
    /// unless the digits are `0`, within `i64`.
    SignedInteger,
    /// Exactly `true` or `false`.
    Boolean,
    /// One of the bounded log levels.
    LogLevel,
    /// One exporter header value in a map keyed by header name.
    HeaderMap,
}

#[cfg(test)]
impl ValueType {
    pub(crate) fn documentation(self) -> &'static str {
        match self {
            Self::Text => "string",
            Self::UnsignedInteger => "unsigned integer",
            Self::SignedInteger => "signed integer",
            Self::Boolean => "`true` or `false`",
            Self::LogLevel => "`error`, `warn`, `info`, `debug`, or `trace`",
            Self::HeaderMap => "string (one header value)",
        }
    }
}

/// The default of one configuration value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DefaultValue {
    /// The value must be present when its section is present.
    Required,
    /// The value is optional and has no default value.
    Optional,
}

#[cfg(test)]
impl DefaultValue {
    pub(crate) fn documentation(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Optional => "none",
        }
    }
}

/// One environment variable in the schema.
#[derive(Debug)]
pub(crate) struct EnvironmentVariable {
    /// The exact variable name. For [`ValueType::HeaderMap`] it ends with the
    /// `<NAME>` placeholder.
    pub(crate) name: &'static str,
    /// The path of the key in the configuration file.
    pub(crate) path: &'static [&'static str],
    pub(crate) value_type: ValueType,
    /// Read only by the documentation table, which is generated in tests.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "only the generated documentation reads it")
    )]
    pub(crate) default: DefaultValue,
    /// A secret value comes only from the environment: the same key in the
    /// file stops startup.
    pub(crate) secret: bool,
}

const fn variable(
    name: &'static str,
    path: &'static [&'static str],
    value_type: ValueType,
    default: DefaultValue,
) -> EnvironmentVariable {
    EnvironmentVariable {
        name,
        path,
        value_type,
        default,
        secret: false,
    }
}

const fn environment_only(
    name: &'static str,
    path: &'static [&'static str],
    value_type: ValueType,
    default: DefaultValue,
) -> EnvironmentVariable {
    EnvironmentVariable {
        name,
        path,
        value_type,
        default,
        secret: true,
    }
}

/// Every environment variable PermissionSync recognizes, in file order.
///
/// The names are public interface, like the file keys. Every scalar value of
/// the file has one entry. Lists stay in the file only.
pub(crate) const ENVIRONMENT_VARIABLES: &[EnvironmentVariable] = {
    use DefaultValue::{Optional, Required};
    use ValueType::{Boolean, HeaderMap, LogLevel, SignedInteger, Text, UnsignedInteger};
    &[
        variable(
            "PERMISSIONSYNC_LISTENER__ADDRESS",
            &["listener", "address"],
            Text,
            Required,
        ),
        variable(
            "PERMISSIONSYNC_LISTENER__PORT",
            &["listener", "port"],
            UnsignedInteger,
            Required,
        ),
        variable(
            "PERMISSIONSYNC_REQUEST__OVERALL_DEADLINE_MILLISECONDS",
            &["request", "overall_deadline_milliseconds"],
            UnsignedInteger,
            Required,
        ),
        variable(
            "PERMISSIONSYNC_REQUEST__INBOUND_ADMISSION_LIMIT",
            &["request", "inbound_admission_limit"],
            UnsignedInteger,
            Required,
        ),
        variable(
            "PERMISSIONSYNC_REQUEST__SYNCHRONIZATION_CAPACITY",
            &["request", "synchronization_capacity"],
            UnsignedInteger,
            Required,
        ),
        variable(
            "PERMISSIONSYNC_SHUTDOWN__GRACE_MILLISECONDS",
            &["shutdown", "grace_milliseconds"],
            UnsignedInteger,
            Required,
        ),
        variable(
            "PERMISSIONSYNC_AUTHENTICATION__ISSUER",
            &["authentication", "issuer"],
            Text,
            Required,
        ),
        variable(
            "PERMISSIONSYNC_AUTHENTICATION__AUDIENCE",
            &["authentication", "audience"],
            Text,
            Required,
        ),
        variable(
            "PERMISSIONSYNC_AUTHENTICATION__SOURCE__JWKS_URI",
            &["authentication", "source", "jwks_uri"],
            Text,
            Optional,
        ),
        variable(
            "PERMISSIONSYNC_AUTHENTICATION__SOURCE__OIDC_DISCOVERY_URI",
            &["authentication", "source", "oidc_discovery_uri"],
            Text,
            Optional,
        ),
        variable(
            "PERMISSIONSYNC_AUTHENTICATION__CACHE__FRESHNESS_MILLISECONDS",
            &["authentication", "cache", "freshness_milliseconds"],
            UnsignedInteger,
            Required,
        ),
        variable(
            "PERMISSIONSYNC_AUTHENTICATION__CACHE__STALE_IF_ERROR_MILLISECONDS",
            &["authentication", "cache", "stale_if_error_milliseconds"],
            UnsignedInteger,
            Required,
        ),
        variable(
            "PERMISSIONSYNC_AUTHENTICATION__METADATA_OPERATION_TIMEOUT_MILLISECONDS",
            &["authentication", "metadata_operation_timeout_milliseconds"],
            UnsignedInteger,
            Required,
        ),
        variable(
            "PERMISSIONSYNC_AUTHENTICATION__CLOCK_SKEW_MILLISECONDS",
            &["authentication", "clock_skew_milliseconds"],
            UnsignedInteger,
            Required,
        ),
        variable(
            "PERMISSIONSYNC_OBSERVABILITY__LOG_LEVEL",
            &["observability", "log_level"],
            LogLevel,
            Required,
        ),
        variable(
            "PERMISSIONSYNC_OBSERVABILITY__TRACING__ENABLED",
            &["observability", "tracing", "enabled"],
            Boolean,
            Required,
        ),
        variable(
            "PERMISSIONSYNC_OBSERVABILITY__TRACING__ENDPOINT",
            &["observability", "tracing", "endpoint"],
            Text,
            Optional,
        ),
        variable(
            "PERMISSIONSYNC_OBSERVABILITY__TRACING__EXPORT_TIMEOUT_MILLISECONDS",
            &["observability", "tracing", "export_timeout_milliseconds"],
            UnsignedInteger,
            Optional,
        ),
        environment_only(
            "PERMISSIONSYNC_OBSERVABILITY__TRACING__HEADERS__<NAME>",
            &["observability", "tracing", "headers"],
            HeaderMap,
            Optional,
        ),
        variable(
            "PERMISSIONSYNC_PROVIDER__GENERIC_REST__ENDPOINT",
            &["provider", "generic_rest", "endpoint"],
            Text,
            Required,
        ),
        variable(
            "PERMISSIONSYNC_PROVIDER__GENERIC_REST__OPERATION_TIMEOUT_MILLISECONDS",
            &["provider", "generic_rest", "operation_timeout_milliseconds"],
            UnsignedInteger,
            Required,
        ),
        variable(
            "PERMISSIONSYNC_GLPI__ENDPOINT",
            &["glpi", "endpoint"],
            Text,
            Required,
        ),
        environment_only(
            "PERMISSIONSYNC_GLPI__APP_TOKEN",
            &["glpi", "app_token"],
            Text,
            Required,
        ),
        environment_only(
            "PERMISSIONSYNC_GLPI__USER_TOKEN",
            &["glpi", "user_token"],
            Text,
            Required,
        ),
        variable(
            "PERMISSIONSYNC_GLPI__OPERATION_TIMEOUT_MILLISECONDS",
            &["glpi", "operation_timeout_milliseconds"],
            UnsignedInteger,
            Required,
        ),
        variable(
            "PERMISSIONSYNC_GLPI__AUTHENTICATION_SOURCE__AUTHTYPE",
            &["glpi", "authentication_source", "authtype"],
            SignedInteger,
            Required,
        ),
        variable(
            "PERMISSIONSYNC_GLPI__AUTHENTICATION_SOURCE__AUTHS_ID",
            &["glpi", "authentication_source", "auths_id"],
            SignedInteger,
            Required,
        ),
    ]
};

/// A captured set of environment variables.
///
/// The runtime captures the process environment once, through
/// [`Environment::from_process`]. Every other function receives an injected
/// value, so tests never mutate the real process environment.
///
/// Values can be credentials, so this type implements neither `Debug` nor
/// `Display`.
pub(crate) struct Environment {
    variables: BTreeMap<OsString, OsString>,
}

impl Environment {
    /// Captures the process environment. This is the only place where the
    /// runtime reads `std::env`.
    pub(crate) fn from_process() -> Self {
        std::env::vars_os().collect()
    }

    pub(crate) fn get(&self, name: &str) -> Option<&OsStr> {
        self.variables
            .get(OsStr::new(name))
            .map(OsString::as_os_str)
    }
}

impl<N, V> FromIterator<(N, V)> for Environment
where
    N: Into<OsString>,
    V: Into<OsString>,
{
    fn from_iter<I: IntoIterator<Item = (N, V)>>(iter: I) -> Self {
        Self {
            variables: iter
                .into_iter()
                .map(|(name, value)| (name.into(), value.into()))
                .collect(),
        }
    }
}

/// Returns true when the file sets a key that must come only from the
/// environment.
///
/// A present key counts, whatever its value, including an empty or null value.
pub(crate) fn contains_secret(document: &Value) -> bool {
    ENVIRONMENT_VARIABLES
        .iter()
        .filter(|variable| variable.secret)
        .any(|variable| lookup(document, variable.path).is_some())
}

fn lookup<'a>(document: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(document, |current, segment| {
        current.as_mapping()?.get(*segment)
    })
}

/// How one environment variable relates to the configuration.
enum Classification {
    /// Not a `PERMISSIONSYNC_*` variable, or the configuration path variable.
    Ignored,
    /// A recognized override of the value at this file key path.
    Override(Vec<String>, ValueType),
    /// An unknown `PERMISSIONSYNC_*` variable, with its name only.
    Unknown(String),
}

fn classify(name: &OsStr) -> Classification {
    if !name.as_encoded_bytes().starts_with(PREFIX.as_bytes()) {
        return Classification::Ignored;
    }
    let Some(name) = name.to_str() else {
        return Classification::Unknown(name.to_string_lossy().into_owned());
    };
    if name == CONFIGURATION_PATH_VARIABLE {
        return Classification::Ignored;
    }
    match resolve(name) {
        Some((path, value_type)) => Classification::Override(path, value_type),
        None => Classification::Unknown(name.to_owned()),
    }
}

/// Returns the names of the unknown `PERMISSIONSYNC_*` variables, in a
/// deterministic order.
///
/// The names depend on the environment only, so startup can report them even
/// when the configuration file is unusable. No value is returned.
pub(crate) fn unknown_variables(environment: &Environment) -> Vec<String> {
    environment
        .variables
        .keys()
        .filter_map(|name| match classify(name) {
            Classification::Unknown(name) => Some(name),
            Classification::Ignored | Classification::Override(..) => None,
        })
        .collect()
}

/// Merges every recognized `PERMISSIONSYNC_*` variable into `document`.
///
/// Unknown variables are skipped here; [`report_unknown_variables`] reports
/// them.
pub(crate) fn merge(document: &mut Value, environment: &Environment) {
    for (name, value) in &environment.variables {
        if let Classification::Override(path, value_type) = classify(name) {
            insert(document, &path, decode(value, value_type));
        }
    }
}

/// Returns true when any node of the document carries a YAML tag.
///
/// No configuration value uses a tag, and a tagged key or node would hide from
/// the secret check and from the merge while typed decoding still accepts it.
/// A tag anywhere therefore makes the document structure invalid.
pub(crate) fn contains_tag(value: &Value) -> bool {
    match value {
        Value::Tagged(_) => true,
        Value::Sequence(items) => items.iter().any(contains_tag),
        Value::Mapping(mapping) => mapping
            .iter()
            .any(|(key, child)| contains_tag(key) || contains_tag(child)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

/// Resolves one variable name to its file key path and declared type.
fn resolve(name: &str) -> Option<(Vec<String>, ValueType)> {
    if let Some(variable) = ENVIRONMENT_VARIABLES
        .iter()
        .find(|variable| variable.value_type != ValueType::HeaderMap && variable.name == name)
    {
        return Some((owned_path(variable.path), variable.value_type));
    }

    let header = header_name(name.strip_prefix(TRACING_HEADER_PREFIX)?)?;
    let headers = ENVIRONMENT_VARIABLES
        .iter()
        .find(|variable| variable.value_type == ValueType::HeaderMap)?;
    let mut path = owned_path(headers.path);
    path.push(header);
    Some((path, ValueType::HeaderMap))
}

fn owned_path(path: &[&str]) -> Vec<String> {
    path.iter().map(|segment| (*segment).to_owned()).collect()
}

/// Derives an exporter header name from the `<NAME>` part of a header
/// variable.
///
/// `<NAME>` is one or more groups of uppercase ASCII letters and digits,
/// separated by a single `_`. The header name is `<NAME>` in lowercase with
/// every `_` replaced by `-`, so `AUTHORIZATION` gives `authorization` and
/// `X_API_KEY` gives `x-api-key`. Any other `<NAME>` is not a recognized
/// variable.
pub(crate) fn header_name(suffix: &str) -> Option<String> {
    let valid = !suffix.is_empty()
        && suffix.split('_').all(|group| {
            !group.is_empty()
                && group
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        });
    valid.then(|| suffix.to_ascii_lowercase().replace('_', "-"))
}

/// The value inserted when an environment value cannot be decoded with its
/// declared type.
///
/// No typed decoding of a scalar or a string map accepts a sequence, so the
/// section that contains the key fails exactly as a wrongly typed file value
/// does.
fn undecodable() -> Value {
    Value::Sequence(Vec::new())
}

fn decode(value: &OsStr, value_type: ValueType) -> Value {
    let Some(text) = value.to_str() else {
        return undecodable();
    };
    match value_type {
        ValueType::Text | ValueType::LogLevel | ValueType::HeaderMap => {
            Value::String(text.to_owned())
        }
        ValueType::UnsignedInteger => {
            if !is_decimal(text) {
                return undecodable();
            }
            text.parse::<u64>()
                .map_or_else(|_| undecodable(), |number| Value::Number(number.into()))
        }
        ValueType::SignedInteger => {
            if !is_decimal(text.strip_prefix('-').unwrap_or(text)) {
                return undecodable();
            }
            text.parse::<i64>()
                .map_or_else(|_| undecodable(), |number| Value::Number(number.into()))
        }
        ValueType::Boolean => match text {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            _ => undecodable(),
        },
    }
}

/// Decimal ASCII digits, with no leading `0` unless the text is exactly `0`.
///
/// A leading `0` is rejected, so a value such as `08080` fails as it does in
/// the file.
fn is_decimal(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'))
}

/// Inserts one value at `path`, creating missing or null mappings.
///
/// The merge never repairs the document: when a node on the path exists and is
/// not a mapping, the value is not inserted, and strict decoding then reports
/// that node exactly as it would without the environment.
fn insert(document: &mut Value, path: &[String], value: Value) {
    let Some((leaf, parents)) = path.split_last() else {
        return;
    };
    let mut current = document;
    for segment in parents {
        let Value::Mapping(mapping) = current else {
            return;
        };
        let child = mapping
            .entry(Value::String(segment.clone()))
            .or_insert(Value::Null);
        if child.is_null() {
            *child = Value::Mapping(Mapping::new());
        }
        current = child;
    }
    if let Value::Mapping(mapping) = current {
        mapping.insert(Value::String(leaf.clone()), value);
    }
}

/// Renders the documentation table of every environment variable.
///
/// `docs/environment-variables.md` contains exactly this table, and a test
/// checks that the two stay equal.
#[cfg(test)]
pub(crate) fn documentation_table() -> String {
    const HEADER: [&str; 5] = ["Variable", "File key", "Type", "Default", "Secret"];

    let rows: Vec<[String; 5]> = ENVIRONMENT_VARIABLES
        .iter()
        .map(|variable| {
            let mut key = variable.path.join(".");
            if variable.value_type == ValueType::HeaderMap {
                key.push_str(".<name>");
            }
            [
                format!("`{}`", variable.name),
                format!("`{key}`"),
                variable.value_type.documentation().to_owned(),
                variable.default.documentation().to_owned(),
                if variable.secret { "yes" } else { "no" }.to_owned(),
            ]
        })
        .collect();

    let mut widths = HEADER.map(str::len);
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.len());
        }
    }

    let line = |cells: &[String]| {
        let padded: Vec<String> = cells
            .iter()
            .zip(widths)
            .map(|(cell, width)| format!("{cell:<width$}"))
            .collect();
        format!("| {} |\n", padded.join(" | "))
    };

    let mut table = line(&HEADER.map(str::to_owned));
    table.push_str(&line(&widths.map(|width| "-".repeat(width))));
    for row in &rows {
        table.push_str(&line(row));
    }
    table
}

/// Writes one line to `writer` for each unknown `PERMISSIONSYNC_*` variable.
///
/// The line contains only the name, never the value.
pub(crate) fn report_unknown_variables(environment: &Environment, mut writer: impl Write) {
    for name in unknown_variables(environment) {
        // A failed diagnostic write cannot be reported anywhere else.
        let _ = writeln!(
            writer,
            "permissionsync: unknown PermissionSync environment variable was ignored: {name}"
        );
    }
}
