//! Executable configuration delivery: one strict external YAML document,
//! with environment-variable overrides of its scalar values (ADR 0012).
//!
//! This module owns the delivery/wire model only. It is deliberately separate
//! from the semantic [`RuntimeConfiguration`] it projects into: listener,
//! admission, deadline, shutdown, logging, metrics, and OTLP values are
//! executable concerns and never enter the semantic model.
//!
//! # Global versus component-local decoding
//!
//! The document is decoded in steps so strict decoding cannot promote a
//! component-local defect into a global startup failure.
//!
//! 1. The file is parsed into one YAML tree. A YAML tag anywhere in the file
//!    makes the document structure invalid, and a secret key in the file
//!    stops startup. Then [`environment::merge`] inserts every recognized
//!    environment value into the tree, so every later rule applies equally to
//!    file values and environment values.
//! 2. The whole merged document is decoded into [`DocumentDelivery`], which names
//!    exactly the required top-level sections, rejects unknown top-level
//!    fields, and keeps `provider` and `glpi` as still-undecoded YAML values.
//! 3. Each global section is then decoded and validated on its own, so a
//!    schema mistake reports which section was unusable without reporting any
//!    value from it.
//! 4. The `provider` and `glpi` values are decoded and validated separately.
//!    Either failing leaves only that component unavailable.
//!
//! # Durations
//!
//! Every duration is an integer number of whole milliseconds, spelled with a
//! `_milliseconds` field suffix. There is no second duration syntax, no unit
//! suffix parsing, and no default: a required duration must be present and
//! positive.

use std::{
    collections::BTreeMap,
    ffi::OsString,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    path::Path,
    time::Duration,
};

use permissionsync::{ConfiguredTarget, ProviderConfiguration, RuntimeConfiguration};
use permissionsync_adapter_glpi::{
    GlpiAdapterConfig, GlpiAppToken, GlpiAuthenticationSource, GlpiUserToken,
};
use permissionsync_auth::{
    JwtAlgorithm, TechnicalCallerAuthenticatorConfig, TrustedVerificationSource,
    VerificationCachePolicy,
};
use permissionsync_provider_generic_rest::GenericRestPermissionProviderConfig;
use serde::Deserialize;
use yaml_serde::Value;

use crate::runtime::{
    admission,
    environment::{self, CONFIGURATION_PATH_VARIABLE, Environment},
    failure::RuntimeFailure,
    observability::{LogLevel, ObservabilityConfiguration, TracingConfiguration},
};

/// The finite product safety ceiling on configured selected-target
/// synchronization capacity required by ADR 0011.
///
/// It is well below Tokio's own semaphore maximum, which
/// [`crate::runtime::capacity`] asserts at compile time, so a capacity value
/// accepted here is always constructible.
pub(crate) const MAX_SYNCHRONIZATION_CAPACITY: usize = 1024;

/// Whether one optional component section produced a usable component.
///
/// This distinction exists only so startup can log which coarse reason left a
/// component unavailable. It carries no configured value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ComponentOutcome {
    /// The section was present and produced usable construction input.
    Configured,
    /// The section was absent.
    Absent,
    /// The section was present but could not be decoded or validated under its
    /// own component contract.
    Invalid,
}

/// The validated executable runtime configuration.
///
/// This type owns GLPI credentials, private trust material, and OTLP exporter
/// headers, so it deliberately implements neither `Debug` nor `Display`.
pub(crate) struct ExecutableConfiguration {
    pub(crate) listener: SocketAddr,
    pub(crate) overall_request_deadline: Duration,
    pub(crate) inbound_admission_limit: NonZeroUsize,
    pub(crate) synchronization_capacity: NonZeroUsize,
    pub(crate) shutdown_grace: Duration,
    pub(crate) authentication: TechnicalCallerAuthenticatorConfig,
    pub(crate) metadata_operation_timeout: Duration,
    pub(crate) observability: ObservabilityConfiguration,
    pub(crate) runtime: RuntimeConfiguration,
    pub(crate) provider_outcome: ComponentOutcome,
    pub(crate) glpi_outcome: ComponentOutcome,
}

/// Resolves the single configuration path from the required environment
/// variable.
///
/// The environment is injected, so every loading and validation rule stays
/// testable without mutating process environment state.
pub(crate) fn configuration_path(environment: &Environment) -> Result<OsString, RuntimeFailure> {
    match environment.get(CONFIGURATION_PATH_VARIABLE) {
        Some(path) if !path.is_empty() => Ok(path.to_owned()),
        Some(_) | None => Err(RuntimeFailure::ConfigurationPathMissing),
    }
}

/// Loads the single configuration document, merges the environment into it,
/// and decodes and validates the result.
pub(crate) fn load(
    path: &Path,
    environment: &Environment,
) -> Result<ExecutableConfiguration, RuntimeFailure> {
    let bytes = std::fs::read(path).map_err(|_| RuntimeFailure::ConfigurationUnreadable)?;
    let text = String::from_utf8(bytes).map_err(|_| RuntimeFailure::ConfigurationNotUtf8)?;
    decode(&text, environment)
}

/// Decodes one already-read UTF-8 configuration document, merges the
/// environment into it, and validates the result.
pub(crate) fn decode(
    text: &str,
    environment: &Environment,
) -> Result<ExecutableConfiguration, RuntimeFailure> {
    let mut value = single_document(text)?;
    // No configuration value uses a tag. A tagged key would hide from the
    // secret check and the merge while typed decoding still accepts it.
    if environment::contains_tag(&value) {
        return Err(RuntimeFailure::InvalidDocumentStructure);
    }
    // Secrets come only from the environment. The check runs on the file
    // alone, before the merge inserts environment secrets.
    if environment::contains_secret(&value) {
        return Err(RuntimeFailure::SecretInConfigurationFile);
    }
    environment::merge(&mut value, environment);
    let document: DocumentDelivery =
        yaml_serde::from_value(value).map_err(|_| RuntimeFailure::InvalidDocumentStructure)?;

    let listener = listener(&document.listener)?;
    let request = request(&document.request)?;
    let shutdown = shutdown(&document.shutdown, request.overall_request_deadline)?;
    let authentication =
        authentication(&document.authentication, request.overall_request_deadline)?;
    let observability = observability(&document.observability)?;
    let targets = targets(&document.targets)?;

    let (provider, provider_outcome) =
        component(document.provider.as_ref(), |delivery: ProviderDelivery| {
            delivery.project(request.overall_request_deadline)
        });
    let (glpi, glpi_outcome) = component(document.glpi.as_ref(), |delivery: GlpiDelivery| {
        delivery.project(request.overall_request_deadline)
    });

    Ok(ExecutableConfiguration {
        listener,
        overall_request_deadline: request.overall_request_deadline,
        inbound_admission_limit: request.inbound_admission_limit,
        synchronization_capacity: request.synchronization_capacity,
        shutdown_grace: shutdown,
        metadata_operation_timeout: authentication.metadata_operation_timeout,
        authentication: authentication.config,
        observability,
        runtime: RuntimeConfiguration {
            provider,
            glpi,
            targets,
        },
        provider_outcome,
        glpi_outcome,
    })
}

/// Parses exactly one YAML document into an untyped tree.
///
/// The first document is parsed before the stream is asked for a second one, so
/// a malformed single document is reported as malformed rather than as a
/// multi-document stream. A stream that really does carry a second document is
/// a global failure rather than a silently used first document.
fn single_document(text: &str) -> Result<Value, RuntimeFailure> {
    let mut documents = yaml_serde::Deserializer::from_str(text);
    let first = documents.next().ok_or(RuntimeFailure::ConfigurationEmpty)?;
    let value = Value::deserialize(first).map_err(|_| RuntimeFailure::InvalidDocumentStructure)?;
    if value.is_null() {
        return Err(RuntimeFailure::ConfigurationEmpty);
    }
    if documents.next().is_some() {
        return Err(RuntimeFailure::ConfigurationMultipleDocuments);
    }
    Ok(value)
}

/// The strict top-level document shape.
///
/// `provider` and `glpi` stay undecoded here on purpose: decoding them at this
/// level would let one malformed component field abort startup.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentDelivery {
    listener: Value,
    request: Value,
    shutdown: Value,
    authentication: Value,
    observability: Value,
    targets: Value,
    #[serde(default)]
    provider: Option<Value>,
    #[serde(default)]
    glpi: Option<Value>,
}

fn section<T>(value: &Value, failure: RuntimeFailure) -> Result<T, RuntimeFailure>
where
    T: serde::de::DeserializeOwned,
{
    yaml_serde::from_value(value.clone()).map_err(|_| failure)
}

/// Decodes and validates one optional component section.
///
/// A component-local defect is never propagated: both an undecodable section
/// and a section that fails its own validation yield no usable configuration
/// and leave the component unavailable.
fn component<D, T>(
    value: Option<&Value>,
    project: impl FnOnce(D) -> Option<T>,
) -> (Option<T>, ComponentOutcome)
where
    D: serde::de::DeserializeOwned,
{
    let Some(value) = value else {
        return (None, ComponentOutcome::Absent);
    };
    let Ok(delivery) = yaml_serde::from_value::<D>(value.clone()) else {
        return (None, ComponentOutcome::Invalid);
    };
    match project(delivery) {
        Some(configuration) => (Some(configuration), ComponentOutcome::Configured),
        None => (None, ComponentOutcome::Invalid),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListenerDelivery {
    address: String,
    port: u16,
}

fn listener(value: &Value) -> Result<SocketAddr, RuntimeFailure> {
    let delivery: ListenerDelivery = section(value, RuntimeFailure::InvalidListener)?;
    let address: IpAddr = delivery
        .address
        .parse()
        .map_err(|_| RuntimeFailure::InvalidListener)?;
    if delivery.port == 0 {
        return Err(RuntimeFailure::InvalidListener);
    }
    Ok(SocketAddr::new(address, delivery.port))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestDelivery {
    overall_deadline_milliseconds: u64,
    inbound_admission_limit: usize,
    synchronization_capacity: usize,
}

struct RequestConfiguration {
    overall_request_deadline: Duration,
    inbound_admission_limit: NonZeroUsize,
    synchronization_capacity: NonZeroUsize,
}

/// Validates the `request` section, including that every bounded-concurrency
/// value the runtime derives from it is actually constructible.
///
/// The runtime turns these values into Tokio semaphores, and Tokio panics when a
/// semaphore is created with more than `Semaphore::MAX_PERMITS` permits. An
/// impossible admission or capacity value therefore has to be a deterministic
/// startup failure here, never a panic after successful decoding.
fn request(value: &Value) -> Result<RequestConfiguration, RuntimeFailure> {
    let delivery: RequestDelivery = section(value, RuntimeFailure::InvalidRequest)?;
    let overall_request_deadline = positive_duration(delivery.overall_deadline_milliseconds)
        .ok_or(RuntimeFailure::InvalidRequest)?;

    let inbound_admission_limit = NonZeroUsize::new(delivery.inbound_admission_limit)
        .ok_or(RuntimeFailure::InvalidRequest)?;
    // Proves every semaphore size that inbound admission derives from this one
    // configured value, using checked arithmetic rather than clamping an
    // impossible value into a seemingly valid one.
    admission::derived_semaphore_sizes(inbound_admission_limit)
        .ok_or(RuntimeFailure::InvalidRequest)?;

    let synchronization_capacity = NonZeroUsize::new(delivery.synchronization_capacity)
        .ok_or(RuntimeFailure::InvalidRequest)?;
    if synchronization_capacity.get() > MAX_SYNCHRONIZATION_CAPACITY {
        return Err(RuntimeFailure::InvalidRequest);
    }

    Ok(RequestConfiguration {
        overall_request_deadline,
        inbound_admission_limit,
        synchronization_capacity,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShutdownDelivery {
    grace_milliseconds: u64,
}

/// The grace period must cover one complete compliant request, so every
/// request accepted before shutdown has time to return.
fn shutdown(value: &Value, overall_request_deadline: Duration) -> Result<Duration, RuntimeFailure> {
    let delivery: ShutdownDelivery = section(value, RuntimeFailure::InvalidShutdown)?;
    let grace =
        positive_duration(delivery.grace_milliseconds).ok_or(RuntimeFailure::InvalidShutdown)?;
    if grace < overall_request_deadline {
        return Err(RuntimeFailure::InvalidShutdown);
    }
    Ok(grace)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticationDelivery {
    issuer: String,
    audience: String,
    algorithms: Vec<AlgorithmDelivery>,
    source: SourceDelivery,
    cache: CacheDelivery,
    metadata_operation_timeout_milliseconds: u64,
    clock_skew_milliseconds: u64,
    #[serde(default)]
    additional_trust_anchors_pem: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum AlgorithmDelivery {
    Rs256,
    Rs384,
    Rs512,
    Ps256,
    Ps384,
    Ps512,
    Es256,
    Es384,
    Es512,
    #[serde(rename = "EdDSA")]
    EdDsa,
}

impl AlgorithmDelivery {
    fn project(&self) -> JwtAlgorithm {
        match self {
            Self::Rs256 => JwtAlgorithm::RS256,
            Self::Rs384 => JwtAlgorithm::RS384,
            Self::Rs512 => JwtAlgorithm::RS512,
            Self::Ps256 => JwtAlgorithm::PS256,
            Self::Ps384 => JwtAlgorithm::PS384,
            Self::Ps512 => JwtAlgorithm::PS512,
            Self::Es256 => JwtAlgorithm::ES256,
            Self::Es384 => JwtAlgorithm::ES384,
            Self::Es512 => JwtAlgorithm::ES512,
            Self::EdDsa => JwtAlgorithm::EdDSA,
        }
    }
}

/// The one trusted verification source.
///
/// Exactly one of the two keys must be present: an unknown key is rejected,
/// and neither naming both nor naming none can select a source.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceDelivery {
    #[serde(default)]
    jwks_uri: Option<String>,
    #[serde(default)]
    oidc_discovery_uri: Option<String>,
}

impl SourceDelivery {
    fn project(self) -> Option<TrustedVerificationSource> {
        match (self.jwks_uri, self.oidc_discovery_uri) {
            (Some(uri), None) => Some(TrustedVerificationSource::DirectJwks { uri }),
            (None, Some(uri)) => Some(TrustedVerificationSource::OidcDiscovery { uri }),
            (Some(_), Some(_)) | (None, None) => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheDelivery {
    freshness_milliseconds: u64,
    stale_if_error_milliseconds: u64,
}

struct AuthenticationConfiguration {
    config: TechnicalCallerAuthenticatorConfig,
    metadata_operation_timeout: Duration,
}

fn authentication(
    value: &Value,
    overall_request_deadline: Duration,
) -> Result<AuthenticationConfiguration, RuntimeFailure> {
    let delivery: AuthenticationDelivery = section(value, RuntimeFailure::InvalidAuthentication)?;
    let metadata_operation_timeout =
        positive_duration(delivery.metadata_operation_timeout_milliseconds)
            .ok_or(RuntimeFailure::InvalidAuthentication)?;
    // A child operation may shorten the remaining budget but must never
    // create a later deadline than the one overall request deadline.
    if metadata_operation_timeout > overall_request_deadline {
        return Err(RuntimeFailure::InvalidAuthentication);
    }
    let cache_policy = VerificationCachePolicy::new(
        positive_duration(delivery.cache.freshness_milliseconds)
            .ok_or(RuntimeFailure::InvalidAuthentication)?,
        Duration::from_millis(delivery.cache.stale_if_error_milliseconds),
    );
    let source = delivery
        .source
        .project()
        .ok_or(RuntimeFailure::InvalidAuthentication)?;
    let config = TechnicalCallerAuthenticatorConfig::new(
        delivery.issuer,
        delivery.audience,
        source,
        delivery
            .algorithms
            .iter()
            .map(AlgorithmDelivery::project)
            .collect(),
        metadata_operation_timeout,
        cache_policy,
        Duration::from_millis(delivery.clock_skew_milliseconds),
        trust_anchors(delivery.additional_trust_anchors_pem),
    )
    .map_err(|_| RuntimeFailure::InvalidAuthentication)?;

    Ok(AuthenticationConfiguration {
        config,
        metadata_operation_timeout,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservabilityDelivery {
    log_level: LogLevelDelivery,
    #[serde(default)]
    tracing: Option<TracingDelivery>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum LogLevelDelivery {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevelDelivery {
    fn project(&self) -> LogLevel {
        match self {
            Self::Error => LogLevel::Error,
            Self::Warn => LogLevel::Warn,
            Self::Info => LogLevel::Info,
            Self::Debug => LogLevel::Debug,
            Self::Trace => LogLevel::Trace,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TracingDelivery {
    enabled: bool,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    export_timeout_milliseconds: Option<u64>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    additional_trust_anchors_pem: Vec<String>,
}

fn observability(value: &Value) -> Result<ObservabilityConfiguration, RuntimeFailure> {
    let delivery: ObservabilityDelivery = section(value, RuntimeFailure::InvalidObservability)?;
    let tracing = match delivery.tracing {
        // Trace export is an additional optional channel, disabled unless the
        // document explicitly enables it. An absent section and an explicitly
        // disabled section behave identically and validate nothing further.
        None => None,
        Some(tracing) if !tracing.enabled => None,
        Some(tracing) => Some(
            TracingConfiguration::new(
                tracing
                    .endpoint
                    .ok_or(RuntimeFailure::InvalidObservability)?,
                positive_duration(
                    tracing
                        .export_timeout_milliseconds
                        .ok_or(RuntimeFailure::InvalidObservability)?,
                )
                .ok_or(RuntimeFailure::InvalidObservability)?,
                tracing.headers,
                trust_anchors(tracing.additional_trust_anchors_pem),
            )
            .map_err(|_| RuntimeFailure::InvalidObservability)?,
        ),
    };

    Ok(ObservabilityConfiguration {
        log_level: delivery.log_level.project(),
        tracing,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetDelivery {
    logical_target: String,
    adapter: String,
}

/// Target routes keep their configured input order. Composition owns grammar
/// validation, duplicate detection, and adapter resolution.
fn targets(value: &Value) -> Result<Vec<ConfiguredTarget>, RuntimeFailure> {
    let delivery: Vec<TargetDelivery> = section(value, RuntimeFailure::InvalidTargets)?;
    Ok(delivery
        .into_iter()
        .map(|target| ConfiguredTarget {
            logical_target: target.logical_target,
            adapter_identifier: target.adapter,
        })
        .collect())
}

/// The one configured Permission Provider implementation.
///
/// Exactly one supported implementation key must be present; an unknown key is
/// rejected as invalid component configuration.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderDelivery {
    #[serde(default)]
    generic_rest: Option<GenericRestDelivery>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenericRestDelivery {
    endpoint: String,
    operation_timeout_milliseconds: u64,
    #[serde(default)]
    additional_trust_anchors_pem: Vec<String>,
}

impl ProviderDelivery {
    /// Projects Provider delivery values into semantic Provider configuration.
    ///
    /// A non-positive operation timeout, or one longer than the overall request
    /// deadline, is a Provider-local validation failure: it leaves the Provider
    /// unavailable instead of aborting startup.
    fn project(self, overall_request_deadline: Duration) -> Option<ProviderConfiguration> {
        let delivery = self.generic_rest?;
        let operation_timeout = positive_duration(delivery.operation_timeout_milliseconds)?;
        if operation_timeout > overall_request_deadline {
            return None;
        }
        Some(ProviderConfiguration::GenericRest(
            GenericRestPermissionProviderConfig {
                endpoint: delivery.endpoint,
                operation_timeout,
                additional_trust_anchors_pem: trust_anchors(delivery.additional_trust_anchors_pem),
            },
        ))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GlpiDelivery {
    endpoint: String,
    app_token: String,
    user_token: String,
    operation_timeout_milliseconds: u64,
    #[serde(default)]
    additional_trust_anchors_pem: Vec<String>,
    #[serde(default)]
    authentication_source: Option<GlpiAuthenticationSourceDelivery>,
}

/// `authtype` and `auths_id` form one coherent selection, so the YAML shape
/// requires both together or neither.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GlpiAuthenticationSourceDelivery {
    authtype: i64,
    auths_id: i64,
}

impl GlpiDelivery {
    /// Projects GLPI delivery values into GLPI adapter configuration.
    ///
    /// Endpoint, token, and trust-material validation belong to the GLPI
    /// adapter contract and happen during composition; this only rejects a
    /// timeout that cannot fit the one overall request deadline, which is also
    /// a GLPI-local failure leaving GLPI unavailable.
    fn project(self, overall_request_deadline: Duration) -> Option<GlpiAdapterConfig> {
        let operation_timeout = positive_duration(self.operation_timeout_milliseconds)?;
        if operation_timeout > overall_request_deadline {
            return None;
        }
        Some(GlpiAdapterConfig {
            endpoint: self.endpoint,
            app_token: GlpiAppToken::new(self.app_token),
            user_token: GlpiUserToken::new(self.user_token),
            operation_timeout,
            additional_trust_anchors_pem: trust_anchors(self.additional_trust_anchors_pem),
            authentication_source: match self.authentication_source {
                None => GlpiAuthenticationSource::Default,
                Some(source) => GlpiAuthenticationSource::Explicit {
                    authtype: source.authtype,
                    auths_id: source.auths_id,
                },
            },
        })
    }
}

fn positive_duration(milliseconds: u64) -> Option<Duration> {
    (milliseconds > 0).then(|| Duration::from_millis(milliseconds))
}

/// PEM trust material is supplied inline in the configuration document. There
/// is no file-reference or include mechanism, and no environment override of a
/// list.
fn trust_anchors(pem: Vec<String>) -> Vec<Vec<u8>> {
    pem.into_iter().map(String::into_bytes).collect()
}

/// Every delivery section with its file key path and its field names.
///
/// The field names come from the derived `Deserialize` implementations, so a
/// new field in a delivery struct appears here without a manual list. The
/// schema completeness test compares these fields with the environment
/// variable schema. `targets[]` names the fields of one list element.
#[cfg(test)]
pub(crate) fn delivery_sections() -> Vec<(&'static str, &'static [&'static str])> {
    use field_probe::fields_of;

    vec![
        ("", fields_of::<DocumentDelivery>()),
        ("listener", fields_of::<ListenerDelivery>()),
        ("request", fields_of::<RequestDelivery>()),
        ("shutdown", fields_of::<ShutdownDelivery>()),
        ("authentication", fields_of::<AuthenticationDelivery>()),
        ("authentication.source", fields_of::<SourceDelivery>()),
        ("authentication.cache", fields_of::<CacheDelivery>()),
        ("observability", fields_of::<ObservabilityDelivery>()),
        ("observability.tracing", fields_of::<TracingDelivery>()),
        ("provider", fields_of::<ProviderDelivery>()),
        ("provider.generic_rest", fields_of::<GenericRestDelivery>()),
        ("glpi", fields_of::<GlpiDelivery>()),
        (
            "glpi.authentication_source",
            fields_of::<GlpiAuthenticationSourceDelivery>(),
        ),
        ("targets[]", fields_of::<TargetDelivery>()),
    ]
}

/// Reads the field names of a derived `Deserialize` struct.
///
/// Serde passes the complete field list to `deserialize_struct`, so this
/// deserializer records that list and then stops.
#[cfg(test)]
mod field_probe {
    use std::cell::Cell;

    use serde::{
        Deserialize,
        de::{self, Deserializer, Visitor, value::Error},
    };

    struct Probe<'a>(&'a Cell<&'static [&'static str]>);

    impl<'de> Deserializer<'de> for Probe<'_> {
        type Error = Error;

        fn deserialize_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Error> {
            Err(de::Error::custom("only a struct can be probed"))
        }

        fn deserialize_struct<V: Visitor<'de>>(
            self,
            _name: &'static str,
            fields: &'static [&'static str],
            _visitor: V,
        ) -> Result<V::Value, Error> {
            self.0.set(fields);
            Err(de::Error::custom("probed"))
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf option unit unit_struct newtype_struct seq tuple
            tuple_struct map enum identifier ignored_any
        }
    }

    pub(super) fn fields_of<T: for<'de> Deserialize<'de>>() -> &'static [&'static str] {
        let fields = Cell::new(&[][..]);
        let _ = T::deserialize(Probe(&fields));
        assert!(!fields.get().is_empty(), "the probed type must be a struct");
        fields.get()
    }
}
