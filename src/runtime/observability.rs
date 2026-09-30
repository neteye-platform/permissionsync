//! Structured JSON logging, Prometheus metrics, and optional OTLP tracing.
//!
//! Structured logs and Prometheus metrics are the required always-available
//! channels. Trace export is an additional optional channel that is disabled
//! unless configuration explicitly enables it, and whose failure can never
//! affect a synchronization outcome, readiness, or capacity.
//!
//! # Bounded observability data
//!
//! Every metric label in this module is a closed set of compile-time constants.
//! Nothing derived from a request, a caller, a user, a target, an endpoint, a
//! credential, or an error message is ever used as a label or a span field.

use std::{collections::BTreeMap, time::Duration};

use http::{
    Uri,
    header::{CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderName, HeaderValue},
    uri::Scheme,
};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use native_tls::{Certificate, Protocol, TlsConnector as NativeTlsConnector};
use opentelemetry_otlp::{
    Protocol as OtlpProtocol, RetryPolicy, SpanExporter, WithExportConfig, WithHttpConfig,
};
use opentelemetry_sdk::{
    Resource,
    trace::{BatchConfigBuilder, BatchSpanProcessor, SdkTracerProvider},
};
use tracing_subscriber::{
    Layer, filter::LevelFilter, layer::SubscriberExt, util::SubscriberInitExt,
};

use crate::runtime::{
    failure::RuntimeFailure,
    otlp::{ExporterOrigin, PinnedExporterClient},
};

/// The Prometheus metric namespace. Every metric name below is stable API for
/// operators and dashboards.
pub(crate) const REQUESTS_TOTAL: &str = "permissionsync_requests_total";
pub(crate) const REQUEST_DURATION_SECONDS: &str = "permissionsync_request_duration_seconds";
pub(crate) const REQUEST_STAGE_TOTAL: &str = "permissionsync_request_stage_total";
pub(crate) const REQUESTS_IN_FLIGHT: &str = "permissionsync_requests_in_flight";
pub(crate) const ADMISSION_WAITERS: &str = "permissionsync_inbound_admission_waiters";
pub(crate) const ADMISSION_SATURATED_TOTAL: &str =
    "permissionsync_inbound_admission_saturated_total";
pub(crate) const ADMISSION_ABANDONED_TOTAL: &str =
    "permissionsync_inbound_admission_abandoned_total";
pub(crate) const ADMISSION_QUEUE_FULL_TOTAL: &str =
    "permissionsync_inbound_admission_queue_full_total";
pub(crate) const CAPACITY_IN_USE: &str = "permissionsync_synchronization_capacity_in_use";
pub(crate) const CAPACITY_SATURATED_TOTAL: &str =
    "permissionsync_synchronization_capacity_saturated_total";
pub(crate) const CAPACITY_UNAVAILABLE_TOTAL: &str =
    "permissionsync_synchronization_capacity_unavailable_total";
pub(crate) const COMPONENT_AVAILABLE: &str = "permissionsync_component_available";
pub(crate) const READY: &str = "permissionsync_ready";

/// The only metric label keys this process emits.
pub(crate) const OUTCOME_LABEL: &str = "outcome";
pub(crate) const STAGE_LABEL: &str = "stage";
pub(crate) const COMPONENT_LABEL: &str = "component";

/// Duration buckets shared by every PermissionSync latency histogram. Fixed
/// buckets keep the rendered series count bounded and comparable.
const DURATION_BUCKETS: [f64; 12] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

/// The bounded log-level threshold selected by runtime configuration.
///
/// This is deliberately a closed enum rather than an arbitrary tracing filter
/// expression: JSON format and redaction rules are fixed, and only the
/// threshold is deployment-selectable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    fn filter(self) -> LevelFilter {
        match self {
            Self::Error => LevelFilter::ERROR,
            Self::Warn => LevelFilter::WARN,
            Self::Info => LevelFilter::INFO,
            Self::Debug => LevelFilter::DEBUG,
            Self::Trace => LevelFilter::TRACE,
        }
    }
}

/// Validated observability configuration.
///
/// Contains OTLP exporter credentials when trace export is enabled, so it
/// implements neither `Debug` nor `Display`.
pub(crate) struct ObservabilityConfiguration {
    pub(crate) log_level: LogLevel,
    pub(crate) tracing: Option<TracingConfiguration>,
}

/// An invalid local tracing configuration while export is explicitly enabled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InvalidTracingConfiguration;

/// Validated optional trace-export configuration.
///
/// Contains exporter credentials, so it implements neither `Debug` nor
/// `Display`, and its header values are never rendered anywhere.
pub(crate) struct TracingConfiguration {
    endpoint: Uri,
    origin: ExporterOrigin,
    export_timeout: Duration,
    headers: Vec<(HeaderName, HeaderValue)>,
    tls: NativeTlsConnector,
}

impl TracingConfiguration {
    /// Validates trace-export configuration without contacting the backend.
    ///
    /// The endpoint must be an absolute HTTPS URI with a non-empty host and no
    /// userinfo, query, or fragment component. Certificate and hostname
    /// validation are always enabled and cannot be configured away; private
    /// trust anchors may be added.
    pub(crate) fn new(
        endpoint: String,
        export_timeout: Duration,
        headers: BTreeMap<String, String>,
        additional_trust_anchors_pem: Vec<Vec<u8>>,
    ) -> Result<Self, InvalidTracingConfiguration> {
        let endpoint = parse_endpoint(&endpoint)?;
        let origin = ExporterOrigin::of(&endpoint).ok_or(InvalidTracingConfiguration)?;

        let mut exporter_headers = Vec::with_capacity(headers.len());
        for (name, value) in headers {
            let name: HeaderName = name.parse().map_err(|_| InvalidTracingConfiguration)?;
            // The OTLP request framing belongs to the protocol, not to
            // deployment configuration.
            if name == CONTENT_TYPE || name == CONTENT_LENGTH || name == HOST {
                return Err(InvalidTracingConfiguration);
            }
            let value: HeaderValue = value.parse().map_err(|_| InvalidTracingConfiguration)?;
            exporter_headers.push((name, value));
        }

        let mut builder = NativeTlsConnector::builder();
        builder
            .min_protocol_version(Some(Protocol::Tlsv12))
            .danger_accept_invalid_certs(false)
            .danger_accept_invalid_hostnames(false)
            .use_sni(true);
        for pem in additional_trust_anchors_pem {
            let certificates =
                Certificate::stack_from_pem(&pem).map_err(|_| InvalidTracingConfiguration)?;
            if certificates.is_empty() {
                return Err(InvalidTracingConfiguration);
            }
            for certificate in certificates {
                builder.add_root_certificate(certificate);
            }
        }
        let tls = builder.build().map_err(|_| InvalidTracingConfiguration)?;

        Ok(Self {
            endpoint,
            origin,
            export_timeout,
            headers: exporter_headers,
            tls,
        })
    }

    /// Returns the configured endpoint origin, for deliberate inspection.
    #[cfg(test)]
    pub(crate) fn origin(&self) -> &ExporterOrigin {
        &self.origin
    }

    /// Builds the origin-pinned exporter client for this configuration.
    pub(crate) fn client(&self) -> PinnedExporterClient {
        PinnedExporterClient::new(
            self.tls.clone(),
            self.origin.clone(),
            self.headers.clone(),
            self.export_timeout,
        )
    }
}

fn parse_endpoint(endpoint: &str) -> Result<Uri, InvalidTracingConfiguration> {
    if endpoint.contains(['{', '}', '#']) {
        return Err(InvalidTracingConfiguration);
    }
    let uri: Uri = endpoint.parse().map_err(|_| InvalidTracingConfiguration)?;
    if uri.scheme() != Some(&Scheme::HTTPS)
        || uri.host().is_none_or(str::is_empty)
        || uri.query().is_some()
        || uri
            .authority()
            .is_none_or(|authority| authority.as_str().contains('@'))
    {
        return Err(InvalidTracingConfiguration);
    }
    Ok(uri)
}

/// The initialized observability channels owned by the runtime.
pub(crate) struct Observability {
    metrics: PrometheusHandle,
    tracer_provider: Option<SdkTracerProvider>,
}

impl Observability {
    /// Returns the handle used to render the Prometheus text exposition.
    pub(crate) fn metrics(&self) -> PrometheusHandle {
        self.metrics.clone()
    }

    /// Requests a bounded flush and shutdown of the trace provider.
    ///
    /// The bound is the exporter's own configured export timeout, so an
    /// unavailable backend loses final telemetry instead of extending process
    /// shutdown. Telemetry loss here is deliberate and never reported as a
    /// service failure.
    pub(crate) fn shutdown_tracing(&self, flush_budget: Duration) {
        if let Some(provider) = &self.tracer_provider {
            let _ = provider.shutdown_with_timeout(flush_budget);
        }
    }

    /// Returns whether optional trace export is active.
    pub(crate) fn tracing_enabled(&self) -> bool {
        self.tracer_provider.is_some()
    }
}

/// Initializes the required and optional observability channels.
///
/// Called from within the Tokio runtime because the batch span processor owns a
/// runtime task.
pub(crate) fn initialize(
    configuration: &ObservabilityConfiguration,
) -> Result<Observability, RuntimeFailure> {
    let recorder = PrometheusBuilder::new()
        .set_buckets(&DURATION_BUCKETS)
        .map_err(|_| RuntimeFailure::ObservabilityUnavailable)?
        .build_recorder();
    let metrics = recorder.handle();

    let tracer_provider = match &configuration.tracing {
        None => None,
        Some(tracing) => Some(build_tracer_provider(tracing)?),
    };

    // JSON to standard output with a fixed field set; the threshold is the
    // only configurable part.
    let logs = tracing_subscriber::fmt::layer()
        .json()
        .flatten_event(true)
        .with_current_span(true)
        .with_span_list(false)
        .with_target(true)
        .with_writer(std::io::stdout)
        .with_filter(configuration.log_level.filter());

    let registry = tracing_subscriber::registry().with(logs);
    match &tracer_provider {
        None => registry
            .try_init()
            .map_err(|_| RuntimeFailure::ObservabilityUnavailable)?,
        Some(provider) => {
            let tracer = opentelemetry::trace::TracerProvider::tracer(provider, "permissionsync");
            registry
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .try_init()
                .map_err(|_| RuntimeFailure::ObservabilityUnavailable)?;
        }
    }

    metrics::set_global_recorder(recorder).map_err(|_| RuntimeFailure::ObservabilityUnavailable)?;

    Ok(Observability {
        metrics,
        tracer_provider,
    })
}

/// Builds a bounded, batched OTLP/HTTP span exporter and its provider.
///
/// The batch queue is bounded and drops spans when full, the exporter performs
/// exactly one attempt per batch, and the transport is the origin-pinned
/// HTTPS client. None of these paths can backpressure synchronization work.
pub(crate) fn build_tracer_provider(
    configuration: &TracingConfiguration,
) -> Result<SdkTracerProvider, RuntimeFailure> {
    let exporter = SpanExporter::builder()
        .with_http()
        .with_http_client(configuration.client())
        .with_endpoint(configuration.endpoint.to_string())
        .with_protocol(OtlpProtocol::HttpBinary)
        .with_timeout(configuration.export_timeout)
        // Telemetry is never retried: a failed batch is dropped rather than
        // becoming a queue of repeated work.
        .with_retry_policy(RetryPolicy::disabled())
        .build()
        .map_err(|_| RuntimeFailure::InvalidObservability)?;

    let processor = BatchSpanProcessor::builder(exporter)
        .with_batch_config(
            BatchConfigBuilder::default()
                .with_max_queue_size(BOUNDED_SPAN_QUEUE)
                .with_max_export_batch_size(BOUNDED_EXPORT_BATCH)
                .with_scheduled_delay(SPAN_EXPORT_INTERVAL)
                .build(),
        )
        .build();

    Ok(SdkTracerProvider::builder()
        .with_span_processor(processor)
        .with_resource(
            Resource::builder()
                .with_service_name(env!("CARGO_PKG_NAME"))
                .build(),
        )
        .build())
}

/// The bounded span queue. Spans are dropped once it is full, which is
/// preferable to backpressuring synchronization work.
pub(crate) const BOUNDED_SPAN_QUEUE: usize = 2048;
/// The maximum spans in one export request.
pub(crate) const BOUNDED_EXPORT_BATCH: usize = 512;
/// The interval at which queued spans are exported.
pub(crate) const SPAN_EXPORT_INTERVAL: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, time::Duration};

    use super::{DURATION_BUCKETS, LogLevel, TracingConfiguration, parse_endpoint};

    fn headers(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn only_absolute_https_endpoints_without_query_userinfo_or_fragment_are_accepted() {
        assert!(parse_endpoint("https://otlp.example.test/v1/traces").is_ok());
        assert!(parse_endpoint("https://otlp.example.test:4318/v1/traces").is_ok());

        for invalid in [
            "http://otlp.example.test/v1/traces",
            "https://user:secret@otlp.example.test/v1/traces",
            "https://otlp.example.test/v1/traces?token=sentinel",
            "https://otlp.example.test/v1/traces#fragment",
            "https://{host}/v1/traces",
            "https:///v1/traces",
            "/v1/traces",
            "not-a-uri",
        ] {
            assert!(
                parse_endpoint(invalid).is_err(),
                "{invalid} must be rejected"
            );
        }
    }

    #[test]
    fn a_valid_enabled_tracing_configuration_pins_its_origin() {
        let configuration = TracingConfiguration::new(
            "https://otlp.example.test:4318/v1/traces".to_owned(),
            Duration::from_secs(5),
            headers(&[("authorization", "ApiKey sentinel-exporter-credential")]),
            Vec::new(),
        )
        .expect("valid tracing configuration");

        let expected = super::ExporterOrigin::of(
            &"https://otlp.example.test:4318/v1/traces"
                .parse::<http::Uri>()
                .unwrap(),
        )
        .unwrap();
        assert!(configuration.origin() == &expected);
    }

    #[test]
    fn protocol_framing_headers_cannot_be_configured() {
        for reserved in ["content-type", "content-length", "host"] {
            assert!(
                TracingConfiguration::new(
                    "https://otlp.example.test/v1/traces".to_owned(),
                    Duration::from_secs(5),
                    headers(&[(reserved, "sentinel")]),
                    Vec::new(),
                )
                .is_err(),
                "{reserved} must be rejected"
            );
        }
    }

    #[test]
    fn malformed_headers_and_trust_anchors_are_rejected() {
        assert!(
            TracingConfiguration::new(
                "https://otlp.example.test/v1/traces".to_owned(),
                Duration::from_secs(5),
                headers(&[("invalid header name", "value")]),
                Vec::new(),
            )
            .is_err()
        );
        assert!(
            TracingConfiguration::new(
                "https://otlp.example.test/v1/traces".to_owned(),
                Duration::from_secs(5),
                headers(&[("authorization", "line\nbreak")]),
                Vec::new(),
            )
            .is_err()
        );
        assert!(
            TracingConfiguration::new(
                "https://otlp.example.test/v1/traces".to_owned(),
                Duration::from_secs(5),
                BTreeMap::new(),
                vec![b"not a pem certificate\n".to_vec()],
            )
            .is_err()
        );
    }

    /// A tracing configuration owns exporter credentials, so nothing about it
    /// may be formattable.
    #[test]
    fn tracing_configuration_has_no_formatting_implementation() {
        fn assert_not_debug<T>() {}
        assert_not_debug::<TracingConfiguration>();

        let configuration = TracingConfiguration::new(
            "https://otlp.example.test/v1/traces".to_owned(),
            Duration::from_secs(5),
            headers(&[("authorization", "ApiKey sentinel-exporter-credential")]),
            Vec::new(),
        )
        .unwrap();
        let client = format!("{:?}", configuration.client());
        assert_eq!(client, "PinnedExporterClient");
    }

    #[test]
    fn log_levels_map_to_the_finite_tracing_thresholds() {
        use tracing_subscriber::filter::LevelFilter;

        assert_eq!(LogLevel::Error.filter(), LevelFilter::ERROR);
        assert_eq!(LogLevel::Warn.filter(), LevelFilter::WARN);
        assert_eq!(LogLevel::Info.filter(), LevelFilter::INFO);
        assert_eq!(LogLevel::Debug.filter(), LevelFilter::DEBUG);
        assert_eq!(LogLevel::Trace.filter(), LevelFilter::TRACE);
    }

    #[test]
    fn duration_buckets_are_finite_and_increasing() {
        assert!(DURATION_BUCKETS.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(DURATION_BUCKETS.iter().all(|bucket| bucket.is_finite()));
    }
}
