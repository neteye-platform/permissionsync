//! W3C inbound trace context, and the security and isolation properties of the
//! optional OTLP exporter transport.
//!
//! The exporter transport is exercised directly against local TLS endpoints,
//! because its contract — HTTPS only, origin pinning, refused redirects, and
//! credentials that cannot escape the configured origin — is security-sensitive
//! and not merely configuration parsing.

use std::{collections::BTreeMap, time::Duration};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use opentelemetry_http::{Bytes, HttpClient};

use crate::runtime::{
    observability::{
        BOUNDED_CONCURRENT_EXPORTS, BOUNDED_EXPORT_BATCH, BOUNDED_SPAN_QUEUE,
        MAX_ATTRIBUTES_PER_SPAN_EVENT, MAX_ATTRIBUTES_PER_SPAN_LINK, MAX_SPAN_ATTRIBUTES,
        MAX_SPAN_EVENTS, MAX_SPAN_LINKS, TracingConfiguration, build_tracer_provider,
        shutdown_tracer_provider,
    },
    tests::support::{
        GLPI, HttpsFixture, RefusingEndpoint, RuntimeFixture, RuntimeFixtureOptions,
        ScriptedResponse, SigningMaterial, authenticator, emit_one_span, glpi_configuration,
        jwks_fixture, provider_configuration, target, valid_body,
    },
    transport::SYNCHRONIZATION_ROUTE,
};

const UNREACHABLE_GLPI: &str = "https://127.0.0.1:1/apirest.php";
const EXPORTER_CREDENTIAL: &str = "ApiKey sentinel-exporter-credential";
const VALID_TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

struct Scenario {
    jwks: HttpsFixture,
    signing: SigningMaterial,
    fixture: RuntimeFixture,
}

impl Scenario {
    async fn build(options: impl FnOnce(&mut RuntimeFixtureOptions)) -> Self {
        let signing = SigningMaterial::new("trace-test-key");
        let jwks = jwks_fixture(&signing, 8).await;
        let mut fixture_options = RuntimeFixtureOptions {
            trace_context_enabled: true,
            ..RuntimeFixtureOptions::default()
        };
        options(&mut fixture_options);
        let fixture = RuntimeFixture::new(
            authenticator(jwks.endpoint("/keys"), jwks.trust_anchor_pem().to_vec()),
            fixture_options,
        );
        Self {
            jwks,
            signing,
            fixture,
        }
    }

    async fn finish(self) {
        self.jwks.shutdown().await;
    }
}

fn tracing_configuration(endpoint: &str, trust: Vec<Vec<u8>>) -> TracingConfiguration {
    let mut headers = BTreeMap::new();
    headers.insert("authorization".to_owned(), EXPORTER_CREDENTIAL.to_owned());
    TracingConfiguration::new(endpoint.to_owned(), Duration::from_secs(5), headers, trust)
        .expect("a valid enabled tracing configuration")
}

/// Builds an OTLP-shaped export request for the configured endpoint.
fn export_request(uri: &str) -> Request<Bytes> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-protobuf")
        .body(Bytes::from_static(b"\x00\x01\x02"))
        .expect("a valid export request")
}

// ---------------------------------------------------------------------------
// Inbound trace context
// ---------------------------------------------------------------------------

/// Absent, valid, and malformed trace context must all produce the same
/// synchronization outcome. Trace context is transport metadata only.
#[tokio::test]
async fn inbound_trace_context_never_changes_a_synchronization_outcome() {
    let scenario = Scenario::build(|_| {}).await;
    let token = scenario.signing.token(Some("service_account"));

    for traceparent in [
        None,
        Some(VALID_TRACEPARENT),
        // Malformed values: wrong version, wrong lengths, all-zero ids,
        // non-hexadecimal characters, and an empty value.
        Some("not-a-traceparent"),
        Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7"),
        Some("00-00000000000000000000000000000000-0000000000000000-01"),
        Some("zz-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        Some(""),
    ] {
        let mut request = Request::builder()
            .method("POST")
            .uri(SYNCHRONIZATION_ROUTE)
            .header("authorization", format!("Bearer {token}"));
        if let Some(traceparent) = traceparent {
            request = request.header("traceparent", traceparent);
        }
        let status = scenario
            .fixture
            .call(request.body(Body::from(valid_body())).unwrap())
            .await
            .status();

        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "traceparent {traceparent:?} must not affect the outcome"
        );
    }

    scenario.finish().await;
}

/// `tracestate` is likewise transport metadata, including when it accompanies a
/// malformed `traceparent`.
#[tokio::test]
async fn inbound_tracestate_never_changes_a_synchronization_outcome() {
    let scenario = Scenario::build(|_| {}).await;
    let token = scenario.signing.token(Some("service_account"));

    for (traceparent, tracestate) in [
        (VALID_TRACEPARENT, "vendor=value"),
        (VALID_TRACEPARENT, "!!!not-valid!!!"),
        ("malformed", "vendor=value"),
    ] {
        let status = scenario
            .fixture
            .call(
                Request::builder()
                    .method("POST")
                    .uri(SYNCHRONIZATION_ROUTE)
                    .header("authorization", format!("Bearer {token}"))
                    .header("traceparent", traceparent)
                    .header("tracestate", tracestate)
                    .body(Body::from(valid_body()))
                    .unwrap(),
            )
            .await
            .status();

        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    scenario.finish().await;
}

/// Trace context must never influence authentication or authorization: a
/// perfectly valid trace context cannot rescue a rejected credential, and a
/// malformed one cannot spoil a valid request.
#[tokio::test]
async fn trace_context_never_influences_authorization() {
    let scenario = Scenario::build(|options| {
        options.glpi = Some(glpi_configuration(UNREACHABLE_GLPI));
        options.targets = vec![target("glpi", GLPI)];
    })
    .await;

    let unauthorized = scenario
        .fixture
        .call(
            Request::builder()
                .method("POST")
                .uri(SYNCHRONIZATION_ROUTE)
                .header("authorization", "Basic secret")
                .header("traceparent", VALID_TRACEPARENT)
                .body(Body::from(valid_body()))
                .unwrap(),
        )
        .await
        .status();
    assert_eq!(unauthorized, StatusCode::UNAUTHORIZED);

    let ambiguous = scenario
        .signing
        .token(Some("permissionsync:glpi permissionsync:other"));
    let forbidden = scenario
        .fixture
        .call(
            Request::builder()
                .method("POST")
                .uri(SYNCHRONIZATION_ROUTE)
                .header("authorization", format!("Bearer {ambiguous}"))
                .header("traceparent", "malformed")
                .body(Body::from(valid_body()))
                .unwrap(),
        )
        .await
        .status();
    assert_eq!(forbidden, StatusCode::FORBIDDEN);

    scenario.finish().await;
}

/// The decisive ADR 0008/0009 regression: enabling tracing must not add trace
/// propagation headers to the outbound Provider request, and must not add any
/// field to its wire body.
#[tokio::test]
async fn enabling_tracing_does_not_change_provider_wire_requests() {
    let provider = HttpsFixture::start(vec![ScriptedResponse::json(
        200,
        br#"{"version":2,"payload":null}"#.to_vec(),
    )])
    .await;
    let scenario = Scenario::build(|options| {
        options.provider = Some(provider_configuration(
            &provider.endpoint("/permissions"),
            vec![provider.trust_anchor_pem().to_vec()],
        ));
        options.glpi = Some(glpi_configuration(UNREACHABLE_GLPI));
        options.targets = vec![target("glpi", GLPI)];
    })
    .await;
    let token = scenario.signing.token(Some("permissionsync:glpi"));

    let status = scenario
        .fixture
        .call(
            Request::builder()
                .method("POST")
                .uri(SYNCHRONIZATION_ROUTE)
                .header("authorization", format!("Bearer {token}"))
                .header("traceparent", VALID_TRACEPARENT)
                .header("tracestate", "vendor=value")
                .body(Body::from(valid_body()))
                .unwrap(),
        )
        .await
        .status();
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

    let observed = provider.observed();
    assert_eq!(observed.len(), 1, "exactly one Provider request");
    let request = &observed[0];

    // The ADR 0008 request line is unchanged by tracing.
    assert!(
        request
            .request_line
            .starts_with("POST /permissions HTTP/1.1"),
        "unexpected Provider request line: {}",
        request.request_line
    );

    for propagation_header in [
        "traceparent",
        "tracestate",
        "baggage",
        "b3",
        "x-b3-traceid",
        "x-b3-spanid",
        "uber-trace-id",
    ] {
        assert!(
            request.header(propagation_header).is_none(),
            "the Provider wire contract must not gain {propagation_header}"
        );
    }

    // The Provider request body remains exactly the two-field contract.
    let body = String::from_utf8(request.body.clone()).expect("the Provider body is UTF-8 JSON");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let object = parsed.as_object().expect("a JSON object");
    let mut members: Vec<&str> = object.keys().map(String::as_str).collect();
    members.sort_unstable();
    assert_eq!(
        members,
        ["groups", "username"],
        "trace metadata must never become Provider request data"
    );

    provider.shutdown().await;
    scenario.finish().await;
}

/// Enabling trace-context handling does not change any outcome relative to the
/// same scenario with it disabled.
#[tokio::test]
async fn trace_context_handling_is_outcome_neutral() {
    let mut statuses = Vec::new();
    for trace_context_enabled in [false, true] {
        let signing = SigningMaterial::new("trace-neutral-key");
        let jwks = jwks_fixture(&signing, 8).await;
        let fixture = RuntimeFixture::new(
            authenticator(jwks.endpoint("/keys"), jwks.trust_anchor_pem().to_vec()),
            RuntimeFixtureOptions {
                glpi: Some(glpi_configuration(UNREACHABLE_GLPI)),
                targets: vec![target("glpi", GLPI)],
                trace_context_enabled,
                ..RuntimeFixtureOptions::default()
            },
        );

        let mut observed = Vec::new();
        for scope in [
            Some("service_account"),
            Some("permissionsync:glpi"),
            Some("permissionsync:absent"),
            Some("permissionsync:a permissionsync:b"),
        ] {
            let token = signing.token(scope);
            observed.push(
                fixture
                    .call(
                        Request::builder()
                            .method("POST")
                            .uri(SYNCHRONIZATION_ROUTE)
                            .header("authorization", format!("Bearer {token}"))
                            .header("traceparent", VALID_TRACEPARENT)
                            .body(Body::from(valid_body()))
                            .unwrap(),
                    )
                    .await
                    .status(),
            );
        }
        statuses.push(observed);
        jwks.shutdown().await;
    }

    assert_eq!(
        statuses[0], statuses[1],
        "enabling trace context must not change any outcome"
    );
}

// ---------------------------------------------------------------------------
// OTLP exporter transport security
// ---------------------------------------------------------------------------

/// A plaintext endpoint cannot be configured at all.
#[test]
fn a_plaintext_otlp_endpoint_is_rejected() {
    assert!(
        TracingConfiguration::new(
            "http://otlp.example.test/v1/traces".to_owned(),
            Duration::from_secs(5),
            BTreeMap::new(),
            Vec::new(),
        )
        .is_err()
    );
}

/// An HTTPS endpoint with an explicitly configured private trust anchor works,
/// and the configured credential reaches exactly that endpoint.
#[tokio::test]
async fn the_configured_credential_reaches_the_configured_https_endpoint() {
    let backend = HttpsFixture::start(vec![ScriptedResponse::empty(200)]).await;
    let configuration = tracing_configuration(
        &backend.endpoint("/v1/traces"),
        vec![backend.trust_anchor_pem().to_vec()],
    );
    let client = configuration.client();

    let response = client
        .send_bytes(export_request(&backend.endpoint("/v1/traces")))
        .await
        .expect("export to the configured endpoint succeeds");

    assert_eq!(response.status(), 200);
    let observed = backend.observed();
    assert_eq!(observed.len(), 1);
    assert_eq!(
        observed[0].header("authorization"),
        Some(EXPORTER_CREDENTIAL),
        "the configured exporter credential must reach the configured endpoint"
    );

    backend.shutdown().await;
}

/// Certificate validation is not disabled: an endpoint whose certificate is not
/// covered by the configured trust anchors cannot be exported to.
#[tokio::test]
async fn an_untrusted_certificate_is_refused() {
    let backend = HttpsFixture::start(vec![ScriptedResponse::empty(200)]).await;
    // Deliberately configure no trust anchor for this backend's private root.
    let configuration = tracing_configuration(&backend.endpoint("/v1/traces"), Vec::new());
    let client = configuration.client();

    let result = client
        .send_bytes(export_request(&backend.endpoint("/v1/traces")))
        .await;

    assert!(
        result.is_err(),
        "an untrusted certificate must make export fail"
    );

    backend.shutdown().await;
}

/// Every `3xx` is an export failure: the response is discarded, its `Location`
/// is never requested, and the credential never reaches the redirect target.
#[tokio::test]
async fn a_redirect_is_refused_and_its_location_is_never_requested() {
    let redirect_target = HttpsFixture::start(vec![ScriptedResponse::empty(200)]).await;
    let backend = HttpsFixture::start(vec![
        ScriptedResponse::empty(302)
            .with_header("location", &redirect_target.endpoint("/v1/traces")),
    ])
    .await;
    let configuration = tracing_configuration(
        &backend.endpoint("/v1/traces"),
        vec![backend.trust_anchor_pem().to_vec()],
    );
    let client = configuration.client();

    let result = client
        .send_bytes(export_request(&backend.endpoint("/v1/traces")))
        .await;

    assert!(result.is_err(), "a redirect must be an export failure");
    assert_eq!(
        backend.request_count(),
        1,
        "exactly one request is made, with no follow-up"
    );
    assert_eq!(
        redirect_target.request_count(),
        0,
        "the redirect Location must never be requested"
    );

    // The failure must not name the endpoint, the redirect target, or the
    // credential.
    let rendered = result
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    for sensitive in [
        backend.base_uri(),
        redirect_target.base_uri(),
        EXPORTER_CREDENTIAL,
        "sentinel-exporter-credential",
    ] {
        assert!(
            !rendered.contains(sensitive),
            "the export failure leaked {sensitive}"
        );
    }

    backend.shutdown().await;
    redirect_target.shutdown().await;
}

/// Every `3xx` status is refused, not just the common ones.
#[tokio::test]
async fn every_redirection_status_is_refused() {
    for status in [301_u16, 302, 303, 307, 308] {
        let backend = HttpsFixture::start(vec![
            ScriptedResponse::empty(status).with_header("location", "https://elsewhere.test/v1"),
        ])
        .await;
        let configuration = tracing_configuration(
            &backend.endpoint("/v1/traces"),
            vec![backend.trust_anchor_pem().to_vec()],
        );

        let result = configuration
            .client()
            .send_bytes(export_request(&backend.endpoint("/v1/traces")))
            .await;

        assert!(result.is_err(), "{status} must be an export failure");
        backend.shutdown().await;
    }
}

/// A request aimed at any other origin is refused before a connection is made,
/// so exporter credentials cannot escape the configured origin even if the
/// library or an ambient environment variable names another endpoint.
#[tokio::test]
async fn a_foreign_origin_is_refused_before_any_request_is_sent() {
    let configured = HttpsFixture::start(vec![ScriptedResponse::empty(200)]).await;
    let foreign = HttpsFixture::start(vec![ScriptedResponse::empty(200)]).await;
    let configuration = tracing_configuration(
        &configured.endpoint("/v1/traces"),
        vec![configured.trust_anchor_pem().to_vec()],
    );
    let client = configuration.client();

    for foreign_uri in [
        foreign.endpoint("/v1/traces"),
        "http://127.0.0.1:1/v1/traces".to_owned(),
        "https://other.example.test/v1/traces".to_owned(),
    ] {
        let result = client.send_bytes(export_request(&foreign_uri)).await;
        assert!(result.is_err(), "{foreign_uri} must be refused");
    }

    assert_eq!(
        foreign.request_count(),
        0,
        "no request may be sent to a non-configured origin"
    );
    assert_eq!(
        configured.request_count(),
        0,
        "no request was aimed at the configured origin in this test"
    );

    configured.shutdown().await;
    foreign.shutdown().await;
}

/// Only the configured headers plus the protocol framing headers are sent, so an
/// ambient value cannot add a header to exported telemetry.
#[tokio::test]
async fn only_configured_and_protocol_headers_reach_the_backend() {
    let backend = HttpsFixture::start(vec![ScriptedResponse::empty(200)]).await;
    let configuration = tracing_configuration(
        &backend.endpoint("/v1/traces"),
        vec![backend.trust_anchor_pem().to_vec()],
    );
    let client = configuration.client();

    let mut request = export_request(&backend.endpoint("/v1/traces"));
    // An ambient header the exporter or its environment might have added.
    request
        .headers_mut()
        .insert("x-ambient", "sentinel-ambient-value".parse().unwrap());

    let response = client.send_bytes(request).await.expect("export succeeds");
    assert_eq!(response.status(), 200);

    let observed = backend.observed();
    assert_eq!(observed.len(), 1);
    assert!(
        observed[0].header("x-ambient").is_none(),
        "an ambient header must not reach the telemetry backend"
    );
    assert_eq!(
        observed[0].header("content-type"),
        Some("application/x-protobuf"),
        "protocol framing headers are preserved"
    );

    backend.shutdown().await;
}

// ---------------------------------------------------------------------------
// Trace configuration comes only from the configuration document
// ---------------------------------------------------------------------------

/// The OpenTelemetry environment variables the SDK would otherwise consume.
///
/// `Resource::builder()` runs detectors for the first two,
/// `TracerProviderBuilder`'s default configuration reads the sampler pair, and
/// the same default reads the three span-limit variables. Every value here is
/// deliberately hostile: a foreign service identity, an injected resource
/// attribute, sampling turned off, and span limits reduced to one.
const AMBIENT_OTEL_ENVIRONMENT: [(&str, &str); 7] = [
    ("OTEL_SERVICE_NAME", "sentinel-ambient-service"),
    (
        "OTEL_RESOURCE_ATTRIBUTES",
        "sentinel.key=sentinel-ambient-attribute,service.namespace=sentinel-ambient-namespace",
    ),
    ("OTEL_TRACES_SAMPLER", "always_off"),
    ("OTEL_TRACES_SAMPLER_ARG", "0.0"),
    ("OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT", "1"),
    ("OTEL_SPAN_EVENT_COUNT_LIMIT", "1"),
    ("OTEL_SPAN_LINK_COUNT_LIMIT", "1"),
];

/// The distinctive parts of [`AMBIENT_OTEL_ENVIRONMENT`] that must never appear
/// in the trace configuration.
const AMBIENT_SENTINELS: [&str; 4] = [
    "sentinel-ambient-service",
    "sentinel-ambient-attribute",
    "sentinel-ambient-namespace",
    "sentinel.key",
];

/// Marks the re-executed child of the ambient-environment test.
const AMBIENT_ENVIRONMENT_CHILD: &str = "PERMISSIONSYNC_TEST_AMBIENT_OTEL_CHILD";

/// Asserts that a built provider's configuration is exactly the fixed
/// PermissionSync configuration.
///
/// The provider renders its own sampler, span limits, and resource, so this
/// inspects what the SDK will actually apply rather than what the builder was
/// asked for.
async fn assert_trace_configuration_is_exactly_pinned() {
    let configuration = TracingConfiguration::new(
        "https://otlp.example.test/v1/traces".to_owned(),
        Duration::from_secs(5),
        BTreeMap::new(),
        Vec::new(),
    )
    .expect("a valid enabled tracing configuration");
    let provider = build_tracer_provider(&configuration).expect("the provider builds locally");
    // The provider renders the configuration the SDK will actually apply.
    let rendered = format!("{provider:?}");
    // Shut it down through the production path rather than dropping it: an
    // un-shut-down provider's own `Drop` blocks the calling thread waiting for
    // its batch worker to answer, which on a current-thread runtime is the very
    // thread that worker needs.
    shutdown_tracer_provider(provider, Duration::from_secs(10)).await;

    // The SDK default behaviour, stated explicitly so `OTEL_TRACES_SAMPLER`
    // cannot replace it.
    assert!(
        rendered.contains("sampler: ParentBased(AlwaysOn)"),
        "unexpected sampler in {rendered}"
    );

    for (field, expected) in [
        ("max_attributes_per_span", MAX_SPAN_ATTRIBUTES),
        ("max_events_per_span", MAX_SPAN_EVENTS),
        ("max_links_per_span", MAX_SPAN_LINKS),
        ("max_attributes_per_event", MAX_ATTRIBUTES_PER_SPAN_EVENT),
        ("max_attributes_per_link", MAX_ATTRIBUTES_PER_SPAN_LINK),
    ] {
        assert!(expected > 0, "{field} must be a finite positive limit");
        assert!(
            rendered.contains(&format!("{field}: {expected}")),
            "{field} must be exactly {expected} in {rendered}"
        );
    }

    // The exported resource is exactly the fixed service name plus the SDK's own
    // fixed telemetry identity, and nothing else.
    let attributes = rendered
        .split_once("attrs: {")
        .and_then(|(_, rest)| rest.split_once('}'))
        .map(|(attributes, _)| attributes)
        .expect("the rendered provider names its resource attributes");
    for expected in [
        "\"service.name\"",
        "\"telemetry.sdk.name\"",
        "\"telemetry.sdk.language\"",
        "\"telemetry.sdk.version\"",
    ] {
        assert!(
            attributes.contains(expected),
            "{expected} must be a resource attribute in {attributes}"
        );
    }
    assert_eq!(
        attributes.matches("): ").count(),
        4,
        "the resource must carry exactly the four fixed attributes: {attributes}"
    );
    assert!(
        rendered.contains("\"service.name\"): String(Static(\"permissionsync\"))"),
        "the service name must be the fixed package name in {rendered}"
    );

    // No distinctive ambient value may appear anywhere. The numeric ambient
    // values are not checked as substrings, because digits occur throughout the
    // rendering; their effect is excluded by the exact sampler and span-limit
    // assertions above, and by this one.
    for sentinel in AMBIENT_SENTINELS {
        assert!(
            !rendered.contains(sentinel),
            "the ambient environment leaked {sentinel} into the trace configuration: {rendered}"
        );
    }
    assert!(
        !rendered.contains("AlwaysOff"),
        "OTEL_TRACES_SAMPLER must not be able to disable sampling: {rendered}"
    );
}

/// The trace configuration the runtime applies is exactly the fixed
/// PermissionSync configuration.
#[tokio::test]
async fn the_trace_configuration_is_exactly_pinned() {
    assert_trace_configuration_is_exactly_pinned().await;
}

/// Ambient OpenTelemetry environment variables cannot change any of it.
///
/// ADR 0011 defines one configuration source and rejects environment-value
/// overrides, but the SDK's own defaults read `OTEL_SERVICE_NAME`,
/// `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG`,
/// and the `OTEL_SPAN_*_COUNT_LIMIT` variables.
///
/// The hostile environment is applied to a re-executed child process rather than
/// to this one. Setting variables on a child requires no `unsafe`, which this
/// crate forbids, and mutates nothing that this or any concurrent test can
/// observe, so the test stays hermetic.
#[tokio::test]
async fn ambient_opentelemetry_environment_cannot_change_the_trace_configuration() {
    if std::env::var_os(AMBIENT_ENVIRONMENT_CHILD).is_some() {
        // The re-executed child, running with every hostile value set.
        assert_trace_configuration_is_exactly_pinned().await;
        return;
    }

    let status = std::process::Command::new(
        std::env::current_exe().expect("the running test binary has a path"),
    )
    .args([
        "--exact",
        "--nocapture",
        "runtime::tests::trace_context::ambient_opentelemetry_environment_cannot_change_the_trace_configuration",
    ])
    .env(AMBIENT_ENVIRONMENT_CHILD, "1")
    .envs(AMBIENT_OTEL_ENVIRONMENT)
    .status()
    .expect("the test binary must be re-executable");

    assert!(
        status.success(),
        "the trace configuration changed under ambient OpenTelemetry environment variables"
    );
}

/// The batch values stay the fixed product values too, so no `OTEL_BSP_*`
/// variable can widen the queue, the batch, or the export fan-out.
#[test]
fn the_batch_configuration_is_bounded_and_explicit() {
    const { assert!(BOUNDED_SPAN_QUEUE > 0) };
    const { assert!(BOUNDED_EXPORT_BATCH > 0 && BOUNDED_EXPORT_BATCH <= BOUNDED_SPAN_QUEUE) };
    const { assert!(BOUNDED_CONCURRENT_EXPORTS == 1) };
}

// ---------------------------------------------------------------------------
// The batch-export path
// ---------------------------------------------------------------------------

/// The decisive batch-export regression: a span emitted through the configured
/// tracer provider must actually reach the configured local OTLP endpoint while
/// running under Tokio.
///
/// This exercises the real span processor and exporter, not the HTTP client on
/// its own. It is what proves the Tokio-runtime batch span processor is in use:
/// the SDK's default thread-based processor exports from a plain thread with no
/// reactor, so it cannot drive the origin-pinned asynchronous Hyper client at
/// all and no request would arrive here.
#[tokio::test]
async fn an_emitted_span_reaches_the_configured_endpoint_through_the_batch_processor() {
    let backend = HttpsFixture::start(vec![ScriptedResponse::empty(200)]).await;
    let configuration = tracing_configuration(
        &backend.endpoint("/v1/traces"),
        vec![backend.trust_anchor_pem().to_vec()],
    );
    let provider = build_tracer_provider(&configuration).expect("the provider builds locally");

    emit_one_span(&provider);

    // Shutting the provider down is the flush: it exports everything still
    // queued, bounded.
    shutdown_tracer_provider(provider, Duration::from_secs(10)).await;

    assert_eq!(
        backend.request_count(),
        1,
        "the batch processor must export the emitted span to the configured endpoint"
    );
    let observed = backend.observed();
    assert!(
        observed[0]
            .request_line
            .starts_with("POST /v1/traces HTTP/1.1"),
        "unexpected export request line: {}",
        observed[0].request_line
    );
    assert_eq!(
        observed[0].header("content-type"),
        Some("application/x-protobuf"),
        "OTLP/HTTP protobuf encoding must be used"
    );
    assert_eq!(
        observed[0].header("authorization"),
        Some(EXPORTER_CREDENTIAL),
        "the configured exporter credential must reach the configured endpoint"
    );
    assert!(
        !observed[0].body.is_empty(),
        "an exported batch must carry a protobuf payload"
    );

    backend.shutdown().await;
}

/// A batch export must not reach any other origin, even when a span really was
/// emitted: origin pinning applies to the exporter's own requests, not only to
/// requests a test aims by hand.
#[tokio::test]
async fn a_batch_export_never_reaches_another_origin() {
    let configured = HttpsFixture::start(vec![ScriptedResponse::empty(200)]).await;
    let foreign = HttpsFixture::start(vec![ScriptedResponse::empty(200)]).await;
    // Trust only the foreign backend's root, so the configured endpoint cannot
    // be exported to either; neither backend may see a credential.
    let configuration = tracing_configuration(
        &configured.endpoint("/v1/traces"),
        vec![foreign.trust_anchor_pem().to_vec()],
    );
    let provider = build_tracer_provider(&configuration).expect("the provider builds locally");

    emit_one_span(&provider);
    shutdown_tracer_provider(provider, Duration::from_secs(10)).await;

    assert_eq!(
        foreign.request_count(),
        0,
        "no export may reach a non-configured origin"
    );

    configured.shutdown().await;
    foreign.shutdown().await;
}

// ---------------------------------------------------------------------------
// OTLP failure isolation
// ---------------------------------------------------------------------------

/// An unreachable telemetry backend must not affect a synchronization response
/// or readiness.
#[tokio::test]
async fn an_unreachable_telemetry_backend_affects_neither_requests_nor_readiness() {
    let unreachable = RefusingEndpoint::start().await;
    let configuration = tracing_configuration(&unreachable.endpoint("/v1/traces"), Vec::new());

    // The exporter transport itself fails, which is the outage being simulated.
    assert!(
        configuration
            .client()
            .send_bytes(export_request(&unreachable.endpoint("/v1/traces")))
            .await
            .is_err(),
        "the simulated backend must be unavailable"
    );

    let scenario = Scenario::build(|options| {
        options.glpi = Some(glpi_configuration(UNREACHABLE_GLPI));
        options.targets = vec![target("glpi", GLPI)];
    })
    .await;

    // Readiness is unaffected.
    assert_eq!(
        scenario
            .fixture
            .get(crate::runtime::transport::READINESS_ROUTE)
            .await
            .status(),
        StatusCode::OK
    );

    // Synchronization outcomes are unaffected.
    let targetless = scenario.signing.token(Some("service_account"));
    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&targetless), Body::from(valid_body()))
            .await,
        StatusCode::NO_CONTENT
    );
    let selected = scenario.signing.token(Some("permissionsync:glpi"));
    assert_eq!(
        scenario
            .fixture
            .synchronize(Some(&selected), Body::from(valid_body()))
            .await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        scenario.fixture.state.capacity().available_permits(),
        RuntimeFixtureOptions::default()
            .synchronization_capacity
            .get(),
        "telemetry never consumes selected-target capacity"
    );

    scenario.finish().await;
}

/// A failing backend must not produce repeated attempts for one export: the
/// exporter is configured with retries disabled.
#[tokio::test]
async fn a_failing_export_is_attempted_once() {
    let backend = HttpsFixture::start(vec![
        ScriptedResponse::empty(500),
        ScriptedResponse::empty(500),
        ScriptedResponse::empty(500),
    ])
    .await;
    let configuration = tracing_configuration(
        &backend.endpoint("/v1/traces"),
        vec![backend.trust_anchor_pem().to_vec()],
    );

    let response = configuration
        .client()
        .send_bytes(export_request(&backend.endpoint("/v1/traces")))
        .await
        .expect("the transport returns the response, including error statuses");

    assert_eq!(response.status(), 500);
    assert_eq!(
        backend.request_count(),
        1,
        "the transport makes exactly one attempt per export"
    );

    backend.shutdown().await;
}
