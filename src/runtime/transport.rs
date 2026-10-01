//! The Axum transport adapter and the operational endpoints.
//!
//! This module is only a transport adapter. It preserves header multiplicity,
//! starts the one absolute request deadline, takes inbound admission, collects
//! a bounded body, builds one `SynchronizationContext`, invokes the existing
//! `InboundHttpHandler`, and maps its `HttpOutcome` to that outcome's status
//! with an empty response body. It contains no authentication, authorization,
//! scope, routing, Provider, Adapter, or reconciliation policy.
//!
//! # Stage order for `POST /api/sync-user`
//!
//! 1. The absolute deadline starts here, at transport acceptance.
//! 2. Request headers are copied with their multiplicity intact.
//! 3. Inbound admission is taken, bounded by that same deadline.
//! 4. Only then is the body collected, bounded by the fixed product limit and
//!    by that same deadline.
//! 5. The existing inbound boundary owns everything after that.
//!
//! # Requests that cannot enter the bounded admission population
//!
//! A request that can neither be admitted nor take one of the bounded waiter
//! slots has no PermissionSync outcome: it was not cancelled, it did not expire,
//! and it was never processed. Manufacturing any existing outcome for it would
//! change the precedence ADR 0001 fixes, so this module produces no application
//! response at all. The route returns a placeholder marked with
//! [`ConnectionRefusal`], and [`RefusingService`] turns that marker into a
//! service failure, which makes the connection driver terminate the connection
//! without writing a response. Only the operational endpoints and genuinely
//! processed synchronization requests ever produce an HTTP response.

use std::{
    error::Error,
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, Request, Response, StatusCode, header::CONTENT_TYPE},
    routing::{get, post},
};
use http_body_util::BodyExt;
use hyper::{body::Incoming, service::Service as HyperService};
use hyper_util::service::TowerToHyperService;
use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::PrometheusHandle;
use opentelemetry::propagation::TextMapPropagator;
use opentelemetry_http::HeaderExtractor;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use permissionsync::ComposedApplication;
use permissionsync_auth::{TechnicalCallerAuthenticator, TrustedVerifierState};
use permissionsync_core::{CancellationSignal, SynchronizationContext};
use permissionsync_inbound_http::{
    HeaderField, HeaderList, HttpOutcome, InboundBody, InboundHttpHandler,
};
use tokio::time::{Instant as TokioInstant, timeout_at};
use tracing::{Instrument, Span, field::Empty, info_span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::runtime::{
    admission::{Admission, InboundAdmission},
    capacity::SemaphoreCapacity,
    lifecycle::{Lifecycle, RequestCancellation},
    observability::{
        COMPONENT_AVAILABLE, COMPONENT_LABEL, OUTCOME_LABEL, READY, REQUEST_DURATION_SECONDS,
        REQUEST_STAGE_TOTAL, REQUESTS_TOTAL, STAGE_LABEL,
    },
};

/// The fixed product limit on the inbound synchronization body.
///
/// This is one mebibyte and is deliberately not configurable: there is no
/// unbounded mode and no deployment tuning knob. Exceeding it is a
/// body-validation outcome in ADR 0001 order, never an immediate transport
/// rejection.
pub(crate) const INBOUND_BODY_LIMIT_BYTES: usize = 1_048_576;

/// The synchronization route.
pub(crate) const SYNCHRONIZATION_ROUTE: &str = "/api/sync-user";
/// The liveness route.
pub(crate) const HEALTH_ROUTE: &str = "/healthz";
/// The readiness route.
pub(crate) const READINESS_ROUTE: &str = "/readyz";
/// The Prometheus exposition route.
pub(crate) const METRICS_ROUTE: &str = "/metrics";

/// The Prometheus text exposition media type.
const PROMETHEUS_MEDIA_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The bounded stage a request finished or failed in.
///
/// These are the closed ADR 0006 categories. They are derived from the coarse
/// outcome plus whether admission was obtained, and carry nothing
/// request-specific.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Admission,
    Authentication,
    Authorization,
    Validation,
    Routing,
    Capacity,
    Provider,
    Adapter,
    Deadline,
    Completed,
}

impl Stage {
    const fn label(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::Authentication => "authentication",
            Self::Authorization => "authorization",
            Self::Validation => "validation",
            Self::Routing => "routing",
            Self::Capacity => "capacity",
            Self::Provider => "provider",
            Self::Adapter => "adapter",
            Self::Deadline => "deadline",
            Self::Completed => "completed",
        }
    }

    /// Maps a coarse outcome onto the stage it resolved in.
    const fn of(outcome: HttpOutcome) -> Self {
        match outcome {
            HttpOutcome::Changed | HttpOutcome::TargetlessNoop | HttpOutcome::Unchanged => {
                Self::Completed
            }
            HttpOutcome::InvalidRequest => Self::Validation,
            HttpOutcome::UnknownTarget | HttpOutcome::TargetUnavailable => Self::Routing,
            HttpOutcome::AuthenticationRejected | HttpOutcome::VerifierUnavailable => {
                Self::Authentication
            }
            HttpOutcome::AuthorizationForbidden => Self::Authorization,
            HttpOutcome::CapacityUnavailable => Self::Capacity,
            HttpOutcome::ProviderFailed => Self::Provider,
            HttpOutcome::AdapterFailed => Self::Adapter,
            HttpOutcome::CancelledOrExpired => Self::Deadline,
        }
    }
}

/// The closed set of coarse outcome labels.
const fn outcome_label(outcome: HttpOutcome) -> &'static str {
    match outcome {
        HttpOutcome::Changed => "changed",
        HttpOutcome::TargetlessNoop => "targetless_noop",
        HttpOutcome::Unchanged => "unchanged",
        HttpOutcome::InvalidRequest => "invalid_request",
        HttpOutcome::UnknownTarget => "unknown_target",
        HttpOutcome::AuthenticationRejected => "authentication_rejected",
        HttpOutcome::AuthorizationForbidden => "authorization_forbidden",
        HttpOutcome::VerifierUnavailable => "verifier_unavailable",
        HttpOutcome::CancelledOrExpired => "cancelled_or_expired",
        HttpOutcome::TargetUnavailable => "target_unavailable",
        HttpOutcome::CapacityUnavailable => "capacity_unavailable",
        HttpOutcome::ProviderFailed => "provider_failed",
        HttpOutcome::AdapterFailed => "adapter_failed",
    }
}

/// The composed, process-wide state the transport borrows per request.
pub(crate) struct RuntimeState {
    application: ComposedApplication,
    capacity: SemaphoreCapacity,
    authenticator: TechnicalCallerAuthenticator,
    admission: InboundAdmission,
    lifecycle: Arc<Lifecycle>,
    metrics: PrometheusHandle,
    overall_request_deadline: Duration,
    readiness_budget: Duration,
    trace_context: Option<TraceContextPropagator>,
}

impl RuntimeState {
    /// Wires composed application state into the transport.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        application: ComposedApplication,
        capacity: SemaphoreCapacity,
        authenticator: TechnicalCallerAuthenticator,
        admission: InboundAdmission,
        lifecycle: Arc<Lifecycle>,
        metrics: PrometheusHandle,
        overall_request_deadline: Duration,
        readiness_budget: Duration,
        trace_context_enabled: bool,
    ) -> Self {
        Self {
            application,
            capacity,
            authenticator,
            admission,
            lifecycle,
            metrics,
            overall_request_deadline,
            readiness_budget,
            trace_context: trace_context_enabled.then(TraceContextPropagator::new),
        }
    }

    /// Returns the shared lifecycle state.
    pub(crate) fn lifecycle(&self) -> &Arc<Lifecycle> {
        &self.lifecycle
    }

    /// Returns the inbound admission boundary, for deliberate inspection.
    #[cfg(test)]
    pub(crate) fn admission(&self) -> &InboundAdmission {
        &self.admission
    }

    /// Returns the process-wide authenticator.
    pub(crate) fn authenticator(&self) -> &TechnicalCallerAuthenticator {
        &self.authenticator
    }

    /// Returns the bounded readiness and warm-up budget.
    pub(crate) fn readiness_budget(&self) -> Duration {
        self.readiness_budget
    }

    /// Returns the concrete selected-target capacity, for deliberate inspection.
    #[cfg(test)]
    pub(crate) fn capacity(&self) -> &SemaphoreCapacity {
        &self.capacity
    }
}

/// Builds the router for the one configured listener.
///
/// Unsupported paths and methods keep normal framework behavior.
pub(crate) fn router(state: Arc<RuntimeState>) -> Router {
    Router::new()
        .route(SYNCHRONIZATION_ROUTE, post(synchronize))
        .route(HEALTH_ROUTE, get(health))
        .route(READINESS_ROUTE, get(readiness))
        .route(METRICS_ROUTE, get(metrics))
        .with_state(state)
}

/// `POST /api/sync-user`.
async fn synchronize(
    State(state): State<Arc<RuntimeState>>,
    request: Request<Body>,
) -> Response<Body> {
    // The one absolute deadline starts here, at transport acceptance, before
    // admission waiting and before body collection.
    let accepted_at = Instant::now();
    let deadline = accepted_at + state.overall_request_deadline;

    let (parts, body) = request.into_parts();
    let span = info_span!(
        "permissionsync.synchronize",
        route = SYNCHRONIZATION_ROUTE,
        outcome = Empty,
        stage = Empty
    );
    // Inbound trace context is transport metadata only. A malformed value
    // yields an empty context, which simply starts a local root trace; it can
    // never influence authentication, authorization, routing, or the outcome.
    if let Some(propagator) = &state.trace_context {
        // A malformed or absent context simply fails to attach a parent, which
        // starts a local root trace. It is never an error for the request.
        let _ = span.set_parent(propagator.extract(&HeaderExtractor(&parts.headers)));
    }

    handle_synchronization(state, parts.headers, body, accepted_at, deadline)
        .instrument(span)
        .await
}

async fn handle_synchronization(
    state: Arc<RuntimeState>,
    headers: HeaderMap,
    body: Body,
    accepted_at: Instant,
    deadline: Instant,
) -> Response<Body> {
    let cancellation = RequestCancellation::new(state.lifecycle());

    // Admission precedes body collection, so no body is buffered and no
    // authentication is attempted for a request that was not admitted.
    let _admitted = match state.admission.admit(deadline, state.lifecycle()).await {
        Admission::Admitted(admitted) => admitted,
        Admission::NotAdmitted => {
            return finish(
                accepted_at,
                HttpOutcome::CancelledOrExpired,
                Stage::Admission,
            );
        }
        // Neither bounded population had room. This request was never parked,
        // never processed, and neither cancelled nor expired, so it gets no
        // application outcome at all: it is refused at the transport boundary.
        Admission::RefusedWithoutWaiting => return refuse_at_transport(),
    };

    let collected = collect_body(body, deadline, &cancellation).await;
    let owned_headers = owned_header_fields(&headers);
    let fields: Vec<HeaderField<'_>> = owned_headers
        .iter()
        .map(|(name, value)| HeaderField::new(name, value))
        .collect();

    let inbound_body = match &collected {
        CollectedBody::Collected(bytes) => InboundBody::Collected(bytes),
        CollectedBody::BoundExceeded => InboundBody::BoundExceeded,
        // A body that could not be read at all is not a validated request
        // body; an expired or cancelled request keeps the existing
        // server-side deadline semantics.
        CollectedBody::TransportFailure => {
            return finish(accepted_at, HttpOutcome::InvalidRequest, Stage::Validation);
        }
        CollectedBody::Unavailable => {
            return finish(
                accepted_at,
                HttpOutcome::CancelledOrExpired,
                Stage::Deadline,
            );
        }
    };

    let synchronizer = state
        .application
        .selected_target_synchronizer(&state.capacity);
    let handler = InboundHttpHandler::new(&state.authenticator, &synchronizer);
    let outcome = handler
        .handle(
            HeaderList::new(&fields),
            inbound_body,
            SynchronizationContext::new(deadline, &cancellation),
        )
        .await;

    finish(accepted_at, outcome, Stage::of(outcome))
}

/// Records the bounded outcome evidence and produces the contract response.
fn finish(accepted_at: Instant, outcome: HttpOutcome, stage: Stage) -> Response<Body> {
    let outcome_label = outcome_label(outcome);
    let stage_label = stage.label();

    let span = Span::current();
    span.record("outcome", outcome_label);
    span.record("stage", stage_label);

    counter!(REQUESTS_TOTAL, OUTCOME_LABEL => outcome_label).increment(1);
    counter!(REQUEST_STAGE_TOTAL, STAGE_LABEL => stage_label).increment(1);
    histogram!(REQUEST_DURATION_SECONDS, OUTCOME_LABEL => outcome_label)
        .record(accepted_at.elapsed().as_secs_f64());

    empty_response(
        StatusCode::from_u16(outcome.status_code())
            .expect("every HttpOutcome status is a valid HTTP status code"),
    )
}

/// A private marker on the one response that must never reach a caller.
///
/// It exists only to carry the refusal decision from the route to the
/// connection driver. It is never serialized and never observable by a caller.
#[derive(Clone, Copy)]
struct ConnectionRefusal;

/// Refuses a synchronization request at the transport boundary.
///
/// The returned response is a placeholder that [`RefusingService`] converts into
/// a service failure, so nothing is written to the connection. No outcome,
/// stage, duration, or span field is recorded, because no PermissionSync outcome
/// occurred; the refusal is counted by the dedicated admission-refusal metric
/// inside the admission boundary itself.
fn refuse_at_transport() -> Response<Body> {
    let mut response = Response::new(Body::empty());
    response.extensions_mut().insert(ConnectionRefusal);
    response
}

/// Returns whether a response is the transport-refusal placeholder.
#[cfg(test)]
pub(crate) fn is_transport_refusal(response: &Response<Body>) -> bool {
    response.extensions().get::<ConnectionRefusal>().is_some()
}

/// The service failure that terminates a connection without a response.
///
/// It is a fixed category and carries no request, caller, or configuration
/// detail.
#[derive(Debug)]
pub(crate) struct RefusedConnection;

impl fmt::Display for RefusedConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the request was refused at the inbound admission boundary")
    }
}

impl Error for RefusedConnection {}

/// Serves the router, turning an admission refusal into a service failure.
///
/// Hyper writes no response for a failed service call, so this is what makes a
/// beyond-bound synchronization request end as a terminated connection rather
/// than as a manufactured PermissionSync outcome. Every other request, including
/// every operational request, passes through unchanged.
pub(crate) struct RefusingService {
    inner: TowerToHyperService<Router>,
}

impl RefusingService {
    /// Wraps the router for one connection.
    pub(crate) fn new(router: Router) -> Self {
        Self {
            inner: TowerToHyperService::new(router),
        }
    }
}

impl HyperService<Request<Incoming>> for RefusingService {
    type Response = Response<Body>;
    type Error = RefusedConnection;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, RefusedConnection>> + Send>>;

    fn call(&self, request: Request<Incoming>) -> Self::Future {
        let inner = self.inner.call(request);
        Box::pin(async move {
            // The router's own service is infallible; only the refusal marker
            // can make this call fail.
            let response = inner.await.map_err(|_| RefusedConnection)?;
            if response.extensions().get::<ConnectionRefusal>().is_some() {
                return Err(RefusedConnection);
            }
            Ok(response)
        })
    }
}

fn empty_response(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .expect("an empty response body is always valid")
}

/// `GET /healthz`. Liveness of the process and HTTP runtime only.
///
/// It deliberately depends on no authentication metadata source, Provider,
/// GLPI, target, or telemetry backend.
async fn health() -> StatusCode {
    StatusCode::OK
}

/// `GET /readyz`. Ready exactly while the authenticator has usable trusted
/// verifier state.
///
/// Readiness turns false the moment shutdown begins. Otherwise it reflects only
/// the authenticator's own ADR 0002 cache rules, so still-usable cached state
/// stays ready during a temporary metadata outage, and evaluation may initiate
/// at most one bounded refresh when no usable state exists.
///
/// # Why the evaluation is raced against shutdown
///
/// The bounded refresh this may start can be waiting on the trusted metadata
/// source when shutdown begins. Checking the flag once up front would then let a
/// probe that started while the process was still serving answer `200` after
/// shutdown had already begun, because the refresh it was waiting for finally
/// succeeded. ADR 0011 requires readiness to be false from the start of
/// shutdown, so the evaluation is raced against
/// [`Lifecycle::shutdown_started`](crate::runtime::lifecycle::Lifecycle::shutdown_started)
/// with shutdown biased ahead of it: an in-flight probe abandons the refresh and
/// answers `503` instead of waiting for it.
///
/// The request cancellation signal cannot serve this purpose: it is raised only
/// when the shutdown grace period expires, which is deliberately much later.
async fn readiness(State(state): State<Arc<RuntimeState>>) -> StatusCode {
    let cancellation = RequestCancellation::new(state.lifecycle());
    let context =
        SynchronizationContext::new(Instant::now() + state.readiness_budget(), &cancellation);
    let evaluate = state
        .authenticator()
        .ensure_trusted_verifier_state(&context);

    // `shutdown_started` resolves immediately when shutdown already began, so
    // the biased branch also covers the probe that arrives during draining.
    let ready = tokio::select! {
        biased;
        () = state.lifecycle().shutdown_started() => TrustedVerifierState::Unusable,
        ready = evaluate => ready,
    };

    match ready {
        TrustedVerifierState::Usable => {
            gauge!(READY).set(1.0);
            StatusCode::OK
        }
        TrustedVerifierState::Unusable => {
            gauge!(READY).set(0.0);
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

/// `GET /metrics`. The Prometheus text exposition.
async fn metrics(State(state): State<Arc<RuntimeState>>) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, PROMETHEUS_MEDIA_TYPE)
        .body(Body::from(state.metrics.render()))
        .expect("a rendered Prometheus exposition is always a valid response")
}

/// Records which components are usable, once, after composition.
pub(crate) fn record_component_availability(component: &'static str, available: bool) {
    gauge!(COMPONENT_AVAILABLE, COMPONENT_LABEL => component).set(if available {
        1.0
    } else {
        0.0
    });
}

/// Converts received header fields into owned bytes without normalizing them.
///
/// `HeaderMap` iteration yields one entry per received value, so duplicate
/// `Authorization` fields survive to the inbound boundary and can be rejected
/// there as ambiguous rather than being silently reduced to one value. Values
/// are never decoded to text here, and headers are never logged.
fn owned_header_fields(headers: &HeaderMap) -> Vec<(Vec<u8>, Vec<u8>)> {
    headers
        .iter()
        .map(|(name, value)| (name.as_str().as_bytes().to_vec(), value.as_bytes().to_vec()))
        .collect()
}

/// The result of bounded body collection.
enum CollectedBody {
    /// The complete body, within the fixed product limit.
    Collected(Vec<u8>),
    /// The fixed product limit was exceeded; accumulation stopped there.
    BoundExceeded,
    /// The body could not be read from the transport.
    TransportFailure,
    /// The request deadline expired or cancellation was observed.
    Unavailable,
}

/// Collects the request body, bounded by the fixed product limit and by the one
/// absolute request deadline.
///
/// Accumulation stops as soon as the limit would be exceeded, so buffering never
/// exceeds the bound regardless of `Content-Length`, chunked framing, or a
/// misleading declared length. Exactly the limit is permitted.
async fn collect_body(
    body: Body,
    deadline: Instant,
    cancellation: &dyn CancellationSignal,
) -> CollectedBody {
    let mut body = body;
    let mut collected: Vec<u8> = Vec::new();

    loop {
        if cancellation.is_cancelled() || Instant::now() >= deadline {
            return CollectedBody::Unavailable;
        }
        let frame = match timeout_at(TokioInstant::from_std(deadline), body.frame()).await {
            Err(_) => return CollectedBody::Unavailable,
            Ok(None) => break,
            Ok(Some(Err(_))) => return CollectedBody::TransportFailure,
            Ok(Some(Ok(frame))) => frame,
        };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let received = collected.len().saturating_add(data.len());
        if received > INBOUND_BODY_LIMIT_BYTES {
            return CollectedBody::BoundExceeded;
        }
        // Grow geometrically, but never past the fixed bound, so the allocation
        // itself also stays within the limit. Growing by exactly one frame
        // instead would re-allocate once per received frame, which a body split
        // into very many tiny frames could turn into quadratic copying; this
        // keeps accumulation linear in the bytes actually received.
        if received > collected.capacity() {
            let target = collected
                .capacity()
                .saturating_mul(2)
                .max(received)
                .min(INBOUND_BODY_LIMIT_BYTES);
            collected.reserve_exact(target - collected.len());
        }
        collected.extend_from_slice(&data);
    }

    CollectedBody::Collected(collected)
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
    use permissionsync_inbound_http::HttpOutcome;

    use super::{INBOUND_BODY_LIMIT_BYTES, Stage, outcome_label, owned_header_fields};

    const EVERY_OUTCOME: [HttpOutcome; 13] = [
        HttpOutcome::Changed,
        HttpOutcome::TargetlessNoop,
        HttpOutcome::Unchanged,
        HttpOutcome::InvalidRequest,
        HttpOutcome::UnknownTarget,
        HttpOutcome::AuthenticationRejected,
        HttpOutcome::AuthorizationForbidden,
        HttpOutcome::VerifierUnavailable,
        HttpOutcome::CancelledOrExpired,
        HttpOutcome::TargetUnavailable,
        HttpOutcome::CapacityUnavailable,
        HttpOutcome::ProviderFailed,
        HttpOutcome::AdapterFailed,
    ];

    #[test]
    fn the_inbound_body_limit_is_exactly_one_mebibyte() {
        assert_eq!(INBOUND_BODY_LIMIT_BYTES, 1024 * 1024);
    }

    /// Labels must be a closed, low-cardinality set of compile-time constants.
    #[test]
    fn outcome_and_stage_labels_are_closed_and_bounded() {
        let mut outcomes: Vec<&str> = EVERY_OUTCOME.iter().copied().map(outcome_label).collect();
        outcomes.sort_unstable();
        outcomes.dedup();
        assert_eq!(outcomes.len(), EVERY_OUTCOME.len());

        let mut stages: Vec<&str> = EVERY_OUTCOME
            .iter()
            .copied()
            .map(|outcome| Stage::of(outcome).label())
            .collect();
        stages.sort_unstable();
        stages.dedup();
        assert!(
            stages.len() <= 10,
            "stage labels must stay a small closed set"
        );

        for label in outcomes.iter().chain(stages.iter()) {
            assert!(
                label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
                "{label} is not a fixed snake_case constant"
            );
        }
    }

    #[test]
    fn every_outcome_maps_to_its_owning_stage() {
        assert_eq!(Stage::of(HttpOutcome::Changed), Stage::Completed);
        assert_eq!(Stage::of(HttpOutcome::TargetlessNoop), Stage::Completed);
        assert_eq!(Stage::of(HttpOutcome::Unchanged), Stage::Completed);
        assert_eq!(Stage::of(HttpOutcome::InvalidRequest), Stage::Validation);
        assert_eq!(Stage::of(HttpOutcome::UnknownTarget), Stage::Routing);
        assert_eq!(Stage::of(HttpOutcome::TargetUnavailable), Stage::Routing);
        assert_eq!(
            Stage::of(HttpOutcome::AuthenticationRejected),
            Stage::Authentication
        );
        assert_eq!(
            Stage::of(HttpOutcome::VerifierUnavailable),
            Stage::Authentication
        );
        assert_eq!(
            Stage::of(HttpOutcome::AuthorizationForbidden),
            Stage::Authorization
        );
        assert_eq!(Stage::of(HttpOutcome::CapacityUnavailable), Stage::Capacity);
        assert_eq!(Stage::of(HttpOutcome::ProviderFailed), Stage::Provider);
        assert_eq!(Stage::of(HttpOutcome::AdapterFailed), Stage::Adapter);
        assert_eq!(Stage::of(HttpOutcome::CancelledOrExpired), Stage::Deadline);
    }

    /// Axum must not be allowed to collapse duplicate credentials: the inbound
    /// boundary needs both values to reject the ambiguity itself.
    #[test]
    fn duplicate_authorization_fields_survive_header_conversion() {
        let mut headers = HeaderMap::new();
        headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer first"));
        headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer second"));

        let owned = owned_header_fields(&headers);
        let authorization: Vec<&[u8]> = owned
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(b"authorization"))
            .map(|(_, value)| value.as_slice())
            .collect();

        assert_eq!(
            authorization,
            [b"Bearer first".as_slice(), b"Bearer second".as_slice()]
        );
    }

    #[test]
    fn header_conversion_preserves_exact_value_bytes() {
        let mut headers = HeaderMap::new();
        headers.append(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer   token.with.dots"),
        );
        headers.append("x-other", HeaderValue::from_static("kept"));

        let owned = owned_header_fields(&headers);
        assert!(
            owned
                .iter()
                .any(|(name, value)| name == b"authorization"
                    && value == b"Bearer   token.with.dots")
        );
        assert!(
            owned
                .iter()
                .any(|(name, value)| name == b"x-other" && value == b"kept")
        );
    }
}
