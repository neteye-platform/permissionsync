//! The executable PermissionSync runtime.
//!
//! These modules are private to the binary on purpose. The root library owns
//! semantic configuration and deterministic composition without selecting a
//! delivery format or a startup mechanism; everything here is the executable's
//! own concern: configuration delivery, HTTP transport, inbound admission,
//! concrete synchronization capacity, operational lifecycle, and observability.
//!
//! Business semantics stay in the existing components. Nothing here
//! re-implements authentication, scope processing, body validation, routing,
//! Provider work, or reconciliation.

pub(crate) mod admission;
pub(crate) mod capacity;
pub(crate) mod configuration;
pub(crate) mod failure;
pub(crate) mod lifecycle;
pub(crate) mod observability;
pub(crate) mod otlp;
pub(crate) mod transport;

#[cfg(test)]
mod tests;

use std::{
    io::{self, ErrorKind},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::Router;
use hyper_util::rt::{TokioIo, TokioTimer};
use permissionsync::{
    ComposedApplication, GLPI_ADAPTER_IDENTIFIER, ProviderAvailability, TargetAvailability,
};
use permissionsync_auth::TechnicalCallerAuthenticator;
use permissionsync_core::{LogicalTarget, SynchronizationContext};
use tokio::{
    net::{TcpListener, TcpStream},
    signal::unix::{Signal, SignalKind, signal},
    sync::oneshot,
    task::JoinSet,
    time::{sleep, timeout},
};
use tracing::{info, warn};

use crate::runtime::{
    admission::InboundAdmission,
    capacity::SemaphoreCapacity,
    configuration::{ComponentOutcome, ExecutableConfiguration},
    failure::RuntimeFailure,
    lifecycle::{Lifecycle, RequestCancellation},
    transport::{RefusingService, RuntimeState, record_component_availability, router},
};

/// The bounded window in which cooperatively cancelled requests may return
/// after the configured grace period expired, before remaining owned tasks are
/// terminated.
///
/// Shutdown stays bounded overall: grace period, then this window, then
/// termination. It is a fixed product value, not a deployment knob.
const CANCELLED_REQUEST_WINDOW: Duration = Duration::from_secs(1);

/// The bounded budget for the final trace-provider flush.
///
/// A backend that is still unavailable loses final telemetry rather than
/// extending shutdown.
const TRACE_FLUSH_BUDGET: Duration = Duration::from_secs(2);

/// Consecutive listener-accept failures tolerated before the process stops
/// serving, so a permanently broken listener cannot become a hot loop.
///
/// Only failures classified as [`AcceptFailure::ListenerUnusable`] advance this
/// count: a per-connection, network, or resource-pressure failure leaves the
/// listener healthy and must not push the process toward shutdown.
const MAX_CONSECUTIVE_ACCEPT_FAILURES: u32 = 16;

/// The fixed pause applied after a listener-accept failure caused by local
/// resource pressure.
///
/// It exists only so exhaustion cannot become a hot accept loop. It is
/// deliberately short, because the listener is still healthy and the condition
/// is usually transient, and it is always interruptible by shutdown.
const ACCEPT_RESOURCE_PRESSURE_BACKOFF: Duration = Duration::from_millis(100);

/// The bounded window in which a client must deliver one complete request head.
///
/// Hyper's HTTP/1 server carries a default header-read timeout, but it only
/// takes effect when a timer is configured, so the runtime configures both and
/// states the value itself instead of inheriting a library default that is not
/// part of PermissionSync's own contract. Hyper re-arms the bound for every
/// request head on a connection, so it covers an incomplete initial head and an
/// idle keep-alive connection waiting for the next request alike.
///
/// It is a fixed product safety value, not a deployment knob, and it is
/// unrelated to the configured overall request deadline, which ADR 0011 starts
/// only once a synchronization request has reached the transport handler.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Runs the executable runtime to completion.
///
/// Startup order follows ADR 0011: resolve and read the single configuration
/// file, validate global and static values, construct the authenticator,
/// project semantic configuration and compose, construct admission and
/// capacity, initialize required observability, wire orchestration and inbound
/// handling, build the transport, bind the listener, begin serving, and only
/// then allow bounded verifier warm-up.
///
/// Reading and validating configuration happens before the asynchronous runtime
/// exists, so a global defect aborts before any listener, task, or telemetry
/// channel is created.
pub(crate) fn run() -> Result<(), RuntimeFailure> {
    let path = configuration::configuration_path()?;
    let configuration = configuration::load(Path::new(&path))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| RuntimeFailure::RuntimeUnavailable)?;

    runtime.block_on(serve_configured(configuration))
}

async fn serve_configured(configuration: ExecutableConfiguration) -> Result<(), RuntimeFailure> {
    let ExecutableConfiguration {
        listener: listen_address,
        overall_request_deadline,
        inbound_admission_limit,
        synchronization_capacity,
        shutdown_grace,
        authentication,
        metadata_operation_timeout,
        observability: observability_configuration,
        runtime: semantic_configuration,
        provider_outcome,
        glpi_outcome,
    } = configuration;

    // Construction performs no remote connectivity check: unreachable JWKS or
    // discovery must not prevent startup.
    let authenticator = TechnicalCallerAuthenticator::new(authentication);

    let glpi_routes: Vec<String> = semantic_configuration
        .targets
        .iter()
        .filter(|target| target.adapter_identifier == GLPI_ADAPTER_IDENTIFIER)
        .map(|target| target.logical_target.clone())
        .collect();

    let application = ComposedApplication::compose(semantic_configuration)
        .map_err(|_| RuntimeFailure::InvalidComposition)?;

    // Configuration validation already proved every derived semaphore size, so
    // neither constructor can reach a panicking semaphore; both still report
    // rather than assume it.
    let admission =
        InboundAdmission::new(inbound_admission_limit).ok_or(RuntimeFailure::InvalidRequest)?;
    let capacity =
        SemaphoreCapacity::new(synchronization_capacity).ok_or(RuntimeFailure::InvalidRequest)?;

    let observability = observability::initialize(&observability_configuration)?;
    report_component_availability(&application, provider_outcome, glpi_outcome, &glpi_routes);

    let lifecycle = Arc::new(Lifecycle::new());
    let state = Arc::new(RuntimeState::new(
        application,
        capacity,
        authenticator,
        admission,
        Arc::clone(&lifecycle),
        observability.metrics(),
        overall_request_deadline,
        metadata_operation_timeout,
        observability.tracing_enabled(),
    ));
    let router = router(Arc::clone(&state));

    let result = bind_and_serve(
        listen_address,
        router,
        &state,
        lifecycle,
        shutdown_grace,
        metadata_operation_timeout,
        observability.tracing_enabled(),
    )
    .await;

    // The bounded trace flush runs on every exit path, including a listener
    // that could not be bound, so the exporter is always asked to stop. The
    // budget is what keeps that request from extending shutdown.
    observability.shutdown_tracing(TRACE_FLUSH_BUDGET).await;

    result
}

/// Binds the configured listener, begins serving, and then allows bounded
/// verifier warm-up.
async fn bind_and_serve(
    listen_address: std::net::SocketAddr,
    router: Router,
    state: &Arc<RuntimeState>,
    lifecycle: Arc<Lifecycle>,
    shutdown_grace: Duration,
    metadata_operation_timeout: Duration,
    tracing_enabled: bool,
) -> Result<(), RuntimeFailure> {
    let listener = TcpListener::bind(listen_address)
        .await
        .map_err(|_| RuntimeFailure::ListenerUnavailable)?;

    // ADR 0011 makes `SIGTERM` and `SIGINT` handling mandatory on Linux, so
    // both handlers are installed before anything is served. A process that
    // could not install them cannot shut down gracefully, and serving requests
    // it could only ever terminate abruptly would be worse than refusing to
    // start.
    let signals = register_termination_signals()?;

    info!(
        target: "permissionsync::runtime",
        tracing_export = tracing_enabled,
        "permissionsync bound its listener and is serving"
    );

    // The warm-up task's first action is to await this signal, which `serve`
    // sends immediately before its first accept. That is a happens-before
    // relation rather than a scheduling assumption: no metadata retrieval can
    // precede serving, whichever worker the task starts on. Warm-up stays
    // bounded, asynchronous, and non-gating.
    let (serving_started, serving_has_started) = oneshot::channel();
    let warm_up = spawn_verifier_warm_up(state, metadata_operation_timeout, serving_has_started);
    let signals = tokio::spawn(signal_shutdown(signals, Arc::clone(&lifecycle)));

    let served = serve(
        listener,
        router,
        Arc::clone(&lifecycle),
        shutdown_grace,
        serving_started,
    )
    .await;

    // Both auxiliary tasks are owned, so neither is detached at exit.
    signals.abort();
    let _ = signals.await;
    warm_up.abort();
    let _ = warm_up.await;

    served
}

/// Reports which optional components are usable, using bounded labels only.
fn report_component_availability(
    application: &ComposedApplication,
    provider_outcome: ComponentOutcome,
    glpi_outcome: ComponentOutcome,
    glpi_routes: &[String],
) {
    let provider_usable = matches!(application.provider(), ProviderAvailability::Usable(_));
    record_component_availability("provider", provider_usable);
    match provider_outcome {
        ComponentOutcome::Configured if provider_usable => {}
        ComponentOutcome::Configured => warn!(
            target: "permissionsync::runtime",
            component = "provider",
            "configured component could not produce a usable instance; selected-target \
             synchronization will fail server-side"
        ),
        ComponentOutcome::Invalid => warn!(
            target: "permissionsync::runtime",
            component = "provider",
            "component configuration was present but unusable; the component is unavailable"
        ),
        ComponentOutcome::Absent => info!(
            target: "permissionsync::runtime",
            component = "provider",
            "component is not configured and is therefore unavailable"
        ),
    }

    // GLPI is process-wide: every configured route selecting it stays
    // recognized, and is usable only when the one instance was constructed.
    let glpi_usable = glpi_routes.first().is_some_and(|route| {
        LogicalTarget::try_from(route.clone()).is_ok_and(|target| {
            matches!(
                application.resolve_target(&target),
                TargetAvailability::Usable(_)
            )
        })
    });
    record_component_availability("glpi", glpi_usable);
    match glpi_outcome {
        ComponentOutcome::Configured if glpi_usable || glpi_routes.is_empty() => {}
        ComponentOutcome::Configured => warn!(
            target: "permissionsync::runtime",
            component = "glpi",
            "configured component could not produce a usable instance; configured routes \
             selecting it stay recognized and unavailable"
        ),
        ComponentOutcome::Invalid => warn!(
            target: "permissionsync::runtime",
            component = "glpi",
            "component configuration was present but unusable; configured routes selecting it \
             stay recognized and unavailable"
        ),
        ComponentOutcome::Absent => info!(
            target: "permissionsync::runtime",
            component = "glpi",
            "component is not configured and is therefore unavailable"
        ),
    }
}

/// Starts the single bounded, non-gating verifier warm-up.
///
/// The task waits for `serving_has_started` before anything else, so it cannot
/// consult the trusted metadata source before serving has begun. A dropped
/// sender means serving never started, and then warm-up performs no work at
/// all. The bounded budget is measured from the moment serving started, not
/// from when the task was spawned.
fn spawn_verifier_warm_up(
    state: &Arc<RuntimeState>,
    budget: Duration,
    serving_has_started: oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    let authenticator = state.authenticator().clone();
    let lifecycle = Arc::clone(state.lifecycle());
    tokio::spawn(async move {
        if serving_has_started.await.is_err() {
            return;
        }

        let cancellation = RequestCancellation::new(&lifecycle);
        let context = SynchronizationContext::new(Instant::now() + budget, &cancellation);
        // The outcome is deliberately ignored: warm-up never gates serving,
        // and readiness is evaluated independently on every probe.
        let _ = authenticator.ensure_trusted_verifier_state(&context).await;
    })
}

/// Accepts and serves connections until shutdown, then terminates in bounded
/// phases.
///
/// Connections are not gated behind an application semaphore. Bounding them
/// that way could not reserve a share for operational endpoints, because a
/// request's class is only known after its head has been read, so a saturated
/// synchronization workload could occupy every slot and hide `/healthz`,
/// `/readyz`, and `/metrics` behind accept backpressure. What ADR 0011 requires
/// bounded — admitted synchronization requests, aggregate body buffering, and
/// application-owned waiter state — is bounded by
/// [`InboundAdmission`](crate::runtime::admission::InboundAdmission) instead,
/// which no operational request touches.
///
/// Every connection task is owned by the local [`JoinSet`] and finished tasks
/// are reaped each iteration, so nothing is detached and the owned set tracks
/// only live connections.
///
/// The *number* of simultaneously accepted connections is deliberately not
/// bounded here. ADR 0011 bounds the application-owned populations — admitted
/// synchronization requests, admission waiters, aggregate body buffering, and
/// selected-target capacity — and requires the operational endpoints to stay
/// reachable under synchronization saturation, which a bound taken at accept time
/// cannot preserve: a connection's route is unknown until its first request head
/// has been read, so no share can be reserved for a class of request that has not
/// been identified yet. What limits the accepted population is therefore the
/// descriptor limit of the process together with [`HEADER_READ_TIMEOUT`], and
/// descriptor exhaustion degrades through
/// [`AcceptFailure::ResourcePressure`] rather than through fatal termination.
/// Bounding the population itself needs an architectural decision ADR 0011 does
/// not make, so it is not invented here.
///
/// `serving_started` is signalled once, immediately before the first accept, so
/// anything that must not precede serving can wait on it.
async fn serve(
    listener: TcpListener,
    router: Router,
    lifecycle: Arc<Lifecycle>,
    shutdown_grace: Duration,
    serving_started: oneshot::Sender<()>,
) -> Result<(), RuntimeFailure> {
    let mut connections: JoinSet<()> = JoinSet::new();
    let shutdown_lifecycle = Arc::clone(&lifecycle);
    let mut shutdown = Box::pin(async move { shutdown_lifecycle.shutdown_started().await });
    let mut consecutive_failures = 0_u32;
    // Resource pressure is reported once per episode rather than once per
    // failed accept, so a sustained shortage cannot turn a paced retry into a
    // log flood. A successful accept ends the episode.
    let mut reported_resource_pressure = false;

    // The listener is bound and this loop is about to accept: serving has
    // begun. Anything awaiting this signal therefore cannot run earlier.
    let _ = serving_started.send(());

    loop {
        // Reap finished connections so the owned set stays bounded.
        while connections.try_join_next().is_some() {}

        let accepted = tokio::select! {
            biased;
            () = &mut shutdown => break,
            accepted = listener.accept() => accepted,
            Some(_) = connections.join_next() => continue,
        };

        match accepted {
            Ok((stream, _)) => {
                consecutive_failures = 0;
                reported_resource_pressure = false;
                connections.spawn(serve_connection(
                    stream,
                    router.clone(),
                    Arc::clone(&lifecycle),
                    HEADER_READ_TIMEOUT,
                ));
            }
            Err(error) => match classify_accept_failure(&error) {
                // The listener is healthy: retry at once, and never let a
                // hostile or unlucky client push the process toward shutdown.
                AcceptFailure::Transient => {}
                // Also not a listener defect, so it advances no fatal count.
                // The fixed backoff is what keeps retrying from spinning.
                AcceptFailure::ResourcePressure => {
                    if !reported_resource_pressure {
                        reported_resource_pressure = true;
                        warn!(
                            target: "permissionsync::runtime",
                            reason = "resource_pressure",
                            "the listener cannot accept connections; retrying behind a fixed backoff"
                        );
                    }
                    if accept_backoff(&lifecycle, ACCEPT_RESOURCE_PRESSURE_BACKOFF).await
                        == AcceptBackoff::Stop
                    {
                        break;
                    }
                }
                AcceptFailure::ListenerUnusable => {
                    warn!(
                        target: "permissionsync::runtime",
                        reason = "listener_unusable",
                        "the listener reported a state in which it can no longer accept"
                    );
                    if accept_failure_is_fatal(&mut consecutive_failures) {
                        return Err(terminate_after_fatal_accept_failure(
                            &mut connections,
                            &lifecycle,
                            shutdown_grace,
                        )
                        .await);
                    }
                }
            },
        }
    }

    shut_down_connections(&mut connections, &lifecycle, shutdown_grace).await;
    Ok(())
}

/// The `accept(2)` conditions that need raw `errno` inspection, because `std`
/// exposes no stable [`ErrorKind`] that names them exactly.
///
/// Every value comes from `libc`, which resolves it for the target
/// architecture. ADR 0011 requires Linux but not one specific Linux
/// architecture, and the numbers genuinely differ: `ENOBUFS` is 105 on
/// `asm-generic` targets, 55 on SPARC, and 132 on MIPS, and SPARC's `EHOSTDOWN`
/// is 64, which is `ENONET` on `asm-generic`. Hard-coding integers here would
/// therefore not merely miss a condition on those targets but actively
/// misclassify a different one.
///
/// Every other condition below is classified through `std`'s own portable
/// mapping instead.
mod accept_errno {
    /// Local resource pressure: no descriptor, socket buffer, or memory is
    /// available for a new connection right now.
    pub(super) const RESOURCE_PRESSURE: [i32; 3] = [libc::EMFILE, libc::ENFILE, libc::ENOBUFS];

    /// Errors `accept(2)` documents as already-pending network conditions on the
    /// new connection, to be retried like `EAGAIN`, and that `std` leaves
    /// uncategorized.
    pub(super) const PENDING_NETWORK: [i32; 4] = [
        libc::ENONET,
        libc::EPROTO,
        libc::ENOPROTOOPT,
        libc::EHOSTDOWN,
    ];
}

/// How one `TcpListener::accept()` failure has to be handled.
///
/// The distinction exists because the three categories say different things
/// about the listener, and only one of them is evidence that the listener itself
/// stopped working.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AcceptFailure {
    /// A per-connection or already-pending network error. `accept(2)` documents
    /// these as retryable like `EAGAIN`, so the listener is healthy, the next
    /// accept is attempted at once, and nothing counts toward the fatal
    /// threshold.
    Transient,
    /// Local resource pressure: no descriptor, socket buffer, or memory is
    /// available for a new connection right now. The listener is still healthy,
    /// so this never contributes to the fatal threshold either; retrying is
    /// paced by [`ACCEPT_RESOURCE_PRESSURE_BACKOFF`] instead.
    ResourcePressure,
    /// The listener itself can no longer produce connections, for example a
    /// closed, invalid, or wrong-type descriptor. Only this category advances
    /// the fatal threshold.
    ListenerUnusable,
}

/// Classifies one listener-accept failure.
///
/// Deliberately narrow: only conditions Linux's `accept(2)` actually documents
/// as connection-level, network-level, or resource-level are treated as
/// recoverable. Anything else is assumed to be evidence about the listener, so
/// an unrecognized failure still reaches the existing fatal lifecycle rather
/// than being retried forever.
fn classify_accept_failure(error: &io::Error) -> AcceptFailure {
    if let Some(errno) = error.raw_os_error() {
        if accept_errno::RESOURCE_PRESSURE.contains(&errno) {
            return AcceptFailure::ResourcePressure;
        }
        if accept_errno::PENDING_NETWORK.contains(&errno) {
            return AcceptFailure::Transient;
        }
    }

    match error.kind() {
        // `ENOMEM`.
        ErrorKind::OutOfMemory => AcceptFailure::ResourcePressure,
        // `ECONNABORTED`, `ECONNRESET`, `EINTR`, `EAGAIN`, `ETIMEDOUT`, `EPERM`,
        // `ENETDOWN`, `ENETUNREACH`, `EHOSTUNREACH`, and `EOPNOTSUPP`: all about
        // one connection or the network, never about a listener this process
        // bound itself as a TCP stream socket.
        ErrorKind::ConnectionAborted
        | ErrorKind::ConnectionReset
        | ErrorKind::Interrupted
        | ErrorKind::WouldBlock
        | ErrorKind::TimedOut
        | ErrorKind::PermissionDenied
        | ErrorKind::NetworkDown
        | ErrorKind::NetworkUnreachable
        | ErrorKind::HostUnreachable
        | ErrorKind::Unsupported => AcceptFailure::Transient,
        _ => AcceptFailure::ListenerUnusable,
    }
}

/// Whether accepting should resume after a resource-pressure backoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AcceptBackoff {
    /// The backoff elapsed; accept again.
    Continue,
    /// Shutdown began first; stop accepting.
    Stop,
}

/// Waits out the fixed resource-pressure backoff, interruptible by shutdown.
///
/// Shutdown is biased ahead of the timer, so resource pressure cannot delay the
/// bounded shutdown phases by even one backoff.
async fn accept_backoff(lifecycle: &Lifecycle, backoff: Duration) -> AcceptBackoff {
    tokio::select! {
        biased;
        () = lifecycle.shutdown_started() => AcceptBackoff::Stop,
        () = sleep(backoff) => AcceptBackoff::Continue,
    }
}

/// Records one listener-accept failure that indicated an unusable listener and
/// reports whether the listener must now be treated as unusable for good.
///
/// Only [`AcceptFailure::ListenerUnusable`] reaches this. A successful accept
/// resets the count in the loop, so the threshold really does mean consecutive
/// evidence that the listener stopped producing connections.
fn accept_failure_is_fatal(consecutive_failures: &mut u32) -> bool {
    *consecutive_failures = consecutive_failures.saturating_add(1);
    *consecutive_failures >= MAX_CONSECUTIVE_ACCEPT_FAILURES
}

/// Terminates the runtime through the ordinary shutdown lifecycle after the
/// listener became unusable, and reports the fatal category.
///
/// Fatal accept exhaustion is not a quiet stop: readiness becomes false first,
/// no further synchronization request is admitted, pending admission waits are
/// released, already admitted work follows the same bounded grace and
/// cancellation phases, and remaining owned tasks are terminated and awaited.
/// The returned category makes the process report failure rather than normal
/// termination.
async fn terminate_after_fatal_accept_failure(
    connections: &mut JoinSet<()>,
    lifecycle: &Lifecycle,
    shutdown_grace: Duration,
) -> RuntimeFailure {
    lifecycle.begin_shutdown();
    shut_down_connections(connections, lifecycle, shutdown_grace).await;
    RuntimeFailure::ListenerAcceptFailed
}

/// The installed termination-signal handlers.
///
/// Holding both as a value is what makes registration a startup step rather
/// than something the signal task discovers too late to report: this cannot be
/// constructed unless both handlers exist.
pub(crate) struct TerminationSignals {
    terminate: Signal,
    interrupt: Signal,
}

/// Installs the `SIGTERM` and `SIGINT` handlers ADR 0011 requires.
///
/// Both are mandatory, so a failure to install either is a fatal startup
/// failure rather than a silently disabled graceful shutdown. The underlying
/// operating-system error is deliberately discarded: the returned category
/// names only which part of the runtime refused to continue.
fn register_termination_signals() -> Result<TerminationSignals, RuntimeFailure> {
    register_termination_signals_with(signal)
}

/// Installs both handlers through `register`, so the failure mapping can be
/// exercised without a host that actually refuses registration.
///
/// This is the whole abstraction: one function pointer, used only to decide
/// which of the two registrations fails. It adds no signal indirection to the
/// serving path.
fn register_termination_signals_with(
    register: fn(SignalKind) -> std::io::Result<Signal>,
) -> Result<TerminationSignals, RuntimeFailure> {
    let terminate =
        register(SignalKind::terminate()).map_err(|_| RuntimeFailure::SignalRegistrationFailed)?;
    let interrupt =
        register(SignalKind::interrupt()).map_err(|_| RuntimeFailure::SignalRegistrationFailed)?;

    Ok(TerminationSignals {
        terminate,
        interrupt,
    })
}

/// Translates a termination signal into the start of shutdown.
///
/// Signal handling is an owned task rather than part of the accept loop, so the
/// accept loop observes exactly one thing — that shutdown has begun — whatever
/// requested it. The handlers are already installed, so this task can only ever
/// wait: it never discovers a registration failure it would be unable to
/// report.
async fn signal_shutdown(signals: TerminationSignals, lifecycle: Arc<Lifecycle>) {
    await_termination_signal(signals).await;
    lifecycle.begin_shutdown();
}

/// Waits for `SIGTERM` or `SIGINT` on the already-installed handlers.
async fn await_termination_signal(signals: TerminationSignals) {
    let TerminationSignals {
        mut terminate,
        mut interrupt,
    } = signals;

    tokio::select! {
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }
}

/// Terminates remaining connections in bounded phases.
///
/// Requests admitted before shutdown may finish inside the configured grace
/// period. At grace expiry remaining request contexts are cancelled, compliant
/// cooperative work gets one bounded window to return, and anything still
/// running is terminated and awaited. No task, waiter, or permit survives.
async fn shut_down_connections(
    connections: &mut JoinSet<()>,
    lifecycle: &Lifecycle,
    shutdown_grace: Duration,
) {
    if timeout(shutdown_grace, drain(connections)).await.is_ok() {
        return;
    }

    lifecycle.cancel_requests();
    let _ = timeout(CANCELLED_REQUEST_WINDOW, drain(connections)).await;
    connections.shutdown().await;
}

async fn drain(connections: &mut JoinSet<()>) {
    while connections.join_next().await.is_some() {}
}

/// Serves one connection.
///
/// On shutdown the connection stops accepting further requests on itself and
/// lets an in-flight request finish, bounded by the caller's grace handling.
///
/// `header_read_timeout` bounds how long this connection may occupy a task and a
/// descriptor while producing no request: a client that never completes a
/// request head, and an idle keep-alive connection that never starts the next
/// one, are both closed at that bound. Hyper only enforces it when a timer is
/// configured, so both are set together here.
async fn serve_connection(
    stream: TcpStream,
    router: Router,
    lifecycle: Arc<Lifecycle>,
    header_read_timeout: Duration,
) {
    // `RefusingService` is what turns an inbound-admission refusal into a
    // terminated connection instead of a manufactured application response.
    let connection = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout)
        .keep_alive(true)
        .serve_connection(TokioIo::new(stream), RefusingService::new(router));
    let mut connection = Box::pin(connection);

    tokio::select! {
        _ = connection.as_mut() => {}
        () = lifecycle.shutdown_started() => {
            connection.as_mut().graceful_shutdown();
            let _ = connection.await;
        }
    }
}

/// Test-only entry point that serves an already-bound listener.
///
/// It exists so lifecycle correctness can be exercised with ephemeral ports and
/// controlled time instead of real process signals.
#[cfg(test)]
pub(crate) async fn serve_for_test(
    listener: TcpListener,
    router: Router,
    lifecycle: Arc<Lifecycle>,
    shutdown_grace: Duration,
    serving_started: oneshot::Sender<()>,
) -> Result<(), RuntimeFailure> {
    serve(listener, router, lifecycle, shutdown_grace, serving_started).await
}

/// Test-only entry point that serves one already-accepted connection.
///
/// It exists so the connection-level header-read bound can be proven with a
/// short injected value instead of a thirty-second wall-clock wait, without
/// making that bound a production or public configuration knob.
#[cfg(test)]
pub(crate) async fn serve_connection_for_test(
    stream: TcpStream,
    router: Router,
    lifecycle: Arc<Lifecycle>,
    header_read_timeout: Duration,
) {
    serve_connection(stream, router, lifecycle, header_read_timeout).await;
}

/// Test-only access to the termination-signal registration mapping.
#[cfg(test)]
pub(crate) fn register_termination_signals_with_for_test(
    register: fn(SignalKind) -> std::io::Result<Signal>,
) -> Result<TerminationSignals, RuntimeFailure> {
    register_termination_signals_with(register)
}

/// Test-only accessor for the fixed header-read bound the runtime serves with.
#[cfg(test)]
pub(crate) const fn header_read_timeout() -> Duration {
    HEADER_READ_TIMEOUT
}

/// Test-only access to the accept-failure classification.
#[cfg(test)]
pub(crate) fn classify_accept_failure_for_test(error: &io::Error) -> AcceptFailure {
    classify_accept_failure(error)
}

/// Test-only access to the shutdown-interruptible resource-pressure backoff.
#[cfg(test)]
pub(crate) async fn accept_backoff_for_test(
    lifecycle: &Lifecycle,
    backoff: Duration,
) -> AcceptBackoff {
    accept_backoff(lifecycle, backoff).await
}

/// Test-only accessor for the fixed resource-pressure backoff.
#[cfg(test)]
pub(crate) const fn accept_resource_pressure_backoff() -> Duration {
    ACCEPT_RESOURCE_PRESSURE_BACKOFF
}

/// Test-only access to the fatal-accept decision.
#[cfg(test)]
pub(crate) fn accept_failure_is_fatal_for_test(consecutive_failures: &mut u32) -> bool {
    accept_failure_is_fatal(consecutive_failures)
}

/// Test-only access to the fatal-accept lifecycle transition.
#[cfg(test)]
pub(crate) async fn terminate_after_fatal_accept_failure_for_test(
    connections: &mut JoinSet<()>,
    lifecycle: &Lifecycle,
    shutdown_grace: Duration,
) -> RuntimeFailure {
    terminate_after_fatal_accept_failure(connections, lifecycle, shutdown_grace).await
}

/// Test-only access to the consecutive-accept-failure threshold.
#[cfg(test)]
pub(crate) const fn max_consecutive_accept_failures() -> u32 {
    MAX_CONSECUTIVE_ACCEPT_FAILURES
}

/// Test-only access to the bounded verifier warm-up task.
#[cfg(test)]
pub(crate) fn spawn_verifier_warm_up_for_test(
    state: &Arc<RuntimeState>,
    budget: Duration,
    serving_has_started: oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    spawn_verifier_warm_up(state, budget, serving_has_started)
}

/// Test-only accessor for the fixed post-grace cancellation window.
#[cfg(test)]
pub(crate) const fn cancelled_request_window() -> Duration {
    CANCELLED_REQUEST_WINDOW
}

/// Test-only accessor for the bounded trace-flush budget.
#[cfg(test)]
pub(crate) const fn trace_flush_budget() -> Duration {
    TRACE_FLUSH_BUDGET
}
