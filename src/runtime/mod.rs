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
    num::NonZeroUsize,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::Router;
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use permissionsync::{
    ComposedApplication, GLPI_ADAPTER_IDENTIFIER, ProviderAvailability, TargetAvailability,
};
use permissionsync_auth::TechnicalCallerAuthenticator;
use permissionsync_core::{LogicalTarget, SynchronizationContext};
use tokio::{
    net::{TcpListener, TcpStream},
    signal::unix::{SignalKind, signal},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::timeout,
};
use tracing::{info, warn};

use crate::runtime::{
    admission::{InboundAdmission, concurrent_connection_limit},
    capacity::SemaphoreCapacity,
    configuration::{ComponentOutcome, ExecutableConfiguration},
    failure::StartupFailure,
    lifecycle::{Lifecycle, RequestCancellation},
    transport::{RuntimeState, record_component_availability, router},
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
const MAX_CONSECUTIVE_ACCEPT_FAILURES: u32 = 16;

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
pub(crate) fn run() -> Result<(), StartupFailure> {
    let path = configuration::configuration_path()?;
    let configuration = configuration::load(Path::new(&path))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| StartupFailure::RuntimeUnavailable)?;

    runtime.block_on(serve_configured(configuration))
}

async fn serve_configured(configuration: ExecutableConfiguration) -> Result<(), StartupFailure> {
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
        .map_err(|_| StartupFailure::InvalidComposition)?;

    let admission = InboundAdmission::new(inbound_admission_limit);
    let capacity =
        SemaphoreCapacity::new(synchronization_capacity).ok_or(StartupFailure::InvalidRequest)?;

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
        inbound_admission_limit,
        shutdown_grace,
        metadata_operation_timeout,
        observability.tracing_enabled(),
    )
    .await;

    // The bounded trace flush runs on every exit path, including a listener
    // that could not be bound, so no exporter task is left behind.
    observability.shutdown_tracing(TRACE_FLUSH_BUDGET);

    result
}

/// Binds the configured listener, begins serving, and then allows bounded
/// verifier warm-up.
#[allow(clippy::too_many_arguments)]
async fn bind_and_serve(
    listen_address: std::net::SocketAddr,
    router: Router,
    state: &Arc<RuntimeState>,
    lifecycle: Arc<Lifecycle>,
    inbound_admission_limit: NonZeroUsize,
    shutdown_grace: Duration,
    metadata_operation_timeout: Duration,
    tracing_enabled: bool,
) -> Result<(), StartupFailure> {
    let listener = TcpListener::bind(listen_address)
        .await
        .map_err(|_| StartupFailure::ListenerUnavailable)?;

    info!(
        target: "permissionsync::runtime",
        tracing_export = tracing_enabled,
        "permissionsync bound its listener and is serving"
    );

    // Spawned before the accept loop is awaited, so it first runs once this
    // task yields: that is, once serving has begun. It is bounded and never
    // gates readiness or serving.
    let warm_up = spawn_verifier_warm_up(state, metadata_operation_timeout);
    let signals = tokio::spawn(signal_shutdown(Arc::clone(&lifecycle)));

    let connection_limit = concurrent_connection_limit(inbound_admission_limit);
    serve(
        listener,
        router,
        Arc::clone(&lifecycle),
        connection_limit,
        shutdown_grace,
    )
    .await;

    // Both auxiliary tasks are owned, so neither is detached at exit.
    signals.abort();
    let _ = signals.await;
    warm_up.abort();
    let _ = warm_up.await;

    Ok(())
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
fn spawn_verifier_warm_up(
    state: &Arc<RuntimeState>,
    budget: Duration,
) -> tokio::task::JoinHandle<()> {
    let authenticator = state.authenticator().clone();
    let lifecycle = Arc::clone(state.lifecycle());
    tokio::spawn(async move {
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
/// The accept loop holds at most `connection_limit` connections at once and
/// stops calling `accept` while that bound is reached. Surplus load therefore
/// stays in the kernel listen backlog as transport backpressure instead of
/// becoming application state, which is what bounds admission waiters. Every
/// connection task is owned by the local [`JoinSet`], so nothing is detached.
async fn serve(
    listener: TcpListener,
    router: Router,
    lifecycle: Arc<Lifecycle>,
    connection_limit: usize,
    shutdown_grace: Duration,
) {
    let permits = Arc::new(Semaphore::new(connection_limit));
    let mut connections: JoinSet<()> = JoinSet::new();
    let shutdown_lifecycle = Arc::clone(&lifecycle);
    let mut shutdown = Box::pin(async move { shutdown_lifecycle.shutdown_started().await });
    let mut consecutive_failures = 0_u32;

    loop {
        // Reap finished connections so the owned set stays bounded.
        while connections.try_join_next().is_some() {}

        let permit = tokio::select! {
            biased;
            () = &mut shutdown => break,
            permit = Arc::clone(&permits).acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => break,
            },
        };

        let accepted = tokio::select! {
            biased;
            () = &mut shutdown => break,
            accepted = listener.accept() => accepted,
            Some(_) = connections.join_next() => continue,
        };

        match accepted {
            Ok((stream, _)) => {
                consecutive_failures = 0;
                connections.spawn(serve_connection(
                    stream,
                    router.clone(),
                    Arc::clone(&lifecycle),
                    permit,
                ));
            }
            Err(_) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                if consecutive_failures >= MAX_CONSECUTIVE_ACCEPT_FAILURES {
                    break;
                }
            }
        }
    }

    shut_down_connections(&mut connections, &lifecycle, shutdown_grace).await;
}

/// Translates a termination signal into the start of shutdown.
///
/// Signal handling is an owned task rather than part of the accept loop, so the
/// accept loop observes exactly one thing — that shutdown has begun — whatever
/// requested it.
async fn signal_shutdown(lifecycle: Arc<Lifecycle>) {
    await_termination_signal().await;
    lifecycle.begin_shutdown();
}

/// Waits for `SIGTERM` or `SIGINT`.
async fn await_termination_signal() {
    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(terminate) => terminate,
        Err(_) => return std::future::pending().await,
    };
    let mut interrupt = match signal(SignalKind::interrupt()) {
        Ok(interrupt) => interrupt,
        Err(_) => return std::future::pending().await,
    };

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

/// Serves one connection, releasing its transport permit when the task ends.
///
/// On shutdown the connection stops accepting further requests on itself and
/// lets an in-flight request finish, bounded by the caller's grace handling.
async fn serve_connection(
    stream: TcpStream,
    router: Router,
    lifecycle: Arc<Lifecycle>,
    permit: OwnedSemaphorePermit,
) {
    let _permit = permit;
    let connection = hyper::server::conn::http1::Builder::new()
        .keep_alive(true)
        .serve_connection(TokioIo::new(stream), TowerToHyperService::new(router));
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
    connection_limit: usize,
    shutdown_grace: Duration,
) {
    serve(
        listener,
        router,
        lifecycle,
        connection_limit,
        shutdown_grace,
    )
    .await;
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
