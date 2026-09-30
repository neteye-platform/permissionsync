//! Process lifecycle state shared by the transport, admission, readiness, and
//! shutdown.
//!
//! Three distinct facts are tracked, because shutdown needs them at different
//! moments:
//!
//! - `shutting_down`: readiness is false, the accept loop stops, and no further
//!   synchronization request is admitted. Pending admission waits observe this
//!   and are abandoned.
//! - `requests_cancelled`: the configured grace period expired, so remaining
//!   request contexts are cancelled through the runtime-neutral
//!   [`CancellationSignal`] that every component already observes.
//! - A broadcast notification so waiters do not poll.

use std::sync::atomic::{AtomicBool, Ordering};

use permissionsync_core::CancellationSignal;
use tokio::sync::Notify;

/// Shared, process-wide lifecycle state.
#[derive(Default)]
pub(crate) struct Lifecycle {
    shutting_down: AtomicBool,
    requests_cancelled: AtomicBool,
    shutdown: Notify,
}

impl Lifecycle {
    /// Creates lifecycle state for a process that is serving normally.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Marks readiness false, stops accepting, and wakes every waiter.
    ///
    /// Waking admission waiters is what makes shutdown release them instead of
    /// letting them sit until their own deadline.
    pub(crate) fn begin_shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
        self.shutdown.notify_waiters();
    }

    /// Cancels every remaining request context at grace expiry.
    pub(crate) fn cancel_requests(&self) {
        self.requests_cancelled.store(true, Ordering::SeqCst);
        self.shutdown.notify_waiters();
    }

    /// Returns whether shutdown has begun.
    pub(crate) fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    /// Returns whether remaining request contexts have been cancelled.
    pub(crate) fn requests_cancelled(&self) -> bool {
        self.requests_cancelled.load(Ordering::SeqCst)
    }

    /// Resolves as soon as shutdown has begun, including when it already had.
    ///
    /// The waiter is registered before the flag is re-read, so a shutdown that
    /// starts between the two cannot be missed.
    pub(crate) async fn shutdown_started(&self) {
        let notified = self.shutdown.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.is_shutting_down() {
            return;
        }
        notified.await;
    }
}

/// The runtime implementation of the existing runtime-neutral cancellation
/// port.
///
/// Core stays free of Tokio: this borrows only process lifecycle state and
/// answers the same cooperative question every component already asks.
pub(crate) struct RequestCancellation<'a> {
    lifecycle: &'a Lifecycle,
}

impl<'a> RequestCancellation<'a> {
    /// Creates a cancellation signal for one in-flight request.
    pub(crate) const fn new(lifecycle: &'a Lifecycle) -> Self {
        Self { lifecycle }
    }
}

impl CancellationSignal for RequestCancellation<'_> {
    fn is_cancelled(&self) -> bool {
        self.lifecycle.requests_cancelled()
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use permissionsync_core::CancellationSignal;

    use super::{Lifecycle, RequestCancellation};

    #[test]
    fn a_new_lifecycle_is_serving_and_uncancelled() {
        let lifecycle = Lifecycle::new();

        assert!(!lifecycle.is_shutting_down());
        assert!(!lifecycle.requests_cancelled());
        assert!(!RequestCancellation::new(&lifecycle).is_cancelled());
    }

    /// Shutdown and request cancellation are separate steps: beginning
    /// shutdown must not already cancel admitted requests, because they are
    /// allowed to finish inside the grace period.
    #[test]
    fn beginning_shutdown_does_not_cancel_admitted_requests() {
        let lifecycle = Lifecycle::new();

        lifecycle.begin_shutdown();
        assert!(lifecycle.is_shutting_down());
        assert!(!lifecycle.requests_cancelled());
        assert!(!RequestCancellation::new(&lifecycle).is_cancelled());

        lifecycle.cancel_requests();
        assert!(RequestCancellation::new(&lifecycle).is_cancelled());
    }

    #[tokio::test]
    async fn shutdown_started_resolves_for_a_waiter_registered_first() {
        let lifecycle = Arc::new(Lifecycle::new());
        let waiting = {
            let lifecycle = Arc::clone(&lifecycle);
            tokio::spawn(async move { lifecycle.shutdown_started().await })
        };

        // Yield so the waiter is registered, then start shutdown.
        tokio::task::yield_now().await;
        lifecycle.begin_shutdown();

        tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("waiter must be woken")
            .expect("waiter task must not panic");
    }

    #[tokio::test]
    async fn shutdown_started_resolves_immediately_after_shutdown_began() {
        let lifecycle = Lifecycle::new();
        lifecycle.begin_shutdown();

        tokio::time::timeout(Duration::from_secs(5), lifecycle.shutdown_started())
            .await
            .expect("an already-shut-down lifecycle must resolve immediately");
    }

    #[tokio::test]
    async fn many_waiters_are_all_released_by_one_shutdown() {
        let lifecycle = Arc::new(Lifecycle::new());
        let mut waiters = Vec::new();
        for _ in 0..16 {
            let lifecycle = Arc::clone(&lifecycle);
            waiters.push(tokio::spawn(
                async move { lifecycle.shutdown_started().await },
            ));
        }

        tokio::task::yield_now().await;
        lifecycle.begin_shutdown();

        for waiter in waiters {
            tokio::time::timeout(Duration::from_secs(5), waiter)
                .await
                .expect("every waiter must be released")
                .expect("waiter task must not panic");
        }
    }
}
