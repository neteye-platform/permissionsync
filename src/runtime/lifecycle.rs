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
    use std::{
        future::{Future, poll_fn},
        pin::Pin,
        task::Poll,
        time::Duration,
    };

    use permissionsync_core::CancellationSignal;

    use super::{Lifecycle, RequestCancellation};

    /// A bound that only fires when the implementation is wrong; it never
    /// establishes ordering.
    const DEADLOCK_BOUND: Duration = Duration::from_secs(10);

    /// Polls a future exactly once, so a test can register a waiter
    /// deterministically instead of assuming the scheduler ran a spawned task.
    async fn poll_once<F>(future: &mut Pin<Box<F>>) -> Poll<F::Output>
    where
        F: Future,
    {
        poll_fn(|context| Poll::Ready(future.as_mut().poll(context))).await
    }

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

    /// A waiter that registered before shutdown began must still be woken.
    ///
    /// Polling the waiter once registers it deterministically, so the ordering
    /// this test depends on is established by the poll rather than by giving the
    /// scheduler a chance to run a spawned task.
    #[tokio::test]
    async fn shutdown_started_resolves_for_a_waiter_registered_first() {
        let lifecycle = Lifecycle::new();
        let mut waiting = Box::pin(lifecycle.shutdown_started());

        assert!(
            poll_once(&mut waiting).await.is_pending(),
            "the waiter must register and not be ready before shutdown begins"
        );
        lifecycle.begin_shutdown();

        tokio::time::timeout(DEADLOCK_BOUND, waiting)
            .await
            .expect("waiter must be woken");
    }

    #[tokio::test]
    async fn shutdown_started_resolves_immediately_after_shutdown_began() {
        let lifecycle = Lifecycle::new();
        lifecycle.begin_shutdown();

        let mut waiting = Box::pin(lifecycle.shutdown_started());
        assert!(
            poll_once(&mut waiting).await.is_ready(),
            "an already-shut-down lifecycle must resolve on its first poll"
        );
    }

    #[tokio::test]
    async fn many_waiters_are_all_released_by_one_shutdown() {
        let lifecycle = Lifecycle::new();
        let mut waiters: Vec<_> = (0..16)
            .map(|_| Box::pin(lifecycle.shutdown_started()))
            .collect();

        // Every waiter is registered by an explicit poll, so all of them are
        // provably in the notify list before shutdown begins.
        for waiter in &mut waiters {
            assert!(poll_once(waiter).await.is_pending());
        }
        lifecycle.begin_shutdown();

        for waiter in waiters {
            tokio::time::timeout(DEADLOCK_BOUND, waiter)
                .await
                .expect("every waiter must be released");
        }
    }
}
