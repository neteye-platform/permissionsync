//! The process-wide inbound admission boundary.
//!
//! Admission is taken at the transport boundary for `POST /api/sync-user`,
//! before the request body is collected, and is held for that request's
//! complete handling. It therefore bounds concurrently admitted
//! synchronization requests and, with them, aggregate application-owned body
//! buffering and concurrent pre-selected-target work such as authentication
//! and validation. Operational endpoints take no permit.
//!
//! # Why this cannot become an unbounded application waiter queue
//!
//! A permit count alone would not bound waiter state: an unlimited number of
//! independently served connections could each park one request task in the
//! semaphore's wait list. Boundedness therefore comes from two cooperating
//! limits, not from this semaphore alone:
//!
//! - the accept loop serves at most [`concurrent_connection_limit`]
//!   connections at a time and stops calling `accept` while that bound is
//!   reached, so surplus load stays in the kernel's listen backlog as
//!   transport backpressure rather than becoming application state;
//! - HTTP/1 serves one request per connection at a time, so the number of
//!   request tasks that can exist at once is at most that connection bound.
//!
//! Consequently at most `inbound_admission_limit` requests are admitted and at
//! most [`ADMISSION_WAITER_HEADROOM`] requests can be waiting for admission or
//! using an operational endpoint. Saturation adds no caller-facing status: it
//! is expressed as transport backpressure, and a wait that outlives the
//! request's own deadline ends through the existing server-side deadline path.

use std::{num::NonZeroUsize, sync::Arc, time::Instant};

use metrics::{counter, gauge};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{Instant as TokioInstant, sleep_until},
};

use crate::runtime::{
    lifecycle::Lifecycle,
    observability::{
        ADMISSION_ABANDONED_TOTAL, ADMISSION_SATURATED_TOTAL, ADMISSION_WAITERS, REQUESTS_IN_FLIGHT,
    },
};

/// Connections served concurrently beyond the configured admission limit.
///
/// This headroom is what keeps `/healthz`, `/readyz`, and `/metrics` observable
/// while synchronization is saturated, and it is simultaneously the hard bound
/// on how many requests can be waiting for admission. It is a fixed product
/// value rather than a deployment knob: ADR 0011 makes the admission limit the
/// configured bound, and this only sizes the transport backpressure point above
/// it.
pub(crate) const ADMISSION_WAITER_HEADROOM: usize = 64;

/// Returns how many connections the accept loop may serve at once.
///
/// Saturating arithmetic keeps the bound finite for any accepted configuration.
pub(crate) fn concurrent_connection_limit(inbound_admission_limit: NonZeroUsize) -> usize {
    inbound_admission_limit
        .get()
        .saturating_add(ADMISSION_WAITER_HEADROOM)
}

/// The bounded process-wide inbound admission limit.
pub(crate) struct InboundAdmission {
    permits: Arc<Semaphore>,
    /// Retained only for deliberate inspection in tests; the semaphore is the
    /// authoritative bound at runtime.
    #[cfg(test)]
    limit: NonZeroUsize,
}

impl InboundAdmission {
    /// Creates admission for a positive configured limit.
    pub(crate) fn new(limit: NonZeroUsize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(limit.get())),
            #[cfg(test)]
            limit,
        }
    }

    /// Returns the configured limit, for deliberate inspection.
    #[cfg(test)]
    pub(crate) fn limit(&self) -> NonZeroUsize {
        self.limit
    }

    /// Returns the permits not currently held, for deliberate inspection.
    #[cfg(test)]
    pub(crate) fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }

    /// Admits one synchronization request, or reports that it was not admitted.
    ///
    /// Waiting is bounded by the request's own absolute `deadline`; it creates
    /// no second deadline and never extends the budget. Shutdown releases
    /// pending waits immediately, so a request that has not been admitted
    /// reaches neither body collection nor authentication.
    ///
    /// Dropping the returned future removes the waiter and returns any permit
    /// already assigned to it, so an abandoned admission owns nothing.
    pub(crate) async fn admit(
        &self,
        deadline: Instant,
        lifecycle: &Lifecycle,
    ) -> Option<AdmittedRequest> {
        if lifecycle.is_shutting_down() || Instant::now() >= deadline {
            counter!(ADMISSION_ABANDONED_TOTAL).increment(1);
            return None;
        }

        let permits = Arc::clone(&self.permits);
        if let Ok(permit) = permits.clone().try_acquire_owned() {
            return Some(AdmittedRequest::new(permit));
        }

        counter!(ADMISSION_SATURATED_TOTAL).increment(1);
        let _waiting = WaitingGuard::new();
        let admitted = tokio::select! {
            biased;
            () = lifecycle.shutdown_started() => None,
            permit = permits.acquire_owned() => permit.ok().map(AdmittedRequest::new),
            () = sleep_until(TokioInstant::from_std(deadline)) => None,
        };
        if admitted.is_none() {
            counter!(ADMISSION_ABANDONED_TOTAL).increment(1);
        }
        admitted
    }
}

/// A held admission permit, released on drop.
///
/// It is held for the complete handling of one synchronization request,
/// including its cancellation and error paths, so no permit can survive the
/// request that owns it.
pub(crate) struct AdmittedRequest {
    _permit: OwnedSemaphorePermit,
}

impl AdmittedRequest {
    fn new(permit: OwnedSemaphorePermit) -> Self {
        gauge!(REQUESTS_IN_FLIGHT).increment(1.0);
        Self { _permit: permit }
    }
}

impl Drop for AdmittedRequest {
    fn drop(&mut self) {
        gauge!(REQUESTS_IN_FLIGHT).decrement(1.0);
    }
}

/// Keeps the admission-waiter gauge exact on every exit path, including a
/// dropped request future.
struct WaitingGuard;

impl WaitingGuard {
    fn new() -> Self {
        gauge!(ADMISSION_WAITERS).increment(1.0);
        Self
    }
}

impl Drop for WaitingGuard {
    fn drop(&mut self) {
        gauge!(ADMISSION_WAITERS).decrement(1.0);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        num::NonZeroUsize,
        sync::Arc,
        time::{Duration, Instant},
    };

    use super::{ADMISSION_WAITER_HEADROOM, InboundAdmission, concurrent_connection_limit};
    use crate::runtime::lifecycle::Lifecycle;

    fn admission(limit: usize) -> InboundAdmission {
        InboundAdmission::new(NonZeroUsize::new(limit).unwrap())
    }

    fn far_future() -> Instant {
        Instant::now() + Duration::from_secs(3600)
    }

    #[test]
    fn the_connection_bound_is_the_admission_limit_plus_fixed_headroom() {
        assert_eq!(
            concurrent_connection_limit(NonZeroUsize::new(1).unwrap()),
            1 + ADMISSION_WAITER_HEADROOM
        );
        assert_eq!(
            concurrent_connection_limit(NonZeroUsize::new(64).unwrap()),
            64 + ADMISSION_WAITER_HEADROOM
        );
        assert_eq!(
            concurrent_connection_limit(NonZeroUsize::MAX),
            usize::MAX,
            "the bound stays finite for any accepted configuration"
        );
    }

    #[tokio::test]
    async fn no_more_than_the_configured_limit_is_admitted_concurrently() {
        let admission = admission(2);
        let lifecycle = Lifecycle::new();

        let first = admission
            .admit(far_future(), &lifecycle)
            .await
            .expect("first");
        let second = admission
            .admit(far_future(), &lifecycle)
            .await
            .expect("second");
        assert_eq!(admission.available_permits(), 0);

        let third = admission
            .admit(Instant::now() + Duration::from_millis(20), &lifecycle)
            .await;
        assert!(third.is_none(), "a third request must not be admitted");

        drop(first);
        drop(second);
        assert_eq!(admission.available_permits(), 2);
    }

    /// An admission wait consumes the request's own budget and nothing more.
    #[tokio::test(start_paused = true)]
    async fn a_saturated_wait_ends_at_the_request_deadline() {
        let admission = admission(1);
        let lifecycle = Lifecycle::new();
        let held = admission
            .admit(far_future(), &lifecycle)
            .await
            .expect("held");

        let deadline = Instant::now() + Duration::from_secs(2);
        assert!(admission.admit(deadline, &lifecycle).await.is_none());

        drop(held);
        assert_eq!(admission.available_permits(), 1);
    }

    #[tokio::test]
    async fn an_already_expired_deadline_is_not_admitted() {
        let admission = admission(1);
        let lifecycle = Lifecycle::new();

        assert!(
            admission
                .admit(Instant::now() - Duration::from_secs(1), &lifecycle)
                .await
                .is_none()
        );
        assert_eq!(admission.available_permits(), 1);
    }

    #[tokio::test]
    async fn shutdown_admits_no_further_request() {
        let admission = admission(1);
        let lifecycle = Lifecycle::new();
        lifecycle.begin_shutdown();

        assert!(admission.admit(far_future(), &lifecycle).await.is_none());
        assert_eq!(admission.available_permits(), 1);
    }

    /// A wait already in flight must be released by shutdown, long before its
    /// own deadline, and must leave no permit or waiter behind.
    #[tokio::test]
    async fn shutdown_releases_a_pending_admission_wait() {
        let admission = Arc::new(admission(1));
        let lifecycle = Arc::new(Lifecycle::new());
        let held = admission
            .admit(far_future(), &lifecycle)
            .await
            .expect("held");

        let waiting = {
            let admission = Arc::clone(&admission);
            let lifecycle = Arc::clone(&lifecycle);
            tokio::spawn(async move { admission.admit(far_future(), &lifecycle).await.is_some() })
        };
        tokio::task::yield_now().await;

        lifecycle.begin_shutdown();
        let admitted = tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("shutdown must release the pending wait")
            .expect("waiter task must not panic");

        assert!(!admitted, "a released wait is not an admission");
        drop(held);
        assert_eq!(admission.available_permits(), 1);
    }

    /// Dropping the admission future, as happens when a request is abandoned
    /// or its task is terminated, must not retain a reservation.
    #[tokio::test(start_paused = true)]
    async fn dropping_an_unfinished_admission_leaves_no_reservation() {
        let admission = admission(1);
        let lifecycle = Lifecycle::new();
        let held = admission
            .admit(far_future(), &lifecycle)
            .await
            .expect("held");

        let mut abandoned = Box::pin(admission.admit(far_future(), &lifecycle));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut abandoned)
                .await
                .is_err(),
            "a saturated admission must not complete"
        );
        drop(abandoned);
        drop(held);

        assert_eq!(admission.available_permits(), 1);
        assert!(admission.admit(far_future(), &lifecycle).await.is_some());
    }
}
