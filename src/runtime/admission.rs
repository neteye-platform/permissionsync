//! The process-wide inbound admission boundary.
//!
//! Admission is taken at the transport boundary for `POST /api/sync-user`,
//! before the request body is collected, and is held for that request's
//! complete handling. It therefore bounds concurrently admitted
//! synchronization requests and, with them, aggregate application-owned body
//! buffering and concurrent pre-selected-target work such as authentication
//! and validation.
//!
//! # How application-owned waiter state stays bounded
//!
//! A permit count alone would not bound waiter state: without a second bound,
//! an unlimited number of served connections could each park one request task
//! in the permit semaphore's wait list. Admission therefore owns two bounds:
//!
//! - `permits` bounds admitted synchronization requests to the configured
//!   `inbound_admission_limit`;
//! - `waiters` bounds how many further synchronization requests may be parked
//!   in that wait list at once, to [`waiter_slots`], which is derived from the
//!   same configured limit.
//!
//! A waiter slot is taken without waiting. A request that obtains one parks on
//! `permits`, bounded by its own absolute deadline. A request that does not
//! obtain one is never enqueued at all: it waits only on its own absolute
//! deadline and on shutdown, so the wait list can never grow past its bound and
//! no second queue of queued requests appears anywhere.
//!
//! Total application-owned synchronization request state is therefore at most
//! `inbound_admission_limit + waiter_slots(inbound_admission_limit)`, and at
//! most `inbound_admission_limit` bodies can be buffered. Saturation adds no
//! caller-facing status: a wait that outlives the request's own deadline ends
//! through the existing server-side deadline path.
//!
//! # Why operational endpoints stay observable
//!
//! `GET /healthz`, `GET /readyz`, and `GET /metrics` take neither a permit nor
//! a waiter slot, and the accept loop gates no connection behind either
//! semaphore. Nothing a saturated synchronization workload holds can therefore
//! keep an operational request from being accepted and answered. That property
//! is structural rather than a reserved share of a shared connection budget: a
//! shared budget cannot be reserved for a class of request that is only
//! identifiable after the request head has been read.

use std::{num::NonZeroUsize, sync::Arc, time::Instant};

use metrics::{counter, gauge};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{Instant as TokioInstant, sleep_until},
};

use crate::runtime::{
    lifecycle::Lifecycle,
    observability::{
        ADMISSION_ABANDONED_TOTAL, ADMISSION_QUEUE_FULL_TOTAL, ADMISSION_SATURATED_TOTAL,
        ADMISSION_WAITERS, REQUESTS_IN_FLIGHT,
    },
};

/// Returns how many synchronization requests may be parked in the admission
/// wait list at once, for a configured admission limit.
///
/// The bound is the configured limit itself: at most as many requests may be
/// waiting as may be admitted. It is derived rather than configured, so no
/// deployment value can make the wait list unbounded, and it needs no arbitrary
/// product constant.
pub(crate) const fn waiter_slots(inbound_admission_limit: NonZeroUsize) -> NonZeroUsize {
    inbound_admission_limit
}

/// Returns every semaphore size that admission derives from one configured
/// limit, or `None` when any of them could not be constructed.
///
/// Tokio panics when a semaphore is created with more than
/// [`Semaphore::MAX_PERMITS`] permits, so configuration validation proves every
/// derived size here before startup proceeds. Arithmetic is checked: an
/// impossible configuration is reported, never silently clamped into a
/// seemingly valid one.
pub(crate) fn derived_semaphore_sizes(inbound_admission_limit: NonZeroUsize) -> Option<[usize; 2]> {
    let admitted = inbound_admission_limit.get();
    let waiting = waiter_slots(inbound_admission_limit).get();

    [admitted, waiting]
        .iter()
        .all(|size| *size <= Semaphore::MAX_PERMITS)
        .then_some([admitted, waiting])
}

/// Returns the largest configured admission limit for which every derived
/// semaphore size is constructible.
///
/// This is derived from Tokio's own semaphore constraint and from the shape of
/// the sizes admission derives, not from an unrelated product ceiling.
#[cfg(test)]
pub(crate) fn max_inbound_admission_limit() -> NonZeroUsize {
    // Both derived sizes equal the configured limit, so the binding constraint
    // is Tokio's maximum. `MAX_PERMITS` is positive, so this cannot fail.
    NonZeroUsize::new(Semaphore::MAX_PERMITS).expect("MAX_PERMITS is positive")
}

/// The bounded process-wide inbound admission limit.
pub(crate) struct InboundAdmission {
    permits: Arc<Semaphore>,
    /// Bounds the length of the `permits` wait list, so application-owned
    /// waiter state cannot grow with the number of served connections.
    waiters: Arc<Semaphore>,
    /// Retained only for deliberate inspection in tests; the semaphores are the
    /// authoritative bounds at runtime.
    #[cfg(test)]
    limit: NonZeroUsize,
}

impl InboundAdmission {
    /// Creates admission for a configured limit whose derived semaphore sizes
    /// have already been proven constructible.
    ///
    /// Returns `None` when they have not, so an impossible configuration can
    /// never reach a panicking semaphore constructor.
    pub(crate) fn new(limit: NonZeroUsize) -> Option<Self> {
        let [admitted, waiting] = derived_semaphore_sizes(limit)?;

        Some(Self {
            permits: Arc::new(Semaphore::new(admitted)),
            waiters: Arc::new(Semaphore::new(waiting)),
            #[cfg(test)]
            limit,
        })
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

    /// Returns the waiter slots not currently held, for deliberate inspection.
    #[cfg(test)]
    pub(crate) fn available_waiter_slots(&self) -> usize {
        self.waiters.available_permits()
    }

    /// Admits one synchronization request, or reports that it was not admitted.
    ///
    /// Waiting is bounded by the request's own absolute `deadline`; it creates
    /// no second deadline and never extends the budget. Shutdown releases
    /// pending waits immediately, so a request that has not been admitted
    /// reaches neither body collection nor authentication.
    ///
    /// A request only joins the `permits` wait list while a waiter slot is
    /// free, so that list stays bounded. A request that finds no free slot
    /// waits on its own deadline without being enqueued anywhere, which keeps
    /// saturation an existing server-side deadline outcome rather than a new
    /// caller-facing status or an unbounded queue.
    ///
    /// Dropping the returned future removes the waiter, releases its waiter
    /// slot, and returns any permit already assigned to it, so an abandoned
    /// admission owns nothing.
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
        let admitted = match Arc::clone(&self.waiters).try_acquire_owned() {
            // A bounded place in the wait list: park until a permit frees, the
            // request's own deadline expires, or shutdown releases the wait.
            Ok(waiter_slot) => {
                let _waiting = WaitingGuard::new();
                let admitted = tokio::select! {
                    biased;
                    () = lifecycle.shutdown_started() => None,
                    permit = permits.acquire_owned() => permit.ok().map(AdmittedRequest::new),
                    () = sleep_until(TokioInstant::from_std(deadline)) => None,
                };
                drop(waiter_slot);
                admitted
            }
            // The wait list is already at its bound. Do not enqueue: wait only
            // on this request's own budget, so no queue can grow past it.
            Err(_) => {
                counter!(ADMISSION_QUEUE_FULL_TOTAL).increment(1);
                tokio::select! {
                    biased;
                    () = lifecycle.shutdown_started() => {}
                    () = sleep_until(TokioInstant::from_std(deadline)) => {}
                }
                None
            }
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

    use tokio::sync::Semaphore;

    use super::{
        InboundAdmission, derived_semaphore_sizes, max_inbound_admission_limit, waiter_slots,
    };
    use crate::runtime::lifecycle::Lifecycle;

    fn nonzero(value: usize) -> NonZeroUsize {
        NonZeroUsize::new(value).expect("test values are positive")
    }

    fn admission(limit: usize) -> InboundAdmission {
        InboundAdmission::new(nonzero(limit)).expect("test limits are constructible")
    }

    fn far_future() -> Instant {
        Instant::now() + Duration::from_secs(3600)
    }

    /// The wait list is bounded by a value derived from the configured limit, so
    /// no deployment value can make it unbounded.
    #[test]
    fn the_waiter_bound_is_derived_from_the_configured_limit() {
        for limit in [1_usize, 2, 64, 1024] {
            assert_eq!(waiter_slots(nonzero(limit)).get(), limit);
        }
    }

    /// Every derived semaphore size must be proven constructible, because Tokio
    /// panics above its own maximum.
    #[test]
    fn derived_semaphore_sizes_accept_exactly_the_constructible_limits() {
        for limit in [1_usize, 2, 64, 1024, 1_000_000] {
            assert_eq!(
                derived_semaphore_sizes(nonzero(limit)),
                Some([limit, limit]),
                "{limit} must be accepted"
            );
        }

        let largest = max_inbound_admission_limit();
        assert_eq!(largest.get(), Semaphore::MAX_PERMITS);
        assert!(
            derived_semaphore_sizes(largest).is_some(),
            "the largest intentionally accepted limit must be constructible"
        );

        for impossible in [
            Semaphore::MAX_PERMITS + 1,
            Semaphore::MAX_PERMITS * 2,
            usize::MAX,
        ] {
            assert_eq!(
                derived_semaphore_sizes(nonzero(impossible)),
                None,
                "{impossible} must be refused rather than clamped"
            );
        }
    }

    /// Construction reports an impossible limit instead of reaching a panicking
    /// semaphore constructor.
    #[test]
    fn construction_refuses_an_impossible_limit_without_panicking() {
        assert!(InboundAdmission::new(nonzero(1)).is_some());
        assert!(InboundAdmission::new(max_inbound_admission_limit()).is_some());
        assert!(InboundAdmission::new(nonzero(Semaphore::MAX_PERMITS + 1)).is_none());
        assert!(InboundAdmission::new(nonzero(usize::MAX)).is_none());
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
