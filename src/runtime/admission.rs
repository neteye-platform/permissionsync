//! The process-wide inbound admission boundary.
//!
//! Admission is taken at the transport boundary for `POST /api/sync-user`,
//! before the request body is collected, and is held for that request's
//! complete handling. It therefore bounds concurrently admitted
//! synchronization requests and, with them, aggregate application-owned body
//! buffering and concurrent pre-selected-target work such as authentication
//! and validation.
//!
//! # The bound on application-owned synchronization waiting state
//!
//! Two semaphores together define one finite population, and a synchronization
//! request is only ever allowed to wait inside it:
//!
//! - `permits` bounds admitted synchronization requests to the configured
//!   `inbound_admission_limit`;
//! - `waiters` bounds how many further synchronization requests may be parked
//!   in the `permits` wait list, to [`waiter_slots`], derived from the same
//!   configured limit.
//!
//! Both slots are taken without waiting. A request that obtains a waiter slot
//! parks on `permits` and is woken as soon as a permit frees, so a legitimate
//! waiter can still proceed inside its own budget.
//!
//! Holding a permit is not yet admission: every acquisition, immediate or
//! awaited, is finalized by [`InboundAdmission::finalize`], which re-reads the
//! lifecycle and the request's deadline and releases the permit rather than
//! admitting a request once shutdown has begun.
//!
//! A request that obtains neither is refused immediately. It is never parked,
//! never sleeps to its deadline, and never occupies any other application
//! waiting area, so saturation cannot create a second population outside these
//! two bounds. Such a request also gets no PermissionSync outcome: it was not
//! cancelled, it did not expire, and it was never processed, so the transport
//! refuses it by terminating the connection rather than by manufacturing an
//! application response. Saturation therefore adds no caller-facing status at
//! all and changes no precedence, and it accumulates no application state.
//!
//! The complete invariant is therefore: at any instant the number of
//! synchronization requests that are admitted or waiting anywhere in this
//! process is at most `inbound_admission_limit +
//! waiter_slots(inbound_admission_limit)`, and at most
//! `inbound_admission_limit` request bodies can be buffered. That bound does
//! not depend on how many connections are open, because a request that cannot
//! join the population does not wait at all.
//!
//! # Why operational endpoints cannot be starved
//!
//! `GET /healthz`, `GET /readyz`, and `GET /metrics` take neither a permit nor
//! a waiter slot, and no connection is gated behind either semaphore. Nothing a
//! saturated synchronization workload holds is on their path, and a refused
//! synchronization request is released at once instead of holding a connection.
//! That reservation is structural rather than a share of a shared connection
//! budget, which could not work here: a request's class is only known after its
//! head has been read, so a budget taken at accept time cannot be reserved for a
//! class of request that has not been identified yet.

use std::{num::NonZeroUsize, sync::Arc, time::Instant};

use metrics::{counter, gauge};
#[cfg(test)]
use tokio::sync::watch;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{Instant as TokioInstant, sleep_until},
};

use crate::runtime::{
    lifecycle::Lifecycle,
    observability::{
        ADMISSION_ABANDONED_TOTAL, ADMISSION_REFUSED_TOTAL, ADMISSION_SATURATED_TOTAL,
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

/// The result of one admission attempt.
#[must_use]
pub(crate) enum Admission {
    /// The request was admitted. The permit is held for its complete handling.
    Admitted(AdmittedRequest),
    /// The request waited inside the bounded population within its own budget
    /// and was not admitted, or shutdown released its wait.
    NotAdmitted,
    /// The bounded population was already full, so the request was refused
    /// without ever being parked.
    ///
    /// This is not a PermissionSync outcome. The transport terminates the
    /// connection without writing a response, so saturation never changes the
    /// precedence ADR 0001 fixes.
    RefusedWithoutWaiting,
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
    /// Test-only structural observation of the bounded populations.
    #[cfg(test)]
    observer: Observer,
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
            #[cfg(test)]
            observer: Observer::new(),
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

    /// Test-only raw permit acquisition, bypassing the admission decision.
    ///
    /// It exists so a test can hold a permit the way both acquisition paths do
    /// just before [`Self::finalize`] runs, and then drive that decision
    /// directly instead of trying to reproduce the race with timing.
    #[cfg(test)]
    pub(crate) fn acquire_permit_for_test(&self) -> OwnedSemaphorePermit {
        Arc::clone(&self.permits)
            .try_acquire_owned()
            .expect("a free permit")
    }

    /// Test-only access to the shared admission decision.
    #[cfg(test)]
    pub(crate) fn finalize_for_test(
        &self,
        permit: OwnedSemaphorePermit,
        deadline: Instant,
        lifecycle: &Lifecycle,
    ) -> Admission {
        self.finalize(permit, deadline, lifecycle)
    }

    /// Subscribes to the test-only observation of the bounded populations.
    ///
    /// Tests use this to establish, structurally rather than by timing, that a
    /// request has actually reached admission and which population it entered.
    #[cfg(test)]
    pub(crate) fn observe(&self) -> watch::Receiver<AdmissionObservation> {
        self.observer.subscribe()
    }

    /// Admits one synchronization request, or reports that it was not admitted.
    ///
    /// Waiting is bounded by the request's own absolute `deadline`; it creates
    /// no second deadline and never extends the budget. Shutdown releases
    /// pending waits immediately, so a request that has not been admitted
    /// reaches neither body collection nor authentication.
    ///
    /// A request only joins the `permits` wait list while a waiter slot is
    /// free, so that list stays bounded. A request that finds no free slot is
    /// reported as [`Admission::RefusedWithoutWaiting`] straight away: it is not
    /// enqueued, does not sleep, and receives no application outcome, because
    /// the transport refuses it by terminating the connection.
    ///
    /// Dropping the returned future removes the waiter, releases its waiter
    /// slot, and returns any permit already assigned to it, so an abandoned
    /// admission owns nothing.
    pub(crate) async fn admit(&self, deadline: Instant, lifecycle: &Lifecycle) -> Admission {
        if lifecycle.is_shutting_down() || Instant::now() >= deadline {
            counter!(ADMISSION_ABANDONED_TOTAL).increment(1);
            return Admission::NotAdmitted;
        }

        let permits = Arc::clone(&self.permits);
        if let Ok(permit) = permits.clone().try_acquire_owned() {
            return self.finalize(permit, deadline, lifecycle);
        }

        counter!(ADMISSION_SATURATED_TOTAL).increment(1);
        let Ok(waiter_slot) = Arc::clone(&self.waiters).try_acquire_owned() else {
            // The bounded population is full. Refuse now rather than parking
            // this request anywhere: parking it outside the population is
            // exactly the unbounded waiting area the bound exists to prevent.
            // Deliberately not counted as abandoned: nothing was waiting, and
            // the dedicated refusal counter is what ADR 0006 needs for local
            // saturation rejection.
            counter!(ADMISSION_REFUSED_TOTAL).increment(1);
            #[cfg(test)]
            self.observer.refused_without_waiting();
            return Admission::RefusedWithoutWaiting;
        };

        // Inside the bounded population: park until a permit frees, this
        // request's own deadline expires, or shutdown releases the wait.
        let waiting = self.waiting();
        let admitted = tokio::select! {
            biased;
            () = lifecycle.shutdown_started() => None,
            permit = permits.acquire_owned() => permit.ok(),
            () = sleep_until(TokioInstant::from_std(deadline)) => None,
        };
        drop(waiting);
        drop(waiter_slot);

        match admitted {
            Some(permit) => self.finalize(permit, deadline, lifecycle),
            None => {
                counter!(ADMISSION_ABANDONED_TOTAL).increment(1);
                Admission::NotAdmitted
            }
        }
    }

    /// Decides whether an already-acquired permit may actually admit its
    /// request, and releases it if not.
    ///
    /// Acquiring a permit is not the admission decision, because shutdown can
    /// begin between the check that found the process serving and the
    /// acquisition that followed it. Both acquisition paths therefore end here,
    /// and this lifecycle read is the admission linearization point: observing
    /// serving state orders this admission before any later
    /// [`Lifecycle::begin_shutdown`] store, and observing shutdown releases the
    /// permit instead. Because `shutting_down` is stored and loaded with
    /// `SeqCst`, those two outcomes are the only ones possible.
    ///
    /// The request's own absolute deadline is re-checked for the same reason:
    /// it may have expired while the permit was being obtained. Neither
    /// rejection enters the in-flight gauge or the admitted population, and
    /// both are counted as abandoned exactly like the pre-acquisition checks.
    fn finalize(
        &self,
        permit: OwnedSemaphorePermit,
        deadline: Instant,
        lifecycle: &Lifecycle,
    ) -> Admission {
        if lifecycle.is_shutting_down() || Instant::now() >= deadline {
            // Dropping the permit returns it before any admitted state exists,
            // so a request rejected here owns nothing.
            drop(permit);
            counter!(ADMISSION_ABANDONED_TOTAL).increment(1);
            return Admission::NotAdmitted;
        }

        Admission::Admitted(self.admitted(permit))
    }

    fn admitted(&self, permit: OwnedSemaphorePermit) -> AdmittedRequest {
        AdmittedRequest::new(
            permit,
            #[cfg(test)]
            self.observer.clone(),
        )
    }

    fn waiting(&self) -> WaitingGuard {
        WaitingGuard::new(
            #[cfg(test)]
            self.observer.clone(),
        )
    }
}

/// A held admission permit, released on drop.
///
/// It is held for the complete handling of one synchronization request,
/// including its cancellation and error paths, so no permit can survive the
/// request that owns it.
pub(crate) struct AdmittedRequest {
    _permit: OwnedSemaphorePermit,
    #[cfg(test)]
    observer: Observer,
}

impl AdmittedRequest {
    fn new(permit: OwnedSemaphorePermit, #[cfg(test)] observer: Observer) -> Self {
        gauge!(REQUESTS_IN_FLIGHT).increment(1.0);
        #[cfg(test)]
        observer.enter_admitted();
        Self {
            _permit: permit,
            #[cfg(test)]
            observer,
        }
    }
}

impl Drop for AdmittedRequest {
    fn drop(&mut self) {
        gauge!(REQUESTS_IN_FLIGHT).decrement(1.0);
        #[cfg(test)]
        self.observer.leave_admitted();
    }
}

/// Keeps the admission-waiter gauge exact on every exit path, including a
/// dropped request future.
struct WaitingGuard {
    #[cfg(test)]
    observer: Observer,
}

impl WaitingGuard {
    fn new(#[cfg(test)] observer: Observer) -> Self {
        gauge!(ADMISSION_WAITERS).increment(1.0);
        #[cfg(test)]
        observer.enter_waiting();
        Self {
            #[cfg(test)]
            observer,
        }
    }
}

impl Drop for WaitingGuard {
    fn drop(&mut self) {
        gauge!(ADMISSION_WAITERS).decrement(1.0);
        #[cfg(test)]
        self.observer.leave_waiting();
    }
}

/// Test-only structural observation of the bounded admission populations.
///
/// It exists so tests can prove that a request actually reached admission and
/// which population it entered, instead of inferring it from timing. It is
/// compiled only for tests and is never part of a release artifact.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AdmissionObservation {
    /// Requests currently holding an admission permit.
    pub(crate) admitted: usize,
    /// Requests currently parked in the bounded wait list.
    pub(crate) waiting: usize,
    /// Requests refused because the bounded population was already full.
    pub(crate) refused_without_waiting: usize,
}

#[cfg(test)]
#[derive(Clone)]
struct Observer(Arc<watch::Sender<AdmissionObservation>>);

#[cfg(test)]
impl Observer {
    fn new() -> Self {
        Self(Arc::new(
            watch::Sender::new(AdmissionObservation::default()),
        ))
    }

    fn subscribe(&self) -> watch::Receiver<AdmissionObservation> {
        self.0.subscribe()
    }

    fn enter_admitted(&self) {
        self.0.send_modify(|observation| observation.admitted += 1);
    }

    fn leave_admitted(&self) {
        self.0.send_modify(|observation| observation.admitted -= 1);
    }

    fn enter_waiting(&self) {
        self.0.send_modify(|observation| observation.waiting += 1);
    }

    fn leave_waiting(&self) {
        self.0.send_modify(|observation| observation.waiting -= 1);
    }

    fn refused_without_waiting(&self) {
        self.0
            .send_modify(|observation| observation.refused_without_waiting += 1);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::{Future, poll_fn},
        num::NonZeroUsize,
        pin::Pin,
        sync::Arc,
        task::Poll,
        time::{Duration, Instant},
    };

    use tokio::sync::Semaphore;

    use super::{
        Admission, AdmissionObservation, AdmittedRequest, InboundAdmission,
        derived_semaphore_sizes, max_inbound_admission_limit, waiter_slots,
    };
    use crate::runtime::lifecycle::Lifecycle;

    /// A bound that only ever fires when the implementation is wrong; it never
    /// establishes ordering, which the observation channel does.
    const DEADLOCK_BOUND: Duration = Duration::from_secs(10);

    /// Polls a future exactly once, so a test can park a waiter
    /// deterministically instead of assuming the scheduler ran it.
    async fn poll_once<F>(future: &mut Pin<Box<F>>) -> Poll<F::Output>
    where
        F: Future,
    {
        poll_fn(|context| Poll::Ready(future.as_mut().poll(context))).await
    }

    fn nonzero(value: usize) -> NonZeroUsize {
        NonZeroUsize::new(value).expect("test values are positive")
    }

    fn admission(limit: usize) -> InboundAdmission {
        InboundAdmission::new(nonzero(limit)).expect("test limits are constructible")
    }

    fn far_future() -> Instant {
        Instant::now() + Duration::from_secs(3600)
    }

    /// Admits one request, requiring success.
    async fn admit(admission: &InboundAdmission, lifecycle: &Lifecycle) -> AdmittedRequest {
        match admission.admit(far_future(), lifecycle).await {
            Admission::Admitted(admitted) => admitted,
            Admission::NotAdmitted | Admission::RefusedWithoutWaiting => {
                panic!("the configured limit must be admissible")
            }
        }
    }

    /// Waits until the bounded populations reach an expected shape.
    ///
    /// This is the synchronization mechanism the tests rely on: it observes real
    /// admission state rather than assuming a scheduling order.
    async fn await_observation(
        admission: &InboundAdmission,
        expected: impl FnMut(&AdmissionObservation) -> bool,
    ) -> AdmissionObservation {
        let mut observation = admission.observe();
        let reached = tokio::time::timeout(DEADLOCK_BOUND, observation.wait_for(expected))
            .await
            .expect("the expected admission state must be reached")
            .expect("the observation channel stays open");
        *reached
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

        let first = admit(&admission, &lifecycle).await;
        let second = admit(&admission, &lifecycle).await;
        assert_eq!(admission.available_permits(), 0);

        let third = admission
            .admit(Instant::now() + Duration::from_millis(20), &lifecycle)
            .await;
        assert!(
            matches!(third, Admission::NotAdmitted),
            "a third request must not be admitted"
        );

        drop(first);
        drop(second);
        assert_eq!(admission.available_permits(), 2);
    }

    /// Once both bounded populations are full, a further request is refused
    /// immediately instead of parking anywhere, and it says so, so the transport
    /// can turn the refusal into transport backpressure.
    #[tokio::test]
    async fn a_request_beyond_the_bounded_population_is_refused_without_waiting() {
        let admission = Arc::new(admission(1));
        let lifecycle = Arc::new(Lifecycle::new());
        let held = admit(&admission, &lifecycle).await;

        // Occupy the single waiter slot, and prove structurally that the waiting
        // request really is parked in the bounded population.
        let waiting = {
            let admission = Arc::clone(&admission);
            let lifecycle = Arc::clone(&lifecycle);
            tokio::spawn(async move {
                matches!(
                    admission.admit(far_future(), &lifecycle).await,
                    Admission::Admitted(_)
                )
            })
        };
        await_observation(&admission, |observation| observation.waiting == 1).await;

        // A further request must be refused immediately: it never becomes a
        // waiter and never sleeps to its deadline.
        for _ in 0..8 {
            let refused = admission.admit(far_future(), &lifecycle).await;
            assert!(
                matches!(refused, Admission::RefusedWithoutWaiting),
                "a request beyond the bounded population must be refused"
            );
        }
        let observation = await_observation(&admission, |observation| {
            observation.refused_without_waiting == 8
        })
        .await;
        assert_eq!(
            observation.waiting, 1,
            "refused requests must not enlarge the waiting population"
        );
        assert_eq!(observation.admitted, 1);

        // The legitimate waiter still proceeds once the permit frees.
        drop(held);
        assert!(
            tokio::time::timeout(DEADLOCK_BOUND, waiting)
                .await
                .expect("the waiter must be woken by the freed permit")
                .expect("waiter task must not panic"),
            "a waiting request proceeds when capacity becomes available"
        );
        assert_eq!(admission.available_permits(), 1);
        assert_eq!(admission.available_waiter_slots(), 1);
    }

    /// A refusal must never consume a permit or a waiter slot.
    #[tokio::test]
    async fn a_refused_request_holds_nothing() {
        let admission = Arc::new(admission(1));
        let lifecycle = Arc::new(Lifecycle::new());
        let held = admit(&admission, &lifecycle).await;

        let waiting = {
            let admission = Arc::clone(&admission);
            let lifecycle = Arc::clone(&lifecycle);
            tokio::spawn(async move { admission.admit(far_future(), &lifecycle).await })
        };
        await_observation(&admission, |observation| observation.waiting == 1).await;

        assert!(matches!(
            admission.admit(far_future(), &lifecycle).await,
            Admission::RefusedWithoutWaiting
        ));
        assert_eq!(admission.available_permits(), 0);
        assert_eq!(admission.available_waiter_slots(), 0);

        drop(held);
        let _ = tokio::time::timeout(DEADLOCK_BOUND, waiting).await;
        assert_eq!(admission.available_waiter_slots(), 1);
    }

    /// An admission wait consumes the request's own budget and nothing more.
    #[tokio::test(start_paused = true)]
    async fn a_saturated_wait_ends_at_the_request_deadline() {
        let admission = admission(1);
        let lifecycle = Lifecycle::new();
        let held = admit(&admission, &lifecycle).await;

        let deadline = Instant::now() + Duration::from_secs(2);
        assert!(matches!(
            admission.admit(deadline, &lifecycle).await,
            Admission::NotAdmitted
        ));

        drop(held);
        assert_eq!(admission.available_permits(), 1);
    }

    #[tokio::test]
    async fn an_already_expired_deadline_is_not_admitted() {
        let admission = admission(1);
        let lifecycle = Lifecycle::new();

        assert!(matches!(
            admission
                .admit(Instant::now() - Duration::from_secs(1), &lifecycle)
                .await,
            Admission::NotAdmitted
        ));
        assert_eq!(admission.available_permits(), 1);
    }

    #[tokio::test]
    async fn shutdown_admits_no_further_request() {
        let admission = admission(1);
        let lifecycle = Lifecycle::new();
        lifecycle.begin_shutdown();

        assert!(matches!(
            admission.admit(far_future(), &lifecycle).await,
            Admission::NotAdmitted
        ));
        assert_eq!(admission.available_permits(), 1);
    }

    /// A wait already in flight must be released by shutdown, long before its
    /// own deadline, and must leave no permit or waiter behind.
    #[tokio::test]
    async fn shutdown_releases_a_pending_admission_wait() {
        let admission = Arc::new(admission(1));
        let lifecycle = Arc::new(Lifecycle::new());
        let held = admit(&admission, &lifecycle).await;

        let waiting = {
            let admission = Arc::clone(&admission);
            let lifecycle = Arc::clone(&lifecycle);
            tokio::spawn(async move {
                matches!(
                    admission.admit(far_future(), &lifecycle).await,
                    Admission::Admitted(_)
                )
            })
        };
        // Observed admission state, not a scheduling assumption, establishes
        // that the waiter is really parked before shutdown begins.
        await_observation(&admission, |observation| observation.waiting == 1).await;

        lifecycle.begin_shutdown();
        let admitted = tokio::time::timeout(DEADLOCK_BOUND, waiting)
            .await
            .expect("shutdown must release the pending wait")
            .expect("waiter task must not panic");

        assert!(!admitted, "a released wait is not an admission");
        drop(held);
        assert_eq!(admission.available_permits(), 1);
        assert_eq!(admission.available_waiter_slots(), 1);
    }

    /// Dropping the admission future, as happens when a request is abandoned
    /// or its task is terminated, must not retain a reservation.
    #[tokio::test(start_paused = true)]
    async fn dropping_an_unfinished_admission_leaves_no_reservation() {
        let admission = admission(1);
        let lifecycle = Lifecycle::new();
        let held = admit(&admission, &lifecycle).await;

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
        assert_eq!(admission.available_waiter_slots(), 1);
        assert!(matches!(
            admission.admit(far_future(), &lifecycle).await,
            Admission::Admitted(_)
        ));
    }
    /// The decisive shutdown race: a permit acquired while the process was
    /// still serving must not admit its request once shutdown has begun.
    ///
    /// Both acquisition paths end in the same finalization, so driving it
    /// directly proves the property for both without reproducing the timing.
    #[test]
    fn a_permit_acquired_before_shutdown_does_not_admit_after_it() {
        let admission = admission(1);
        let lifecycle = Lifecycle::new();
        let mut observation = admission.observe();

        // Held exactly as both paths hold it immediately before deciding.
        let permit = admission.acquire_permit_for_test();
        assert_eq!(admission.available_permits(), 0);

        // Shutdown wins the race.
        lifecycle.begin_shutdown();

        let decision =
            admission.finalize_for_test(permit, Instant::now() + DEADLOCK_BOUND, &lifecycle);

        assert!(
            matches!(decision, Admission::NotAdmitted),
            "a request may not be admitted once shutdown has begun"
        );
        assert_eq!(
            admission.available_permits(),
            1,
            "the permit must be released, not held by a rejected request"
        );
        assert_eq!(
            *observation.borrow_and_update(),
            AdmissionObservation::default(),
            "no request may enter the admitted population"
        );
    }

    /// The same finalization also catches a deadline that expired while the
    /// permit was being obtained.
    #[test]
    fn a_permit_acquired_for_an_expired_request_does_not_admit_it() {
        let admission = admission(1);
        let lifecycle = Lifecycle::new();
        let mut observation = admission.observe();

        let permit = admission.acquire_permit_for_test();
        let expired = Instant::now() - Duration::from_secs(1);

        let decision = admission.finalize_for_test(permit, expired, &lifecycle);

        assert!(matches!(decision, Admission::NotAdmitted));
        assert_eq!(admission.available_permits(), 1);
        assert_eq!(
            *observation.borrow_and_update(),
            AdmissionObservation::default()
        );
    }

    /// Finalization still admits a request that really is within its budget
    /// while the process is serving, so the checks above reject nothing else.
    #[test]
    fn a_permit_acquired_while_serving_admits_its_request() {
        let admission = admission(1);
        let lifecycle = Lifecycle::new();

        let permit = admission.acquire_permit_for_test();
        let decision =
            admission.finalize_for_test(permit, Instant::now() + DEADLOCK_BOUND, &lifecycle);

        let admitted = match decision {
            Admission::Admitted(admitted) => admitted,
            Admission::NotAdmitted | Admission::RefusedWithoutWaiting => {
                panic!("a serving process within budget must admit")
            }
        };
        assert_eq!(admission.available_permits(), 0);
        drop(admitted);
        assert_eq!(admission.available_permits(), 1);
    }

    /// The waiter path must share that finalization, so a waiter woken by a
    /// freed permit during draining is not admitted either.
    ///
    /// The wait is released by shutdown rather than by the permit here, which
    /// is the ordering ADR 0011 requires; the assertion that matters is that
    /// nothing was admitted and nothing was retained.
    #[tokio::test]
    async fn a_waiter_woken_during_shutdown_is_not_admitted() {
        let admission = admission(1);
        let lifecycle = Lifecycle::new();
        let held = match admission
            .admit(Instant::now() + DEADLOCK_BOUND, &lifecycle)
            .await
        {
            Admission::Admitted(admitted) => admitted,
            Admission::NotAdmitted | Admission::RefusedWithoutWaiting => {
                panic!("the first request must be admitted")
            }
        };

        let mut waiting = Box::pin(admission.admit(Instant::now() + DEADLOCK_BOUND, &lifecycle));
        // One poll parks the waiter deterministically.
        assert!(
            poll_once(&mut waiting).await.is_pending(),
            "the saturated request must park"
        );

        lifecycle.begin_shutdown();
        drop(held);

        let decision = tokio::time::timeout(DEADLOCK_BOUND, waiting)
            .await
            .expect("the released waiter must answer");
        assert!(
            matches!(decision, Admission::NotAdmitted),
            "a waiter must not be admitted during draining"
        );
        assert_eq!(
            admission.available_permits(),
            1,
            "no permit may survive the rejected waiter"
        );
        assert_eq!(admission.available_waiter_slots(), 1);
    }
}
