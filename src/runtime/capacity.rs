//! The concrete selected-target synchronization capacity: one process-local
//! Tokio semaphore.
//!
//! This is the only implementation of the existing
//! [`SynchronizationCapacity`] port. It adds no queue, no distributed
//! coordination, no persistence, no fairness protocol, and no retry: a permit
//! is either acquired within the request's own absolute deadline or the request
//! follows the existing capacity-unavailable server-side path.
//!
//! Inbound admission is a separate, earlier boundary with its own semaphore;
//! see [`crate::runtime::admission`].

use std::{num::NonZeroUsize, sync::Arc, time::Instant};

use metrics::{counter, gauge};
use permissionsync_core::{BoxFuture, SynchronizationContext};
use permissionsync_orchestration::{
    SynchronizationCapacity, SynchronizationCapacityError, SynchronizationPermit,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{Instant as TokioInstant, timeout_at},
};

use crate::runtime::{
    configuration::MAX_SYNCHRONIZATION_CAPACITY,
    observability::{CAPACITY_IN_USE, CAPACITY_SATURATED_TOTAL, CAPACITY_UNAVAILABLE_TOTAL},
};

/// The ADR 0011 product ceiling must stay constructible as a Tokio semaphore.
/// Tokio panics above `Semaphore::MAX_PERMITS`, so this is proven here rather
/// than assumed.
const _: () = assert!(MAX_SYNCHRONIZATION_CAPACITY <= Semaphore::MAX_PERMITS);

/// Bounded selected-target synchronization capacity backed by one semaphore.
pub(crate) struct SemaphoreCapacity {
    permits: Arc<Semaphore>,
}

impl SemaphoreCapacity {
    /// Creates capacity for a positive permit count within the product ceiling.
    ///
    /// Returns `None` above [`MAX_SYNCHRONIZATION_CAPACITY`]; configuration
    /// validation rejects such a value before startup completes.
    pub(crate) fn new(capacity: NonZeroUsize) -> Option<Self> {
        (capacity.get() <= MAX_SYNCHRONIZATION_CAPACITY).then(|| Self {
            permits: Arc::new(Semaphore::new(capacity.get())),
        })
    }

    /// Returns the permits not currently held, for deliberate inspection.
    #[cfg(test)]
    pub(crate) fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }
}

/// One held unit of synchronization capacity.
///
/// Release happens only through [`Drop`], so normal completion, an error, and
/// cancellation all release exactly once.
struct HeldPermit {
    _permit: OwnedSemaphorePermit,
}

impl SynchronizationPermit for HeldPermit {}

impl Drop for HeldPermit {
    fn drop(&mut self) {
        gauge!(CAPACITY_IN_USE).decrement(1.0);
    }
}

impl SynchronizationCapacity for SemaphoreCapacity {
    fn acquire<'a>(
        &'a self,
        context: &'a SynchronizationContext<'a>,
    ) -> BoxFuture<
        'a,
        Result<Box<dyn SynchronizationPermit + Send + 'a>, SynchronizationCapacityError>,
    > {
        Box::pin(async move {
            if unavailable(context) {
                counter!(CAPACITY_UNAVAILABLE_TOTAL).increment(1);
                return Err(SynchronizationCapacityError);
            }

            let permits = Arc::clone(&self.permits);
            let permit = match permits.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    counter!(CAPACITY_SATURATED_TOTAL).increment(1);
                    // Race acquisition against the one absolute request
                    // deadline. Dropping this future on expiry removes the
                    // waiter and returns any permit already assigned to it, so
                    // an abandoned acquisition owns no reservation.
                    match timeout_at(
                        TokioInstant::from_std(context.deadline()),
                        permits.acquire_owned(),
                    )
                    .await
                    {
                        Ok(Ok(permit)) => permit,
                        Ok(Err(_)) | Err(_) => {
                            counter!(CAPACITY_UNAVAILABLE_TOTAL).increment(1);
                            return Err(SynchronizationCapacityError);
                        }
                    }
                }
            };

            // Cancellation or expiry observed while waiting starts no Provider
            // or Adapter work; dropping the permit here releases capacity.
            if unavailable(context) {
                drop(permit);
                counter!(CAPACITY_UNAVAILABLE_TOTAL).increment(1);
                return Err(SynchronizationCapacityError);
            }

            gauge!(CAPACITY_IN_USE).increment(1.0);
            Ok(Box::new(HeldPermit { _permit: permit })
                as Box<dyn SynchronizationPermit + Send + 'a>)
        })
    }
}

fn unavailable(context: &SynchronizationContext<'_>) -> bool {
    context.cancellation().is_cancelled() || Instant::now() >= context.deadline()
}

#[cfg(test)]
mod tests {
    use std::{
        num::NonZeroUsize,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::{Duration, Instant},
    };

    use permissionsync_core::{CancellationSignal, SynchronizationContext};
    use permissionsync_orchestration::SynchronizationCapacity;

    use super::{MAX_SYNCHRONIZATION_CAPACITY, SemaphoreCapacity};

    struct NeverCancelled;
    impl CancellationSignal for NeverCancelled {
        fn is_cancelled(&self) -> bool {
            false
        }
    }

    struct Cancelled;
    impl CancellationSignal for Cancelled {
        fn is_cancelled(&self) -> bool {
            true
        }
    }

    #[derive(Default)]
    struct Toggle(AtomicBool);
    impl CancellationSignal for Toggle {
        fn is_cancelled(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn capacity(permits: usize) -> SemaphoreCapacity {
        SemaphoreCapacity::new(NonZeroUsize::new(permits).unwrap()).unwrap()
    }

    fn far_future() -> Instant {
        Instant::now() + Duration::from_secs(3600)
    }

    #[test]
    fn the_product_ceiling_is_enforced_at_construction() {
        assert!(SemaphoreCapacity::new(NonZeroUsize::new(1).unwrap()).is_some());
        assert!(
            SemaphoreCapacity::new(NonZeroUsize::new(MAX_SYNCHRONIZATION_CAPACITY).unwrap())
                .is_some()
        );
        assert!(
            SemaphoreCapacity::new(NonZeroUsize::new(MAX_SYNCHRONIZATION_CAPACITY + 1).unwrap())
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_permit_is_held_until_dropped_and_then_released() {
        let capacity = capacity(1);
        let cancellation = NeverCancelled;
        let context = SynchronizationContext::new(far_future(), &cancellation);

        assert_eq!(capacity.available_permits(), 1);
        let permit = capacity.acquire(&context).await.expect("first permit");
        assert_eq!(capacity.available_permits(), 0);
        drop(permit);
        assert_eq!(capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn acquisition_is_refused_when_cancellation_is_already_observed() {
        let capacity = capacity(1);
        let cancellation = Cancelled;
        let context = SynchronizationContext::new(far_future(), &cancellation);

        assert!(capacity.acquire(&context).await.is_err());
        assert_eq!(capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn acquisition_is_refused_when_the_deadline_already_expired() {
        let capacity = capacity(1);
        let cancellation = NeverCancelled;
        let context =
            SynchronizationContext::new(Instant::now() - Duration::from_secs(1), &cancellation);

        assert!(capacity.acquire(&context).await.is_err());
        assert_eq!(capacity.available_permits(), 1);
    }

    /// A saturated semaphore must fail at the request's own deadline, not wait
    /// past it, and must leave no waiter or reservation behind.
    #[tokio::test(start_paused = true)]
    async fn a_saturated_wait_ends_at_the_request_deadline_without_a_reservation() {
        let capacity = capacity(1);
        let cancellation = NeverCancelled;
        let held_context = SynchronizationContext::new(far_future(), &cancellation);
        let held = capacity.acquire(&held_context).await.expect("held permit");

        let waiting_context =
            SynchronizationContext::new(Instant::now() + Duration::from_secs(1), &cancellation);
        assert!(capacity.acquire(&waiting_context).await.is_err());

        // The abandoned acquisition owns nothing: releasing the only held
        // permit makes capacity fully available again.
        drop(held);
        assert_eq!(capacity.available_permits(), 1);
    }

    /// Dropping the acquire future itself, rather than letting it time out,
    /// must also leave no reservation.
    #[tokio::test(start_paused = true)]
    async fn dropping_an_unfinished_acquisition_leaves_no_reservation() {
        let capacity = capacity(1);
        let cancellation = NeverCancelled;
        let held_context = SynchronizationContext::new(far_future(), &cancellation);
        let held = capacity.acquire(&held_context).await.expect("held permit");

        let abandoned_context = SynchronizationContext::new(far_future(), &cancellation);
        let mut abandoned = Box::pin(capacity.acquire(&abandoned_context));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut abandoned)
                .await
                .is_err(),
            "a saturated acquisition must not complete"
        );
        drop(abandoned);
        drop(held);

        assert_eq!(capacity.available_permits(), 1);
        let context = SynchronizationContext::new(far_future(), &cancellation);
        assert!(capacity.acquire(&context).await.is_ok());
    }

    /// Cancellation observed after the permit was assigned must still release
    /// it and refuse the acquisition.
    #[tokio::test]
    async fn cancellation_after_assignment_releases_the_permit() {
        let capacity = capacity(1);
        let cancellation = Arc::new(Toggle::default());
        let signal = Arc::clone(&cancellation);

        let permits_before = capacity.available_permits();
        let context = SynchronizationContext::new(far_future(), signal.as_ref());
        // Cancel before acquisition observes its post-acquire check.
        cancellation.0.store(true, Ordering::SeqCst);
        assert!(capacity.acquire(&context).await.is_err());
        assert_eq!(capacity.available_permits(), permits_before);
    }

    #[tokio::test]
    async fn concurrent_holders_never_exceed_the_configured_capacity() {
        let capacity = capacity(2);
        let cancellation = NeverCancelled;
        let first_context = SynchronizationContext::new(far_future(), &cancellation);
        let second_context = SynchronizationContext::new(far_future(), &cancellation);

        let first = capacity.acquire(&first_context).await.expect("first");
        let second = capacity.acquire(&second_context).await.expect("second");
        assert_eq!(capacity.available_permits(), 0);

        let third_context =
            SynchronizationContext::new(Instant::now() + Duration::from_millis(20), &cancellation);
        assert!(capacity.acquire(&third_context).await.is_err());

        drop(first);
        drop(second);
        assert_eq!(capacity.available_permits(), 2);
    }
}
