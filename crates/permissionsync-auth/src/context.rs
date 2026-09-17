//! Shared per-request context propagation helpers: cancellation/deadline
//! checks and deadline arithmetic used throughout an authentication attempt.

use std::time::{Duration, Instant};

use permissionsync_core::SynchronizationContext;

use crate::error::AuthenticationError;

pub(crate) fn check_context(
    context: &SynchronizationContext<'_>,
) -> Result<(), AuthenticationError> {
    if context.cancellation().is_cancelled() || Instant::now() >= context.deadline() {
        Err(AuthenticationError::Cancelled)
    } else {
        Ok(())
    }
}

/// Which budget a computed deadline instant is limited by. Carried explicitly
/// so that a later timer firing can be classified deterministically, instead
/// of re-inferring the cause from a fresh `Instant::now()` comparison at fire
/// time (which can itself race against the deadline it is trying to explain).
#[derive(Clone, Copy)]
pub(crate) enum DeadlineCause {
    /// The overall `SynchronizationContext` request budget is the limiting
    /// instant: a timer firing here must be `Cancelled`.
    OverallRequest,
    /// The bounded per-operation metadata timeout is the limiting instant: a
    /// timer firing here must be `VerifierUnavailable`, not `Cancelled`.
    MetadataOperation,
}

/// A deadline instant paired with the reason it was selected as the limiting
/// bound, so a later `timeout_at` firing can be classified deterministically.
#[derive(Clone, Copy)]
pub(crate) struct EffectiveDeadline {
    pub(crate) instant: Instant,
    pub(crate) cause: DeadlineCause,
}

pub(crate) fn effective_deadline(
    context: &SynchronizationContext<'_>,
    operation_timeout: Duration,
) -> Result<EffectiveDeadline, AuthenticationError> {
    check_context(context)?;
    let overall = context.deadline();
    let operation = Instant::now()
        .checked_add(operation_timeout)
        .unwrap_or(overall);
    if overall <= operation {
        Ok(EffectiveDeadline {
            instant: overall,
            cause: DeadlineCause::OverallRequest,
        })
    } else {
        Ok(EffectiveDeadline {
            instant: operation,
            cause: DeadlineCause::MetadataOperation,
        })
    }
}

/// Classifies a fired `timeout_at` deterministically from the deadline's
/// recorded cause, rather than re-inferring it from a fresh `Instant::now()`
/// comparison (which can itself race against the very deadline it explains).
/// Explicit propagated cancellation always takes precedence.
pub(crate) fn timeout_error(
    context: &SynchronizationContext<'_>,
    cause: DeadlineCause,
) -> AuthenticationError {
    if context.cancellation().is_cancelled() {
        return AuthenticationError::Cancelled;
    }
    match cause {
        DeadlineCause::OverallRequest => AuthenticationError::Cancelled,
        DeadlineCause::MetadataOperation => AuthenticationError::VerifierUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use permissionsync_core::CancellationSignal;

    use super::*;

    struct NotCancelled;

    impl CancellationSignal for NotCancelled {
        fn is_cancelled(&self) -> bool {
            false
        }
    }

    #[test]
    fn cancelled_context_prevents_authentication_before_any_io() {
        let cancellation = NotCancelled;
        let context = SynchronizationContext::new(std::time::Instant::now(), &cancellation);
        assert_eq!(check_context(&context), Err(AuthenticationError::Cancelled));
    }

    #[test]
    fn effective_deadline_selects_the_limiting_cause() {
        let cancellation = NotCancelled;
        let now = Instant::now();

        let short_overall =
            SynchronizationContext::new(now + Duration::from_millis(5), &cancellation);
        let selected = effective_deadline(&short_overall, Duration::from_secs(30)).unwrap();
        assert!(matches!(selected.cause, DeadlineCause::OverallRequest));

        let long_overall =
            SynchronizationContext::new(now + Duration::from_secs(30), &cancellation);
        let selected = effective_deadline(&long_overall, Duration::from_millis(5)).unwrap();
        assert!(matches!(selected.cause, DeadlineCause::MetadataOperation));
    }

    #[test]
    fn timeout_error_maps_cause_to_the_correct_category() {
        let cancellation = NotCancelled;
        let context =
            SynchronizationContext::new(Instant::now() + Duration::from_secs(30), &cancellation);
        assert_eq!(
            timeout_error(&context, DeadlineCause::OverallRequest),
            AuthenticationError::Cancelled
        );
        assert_eq!(
            timeout_error(&context, DeadlineCause::MetadataOperation),
            AuthenticationError::VerifierUnavailable
        );
    }
}
