//! The GLPI Target Adapter: orchestrates the mandatory operation order from
//! ADR 0009 end to end. See the crate-level documentation for the full
//! contract.

use std::time::{Duration, Instant};

use permissionsync_core::{
    BoxFuture, ReconciliationOutcome, SynchronizationContext, TargetAdapter, TargetAdapterError,
    TargetAdapterRequest,
};

use crate::{
    config::{GlpiAdapterConfig, ValidatedConfig, validate},
    error::{GlpiAdapterConfigError, GlpiFailure},
    mutation, payload, plan,
    search::{
        self, REQUIRED_ENTITY_UIDS, REQUIRED_PROFILE_UIDS, REQUIRED_PROFILE_USER_UIDS,
        REQUIRED_USER_UIDS, SearchOptions,
    },
    session::{self, GlpiSession},
};

/// The GLPI Target Adapter. Reconciles one synchronized user's complete
/// `Profile_User` assignment set against a v1 desired-state payload.
pub struct GlpiAdapter {
    config: ValidatedConfig,
}

impl GlpiAdapter {
    /// Validates the given adapter-local configuration and constructs a new
    /// adapter instance. All static configuration is validated eagerly;
    /// no GLPI request is made during construction.
    pub fn new(config: GlpiAdapterConfig) -> Result<Self, GlpiAdapterConfigError> {
        Ok(Self {
            config: validate(config)?,
        })
    }
}

impl TargetAdapter for GlpiAdapter {
    fn reconcile<'a>(
        &'a self,
        request: TargetAdapterRequest<'a>,
    ) -> BoxFuture<'a, Result<ReconciliationOutcome, TargetAdapterError>> {
        Box::pin(async move {
            reconcile(&self.config, request)
                .await
                .map_err(TargetAdapterError::new)
        })
    }
}

fn effective_deadline(
    context: &SynchronizationContext<'_>,
    operation_timeout: Duration,
) -> Result<Instant, GlpiFailure> {
    if context.cancellation().is_cancelled() {
        return Err(GlpiFailure::Cancelled);
    }
    let now = Instant::now();
    if context.deadline() <= now {
        return Err(GlpiFailure::DeadlineExceeded);
    }
    let operation_deadline = now
        .checked_add(operation_timeout)
        .unwrap_or(context.deadline());
    Ok(context.deadline().min(operation_deadline))
}

pub(crate) fn check_context(
    context: &SynchronizationContext<'_>,
    deadline: Instant,
) -> Result<(), GlpiFailure> {
    if context.cancellation().is_cancelled() {
        return Err(GlpiFailure::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(GlpiFailure::DeadlineExceeded);
    }
    Ok(())
}

async fn reconcile(
    config: &ValidatedConfig,
    request: TargetAdapterRequest<'_>,
) -> Result<ReconciliationOutcome, GlpiFailure> {
    let context = request.context();
    check_context(context, context.deadline())?;

    if request.desired_state().version().get() != 1 {
        return Err(GlpiFailure::UnsupportedEnvelopeVersion);
    }

    let desired = payload::parse_and_normalize(request.desired_state().payload().as_json())?;

    // Each outbound operation gets its own freshly recomputed
    // `min(overall_deadline, now+operation_timeout)` window immediately
    // before it is issued, rather than a single deadline threaded unchanged
    // through the whole reconciliation. See `effective_deadline`.
    let init_session_deadline = effective_deadline(context, config.operation_timeout)?;
    let session = session::init_session(config, init_session_deadline).await?;
    let outcome = reconcile_with_session(
        config,
        &session,
        request.identity().username(),
        &desired,
        context,
    )
    .await;
    let cleanup_allowed =
        !context.cancellation().is_cancelled() && Instant::now() < context.deadline();

    if cleanup_allowed {
        let cleanup_deadline =
            effective_deadline(context, config.operation_timeout).unwrap_or(init_session_deadline);
        let cleanup_result = session::kill_session(config, &session, cleanup_deadline).await;
        return match (outcome, cleanup_result) {
            (Ok(outcome), Ok(())) => Ok(outcome),
            (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
            (Err(primary_error), _) => Err(primary_error),
        };
    }

    outcome
}

async fn reconcile_with_session(
    config: &ValidatedConfig,
    session: &GlpiSession,
    username: &str,
    desired: &[payload::CanonicalAssignment],
    context: &SynchronizationContext<'_>,
) -> Result<ReconciliationOutcome, GlpiFailure> {
    let deadline = effective_deadline(context, config.operation_timeout)?;
    session::force_all_entities(config, session, deadline).await?;
    let deadline = effective_deadline(context, config.operation_timeout)?;
    session::verify_complete_visibility(config, session, deadline).await?;

    let entity_options = if desired.is_empty() {
        None
    } else {
        Some(
            resolve_search_options(config, session, "Entity", REQUIRED_ENTITY_UIDS, context)
                .await?,
        )
    };
    let profile_options = if desired.is_empty() {
        None
    } else {
        Some(
            resolve_search_options(config, session, "Profile", REQUIRED_PROFILE_UIDS, context)
                .await?,
        )
    };
    let user_options =
        resolve_search_options(config, session, "User", REQUIRED_USER_UIDS, context).await?;
    let profile_user_options = resolve_search_options(
        config,
        session,
        "Profile_User",
        REQUIRED_PROFILE_USER_UIDS,
        context,
    )
    .await?;

    // Resolve every unique desired entity/profile reference before any user
    // lookup, creation, or mutation. When there is no desired assignment at
    // all, no Entity or Profile GLPI request is issued: `entity_options`/
    // `profile_options` above are never populated in that case, and the
    // loop below runs zero times regardless.
    let mut resolved_entities: Vec<(String, u64)> = Vec::new();
    let mut resolved_profiles: Vec<(String, u64)> = Vec::new();

    for assignment in desired {
        check_context(context, context.deadline())?;
        if !resolved_entities
            .iter()
            .any(|(selector, _)| selector == &assignment.entity)
        {
            let entity_options = entity_options
                .as_ref()
                .expect("entity_options is populated whenever desired is non-empty");
            let deadline = effective_deadline(context, config.operation_timeout)?;
            let id = search::resolve_entity_id(
                config,
                session,
                entity_options,
                &assignment.entity,
                context,
                deadline,
            )
            .await?;
            resolved_entities.push((assignment.entity.clone(), id));
        }

        check_context(context, context.deadline())?;
        if !resolved_profiles
            .iter()
            .any(|(selector, _)| selector == &assignment.profile)
        {
            let profile_options = profile_options
                .as_ref()
                .expect("profile_options is populated whenever desired is non-empty");
            let deadline = effective_deadline(context, config.operation_timeout)?;
            let id = search::resolve_profile_id(
                config,
                session,
                profile_options,
                &assignment.profile,
                context,
                deadline,
            )
            .await?;
            resolved_profiles.push((assignment.profile.clone(), id));
        }
    }

    let deadline = effective_deadline(context, config.operation_timeout)?;
    let existing_user_id =
        search::resolve_user_id(config, session, &user_options, username, context, deadline)
            .await?;

    let (user_id, mut changed) = match existing_user_id {
        Some(id) => (id, false),
        None => {
            let deadline = effective_deadline(context, config.operation_timeout)?;
            let id = mutation::create_user(
                config,
                session,
                username,
                &config.authentication_source,
                deadline,
            )
            .await?;
            (id, true)
        }
    };

    let deadline = effective_deadline(context, config.operation_timeout)?;
    let current = search::read_current_assignments(
        config,
        session,
        &profile_user_options,
        username,
        user_id,
        context,
        deadline,
    )
    .await?;

    let desired_resolved: Vec<plan::DesiredAssignment> = desired
        .iter()
        .map(|assignment| {
            let entities_id = resolved_entities
                .iter()
                .find(|(selector, _)| selector == &assignment.entity)
                .map(|(_, id)| *id)
                .expect("every desired entity was resolved above");
            let profiles_id = resolved_profiles
                .iter()
                .find(|(selector, _)| selector == &assignment.profile)
                .map(|(_, id)| *id)
                .expect("every desired profile was resolved above");
            plan::DesiredAssignment {
                entities_id,
                profiles_id,
                recursive: assignment.recursive,
            }
        })
        .collect();

    let reconciliation_plan = plan::compute(&current, &desired_resolved);
    if !reconciliation_plan.is_empty() {
        changed = true;
    }

    for assignment_id in &reconciliation_plan.removals {
        let deadline = effective_deadline(context, config.operation_timeout)?;
        mutation::delete_assignment(config, session, *assignment_id, deadline).await?;
    }

    for addition in &reconciliation_plan.additions {
        let deadline = effective_deadline(context, config.operation_timeout)?;
        mutation::create_assignment(
            config,
            session,
            user_id,
            addition.profiles_id,
            addition.entities_id,
            addition.recursive,
            deadline,
        )
        .await?;
    }

    if changed {
        Ok(ReconciliationOutcome::Changed)
    } else {
        Ok(ReconciliationOutcome::Unchanged)
    }
}

async fn resolve_search_options(
    config: &ValidatedConfig,
    session: &GlpiSession,
    itemtype: &str,
    required_uids: &[&'static str],
    context: &SynchronizationContext<'_>,
) -> Result<SearchOptions, GlpiFailure> {
    let deadline = effective_deadline(context, config.operation_timeout)?;
    search::resolve_search_options(config, session, itemtype, required_uids, deadline).await
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use permissionsync_core::{CancellationSignal, SynchronizationContext};

    use super::effective_deadline;
    use crate::error::GlpiFailure;

    struct NeverCancelled;

    impl CancellationSignal for NeverCancelled {
        fn is_cancelled(&self) -> bool {
            false
        }
    }

    /// Operation timeout shorter than the overall deadline: the effective
    /// deadline must be `now + operation_timeout`, not the overall deadline.
    #[test]
    fn effective_deadline_uses_operation_timeout_when_shorter_than_overall_deadline() {
        let cancellation = NeverCancelled;
        let overall_deadline = Instant::now() + Duration::from_secs(60);
        let context = SynchronizationContext::new(overall_deadline, &cancellation);
        let operation_timeout = Duration::from_millis(50);

        let before = Instant::now();
        let deadline =
            effective_deadline(&context, operation_timeout).expect("deadline is computed");
        let after = Instant::now();

        assert!(deadline >= before + operation_timeout);
        assert!(deadline <= after + operation_timeout);
        assert!(deadline < overall_deadline);
    }

    /// Overall deadline shorter than the operation timeout: the effective
    /// deadline must be capped at the overall deadline.
    #[test]
    fn effective_deadline_caps_at_overall_deadline_when_shorter_than_operation_timeout() {
        let cancellation = NeverCancelled;
        let overall_deadline = Instant::now() + Duration::from_millis(10);
        let context = SynchronizationContext::new(overall_deadline, &cancellation);
        let operation_timeout = Duration::from_secs(60);

        let deadline =
            effective_deadline(&context, operation_timeout).expect("deadline is computed");

        assert_eq!(deadline, overall_deadline);
    }

    /// Calling `effective_deadline` again later, for an unrelated subsequent
    /// operation, must yield a fresh `now + operation_timeout` window rather
    /// than a value shrunk by time already consumed by a prior operation.
    #[test]
    fn effective_deadline_is_recomputed_fresh_for_each_call() {
        let cancellation = NeverCancelled;
        let overall_deadline = Instant::now() + Duration::from_secs(60);
        let context = SynchronizationContext::new(overall_deadline, &cancellation);
        let operation_timeout = Duration::from_millis(200);

        let first = effective_deadline(&context, operation_timeout).expect("first deadline");
        std::thread::sleep(Duration::from_millis(50));
        let second = effective_deadline(&context, operation_timeout).expect("second deadline");

        // The second window starts later in wall-clock time than the first,
        // so it must not be earlier than (and should be strictly later
        // than) the first window despite elapsed time between calls.
        assert!(second > first);
    }

    /// No operation may start after the overall deadline: `effective_deadline`
    /// must return an error once `context.deadline()` is already in the past.
    #[test]
    fn effective_deadline_fails_once_overall_deadline_has_passed() {
        let cancellation = NeverCancelled;
        let elapsed_deadline = Instant::now() - Duration::from_millis(10);
        let context = SynchronizationContext::new(elapsed_deadline, &cancellation);
        let operation_timeout = Duration::from_secs(60);

        let result = effective_deadline(&context, operation_timeout);

        assert!(matches!(result, Err(GlpiFailure::DeadlineExceeded)));
    }

    #[test]
    fn effective_deadline_fails_when_cancelled() {
        struct AlwaysCancelled;

        impl CancellationSignal for AlwaysCancelled {
            fn is_cancelled(&self) -> bool {
                true
            }
        }

        let cancellation = AlwaysCancelled;
        let overall_deadline = Instant::now() + Duration::from_secs(60);
        let context = SynchronizationContext::new(overall_deadline, &cancellation);

        let result = effective_deadline(&context, Duration::from_secs(1));

        assert!(matches!(result, Err(GlpiFailure::Cancelled)));
    }
}
