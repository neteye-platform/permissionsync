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

fn check_context(
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

    let deadline = effective_deadline(context, config.operation_timeout)?;
    check_context(context, deadline)?;

    let session = session::init_session(config, deadline).await?;
    let outcome = reconcile_with_session(
        config,
        &session,
        request.identity().username(),
        &desired,
        context,
        deadline,
    )
    .await;
    let cleanup_allowed =
        !context.cancellation().is_cancelled() && Instant::now() < context.deadline();

    if cleanup_allowed {
        let cleanup_deadline =
            effective_deadline(context, config.operation_timeout).unwrap_or(deadline);
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
    deadline: Instant,
) -> Result<ReconciliationOutcome, GlpiFailure> {
    check_context(context, deadline)?;
    session::force_all_entities(config, session, deadline).await?;
    check_context(context, deadline)?;
    session::verify_complete_visibility(config, session, deadline).await?;

    check_context(context, deadline)?;
    let entity_options = resolve_search_options(
        config,
        session,
        "Entity",
        REQUIRED_ENTITY_UIDS,
        context,
        deadline,
    )
    .await?;
    let profile_options = resolve_search_options(
        config,
        session,
        "Profile",
        REQUIRED_PROFILE_UIDS,
        context,
        deadline,
    )
    .await?;
    let user_options = resolve_search_options(
        config,
        session,
        "User",
        REQUIRED_USER_UIDS,
        context,
        deadline,
    )
    .await?;
    let profile_user_options = resolve_search_options(
        config,
        session,
        "Profile_User",
        REQUIRED_PROFILE_USER_UIDS,
        context,
        deadline,
    )
    .await?;

    // Resolve every unique desired entity/profile reference before any user
    // lookup, creation, or mutation.
    let mut resolved_entities: Vec<(String, u64)> = Vec::new();
    let mut resolved_profiles: Vec<(String, u64)> = Vec::new();

    for assignment in desired {
        check_context(context, deadline)?;
        if !resolved_entities
            .iter()
            .any(|(selector, _)| selector == &assignment.entity)
        {
            let id = search::resolve_entity_id(
                config,
                session,
                &entity_options,
                &assignment.entity,
                deadline,
            )
            .await?;
            resolved_entities.push((assignment.entity.clone(), id));
        }

        check_context(context, deadline)?;
        if !resolved_profiles
            .iter()
            .any(|(selector, _)| selector == &assignment.profile)
        {
            let id = search::resolve_profile_id(
                config,
                session,
                &profile_options,
                &assignment.profile,
                deadline,
            )
            .await?;
            resolved_profiles.push((assignment.profile.clone(), id));
        }
    }

    check_context(context, deadline)?;
    let existing_user_id =
        search::resolve_user_id(config, session, &user_options, username, deadline).await?;

    let (user_id, mut changed) = match existing_user_id {
        Some(id) => (id, false),
        None => {
            check_context(context, deadline)?;
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

    check_context(context, deadline)?;
    let current =
        search::read_current_assignments(config, session, &profile_user_options, user_id, deadline)
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
        check_context(context, deadline)?;
        mutation::delete_assignment(config, session, *assignment_id, deadline).await?;
    }

    for addition in &reconciliation_plan.additions {
        check_context(context, deadline)?;
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
    deadline: Instant,
) -> Result<SearchOptions, GlpiFailure> {
    check_context(context, deadline)?;
    search::resolve_search_options(config, session, itemtype, required_uids, deadline).await
}
