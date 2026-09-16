use permissionsync_core::{
    IdentityContext, LogicalTarget, SynchronizationContext, TechnicalCallerBearerToken,
};

/// Inputs for one selected-target synchronization attempt.
///
/// A caller must already hold one valid [`LogicalTarget`]; this crate has no
/// representation for the targetless path.
///
/// This type deliberately carries only what selected-target orchestration
/// needs: the synchronized end-user identity, the selected target, the
/// technical-caller bearer token, and the shared deadline/cancellation
/// context. It does not implement `Clone`, `Debug`, or `Display`, and it does
/// not clone the sensitive bearer token.
pub struct SelectedTargetSynchronizationRequest<'a> {
    identity: &'a IdentityContext,
    target: &'a LogicalTarget,
    technical_caller_bearer_token: &'a TechnicalCallerBearerToken,
    context: SynchronizationContext<'a>,
}

impl<'a> SelectedTargetSynchronizationRequest<'a> {
    /// Creates inputs for one selected-target synchronization attempt.
    pub fn new(
        identity: &'a IdentityContext,
        target: &'a LogicalTarget,
        technical_caller_bearer_token: &'a TechnicalCallerBearerToken,
        context: SynchronizationContext<'a>,
    ) -> Self {
        Self {
            identity,
            target,
            technical_caller_bearer_token,
            context,
        }
    }

    /// Returns the synchronized end-user identity context.
    pub(crate) fn identity(&self) -> &IdentityContext {
        self.identity
    }

    /// Returns the already-selected logical target.
    pub(crate) fn target(&self) -> &LogicalTarget {
        self.target
    }

    /// Returns the sensitive technical-caller bearer token for Provider use.
    pub(crate) fn technical_caller_bearer_token(&self) -> &TechnicalCallerBearerToken {
        self.technical_caller_bearer_token
    }

    /// Returns the request deadline and cancellation context.
    pub(crate) fn context(&self) -> &SynchronizationContext<'a> {
        &self.context
    }
}
