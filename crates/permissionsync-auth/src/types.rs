//! Public request/result value types for one authentication attempt.

use permissionsync_core::{LogicalTarget, SynchronizationContext, TechnicalCallerBearerToken};

/// Request inputs for one authentication attempt.
pub struct AuthenticationRequest<'a> {
    pub(crate) raw_compact_token: Option<&'a str>,
    pub(crate) context: SynchronizationContext<'a>,
}

impl<'a> AuthenticationRequest<'a> {
    /// Creates a request from the inbound boundary's already-extracted compact
    /// credential. Bearer scheme and duplicate-header parsing remain inbound
    /// boundary responsibilities.
    pub fn new(raw_compact_token: Option<&'a str>, context: SynchronizationContext<'a>) -> Self {
        Self {
            raw_compact_token,
            context,
        }
    }
}

/// Authenticated technical caller identity.
pub struct TechnicalCallerClientId(pub(crate) String);

impl TechnicalCallerClientId {
    /// Returns the verified client identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Authorization result that intentionally terminates at target selection.
///
/// `NoTarget` means only that authentication and scope target selection
/// produced no PermissionSync target; it does not itself imply a successful
/// HTTP `204`. The inbound HTTP layer still must perform strict body
/// validation before completing a targetless request, per
/// [ADR 0001](../../../docs/adr/0001-inbound-synchronization-contract.md).
///
/// `Selected` means only that scope produced one grammar-valid authorized
/// target. It does not mean routing recognizes or has configured that target;
/// that resolution remains a later boundary's responsibility.
pub enum TargetSelection {
    /// No PermissionSync target was granted by scope.
    NoTarget,
    /// The sole valid selected logical target.
    Selected(LogicalTarget),
}

impl TargetSelection {
    /// Returns the selected target, if one was granted.
    pub fn selected(&self) -> Option<&LogicalTarget> {
        match self {
            Self::NoTarget => None,
            Self::Selected(target) => Some(target),
        }
    }
}

/// Minimal successful authentication output.
pub struct AuthenticatedTechnicalCaller {
    pub(crate) client_id: TechnicalCallerClientId,
    pub(crate) bearer_token: TechnicalCallerBearerToken,
    pub(crate) target_selection: TargetSelection,
}

impl AuthenticatedTechnicalCaller {
    /// Returns the verified technical caller identity.
    pub fn client_id(&self) -> &TechnicalCallerClientId {
        &self.client_id
    }

    /// Returns the exact input bearer token for the later Provider boundary.
    pub fn bearer_token(&self) -> &TechnicalCallerBearerToken {
        &self.bearer_token
    }

    /// Returns this caller's target-selection result.
    pub fn target_selection(&self) -> &TargetSelection {
        &self.target_selection
    }
}
