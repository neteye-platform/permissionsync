//! Public error category for authentication outcomes. Authenticator
//! configuration errors live alongside their validation in
//! [`crate::config`].

use std::{error::Error, fmt};

/// Authentication result category safe for caller-facing mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationError {
    /// Credentials or verified authentication claims are invalid.
    Rejected,
    /// An authenticated caller has an unusable PermissionSync scope grant.
    Forbidden,
    /// Trusted verifier infrastructure cannot establish validity.
    VerifierUnavailable,
    /// The propagated request context prevented required work.
    Cancelled,
}

impl fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Rejected => "technical caller authentication rejected",
            Self::Forbidden => "technical caller authorization forbidden",
            Self::VerifierUnavailable => "technical caller verifier unavailable",
            Self::Cancelled => "technical caller authentication cancelled",
        })
    }
}

impl Error for AuthenticationError {}

#[cfg(test)]
mod tests {
    use super::AuthenticationError;

    #[test]
    fn safe_errors_have_fixed_formatting_and_no_source() {
        for error in [
            AuthenticationError::Rejected,
            AuthenticationError::Forbidden,
            AuthenticationError::VerifierUnavailable,
            AuthenticationError::Cancelled,
        ] {
            assert!(!error.to_string().contains("sentinel-secret"));
            assert!(!format!("{error:?}").contains("sentinel-secret"));
            assert!(std::error::Error::source(&error).is_none());
        }
    }
}
