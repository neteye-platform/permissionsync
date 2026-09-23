use std::{error::Error, fmt};

/// A safe, non-diagnostic category for a GLPI Target Adapter failure.
///
/// GLPI requests, responses, session tokens, selectors, and desired-state
/// content can be sensitive, so this type intentionally retains none of that
/// detail and has fixed `Debug`/`Display` output.
#[derive(Clone, Copy)]
pub(crate) enum GlpiFailure {
    Cancelled,
    DeadlineExceeded,
    RuntimeUnavailable,
    UnsupportedEnvelopeVersion,
    InvalidPayload,
    Transport,
    ResponseBody,
    ResponseTooLarge,
    SessionInitFailed,
    IncompleteVisibility,
    SearchMetadataUnavailable,
    SearchPagination,
    AmbiguousReference,
    MissingReference,
    MalformedReference,
    UserCreationFailed,
    MutationFailed,
    CleanupFailed,
}

impl fmt::Debug for GlpiFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GlpiFailure")
    }
}

impl fmt::Display for GlpiFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GLPI target adapter reconciliation failed")
    }
}

impl Error for GlpiFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

/// A safe, non-diagnostic error for invalid GLPI adapter configuration.
pub struct GlpiAdapterConfigError {
    _private: (),
}

impl GlpiAdapterConfigError {
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }
}

impl fmt::Debug for GlpiAdapterConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GlpiAdapterConfigError")
    }
}

impl fmt::Display for GlpiAdapterConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid GLPI adapter configuration")
    }
}

impl Error for GlpiAdapterConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::{GlpiAdapterConfigError, GlpiFailure};

    #[test]
    fn adapter_failure_has_only_fixed_safe_formatting() {
        let error = GlpiFailure::MutationFailed;

        assert_eq!(format!("{error:?}"), "GlpiFailure");
        assert_eq!(
            error.to_string(),
            "GLPI target adapter reconciliation failed"
        );
        assert!(error.source().is_none());
    }

    #[test]
    fn config_error_has_only_fixed_safe_formatting() {
        let error = GlpiAdapterConfigError::new();

        assert_eq!(format!("{error:?}"), "GlpiAdapterConfigError");
        assert_eq!(error.to_string(), "invalid GLPI adapter configuration");
        assert!(error.source().is_none());
    }
}
