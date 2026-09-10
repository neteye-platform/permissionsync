use std::{error::Error, fmt};

/// A safe, non-diagnostic category for a Generic REST Provider failure.
///
/// Transport and wire details can include sensitive request or response data, so
/// this type intentionally retains neither those details nor an error source.
#[derive(Clone, Copy)]
pub(crate) enum ProviderFailure {
    RuntimeUnavailable,
    Cancelled,
    DeadlineExceeded,
    InvalidAuthorization,
    RequestConstruction,
    RequestSerialization,
    Transport,
    UnexpectedStatus,
    ResponseMetadata,
    ResponseBody,
    ResponseTooLarge,
    ResponseEnvelope,
}

impl fmt::Debug for ProviderFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderFailure")
    }
}

impl fmt::Display for ProviderFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("generic REST provider failure")
    }
}

impl Error for ProviderFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

/// A safe, non-diagnostic error for invalid Generic REST Provider configuration.
///
/// Configuration values can include sensitive trust material or endpoint
/// information, so this type intentionally retains neither those details nor an
/// error source.
pub struct GenericRestPermissionProviderConfigError {
    _private: (),
}

impl GenericRestPermissionProviderConfigError {
    /// Creates a non-diagnostic invalid-configuration category.
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }
}

impl fmt::Debug for GenericRestPermissionProviderConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GenericRestPermissionProviderConfigError")
    }
}

impl fmt::Display for GenericRestPermissionProviderConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid generic REST provider configuration")
    }
}

impl Error for GenericRestPermissionProviderConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::{GenericRestPermissionProviderConfigError, ProviderFailure};

    #[test]
    fn provider_failure_has_only_fixed_safe_formatting() {
        let error = ProviderFailure::ResponseEnvelope;

        assert_eq!(format!("{error:?}"), "ProviderFailure");
        assert_eq!(error.to_string(), "generic REST provider failure");
        assert!(error.source().is_none());
    }

    #[test]
    fn config_error_has_only_fixed_safe_formatting() {
        let error = GenericRestPermissionProviderConfigError::new();

        assert_eq!(
            format!("{error:?}"),
            "GenericRestPermissionProviderConfigError"
        );
        assert_eq!(
            error.to_string(),
            "invalid generic REST provider configuration"
        );
        assert!(error.source().is_none());
    }
}
