//! Fixed, safe runtime-failure categories.

use std::{error::Error, fmt};

/// A fatal runtime defect: a global startup defect, or a serving failure that
/// terminates the process.
///
/// Every variant is a fixed category with no payload. Configuration inputs can
/// contain issuer and endpoint URIs, GLPI credentials, OTLP exporter
/// authentication headers, and private trust material, and a serving failure can
/// carry an operating-system error, so this type deliberately retains neither
/// the offending value, its position in the document, nor an error source. It
/// names only which part of the runtime refused to continue.
///
/// Component-local Provider and GLPI defects are deliberately absent: they
/// never abort startup and instead leave that component unavailable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub(crate) enum RuntimeFailure {
    /// `PERMISSIONSYNC_CONFIG_FILE` was unset or empty.
    ConfigurationPathMissing,
    /// The configuration file could not be read.
    ConfigurationUnreadable,
    /// The configuration file was not valid UTF-8.
    ConfigurationNotUtf8,
    /// The configuration file contained no YAML document.
    ConfigurationEmpty,
    /// The configuration file contained more than one YAML document.
    ConfigurationMultipleDocuments,
    /// The document was not one YAML mapping with exactly the required
    /// top-level runtime sections, or it carried an unknown top-level field.
    InvalidDocumentStructure,
    /// The `listener` section was unusable.
    InvalidListener,
    /// The `request` section was unusable.
    InvalidRequest,
    /// The `shutdown` section was unusable.
    InvalidShutdown,
    /// The `authentication` section was unusable.
    InvalidAuthentication,
    /// The `observability` section was unusable, including invalid tracing
    /// configuration while trace export is explicitly enabled.
    InvalidObservability,
    /// The `targets` section was unusable.
    InvalidTargets,
    /// Application composition was globally ambiguous or structurally unusable.
    InvalidComposition,
    /// Required observability could not be initialized.
    ObservabilityUnavailable,
    /// The configured listener could not be bound.
    ListenerUnavailable,
    /// A required termination-signal handler could not be installed.
    ///
    /// ADR 0011 makes `SIGTERM` and `SIGINT` handling mandatory, so a process
    /// that cannot install both never begins serving.
    SignalRegistrationFailed,
    /// The bound listener repeatedly failed to accept connections, so it can no
    /// longer produce work and the process must terminate.
    ListenerAcceptFailed,
    /// The asynchronous runtime could not be created.
    RuntimeUnavailable,
}

impl fmt::Display for RuntimeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ConfigurationPathMissing => {
                "the PERMISSIONSYNC_CONFIG_FILE environment variable is required"
            }
            Self::ConfigurationUnreadable => "the configuration file could not be read",
            Self::ConfigurationNotUtf8 => "the configuration file is not valid UTF-8",
            Self::ConfigurationEmpty => "the configuration file contains no YAML document",
            Self::ConfigurationMultipleDocuments => {
                "the configuration file contains more than one YAML document"
            }
            Self::InvalidDocumentStructure => {
                "the configuration document is not one mapping with exactly the required sections"
            }
            Self::InvalidListener => "the listener configuration is invalid",
            Self::InvalidRequest => "the request configuration is invalid",
            Self::InvalidShutdown => "the shutdown configuration is invalid",
            Self::InvalidAuthentication => "the authentication configuration is invalid",
            Self::InvalidObservability => "the observability configuration is invalid",
            Self::InvalidTargets => "the target routing configuration is invalid",
            Self::InvalidComposition => "the configured application composition is unusable",
            Self::ObservabilityUnavailable => "required observability could not be initialized",
            Self::ListenerUnavailable => "the configured listener could not be bound",
            Self::SignalRegistrationFailed => {
                "the required termination-signal handlers could not be installed"
            }
            Self::ListenerAcceptFailed => {
                "the listener repeatedly failed to accept connections and serving stopped"
            }
            Self::RuntimeUnavailable => "the asynchronous runtime could not be created",
        })
    }
}

impl Error for RuntimeFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::RuntimeFailure;

    /// Fatal diagnostics are deliberately value-free: a reviewer can read this
    /// list and see that no configured value and no operating-system error can
    /// reach stderr.
    #[test]
    fn every_category_renders_only_fixed_safe_text() {
        const SENSITIVE: [&str; 7] = [
            "https://keycloak.example.test/realms/neteye",
            "sentinel-app-token",
            "sentinel-user-token",
            "BEGIN CERTIFICATE",
            "ApiKey sentinel",
            "/etc/permissionsync/permissionsync.yaml",
            "sentinel-target",
        ];

        for failure in [
            RuntimeFailure::ConfigurationPathMissing,
            RuntimeFailure::ConfigurationUnreadable,
            RuntimeFailure::ConfigurationNotUtf8,
            RuntimeFailure::ConfigurationEmpty,
            RuntimeFailure::ConfigurationMultipleDocuments,
            RuntimeFailure::InvalidDocumentStructure,
            RuntimeFailure::InvalidListener,
            RuntimeFailure::InvalidRequest,
            RuntimeFailure::InvalidShutdown,
            RuntimeFailure::InvalidAuthentication,
            RuntimeFailure::InvalidObservability,
            RuntimeFailure::InvalidTargets,
            RuntimeFailure::InvalidComposition,
            RuntimeFailure::ObservabilityUnavailable,
            RuntimeFailure::ListenerUnavailable,
            RuntimeFailure::SignalRegistrationFailed,
            RuntimeFailure::ListenerAcceptFailed,
            RuntimeFailure::RuntimeUnavailable,
        ] {
            assert!(failure.source().is_none());
            for rendered in [failure.to_string(), format!("{failure:?}")] {
                assert!(!rendered.is_empty());
                for sensitive in SENSITIVE {
                    assert!(
                        !rendered.contains(sensitive),
                        "{rendered} leaked {sensitive}"
                    );
                }
            }
        }
    }
}
