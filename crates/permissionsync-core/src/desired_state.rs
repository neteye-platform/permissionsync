use std::{error::Error, fmt};

use serde_json::value::RawValue;

/// A version carried by a desired-state envelope.
///
/// Core preserves this value but does not decide which versions an adapter
/// supports.
pub struct EnvelopeVersion(u64);

impl EnvelopeVersion {
    /// Creates an envelope version without assigning adapter-specific meaning.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the structural envelope version value.
    pub const fn get(&self) -> u64 {
        self.0
    }
}

/// One syntactically valid JSON value whose semantics belong to a Target Adapter.
pub struct OpaquePayload(Box<RawValue>);

impl OpaquePayload {
    /// Returns the validated raw JSON value without interpreting it.
    pub fn as_json(&self) -> &str {
        self.0.get()
    }
}

impl TryFrom<String> for OpaquePayload {
    type Error = InvalidOpaquePayload;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        RawValue::from_string(value)
            .map(Self)
            .map_err(|_| InvalidOpaquePayload { _private: () })
    }
}

/// Indicates that a payload is not exactly one syntactically valid JSON value.
#[derive(Debug)]
pub struct InvalidOpaquePayload {
    _private: (),
}

impl fmt::Display for InvalidOpaquePayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid opaque payload")
    }
}

impl Error for InvalidOpaquePayload {}

/// The versioned desired state transported from a Permission Provider to an adapter.
pub struct DesiredStateEnvelope {
    version: EnvelopeVersion,
    payload: OpaquePayload,
}

impl DesiredStateEnvelope {
    /// Creates a structurally valid desired-state envelope.
    pub fn new(version: EnvelopeVersion, payload: OpaquePayload) -> Self {
        Self { version, payload }
    }

    /// Returns the opaque payload version.
    pub fn version(&self) -> &EnvelopeVersion {
        &self.version
    }

    /// Returns the opaque adapter-specific payload.
    pub fn payload(&self) -> &OpaquePayload {
        &self.payload
    }
}

#[cfg(test)]
mod tests {
    use super::{DesiredStateEnvelope, EnvelopeVersion, OpaquePayload};

    #[test]
    fn accepts_and_preserves_valid_json_values() {
        let valid = [
            "null",
            "true",
            "42",
            "[\"read\", {\"role\": \"operator\"}]",
            "{\"permissions\": [\"read\"], \"nested\": {\"enabled\": true}}",
        ];

        for value in valid {
            let payload = OpaquePayload::try_from(value.to_owned()).unwrap();

            assert_eq!(payload.as_json(), value);
        }
    }

    #[test]
    fn rejects_invalid_or_multiple_json_values() {
        for value in ["", " ", "{", "{\"permission\": }", "null true"] {
            assert!(
                OpaquePayload::try_from(value.to_owned()).is_err(),
                "{value:?}"
            );
        }
    }

    #[test]
    fn preserves_versions_without_assigning_support_semantics() {
        for value in [0, u64::MAX] {
            let envelope = DesiredStateEnvelope::new(
                EnvelopeVersion::new(value),
                OpaquePayload::try_from("null".to_owned()).unwrap(),
            );

            assert_eq!(envelope.version().get(), value);
        }
    }
}
