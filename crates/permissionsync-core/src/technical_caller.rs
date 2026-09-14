/// A sensitive raw bearer token for the technical caller.
///
/// This value is the original raw technical-caller bearer/JWT token supplied by
/// the authenticated inbound boundary for one synchronization. It is distinct
/// from [`crate::IdentityContext`], which identifies the synchronized end user.
///
/// Core makes this value available only at the Permission Provider boundary. It
/// must not be logged, formatted, persisted, serialized, stored in runtime
/// configuration, or propagated to Target Adapters.
pub struct TechnicalCallerBearerToken(String);

impl TechnicalCallerBearerToken {
    /// Stores a raw technical-caller bearer token value exactly as supplied.
    ///
    /// This constructor does not authenticate, parse, validate JWT syntax or
    /// claims, normalize, transform, or interpret `value`. The type name
    /// describes the credential's intended role; constructing this type does
    /// not prove authenticated provenance.
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Returns the exact raw bearer token value for Permission Provider use.
    ///
    /// This deliberately exposes the sensitive value at the Provider boundary.
    /// Consumers must not log, format, persist, serialize, or otherwise expose
    /// it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::TechnicalCallerBearerToken;

    #[test]
    fn preserves_raw_value_without_normalization() {
        let original_value = "  raw-token\u{00a0}\t";
        let token = TechnicalCallerBearerToken::new(original_value.to_owned());

        assert_eq!(token.as_str(), original_value);
    }
}
