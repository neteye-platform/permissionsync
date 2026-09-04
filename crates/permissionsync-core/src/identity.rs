/// Synchronized end-user identity and inbound group membership.
///
/// This context is distinct from the technical caller authenticated by the
/// inbound boundary. Username and group values are preserved without
/// normalization or additional grammar validation.
pub struct IdentityContext {
    username: String,
    groups: Vec<String>,
}

impl IdentityContext {
    /// Creates an identity context from the supplied username and group values.
    pub fn new(username: String, groups: Vec<String>) -> Self {
        Self { username, groups }
    }

    /// Returns the synchronized username exactly as supplied.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Returns the supplied group values in their original order.
    pub fn groups(&self) -> &[String] {
        &self.groups
    }
}

#[cfg(test)]
mod tests {
    use super::IdentityContext;

    #[test]
    fn preserves_permitted_identity_values() {
        let cases: &[(&str, &[&str])] = &[
            ("", &[]),
            ("  m\u{00fc}ller\t", &["/staff", "/staff"]),
            ("\0", &["", "duplicate", "duplicate", " /\u{00fc}nit "]),
        ];

        for (username, groups) in cases {
            let context = IdentityContext::new(
                (*username).to_owned(),
                groups.iter().map(|group| (*group).to_owned()).collect(),
            );

            assert_eq!(context.username(), *username);
            assert!(
                context
                    .groups()
                    .iter()
                    .map(String::as_str)
                    .eq(groups.iter().copied())
            );
        }
    }
}
