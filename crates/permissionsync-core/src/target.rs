use std::{error::Error, fmt};

/// A logical target identifier that satisfies the inbound v1 target grammar.
pub struct LogicalTarget(String);

impl LogicalTarget {
    /// Returns the validated target identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for LogicalTarget {
    type Error = InvalidLogicalTarget;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let bytes = value.as_bytes();

        if bytes.is_empty() || bytes.len() > 64 {
            return Err(InvalidLogicalTarget { _private: () });
        }

        if !is_edge_character(bytes[0]) || !is_edge_character(bytes[bytes.len() - 1]) {
            return Err(InvalidLogicalTarget { _private: () });
        }

        if bytes.len() > 2
            && !bytes[1..bytes.len() - 1]
                .iter()
                .copied()
                .all(is_inner_character)
        {
            return Err(InvalidLogicalTarget { _private: () });
        }

        Ok(Self(value))
    }
}

fn is_edge_character(value: u8) -> bool {
    value.is_ascii_lowercase() || value.is_ascii_digit()
}

fn is_inner_character(value: u8) -> bool {
    is_edge_character(value) || matches!(value, b'.' | b'_' | b'-')
}

/// Indicates that a logical target does not satisfy the inbound v1 grammar.
#[derive(Debug)]
pub struct InvalidLogicalTarget {
    _private: (),
}

impl fmt::Display for InvalidLogicalTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid logical target")
    }
}

impl Error for InvalidLogicalTarget {}

#[cfg(test)]
mod tests {
    use super::LogicalTarget;

    #[test]
    fn accepts_adr_target_grammar_boundaries() {
        let sixty_four_characters = "a".repeat(64);
        let valid = ["a", "7", sixty_four_characters.as_str(), "a.b_c-d9"];

        for value in valid {
            let target = LogicalTarget::try_from(value.to_owned()).unwrap();

            assert_eq!(target.as_str(), value);
        }
    }

    #[test]
    fn rejects_values_outside_adr_target_grammar() {
        let sixty_five_characters = "a".repeat(65);
        let invalid = [
            "",
            sixty_five_characters.as_str(),
            "-target",
            "target-",
            "_target",
            "target_",
            ".target",
            "target.",
            "Target",
            "target name",
            "target:name",
            "target/name",
            "target\u{00fc}",
            "target\0",
        ];

        for value in invalid {
            assert!(
                LogicalTarget::try_from(value.to_owned()).is_err(),
                "{value:?}"
            );
        }
    }
}
