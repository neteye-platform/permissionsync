//! Strict parsing and normalization of the GLPI adapter's v1 desired-state payload.
//!
//! See ADR 0009 "Desired-state payload v1". Parsing here happens before any
//! GLPI request, and normalization only ever operates on already-valid,
//! already-parsed data. Selector strings are never trimmed, case-folded, or
//! otherwise rewritten.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::error::GlpiFailure;

/// One structurally valid desired assignment, in original request order.
#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RawPermission {
    entity: String,
    profile: String,
    recursive: bool,
}

/// The exactly-one-field v1 payload object.
///
/// `#[serde(deny_unknown_fields)]` on a directly-deserialized struct (rather
/// than a `serde_json::Value` round trip) causes serde to reject a duplicate
/// JSON member name for any field, in addition to rejecting unknown member
/// names; see `payload::tests::rejects_duplicate_json_members` below and the
/// equivalent proven technique in
/// `permissionsync-provider-generic-rest/src/wire.rs`.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct RawPayload {
    permissions: Vec<RawPermission>,
}

/// One canonical, deduplicated desired GLPI assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalAssignment {
    pub(crate) entity: String,
    pub(crate) profile: String,
    pub(crate) recursive: bool,
}

/// Parses and completely structurally validates the v1 payload, then
/// normalizes it into a deterministic, order-independent set of canonical
/// `(entity, profile, recursive)` assignments.
///
/// Rejects: a payload that is not exactly the `permissions` object; wrong
/// types; missing/unknown fields; empty `entity`/`profile`; and duplicate
/// JSON object members (verified by `#[serde(deny_unknown_fields)]` on a
/// direct strict struct, not a `serde_json::Value` round trip, which would
/// silently keep only the last of a duplicate key).
pub(crate) fn parse_and_normalize(json: &str) -> Result<Vec<CanonicalAssignment>, GlpiFailure> {
    let raw: RawPayload = serde_json::from_str(json).map_err(|_| GlpiFailure::InvalidPayload)?;

    for permission in &raw.permissions {
        if permission.entity.is_empty() || permission.profile.is_empty() {
            return Err(GlpiFailure::InvalidPayload);
        }
    }

    // `(entity, profile)` grouping identity: a `BTreeMap` gives deterministic,
    // order-independent iteration for downstream planning and tests.
    let mut groups: BTreeMap<(String, String), bool> = BTreeMap::new();
    for permission in raw.permissions {
        let key = (permission.entity, permission.profile);
        let canonical_recursive = groups.entry(key).or_insert(false);
        *canonical_recursive = *canonical_recursive || permission.recursive;
    }

    Ok(groups
        .into_iter()
        .map(|((entity, profile), recursive)| CanonicalAssignment {
            entity,
            profile,
            recursive,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::parse_and_normalize;
    use crate::error::GlpiFailure;

    fn assert_invalid(json: &str) {
        assert!(
            matches!(parse_and_normalize(json), Err(GlpiFailure::InvalidPayload)),
            "expected invalid payload: {json}"
        );
    }

    #[test]
    fn accepts_the_empty_permissions_list() {
        let assignments = parse_and_normalize(r#"{"permissions": []}"#).unwrap();
        assert!(assignments.is_empty());
    }

    #[test]
    fn accepts_one_valid_permission() {
        let assignments = parse_and_normalize(
            r#"{"permissions": [{"entity": "Root Entity > IT", "profile": "Technician", "recursive": true}]}"#,
        )
        .unwrap();

        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].entity, "Root Entity > IT");
        assert_eq!(assignments[0].profile, "Technician");
        assert!(assignments[0].recursive);
    }

    #[test]
    fn rejects_non_object_top_level_value() {
        for json in ["null", "42", "[]", "\"permissions\""] {
            assert_invalid(json);
        }
    }

    #[test]
    fn rejects_missing_or_unknown_top_level_fields() {
        assert_invalid("{}");
        assert_invalid(r#"{"permissions": [], "unexpected": true}"#);
    }

    #[test]
    fn rejects_permissions_not_an_array() {
        assert_invalid(r#"{"permissions": {}}"#);
        assert_invalid(r#"{"permissions": "x"}"#);
    }

    #[test]
    fn rejects_permission_entries_missing_or_wrong_typed_fields() {
        assert_invalid(r#"{"permissions": [{"entity": "e", "profile": "p"}]}"#);
        assert_invalid(r#"{"permissions": [{"entity": "e", "recursive": true}]}"#);
        assert_invalid(r#"{"permissions": [{"profile": "p", "recursive": true}]}"#);
        assert_invalid(r#"{"permissions": [{"entity": 1, "profile": "p", "recursive": true}]}"#);
        assert_invalid(
            r#"{"permissions": [{"entity": "e", "profile": "p", "recursive": "true"}]}"#,
        );
        assert_invalid(
            r#"{"permissions": [{"entity": "e", "profile": "p", "recursive": true, "extra": 1}]}"#,
        );
    }

    #[test]
    fn rejects_empty_selectors() {
        assert_invalid(r#"{"permissions": [{"entity": "", "profile": "p", "recursive": true}]}"#);
        assert_invalid(r#"{"permissions": [{"entity": "e", "profile": "", "recursive": true}]}"#);
    }

    /// Duplicate JSON *member names* within one object are contract-invalid,
    /// distinct from repeated *complete permission objects* in the array,
    /// which are valid Provider intent (see the normalization tests below).
    #[test]
    fn rejects_duplicate_json_members() {
        assert_invalid(
            r#"{"permissions": [{"entity": "e", "entity": "e", "profile": "p", "recursive": true}]}"#,
        );
        assert_invalid(
            r#"{"permissions": [{"entity": "e", "profile": "p", "profile": "p", "recursive": true}]}"#,
        );
        assert_invalid(
            r#"{"permissions": [{"entity": "e", "profile": "p", "recursive": true, "recursive": false}]}"#,
        );
        assert_invalid(r#"{"permissions": [], "permissions": []}"#);
    }

    #[test]
    fn repeated_complete_permission_objects_are_valid_and_normalize_to_one_assignment() {
        let assignments = parse_and_normalize(
            r#"{"permissions": [
                {"entity": "Root Entity > IT", "profile": "Technician", "recursive": false},
                {"entity": "Root Entity > IT", "profile": "Technician", "recursive": false}
            ]}"#,
        )
        .unwrap();

        assert_eq!(assignments.len(), 1);
        assert!(!assignments[0].recursive);
    }

    #[test]
    fn mixed_recursive_values_for_one_pair_canonicalize_to_true() {
        for (first, second) in [(false, true), (true, false)] {
            let json = format!(
                r#"{{"permissions": [
                    {{"entity": "Root Entity > IT", "profile": "Technician", "recursive": {first}}},
                    {{"entity": "Root Entity > IT", "profile": "Technician", "recursive": {second}}}
                ]}}"#
            );
            let assignments = parse_and_normalize(&json).unwrap();

            assert_eq!(assignments.len(), 1);
            assert!(assignments[0].recursive, "{first} + {second}");
        }
    }

    #[test]
    fn three_or_more_mixed_values_canonicalize_to_true_if_any_is_true() {
        let assignments = parse_and_normalize(
            r#"{"permissions": [
                {"entity": "e", "profile": "p", "recursive": false},
                {"entity": "e", "profile": "p", "recursive": false},
                {"entity": "e", "profile": "p", "recursive": true}
            ]}"#,
        )
        .unwrap();

        assert_eq!(assignments.len(), 1);
        assert!(assignments[0].recursive);
    }

    #[test]
    fn independent_pairs_are_kept_separate_and_order_independent() {
        let json_a = r#"{"permissions": [
            {"entity": "e1", "profile": "p1", "recursive": true},
            {"entity": "e1", "profile": "p2", "recursive": false},
            {"entity": "e2", "profile": "p1", "recursive": false}
        ]}"#;
        let json_b = r#"{"permissions": [
            {"entity": "e2", "profile": "p1", "recursive": false},
            {"entity": "e1", "profile": "p2", "recursive": false},
            {"entity": "e1", "profile": "p1", "recursive": true}
        ]}"#;

        let mut assignments_a = parse_and_normalize(json_a).unwrap();
        let mut assignments_b = parse_and_normalize(json_b).unwrap();
        assignments_a.sort_by(|left, right| {
            (left.entity.as_str(), left.profile.as_str())
                .cmp(&(right.entity.as_str(), right.profile.as_str()))
        });
        assignments_b.sort_by(|left, right| {
            (left.entity.as_str(), left.profile.as_str())
                .cmp(&(right.entity.as_str(), right.profile.as_str()))
        });

        assert_eq!(assignments_a.len(), 3);
        assert_eq!(assignments_a, assignments_b);
    }

    #[test]
    fn selector_strings_are_never_trimmed_or_case_folded() {
        let assignments = parse_and_normalize(
            r#"{"permissions": [{"entity": "  Root Entity > IT ", "profile": "TECH", "recursive": true}]}"#,
        )
        .unwrap();

        assert_eq!(assignments[0].entity, "  Root Entity > IT ");
        assert_eq!(assignments[0].profile, "TECH");
    }

    /// This normalization layer treats `entity` as an opaque selector string;
    /// it must not split, parse, or otherwise interpret the `>` nested-path
    /// separator that the resolution layer later gives meaning to (ADR 0009,
    /// "User, entity, and profile resolution").
    #[test]
    fn nested_path_selectors_survive_as_one_opaque_string() {
        let assignments = parse_and_normalize(
            r#"{"permissions": [{"entity": "Root entity > IT > Operations", "profile": "Technician > Senior", "recursive": true}]}"#,
        )
        .unwrap();

        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].entity, "Root entity > IT > Operations");
        assert_eq!(assignments[0].profile, "Technician > Senior");
    }

    /// Selector strings are opaque byte sequences to this normalization
    /// layer; Unicode content must survive byte-for-byte with no
    /// normalization, case-folding, or encoding change.
    #[test]
    fn unicode_selectors_survive_byte_for_byte() {
        let assignments = parse_and_normalize(
            r#"{"permissions": [{"entity": "Räume > Büro > Abteilung", "profile": "Café Técnico 日本語 🎉", "recursive": false}]}"#,
        )
        .unwrap();

        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].entity, "Räume > Büro > Abteilung");
        assert_eq!(assignments[0].profile, "Café Técnico 日本語 🎉");
    }

    fn assert_normalizes_to(json: &str, expected: &[(&str, &str, bool)]) {
        let mut actual = parse_and_normalize(json)
            .unwrap()
            .into_iter()
            .map(|assignment| (assignment.entity, assignment.profile, assignment.recursive))
            .collect::<Vec<_>>();
        let mut expected = expected
            .iter()
            .map(|&(entity, profile, recursive)| (entity.to_owned(), profile.to_owned(), recursive))
            .collect::<Vec<_>>();

        actual.sort_unstable();
        expected.sort_unstable();
        assert_eq!(actual, expected);
    }

    #[test]
    fn a_single_false_recursive_value_normalizes_to_false() {
        assert_normalizes_to(
            r#"{"permissions": [{"entity": "entity", "profile": "profile", "recursive": false}]}"#,
            &[("entity", "profile", false)],
        );
    }

    #[test]
    fn repeated_true_permission_objects_are_valid_and_normalize_to_true_assignment() {
        assert_normalizes_to(
            r#"{"permissions": [
                {"entity": "entity", "profile": "profile", "recursive": true},
                {"entity": "entity", "profile": "profile", "recursive": true}
            ]}"#,
            &[("entity", "profile", true)],
        );
    }

    #[test]
    fn true_true_false_recursive_values_normalize_to_true() {
        assert_normalizes_to(
            r#"{"permissions": [
                {"entity": "entity", "profile": "profile", "recursive": true},
                {"entity": "entity", "profile": "profile", "recursive": true},
                {"entity": "entity", "profile": "profile", "recursive": false}
            ]}"#,
            &[("entity", "profile", true)],
        );
    }

    #[test]
    fn a_long_mixed_recursive_sequence_normalizes_to_true() {
        assert_normalizes_to(
            r#"{"permissions": [
                {"entity": "entity", "profile": "profile", "recursive": false},
                {"entity": "entity", "profile": "profile", "recursive": true},
                {"entity": "entity", "profile": "profile", "recursive": false},
                {"entity": "entity", "profile": "profile", "recursive": false},
                {"entity": "entity", "profile": "profile", "recursive": true},
                {"entity": "entity", "profile": "profile", "recursive": false}
            ]}"#,
            &[("entity", "profile", true)],
        );
    }

    #[test]
    fn pairs_sharing_an_entity_or_profile_normalize_independently() {
        assert_normalizes_to(
            r#"{"permissions": [
                {"entity": "shared entity", "profile": "shared profile", "recursive": false},
                {"entity": "shared entity", "profile": "shared profile", "recursive": false},
                {"entity": "shared entity", "profile": "other profile", "recursive": true},
                {"entity": "shared entity", "profile": "other profile", "recursive": false},
                {"entity": "other entity", "profile": "shared profile", "recursive": true},
                {"entity": "other entity", "profile": "shared profile", "recursive": true}
            ]}"#,
            &[
                ("shared entity", "shared profile", false),
                ("shared entity", "other profile", true),
                ("other entity", "shared profile", true),
            ],
        );
    }

    #[test]
    fn several_independent_pairs_each_resolve_their_own_duplicate_values() {
        assert_normalizes_to(
            r#"{"permissions": [
                {"entity": "alpha", "profile": "reader", "recursive": false},
                {"entity": "alpha", "profile": "reader", "recursive": false},
                {"entity": "alpha", "profile": "writer", "recursive": true},
                {"entity": "alpha", "profile": "writer", "recursive": true},
                {"entity": "beta", "profile": "reader", "recursive": false},
                {"entity": "beta", "profile": "reader", "recursive": true},
                {"entity": "beta", "profile": "reader", "recursive": false},
                {"entity": "gamma", "profile": "auditor", "recursive": true},
                {"entity": "gamma", "profile": "auditor", "recursive": false},
                {"entity": "gamma", "profile": "auditor", "recursive": true}
            ]}"#,
            &[
                ("alpha", "reader", false),
                ("alpha", "writer", true),
                ("beta", "reader", true),
                ("gamma", "auditor", true),
            ],
        );
    }

    #[test]
    fn duplicate_and_mixed_entries_normalize_independently_of_input_order() {
        let expected = [
            ("entity", "profile", true),
            ("other entity", "other profile", true),
            ("third entity", "third profile", false),
        ];
        let json_a = r#"{"permissions": [
            {"entity": "entity", "profile": "profile", "recursive": false},
            {"entity": "other entity", "profile": "other profile", "recursive": true},
            {"entity": "entity", "profile": "profile", "recursive": true},
            {"entity": "third entity", "profile": "third profile", "recursive": false},
            {"entity": "other entity", "profile": "other profile", "recursive": true},
            {"entity": "entity", "profile": "profile", "recursive": false},
            {"entity": "third entity", "profile": "third profile", "recursive": false}
        ]}"#;
        let json_b = r#"{"permissions": [
            {"entity": "third entity", "profile": "third profile", "recursive": false},
            {"entity": "entity", "profile": "profile", "recursive": true},
            {"entity": "other entity", "profile": "other profile", "recursive": true},
            {"entity": "entity", "profile": "profile", "recursive": false},
            {"entity": "third entity", "profile": "third profile", "recursive": false},
            {"entity": "entity", "profile": "profile", "recursive": false},
            {"entity": "other entity", "profile": "other profile", "recursive": true}
        ]}"#;

        assert_normalizes_to(json_a, &expected);
        assert_normalizes_to(json_b, &expected);
    }

    #[test]
    fn whitespace_and_case_differences_in_selectors_remain_distinct() {
        assert_normalizes_to(
            r#"{"permissions": [
                {"entity": "Root  Entity", "profile": "Role", "recursive": false},
                {"entity": " Root  Entity ", "profile": "Role", "recursive": true},
                {"entity": "Case Entity", "profile": "MiXeD Role", "recursive": false},
                {"entity": "Case Entity", "profile": "mixed role", "recursive": true}
            ]}"#,
            &[
                ("Root  Entity", "Role", false),
                (" Root  Entity ", "Role", true),
                ("Case Entity", "MiXeD Role", false),
                ("Case Entity", "mixed role", true),
            ],
        );
    }

    #[test]
    fn punctuation_in_selectors_survives_byte_for_byte() {
        assert_normalizes_to(
            r#"{"permissions": [{"entity": "Division, (North) & East", "profile": "Read-Only, Level (2) & Audit", "recursive": true}]}"#,
            &[(
                "Division, (North) & East",
                "Read-Only, Level (2) & Audit",
                true,
            )],
        );
    }

    #[test]
    fn unicode_normalization_variants_remain_distinct_entity_selectors() {
        let nfc = "Café";
        let nfd = "Cafe\u{301}";
        assert_ne!(nfc, nfd);

        let json = format!(
            r#"{{"permissions": [
                {{"entity": "{nfc}", "profile": "Reviewer", "recursive": false}},
                {{"entity": "{nfd}", "profile": "Reviewer", "recursive": true}}
            ]}}"#
        );

        assert_normalizes_to(&json, &[(nfc, "Reviewer", false), (nfd, "Reviewer", true)]);
    }
}
