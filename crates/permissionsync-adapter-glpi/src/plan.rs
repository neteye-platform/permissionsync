//! Pure computation of the GLPI `Profile_User` reconciliation plan.
//!
//! See ADR 0009 "Authoritative reconciliation". This module performs no I/O:
//! it takes the complete current assignment set and the canonical desired
//! set and returns a deterministic plan of removals (by physical
//! `Profile_User` id) and additions (`entities_id`, `profiles_id`,
//! `is_recursive`). All removals in the returned plan must be applied before
//! any addition; no row is ever updated in place.

use std::collections::BTreeMap;

/// One physical current `Profile_User` row relevant to reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CurrentRow {
    pub(crate) id: u64,
    pub(crate) entities_id: u64,
    pub(crate) profiles_id: u64,
    pub(crate) is_recursive: bool,
}

/// One canonical desired assignment with resolved numeric GLPI ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DesiredAssignment {
    pub(crate) entities_id: u64,
    pub(crate) profiles_id: u64,
    pub(crate) recursive: bool,
}

/// One addition the plan requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Addition {
    pub(crate) entities_id: u64,
    pub(crate) profiles_id: u64,
    pub(crate) recursive: bool,
}

/// A deterministic reconciliation plan: every removal (by ascending
/// `Profile_User` id) that must happen before every addition (ascending by
/// `(entities_id, profiles_id)`).
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Plan {
    pub(crate) removals: Vec<u64>,
    pub(crate) additions: Vec<Addition>,
}

impl Plan {
    /// Whether applying this plan performs at least one mutation.
    pub(crate) fn is_empty(&self) -> bool {
        self.removals.is_empty() && self.additions.is_empty()
    }
}

/// Computes the deterministic plan for the given current rows and canonical
/// desired assignments.
pub(crate) fn compute(current: &[CurrentRow], desired: &[DesiredAssignment]) -> Plan {
    let mut by_pair: BTreeMap<(u64, u64), Vec<CurrentRow>> = BTreeMap::new();
    for row in current {
        by_pair
            .entry((row.entities_id, row.profiles_id))
            .or_default()
            .push(*row);
    }
    for rows in by_pair.values_mut() {
        rows.sort_by_key(|row| row.id);
    }

    let mut removals = Vec::new();
    let mut additions = Vec::new();

    // Desired pairs are already unique because callers derive them from the
    // normalized `(entity, profile)` grouping; a `BTreeMap` keeps processing
    // order deterministic regardless of input order.
    let mut desired_sorted: Vec<&DesiredAssignment> = desired.iter().collect();
    desired_sorted.sort_by_key(|assignment| (assignment.entities_id, assignment.profiles_id));

    for assignment in &desired_sorted {
        let key = (assignment.entities_id, assignment.profiles_id);
        let Some(rows) = by_pair.remove(&key) else {
            additions.push(Addition {
                entities_id: assignment.entities_id,
                profiles_id: assignment.profiles_id,
                recursive: assignment.recursive,
            });
            continue;
        };

        if let Some(keeper) = rows
            .iter()
            .find(|row| row.is_recursive == assignment.recursive)
        {
            let keeper_id = keeper.id;
            removals.extend(
                rows.iter()
                    .filter(|row| row.id != keeper_id)
                    .map(|row| row.id),
            );
        } else {
            removals.extend(rows.iter().map(|row| row.id));
            additions.push(Addition {
                entities_id: assignment.entities_id,
                profiles_id: assignment.profiles_id,
                recursive: assignment.recursive,
            });
        }
    }

    // Every remaining group is an undesired pair: remove it entirely.
    for rows in by_pair.into_values() {
        removals.extend(rows.into_iter().map(|row| row.id));
    }

    removals.sort_unstable();
    additions.sort_by_key(|addition| (addition.entities_id, addition.profiles_id));

    Plan {
        removals,
        additions,
    }
}

#[cfg(test)]
mod tests {
    use super::{Addition, CurrentRow, DesiredAssignment, compute};

    fn row(id: u64, entity: u64, profile: u64, recursive: bool) -> CurrentRow {
        CurrentRow {
            id,
            entities_id: entity,
            profiles_id: profile,
            is_recursive: recursive,
        }
    }

    fn desired(entity: u64, profile: u64, recursive: bool) -> DesiredAssignment {
        DesiredAssignment {
            entities_id: entity,
            profiles_id: profile,
            recursive,
        }
    }

    #[test]
    fn empty_current_and_desired_produces_an_empty_plan() {
        let plan = compute(&[], &[]);
        assert!(plan.is_empty());
    }

    #[test]
    fn already_canonical_single_row_is_a_no_op() {
        let current = [row(1, 10, 20, true)];
        let desired = [desired(10, 20, true)];

        let plan = compute(&current, &desired);
        assert!(plan.is_empty());
    }

    #[test]
    fn case_a_keeps_lowest_id_canonical_row_and_removes_duplicates_and_opposite_recursive() {
        let current = [
            row(20, 10, 20, true),
            row(10, 10, 20, true),
            row(30, 10, 20, false),
        ];
        let desired = [desired(10, 20, true)];

        let plan = compute(&current, &desired);

        assert_eq!(plan.removals, vec![20, 30]);
        assert!(!plan.removals.contains(&10));
        assert!(plan.additions.is_empty());
    }

    #[test]
    fn case_b_removes_every_non_canonical_row_then_adds_the_canonical_row() {
        let current = [row(1, 10, 20, false), row(2, 10, 20, false)];
        let desired = [desired(10, 20, true)];

        let plan = compute(&current, &desired);

        assert_eq!(plan.removals, vec![1, 2]);
        assert_eq!(
            plan.additions,
            vec![Addition {
                entities_id: 10,
                profiles_id: 20,
                recursive: true
            }]
        );
    }

    #[test]
    fn missing_pair_is_a_pure_addition() {
        let desired = [desired(10, 20, false)];

        let plan = compute(&[], &desired);

        assert!(plan.removals.is_empty());
        assert_eq!(
            plan.additions,
            vec![Addition {
                entities_id: 10,
                profiles_id: 20,
                recursive: false
            }]
        );
    }

    #[test]
    fn undesired_pair_is_fully_removed_regardless_of_recursive_value() {
        let current = [row(1, 10, 20, true), row(2, 10, 20, false)];

        let plan = compute(&current, &[]);

        assert_eq!(plan.removals, vec![1, 2]);
        assert!(plan.additions.is_empty());
    }

    #[test]
    fn empty_desired_state_removes_every_current_row() {
        let current = [row(1, 10, 20, true), row(2, 30, 40, false)];

        let plan = compute(&current, &[]);

        assert_eq!(plan.removals, vec![1, 2]);
        assert!(plan.additions.is_empty());
    }

    #[test]
    fn mixed_multi_pair_plan_is_deterministic_regardless_of_input_order() {
        let current_a = [
            row(30, 10, 20, false),
            row(10, 10, 20, true),
            row(50, 30, 40, true),
            row(40, 5, 6, false),
        ];
        let current_b = [
            row(40, 5, 6, false),
            row(50, 30, 40, true),
            row(10, 10, 20, true),
            row(30, 10, 20, false),
        ];
        let desired_a = [
            desired(10, 20, true),
            desired(7, 8, false),
            desired(5, 6, true),
        ];
        let desired_b = [
            desired(5, 6, true),
            desired(10, 20, true),
            desired(7, 8, false),
        ];

        assert_eq!(
            compute(&current_a, &desired_a),
            compute(&current_b, &desired_b)
        );
    }

    #[test]
    fn plan_collects_all_removals_before_additions_without_updates() {
        let current = [row(5, 1, 1, false), row(6, 2, 2, true)];
        let desired = [desired(1, 1, true), desired(3, 3, false)];

        let plan = compute(&current, &desired);

        // Pair (1,1) has no canonical row: its stale row is removed and a
        // new canonical row is added, never updated in place.
        // Pair (2,2) is undesired: fully removed.
        // Pair (3,3) is missing: pure addition.
        assert_eq!(plan.removals, vec![5, 6]);
        assert_eq!(
            plan.additions,
            vec![
                Addition {
                    entities_id: 1,
                    profiles_id: 1,
                    recursive: true
                },
                Addition {
                    entities_id: 3,
                    profiles_id: 3,
                    recursive: false
                },
            ]
        );
    }

    fn retained_ids(current: &[CurrentRow], removals: &[u64]) -> Vec<u64> {
        current
            .iter()
            .filter(|current_row| !removals.contains(&current_row.id))
            .map(|current_row| current_row.id)
            .collect()
    }

    type DesiredRowCase = (
        &'static str,
        &'static [bool],
        &'static [u64],
        &'static [u64],
        Option<bool>,
    );

    #[test]
    fn desired_false_current_row_matrix_has_exact_cleanup_and_retention() {
        let cases: &[DesiredRowCase] = &[
            ("single canonical false", &[false], &[], &[1], None),
            (
                "duplicate canonical false",
                &[false, false],
                &[2],
                &[1],
                None,
            ),
            ("single opposite true", &[true], &[1], &[], Some(false)),
            ("mixed true then false", &[true, false], &[1], &[2], None),
            (
                "duplicate canonical false with opposite true",
                &[false, false, true],
                &[2, 3],
                &[1],
                None,
            ),
        ];

        for (label, recursive_values, expected_removals, expected_retained, addition) in cases {
            let current: Vec<_> = recursive_values
                .iter()
                .enumerate()
                .map(|(index, recursive)| row(index as u64 + 1, 10, 20, *recursive))
                .collect();
            let plan = compute(&current, &[desired(10, 20, false)]);
            let expected_additions = addition.map_or_else(Vec::new, |recursive| {
                vec![Addition {
                    entities_id: 10,
                    profiles_id: 20,
                    recursive,
                }]
            });

            assert_eq!(plan.removals, *expected_removals, "case {label}: removals");
            assert_eq!(
                retained_ids(&current, &plan.removals),
                *expected_retained,
                "case {label}: retained row ids"
            );
            assert_eq!(
                plan.additions, expected_additions,
                "case {label}: additions"
            );
        }
    }

    #[test]
    fn desired_true_current_row_matrix_has_exact_cleanup_and_retention() {
        let cases: &[DesiredRowCase] = &[
            ("duplicate canonical true", &[true, true], &[2], &[1], None),
            ("single opposite false", &[false], &[1], &[], Some(true)),
            ("mixed false then true", &[false, true], &[1], &[2], None),
        ];

        for (label, recursive_values, expected_removals, expected_retained, addition) in cases {
            let current: Vec<_> = recursive_values
                .iter()
                .enumerate()
                .map(|(index, recursive)| row(index as u64 + 1, 10, 20, *recursive))
                .collect();
            let plan = compute(&current, &[desired(10, 20, true)]);
            let expected_additions = addition.map_or_else(Vec::new, |recursive| {
                vec![Addition {
                    entities_id: 10,
                    profiles_id: 20,
                    recursive,
                }]
            });

            assert_eq!(plan.removals, *expected_removals, "case {label}: removals");
            assert_eq!(
                retained_ids(&current, &plan.removals),
                *expected_retained,
                "case {label}: retained row ids"
            );
            assert_eq!(
                plan.additions, expected_additions,
                "case {label}: additions"
            );
        }
    }

    #[test]
    fn undesired_pair_current_row_matrix_removes_every_row() {
        let cases: &[(&str, &[bool])] = &[
            ("single false", &[false]),
            ("single true", &[true]),
            ("duplicate false", &[false, false]),
            ("duplicate true", &[true, true]),
        ];

        for (label, recursive_values) in cases {
            let current: Vec<_> = recursive_values
                .iter()
                .enumerate()
                .map(|(index, recursive)| row(index as u64 + 1, 10, 20, *recursive))
                .collect();
            let plan = compute(&current, &[]);
            let expected_removals: Vec<_> = (1..=recursive_values.len() as u64).collect();

            assert_eq!(plan.removals, expected_removals, "case {label}: removals");
            assert!(
                retained_ids(&current, &plan.removals).is_empty(),
                "case {label}: no row is retained"
            );
            assert!(plan.additions.is_empty(), "case {label}: no additions");
        }
    }

    #[test]
    fn several_undesired_pairs_are_all_removed_without_cross_contamination() {
        let current = [
            row(101, 10, 20, false),
            row(205, 30, 40, true),
            row(102, 10, 20, true),
            row(303, 50, 60, false),
        ];

        let plan = compute(&current, &[]);

        assert_eq!(plan.removals, vec![101, 102, 205, 303]);
        assert!(retained_ids(&current, &plan.removals).is_empty());
        assert!(plan.additions.is_empty());
    }

    #[test]
    fn same_entity_different_profiles_are_planned_independently() {
        let current = [
            row(1, 10, 20, false),
            row(2, 10, 20, true),
            row(3, 10, 30, true),
        ];
        let desired = [desired(10, 20, true), desired(10, 30, false)];

        let plan = compute(&current, &desired);

        assert_eq!(plan.removals, vec![1, 3]);
        assert_eq!(retained_ids(&current, &plan.removals), vec![2]);
        assert_eq!(
            plan.additions,
            vec![Addition {
                entities_id: 10,
                profiles_id: 30,
                recursive: false,
            }]
        );
    }

    #[test]
    fn same_profile_different_entities_are_planned_independently() {
        let current = [
            row(1, 10, 20, false),
            row(2, 30, 20, true),
            row(3, 30, 20, false),
        ];
        let desired = [desired(10, 20, true), desired(30, 20, false)];

        let plan = compute(&current, &desired);

        assert_eq!(plan.removals, vec![1, 2]);
        assert_eq!(retained_ids(&current, &plan.removals), vec![3]);
        assert_eq!(
            plan.additions,
            vec![Addition {
                entities_id: 10,
                profiles_id: 20,
                recursive: true,
            }]
        );
    }

    #[test]
    fn multiple_desired_pairs_missing_from_current_are_all_pure_additions() {
        let desired = [
            desired(30, 40, true),
            desired(10, 20, false),
            desired(20, 30, true),
        ];

        let plan = compute(&[], &desired);

        assert!(plan.removals.is_empty());
        assert_eq!(
            plan.additions,
            vec![
                Addition {
                    entities_id: 10,
                    profiles_id: 20,
                    recursive: false,
                },
                Addition {
                    entities_id: 20,
                    profiles_id: 30,
                    recursive: true,
                },
                Addition {
                    entities_id: 30,
                    profiles_id: 40,
                    recursive: true,
                },
            ]
        );
    }

    #[test]
    fn desired_and_undesired_pairs_are_reconciled_together_without_cross_contamination() {
        let current = [
            row(1, 10, 20, true),
            row(2, 30, 40, false),
            row(3, 30, 40, true),
        ];
        let desired = [desired(10, 20, true), desired(50, 60, false)];

        let plan = compute(&current, &desired);

        assert_eq!(plan.removals, vec![2, 3]);
        assert_eq!(retained_ids(&current, &plan.removals), vec![1]);
        assert_eq!(
            plan.additions,
            vec![Addition {
                entities_id: 50,
                profiles_id: 60,
                recursive: false,
            }]
        );
    }

    #[test]
    fn independent_case_a_and_case_b_cleanup_are_combined_without_interference() {
        let current = [
            row(1, 10, 20, false),
            row(2, 10, 20, false),
            row(3, 10, 20, true),
            row(4, 30, 40, false),
            row(5, 30, 40, false),
        ];
        let desired = [desired(10, 20, false), desired(30, 40, true)];

        let plan = compute(&current, &desired);

        assert_eq!(plan.removals, vec![2, 3, 4, 5]);
        assert_eq!(retained_ids(&current, &plan.removals), vec![1]);
        assert_eq!(
            plan.additions,
            vec![Addition {
                entities_id: 30,
                profiles_id: 40,
                recursive: true,
            }]
        );
    }
}
