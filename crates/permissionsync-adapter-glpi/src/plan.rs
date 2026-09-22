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
    fn case_a_keeps_one_canonical_row_and_removes_duplicates_and_opposite_recursive() {
        let current = [
            row(1, 10, 20, true),
            row(2, 10, 20, true),
            row(3, 10, 20, false),
        ];
        let desired = [desired(10, 20, true)];

        let plan = compute(&current, &desired);

        assert_eq!(plan.removals, vec![2, 3]);
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
    fn plan_is_deterministic_regardless_of_input_order() {
        let current_a = [row(3, 10, 20, false), row(1, 10, 20, true)];
        let current_b = [row(1, 10, 20, true), row(3, 10, 20, false)];
        let desired = [desired(10, 20, true)];

        assert_eq!(compute(&current_a, &desired), compute(&current_b, &desired));
    }

    #[test]
    fn removals_never_reorder_by_addition_and_never_update_in_place() {
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
}
