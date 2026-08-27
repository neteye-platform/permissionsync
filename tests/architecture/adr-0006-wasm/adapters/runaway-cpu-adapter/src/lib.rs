//! Poison adapter for Gate 8 (deadline and cancellation).
//!
//! A *valid* `adapter`-world component (it passes admission), but its
//! `reconcile` enters an unbounded CPU-bound spin and never returns. The host
//! must interrupt it at the remaining deadline, return 500, and start no new
//! work.

#![allow(warnings)]

mod bindings;

use bindings::exports::permissionsync::adr0006::adapter_api::Document;
use bindings::exports::permissionsync::adr0006::adapter_api::Outcome;
use bindings::exports::permissionsync::adr0006::adapter_api::Guest;
use bindings::export;

struct Component;

impl Guest for Component {
    fn reconcile(_doc: Document) -> Result<Outcome, String> {
        // Unbounded CPU spin: repeatedly fold into a black_box so the loops
        // are never optimized away. No further imports are called; the host's
        // epoch deadline must interrupt this.
        let mut acc: u64 = 0;
        loop {
            acc = acc.wrapping_add(1);
            acc = acc.wrapping_mul(31).wrapping_add(7);
            core::hint::black_box(acc);
        }
    }
}

export!(Component with_types_in bindings);
