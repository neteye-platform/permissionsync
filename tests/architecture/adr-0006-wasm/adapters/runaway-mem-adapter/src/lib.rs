//! Poison adapter for Gate 7 (bounded resources).
//!
//! A *valid* `adapter`-world component (it passes admission), but its
//! `reconcile` grows guest linear memory without bound until the host's
//! `StoreLimits` (max memory) traps it. The host must refuse/trap this before
//! host exhaustion.

#![allow(warnings)]

mod bindings;

use bindings::exports::permissionsync::adr0006::adapter_api::Document;
use bindings::exports::permissionsync::adr0006::adapter_api::Outcome;
use bindings::exports::permissionsync::adr0006::adapter_api::Guest;
use bindings::export;

struct Component;

impl Guest for Component {
    fn reconcile(_doc: Document) -> Result<Outcome, String> {
        // Unbounded guest linear-memory growth: keep appending large chunks so
        // the backing memory grows until the host's configured StoreLimits/max
        // memory bound traps execution before host memory is exhausted.
        let mut v: Vec<u8> = Vec::new();
        loop {
            let chunk: Vec<u8> = vec![0u8; 1_000_000];
            v.extend_from_slice(&chunk);
            core::hint::black_box(&v);
            core::hint::black_box(&chunk);
        }
    }
}

export!(Component with_types_in bindings);
