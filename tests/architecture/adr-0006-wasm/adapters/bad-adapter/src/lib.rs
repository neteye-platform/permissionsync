//! Poison adapter for Gate 2 (admission compatibility).
//!
//! A structurally valid component whose world is incompatible with the
//! `adapter` world: it exports an unrelated interface and neither imports
//! `http`/`runtime` nor exports `adapter-api`. The host must reject it during
//! admission with zero provider calls and zero reconciliation calls.

#![allow(warnings)]

mod bindings;

use bindings::exports::permissionsync::bad_adapter::salute::Guest;
use bindings::export;

struct Component;

impl Guest for Component {
    fn greet() -> String {
        "hello from the incompatible adapter".to_string()
    }
}

export!(Component with_types_in bindings);
