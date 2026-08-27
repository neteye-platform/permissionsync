//! Poison adapter for Gate 2 (admission compatibility) — "unprovided import"
//! case. Exports `adapter-api.reconcile` (the correct shape) but ALSO imports
//! `secret-vault`, an interface the host linker does not provide. The host
//! denies all imports not in its explicit allow-set (`http`, `runtime`, WASI
//! p2), so this component fails admission/instantiation with zero provider
//! calls and zero reconciliation calls.

#![allow(warnings)]

mod bindings;

use bindings::exports::permissionsync::adr0006::adapter_api::{
    Document, Guest, Outcome,
};
use bindings::permissionsync::adr0006::secret_vault;
use bindings::export;

struct Component;

impl Guest for Component {
    fn reconcile(doc: Document) -> Result<Outcome, String> {
        // Reference the unprovided import so it is a real, retained import in
        // the component (it would never actually run — instantiation fails).
        let _ = secret_vault::get("irrelevant");
        Ok(Outcome {
            received: doc,
            effects: Vec::new(),
            diagnostics: Vec::new(),
            context_keys: Vec::new(),
        })
    }
}

export!(Component with_types_in bindings);
