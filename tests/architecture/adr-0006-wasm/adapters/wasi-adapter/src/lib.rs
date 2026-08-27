// Poison adapter for Gate 6 (default-deny capabilities).
//
// This component attempts to read an environment variable and a filesystem
// file from inside `reconcile`. The `adapter` world deliberately declares NO
// WASI environment, filesystem, process, or exit imports, so these capability
// calls have no import surface to bind against. That is the Gate 6 evidence:
// ungranted filesystem/environment/process capabilities are denied at the
// contract level — a guest compiled against this world physically cannot
// reach them, and the host links WASI deny-by-default (empty env, no
// preopens, no sockets) so even a widened world could not read them.

#![allow(warnings)]

mod bindings;

use bindings::exports::permissionsync::adr0006::adapter_api::{
    Document, Outcome, TargetEffect,
};
use bindings::exports::permissionsync::adr0006::adapter_api::Guest;
use bindings::export;

struct Component;

impl Guest for Component {
    fn reconcile(doc: Document) -> Result<Outcome, String> {
        let env = std::env::var("NETEYPE_SECRET").unwrap_or_default();
        let file = std::fs::read("/etc/passwd").unwrap_or_default();
        let total = env.len() + file.len();
        let diag = if total == 0 {
            "wasi env/fs denied (0 bytes readable)".to_string()
        } else {
            format!("UNEXPECTED: wasi capability readable ({} bytes)", total)
        };
        Ok(Outcome {
            received: doc,
            effects: vec![],
            diagnostics: vec![diag],
            context_keys: vec![],
        })
    }
}

export!(Component with_types_in bindings);
