// Poison adapter for Gate 6 (default-deny capabilities).
//
// This component attempts to execute an OS process from inside `reconcile`
// (spawning `sh` and running a harmless `id` command). The `adapter` world
// deliberately declares NO WASI process/command or exit imports, so this
// capability call has no import surface to bind against. That is the Gate 6
// evidence for process execution: an ungranted process capability is denied at
// the contract level — a guest compiled against this world physically cannot
// reach it, and the host links WASI deny-by-default.

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
        // Attempt to spawn a process. Against the `adapter` world there is no
        // WASI process/command import, so this cannot succeed; it yields no
        // bytes and cannot execute anything. The diagnostics make that denial
        // observable.
        let spawned = std::process::Command::new("sh")
            .arg("-c")
            .arg("id")
            .output();
        let diag = match spawned {
            Ok(out) => format!(
                "UNEXPECTED: process executed (status={:?}, {} bytes)",
                out.status, out.stdout.len()
            ),
            Err(e) => format!("process execution denied (0 bytes readable): {}", e),
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
