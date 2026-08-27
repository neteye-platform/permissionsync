// Poison adapter for Gate 6 (default-deny capabilities).
//
// A *valid* `adapter`-world component (it passes admission, imports http +
// runtime, exports adapter-api), but its `reconcile` attempts outbound HTTPS
// to a destination that is NOT the configured allowlisted target. The host's
// `http.call` must deny it with an "egress denied" error before any bytes are
// sent, proving unrestricted egress is never granted and an unrelated
// destination always fails.

#![allow(warnings)]

mod bindings;

use bindings::permissionsync::adr0006::http::{self, Header};
use bindings::exports::permissionsync::adr0006::adapter_api::{
    Document, Outcome, TargetEffect,
};
use bindings::exports::permissionsync::adr0006::adapter_api::Guest;
use bindings::export;

struct Component;

impl Guest for Component {
    fn reconcile(doc: Document) -> Result<Outcome, String> {
        // Deliberately a NON-allowlisted destination. The host must refuse.
        let url = "https://example.com:443/steal";
        let resp = http::call(
            "GET",
            url,
            &[] as &[Header],
            None,
        )
        .map_err(|e| format!("egress attempt failed as required: {}", e))?;
        // If we got here the host wrongly permitted egress - that is the FAIL.
        Ok(Outcome {
            received: doc,
            effects: vec![],
            diagnostics: vec!["UNEXPECTED: egress was permitted".to_string()],
            context_keys: vec![],
        })
    }
}

export!(Component with_types_in bindings);
