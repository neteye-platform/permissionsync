//! The PermissionSync executable.
//!
//! It loads exactly one external YAML configuration document whose path comes
//! only from `PERMISSIONSYNC_CONFIG_FILE`, applies the `PERMISSIONSYNC_*`
//! environment overrides and secrets to it, composes the application, serves the
//! synchronization and operational endpoints on one configured listener, and
//! shuts down in bounded phases on `SIGTERM` or `SIGINT`.
//!
//! Every runtime concern lives in private modules under this binary. Fatal
//! diagnostics, whether from startup or from a listener that stopped accepting,
//! go to standard error as fixed, value-free categories, and the process then
//! reports failure; ordinary runtime events are structured JSON on standard
//! output. The names, never the values, of unknown `PERMISSIONSYNC_*`
//! variables also go to standard error when the structured log cannot show
//! them.

#![forbid(unsafe_code)]

mod runtime;

use std::process::ExitCode;

fn main() -> ExitCode {
    match runtime::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            // Fatal diagnostics deliberately name only the failing category:
            // configuration inputs, from the file or the environment, can
            // contain credentials, private trust material, and exporter
            // authentication headers, and a serving failure can carry an
            // operating-system error.
            eprintln!("permissionsync: {failure}");
            ExitCode::FAILURE
        }
    }
}
