//! The PermissionSync executable.
//!
//! It loads exactly one external YAML configuration document whose path comes
//! only from `PERMISSIONSYNC_CONFIG_FILE`, composes the application, serves the
//! synchronization and operational endpoints on one configured listener, and
//! shuts down in bounded phases on `SIGTERM` or `SIGINT`.
//!
//! Every runtime concern lives in private modules under this binary. Startup
//! and fatal diagnostics go to standard error as fixed, value-free categories;
//! ordinary runtime events are structured JSON on standard output.

#![forbid(unsafe_code)]

mod runtime;

use std::process::ExitCode;

fn main() -> ExitCode {
    match runtime::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            // Startup diagnostics deliberately name only the failing category:
            // configuration inputs can contain credentials, private trust
            // material, and exporter authentication headers.
            eprintln!("permissionsync: startup failed: {failure}");
            ExitCode::FAILURE
        }
    }
}
