//! Hermetic checks for `integration/glpi/teardown.sh`'s fail-closed semantics.
//!
//! These tests run the script directly with a controlled environment; they
//! never require Docker or a bootstrapped GLPI environment.

use std::{env, path::PathBuf, process::Command};

fn teardown_script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("integration/glpi/teardown.sh")
}

/// `GLPI_TEST_RUNTIME_ENV` unset means bootstrap never initialized a runtime:
/// there is genuinely nothing to tear down, so teardown succeeds.
#[test]
fn teardown_succeeds_when_runtime_env_was_never_set() {
    let output = Command::new("bash")
        .arg(teardown_script_path())
        .env_remove("GLPI_TEST_RUNTIME_ENV")
        .output()
        .expect("teardown.sh can be invoked");

    assert!(
        output.status.success(),
        "teardown.sh should exit 0 when no runtime was ever created: {output:?}"
    );
}

/// `GLPI_TEST_RUNTIME_ENV` set but pointing at a runtime env file that does
/// not exist means cleanup state has been unexpectedly lost, not "nothing to
/// tear down": teardown must fail closed with a non-zero exit status.
#[test]
fn teardown_fails_when_runtime_env_locator_is_set_but_file_is_missing() {
    let missing_dir = env::temp_dir().join(format!(
        "permissionsync-glpi.teardown-test-missing-{}",
        std::process::id()
    ));
    let missing_runtime_env = missing_dir.join("runtime.env");
    assert!(
        !missing_runtime_env.exists(),
        "test precondition: locator must not exist on disk"
    );

    let output = Command::new("bash")
        .arg(teardown_script_path())
        .env("GLPI_TEST_RUNTIME_ENV", &missing_runtime_env)
        .output()
        .expect("teardown.sh can be invoked");

    assert!(
        !output.status.success(),
        "teardown.sh must fail closed when the runtime env locator is set but missing: {output:?}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unexpectedly lost"),
        "failure message should explain lost cleanup state, got: {stderr}"
    );
}
