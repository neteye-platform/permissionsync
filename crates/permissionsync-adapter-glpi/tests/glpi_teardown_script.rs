//! Hermetic checks for `integration/glpi/teardown.sh`'s fail-closed semantics.
//!
//! These tests run the script directly with a controlled environment; they
//! never require Docker or a bootstrapped GLPI environment.

use std::{
    env,
    fs::{self, File},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::Command,
};

fn teardown_script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("integration/glpi/teardown.sh")
}

/// Build a real temporary runtime directory that satisfies teardown.sh's
/// safe-generated-directory checks (`.../permissionsync-glpi.XXXXXX`
/// containing a `runtime.env`), plus a fake `docker` executable on its own
/// temporary bin directory that behaves as instructed by `docker_exit_code`.
///
/// Returns `(runtime_dir, runtime_env_path, fake_bin_dir)`.
fn setup_runtime_env_and_fake_docker(
    test_name: &str,
    docker_exit_code: u8,
    secret_marker: &str,
) -> (PathBuf, PathBuf, PathBuf) {
    let suffix = format!("{:06}", std::process::id() % 1_000_000);
    let runtime_dir = env::temp_dir().join(format!("permissionsync-glpi.{suffix}"));
    if runtime_dir.exists() {
        fs::remove_dir_all(&runtime_dir).expect("clean stale test runtime dir");
    }
    fs::create_dir_all(&runtime_dir).expect("create test runtime dir");

    let runtime_env = runtime_dir.join("runtime.env");
    let mut env_file = File::create(&runtime_env).expect("create runtime.env");
    writeln!(
        env_file,
        "export PERMISSIONSYNC_GLPI_PROJECT_NAME=permissionsync-glpi-test-{test_name}"
    )
    .unwrap();
    writeln!(
        env_file,
        "export GLPI_TEST_RUNTIME_DIR={}",
        runtime_dir.display()
    )
    .unwrap();
    writeln!(env_file, "export GLPI_TEST_SECRET_MARKER={secret_marker}").unwrap();
    drop(env_file);

    let fake_bin_dir = env::temp_dir().join(format!("permissionsync-glpi-fakebin-{test_name}"));
    if fake_bin_dir.exists() {
        fs::remove_dir_all(&fake_bin_dir).expect("clean stale fake bin dir");
    }
    fs::create_dir_all(&fake_bin_dir).expect("create fake bin dir");

    let fake_docker = fake_bin_dir.join("docker");
    let mut docker_file = File::create(&fake_docker).expect("create fake docker script");
    writeln!(
        docker_file,
        "#!/usr/bin/env bash\nif [[ \"$1\" == compose ]]; then\n  exit {docker_exit_code}\nfi\nexit 0\n"
    )
    .unwrap();
    drop(docker_file);
    fs::set_permissions(&fake_docker, fs::Permissions::from_mode(0o755))
        .expect("make fake docker executable");

    (runtime_dir, runtime_env, fake_bin_dir)
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

/// When `docker compose down` fails, the runtime directory (and its
/// `runtime.env`) must be preserved so cleanup can be retried, and no secret
/// values from `runtime.env` may leak onto stderr.
#[test]
fn teardown_preserves_runtime_dir_when_docker_compose_down_fails() {
    let secret_marker = "SECRET-MARKER-DOWN-FAILS-DO-NOT-LEAK";
    let (runtime_dir, runtime_env, fake_bin_dir) =
        setup_runtime_env_and_fake_docker("down-fails", 1, secret_marker);

    let path_var = format!(
        "{}:{}",
        fake_bin_dir.display(),
        env::var("PATH").unwrap_or_default()
    );

    let output = Command::new("bash")
        .arg(teardown_script_path())
        .env("GLPI_TEST_RUNTIME_ENV", &runtime_env)
        .env("PATH", &path_var)
        .output()
        .expect("teardown.sh can be invoked");

    assert!(
        !output.status.success(),
        "teardown.sh must fail when docker compose down fails: {output:?}"
    );

    assert!(
        runtime_dir.exists(),
        "runtime directory must be preserved when docker compose down fails"
    );
    assert!(
        runtime_env.exists(),
        "runtime.env must be preserved when docker compose down fails"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains(secret_marker),
        "stderr must not leak runtime.env contents, got: {stderr}"
    );

    // Best-effort cleanup; production teardown.sh does not remove the
    // directory on this failure path, so the test must do it itself.
    let _ = fs::remove_dir_all(&runtime_dir);
    let _ = fs::remove_dir_all(&fake_bin_dir);
}

/// When `docker compose down` succeeds, teardown.sh must remove the
/// generated runtime directory and exit successfully.
#[test]
fn teardown_removes_runtime_dir_when_docker_compose_down_succeeds() {
    let secret_marker = "SECRET-MARKER-DOWN-SUCCEEDS";
    let (runtime_dir, runtime_env, fake_bin_dir) =
        setup_runtime_env_and_fake_docker("down-succeeds", 0, secret_marker);

    let path_var = format!(
        "{}:{}",
        fake_bin_dir.display(),
        env::var("PATH").unwrap_or_default()
    );

    let output = Command::new("bash")
        .arg(teardown_script_path())
        .env("GLPI_TEST_RUNTIME_ENV", &runtime_env)
        .env("PATH", &path_var)
        .output()
        .expect("teardown.sh can be invoked");

    assert!(
        output.status.success(),
        "teardown.sh should exit 0 when docker compose down succeeds: {output:?}"
    );

    assert!(
        !runtime_dir.exists(),
        "runtime directory should be removed after successful docker compose down"
    );

    // Best-effort cleanup in case the assertion above already failed.
    let _ = fs::remove_dir_all(&runtime_dir);
    let _ = fs::remove_dir_all(&fake_bin_dir);
}
