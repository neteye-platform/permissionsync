//! Hermetic checks for `integration/glpi/diagnostics.sh`'s redaction.
//!
//! These tests run the script directly against a fabricated runtime
//! environment; they never require Docker or a bootstrapped GLPI.
//!
//! Diagnostics are the one place in the disposable GLPI layer that reads
//! generated credentials in order to keep them out of its output, so two
//! properties are worth proving directly: the credentials really are redacted,
//! and they never reach the redaction filter's process argument vector, which
//! any local user can read out of `/proc`.

use std::{
    env, fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

/// A value that is recognisable in output but is not a real credential.
const FABRICATED_SECRET: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0deadbeefcafef00d";

fn diagnostics_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("integration/glpi/diagnostics.sh")
}

/// Produces a unique six-character suffix per invocation without relying on
/// unseeded randomness, combining a process-local counter with the process id
/// so parallel tests in this binary cannot collide.
fn unique_suffix() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mixed = (std::process::id() as u64)
        .wrapping_mul(1_000_003)
        .wrapping_add(COUNTER.fetch_add(1, Ordering::Relaxed));
    let alphabet: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut value = mixed % 36u64.pow(6);
    let mut characters = [b'0'; 6];
    for slot in characters.iter_mut().rev() {
        *slot = alphabet[(value % 36) as usize];
        value /= 36;
    }
    String::from_utf8(characters.to_vec()).expect("the alphabet is ASCII")
}

/// Creates an exclusive runtime directory. An existing path is never reused or
/// removed: a collision gets a new deterministic suffix instead.
fn create_runtime_dir() -> PathBuf {
    for _ in 0..1_024 {
        let candidate =
            env::temp_dir().join(format!("permissionsync-glpi-diag.{}", unique_suffix()));
        match fs::create_dir(&candidate) {
            Ok(()) => return candidate,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create {}: {error}", candidate.display()),
        }
    }
    panic!("could not allocate an exclusive runtime directory");
}

/// Installs a `python3` that records each invocation's arguments and then execs
/// the real interpreter, so the test can observe exactly what the script put on
/// the command line.
fn install_python_recorder(directory: &Path) -> (PathBuf, PathBuf) {
    let real = String::from_utf8(
        Command::new("sh")
            .args(["-c", "command -v python3"])
            .output()
            .expect("python3 could be located")
            .stdout,
    )
    .expect("the interpreter path is UTF-8");
    let real = real.trim();
    assert!(
        !real.is_empty(),
        "python3 must be available to run this test"
    );

    let bin = directory.join("bin");
    fs::create_dir(&bin).expect("the shim directory could be created");
    let recorded = directory.join("python-argv.log");
    let shim = bin.join("python3");
    let mut file = fs::File::create(&shim).expect("the shim could be created");
    write!(
        file,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {}\nexec {} \"$@\"\n",
        recorded.display(),
        real
    )
    .expect("the shim could be written");
    drop(file);
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o755))
        .expect("the shim could be made executable");
    (bin, recorded)
}

struct Diagnostics {
    stdout: String,
    runtime_dir: PathBuf,
    recorded_arguments: String,
}

/// Runs the script against a runtime environment whose only interesting
/// content is one fabricated credential planted in a captured compose stream.
fn run_diagnostics() -> Diagnostics {
    let runtime_dir = create_runtime_dir();
    let (shim_directory, recorded) = install_python_recorder(&runtime_dir);

    // Deliberately no PERMISSIONSYNC_GLPI_PROJECT_NAME: the script then skips
    // the `docker compose logs` section, so this test needs no container
    // engine.
    let runtime_env = runtime_dir.join("runtime.env");
    fs::write(
        &runtime_env,
        format!(
            "GLPI_TEST_RUNTIME_DIR=\"{}\"\n\
             GLPI_TEST_APP_TOKEN=\"{FABRICATED_SECRET}\"\n",
            runtime_dir.display()
        ),
    )
    .expect("the runtime env could be written");

    fs::write(
        runtime_dir.join("compose-base.stderr"),
        format!("a captured line mentioning {FABRICATED_SECRET} verbatim\n"),
    )
    .expect("the captured stream could be written");

    let path = env::var("PATH").unwrap_or_default();
    let output = Command::new(diagnostics_script())
        .env("GLPI_TEST_RUNTIME_ENV", &runtime_env)
        .env("PATH", format!("{}:{path}", shim_directory.display()))
        .output()
        .expect("diagnostics.sh could be executed");
    assert!(
        output.status.success(),
        "diagnostics must never fail the calling job"
    );

    let mut stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    stdout.push_str(&String::from_utf8_lossy(&output.stderr));
    Diagnostics {
        stdout,
        recorded_arguments: fs::read_to_string(&recorded).unwrap_or_default(),
        runtime_dir,
    }
}

#[test]
fn diagnostics_redacts_generated_credentials_from_its_output() {
    let diagnostics = run_diagnostics();
    assert!(
        diagnostics.stdout.contains("[REDACTED]"),
        "the planted credential should have been replaced"
    );
    assert!(
        !diagnostics.stdout.contains(FABRICATED_SECRET),
        "diagnostics output must never contain a generated credential"
    );
    fs::remove_dir_all(&diagnostics.runtime_dir).ok();
}

#[test]
fn diagnostics_never_puts_a_credential_in_the_redaction_filter_argv() {
    let diagnostics = run_diagnostics();
    assert!(
        !diagnostics.recorded_arguments.is_empty(),
        "the redaction filter should have been invoked at least once"
    );
    assert!(
        !diagnostics.recorded_arguments.contains(FABRICATED_SECRET),
        "a generated credential reached the redaction filter's command line: \
         it must be passed through a private file instead"
    );
    fs::remove_dir_all(&diagnostics.runtime_dir).ok();
}

#[test]
fn diagnostics_removes_its_private_redaction_pattern_file() {
    let diagnostics = run_diagnostics();
    let leftovers: Vec<PathBuf> = fs::read_dir(&diagnostics.runtime_dir)
        .expect("the runtime directory is readable")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("redaction."))
        })
        .collect();
    assert!(
        leftovers.is_empty(),
        "the redaction pattern file must not outlive the script: {leftovers:?}"
    );
    fs::remove_dir_all(&diagnostics.runtime_dir).ok();
}
