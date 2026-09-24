//! Hermetic, no-Docker regression coverage for `integration/glpi/bootstrap.sh`'s
//! `env_put()` dual-consumer `runtime.env` serialization.
//!
//! `runtime.env` is read by two different parsers: this script's own `source`
//! (Bash), and `docker compose --env-file`'s dotenv grammar
//! (compose-spec/compose-go `dotenv/parser.go`). Both parsers treat a
//! double-quoted value's `\\`, `\"`, and `\$` escapes identically (literal
//! backslash, literal quote, and literal, non-interpolated dollar,
//! respectively), which is exactly the escape set `env_put()` uses. These
//! tests invoke `bootstrap.sh` through an explicit, test-only self-test hook
//! (`PERMISSIONSYNC_BOOTSTRAP_ENV_PUT_SELFTEST=1`) that exercises the real
//! `env_put()` function without running any of bootstrap.sh's Docker/OpenSSL
//! provisioning logic, so no test here requires Docker.

use std::{
    env, fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

fn bootstrap_script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("integration/glpi/bootstrap.sh")
}

/// Run `bootstrap.sh`'s `env_put()` self-test hook with the given `NAME
/// VALUE` pairs, in its own disposable `TMPDIR`/`RUNNER_TEMP` so it never
/// touches a shared runtime directory. Returns the process `Output`.
fn run_env_put_selftest(pairs: &[(&str, &str)]) -> Output {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp_root = env::temp_dir().join(format!(
        "permissionsync-glpi-env-put-selftest-{}-{unique}",
        std::process::id(),
    ));
    fs::create_dir_all(&tmp_root).expect("create disposable TMPDIR for the self-test");

    let mut command = Command::new("bash");
    command
        .arg(bootstrap_script_path())
        .env("PERMISSIONSYNC_BOOTSTRAP_ENV_PUT_SELFTEST", "1")
        .env("TMPDIR", &tmp_root)
        .env_remove("RUNNER_TEMP")
        .env_remove("GITHUB_ACTIONS")
        .env_remove("GITHUB_ENV");
    for (name, value) in pairs {
        command.arg(name).arg(value);
    }

    let output = command
        .output()
        .expect("bootstrap.sh env_put self-test can be invoked");

    let _ = fs::remove_dir_all(&tmp_root);
    output
}

/// Parse one `NAME="..."` line written by `env_put()` into `(name,
/// double_quoted_inner)`, asserting the expected double-quoted shape.
fn split_runtime_env_line(line: &str) -> (&str, &str) {
    let (name, rest) = line
        .split_once('=')
        .unwrap_or_else(|| panic!("runtime.env line is missing '=': {line:?}"));
    assert!(
        rest.starts_with('"') && rest.ends_with('"') && rest.len() >= 2,
        "env_put() must always double-quote its value, got: {line:?}"
    );
    (name, &rest[1..rest.len() - 1])
}

/// Decode a `source`d Bash double-quoted string's `\\`, `\"`, `\$` escapes.
/// This mirrors exactly what Bash itself does inside `"..."`.
fn bash_decode_double_quoted(inner: &str) -> String {
    let mut out = String::new();
    let mut chars = inner.chars().peekable();
    while let Some(char) = chars.next() {
        if char == '\\' {
            match chars.next() {
                Some(escaped @ ('\\' | '"' | '$')) => out.push(escaped),
                Some(other) => {
                    // env_put() never emits any other escaped character; fail
                    // loudly rather than silently mis-decoding.
                    panic!("unexpected Bash escape sequence: \\{other}");
                }
                None => panic!("trailing backslash in double-quoted value: {inner:?}"),
            }
        } else {
            out.push(char);
        }
    }
    out
}

/// Decode a compose `--env-file` double-quoted string's escapes, mirroring
/// compose-spec/compose-go `dotenv/parser.go`'s `expandEscapes` +
/// `expandVariables`: `\\` -> `\`, `\"` -> `"`, and `\$` -> the two-character
/// literal-dollar marker `$$`, which compose's variable expansion then
/// collapses to a single literal, non-interpolated `$`.
fn compose_env_file_decode_double_quoted(inner: &str) -> String {
    // Pass 1 (expandEscapes): decode \\ and \", and turn \$ into the
    // literal-dollar marker "$$" (not yet resolved to a single '$').
    let mut after_escapes = String::new();
    let mut chars = inner.chars().peekable();
    while let Some(char) = chars.next() {
        if char == '\\' {
            match chars.next() {
                Some('\\') => after_escapes.push('\\'),
                Some('"') => after_escapes.push('"'),
                Some('$') => after_escapes.push_str("$$"),
                Some(other) => panic!("unexpected compose escape sequence: \\{other}"),
                None => panic!("trailing backslash in double-quoted value: {inner:?}"),
            }
        } else {
            after_escapes.push(char);
        }
    }

    // Pass 2 (expandVariables, restricted to the "$$ -> literal $" case that
    // env_put()'s escaping ever produces): collapse every "$$" pair down to a
    // single literal '$'. env_put() never emits an unescaped, unpaired '$',
    // so no other interpolation form can appear here.
    after_escapes.replace("$$", "$")
}

const REJECTION_MESSAGE: &str = "runtime.env write refused: a generated value contained a disallowed character (CR, LF, or backtick).";

#[test]
fn env_put_round_trips_a_value_containing_a_single_quote_under_both_consumers() {
    let value = "it's a test";
    let output = run_env_put_selftest(&[("QUOTE", value)]);
    assert!(
        output.status.success(),
        "env_put() must accept a single quote: {output:?}"
    );

    let stdout = String::from_utf8(output.stdout).expect("self-test stdout is UTF-8");
    let line = stdout
        .lines()
        .next()
        .unwrap_or_else(|| panic!("expected exactly one runtime.env line, got: {stdout:?}"));
    let (name, inner) = split_runtime_env_line(line);
    assert_eq!(name, "QUOTE");

    assert_eq!(
        bash_decode_double_quoted(inner),
        value,
        "Bash `source` must round-trip a single quote unchanged"
    );
    assert_eq!(
        compose_env_file_decode_double_quoted(inner),
        value,
        "docker compose --env-file must round-trip a single quote unchanged"
    );
}

#[test]
fn env_put_round_trips_backslash_quote_and_dollar_under_both_consumers() {
    let value = r#"back\slash "quote" $dollar and'apostrophe"#;
    let output = run_env_put_selftest(&[("MIXED", value)]);
    assert!(
        output.status.success(),
        "env_put() must accept backslash/quote/dollar/apostrophe: {output:?}"
    );

    let stdout = String::from_utf8(output.stdout).expect("self-test stdout is UTF-8");
    let line = stdout
        .lines()
        .next()
        .unwrap_or_else(|| panic!("expected exactly one runtime.env line, got: {stdout:?}"));
    let (name, inner) = split_runtime_env_line(line);
    assert_eq!(name, "MIXED");

    assert_eq!(bash_decode_double_quoted(inner), value);
    assert_eq!(compose_env_file_decode_double_quoted(inner), value);
}

#[test]
fn env_put_emits_multiple_values_each_correctly_double_quoted_and_ordered() {
    let pairs = [("FIRST", "a'b"), ("SECOND", r#"c\d"e"#), ("THIRD", "plain")];
    let output = run_env_put_selftest(&pairs);
    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8(output.stdout).expect("self-test stdout is UTF-8");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), pairs.len(), "got: {lines:?}");

    for ((expected_name, expected_value), line) in pairs.iter().zip(lines) {
        let (name, inner) = split_runtime_env_line(line);
        assert_eq!(name, *expected_name);
        assert_eq!(bash_decode_double_quoted(inner), *expected_value);
        assert_eq!(
            compose_env_file_decode_double_quoted(inner),
            *expected_value
        );
    }
}

#[test]
fn env_put_rejects_a_carriage_return_before_writing_anything() {
    let output = run_env_put_selftest(&[("BAD", "has\rCR")]);
    assert!(
        !output.status.success(),
        "env_put() must fail closed on CR: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).is_empty(),
        "no runtime.env content may be emitted when a value is rejected: {output:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(REJECTION_MESSAGE),
        "stderr must contain the fixed, non-secret rejection message, got: {stderr}"
    );
    assert!(
        !stderr.contains("has"),
        "rejection message must not echo the offending value: {stderr}"
    );
}

#[test]
fn env_put_rejects_a_line_feed_before_writing_anything() {
    let output = run_env_put_selftest(&[("BAD", "has\nLF")]);
    assert!(!output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains(REJECTION_MESSAGE));
}

#[test]
fn env_put_rejects_a_backtick_before_writing_anything() {
    let output = run_env_put_selftest(&[("BAD", "has`backtick")]);
    assert!(!output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains(REJECTION_MESSAGE));
}

#[test]
fn env_put_rejects_the_offending_pair_without_partially_writing_earlier_accepted_pairs() {
    // The first pair is valid and would normally be written; the second is
    // rejected. Because env_put() validates a value fully before appending
    // its own line, the accepted first line is written but the rejected
    // second line never appears (no partial/malformed line is ever produced
    // for the rejected value itself).
    let output = run_env_put_selftest(&[("GOOD", "fine"), ("BAD", "bad`tick")]);
    assert!(!output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("BAD"),
        "the rejected pair must never be written, got stdout: {stdout}"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains(REJECTION_MESSAGE));
}
