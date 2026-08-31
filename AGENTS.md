# Coding Agent Guide

## Sources of truth

- Inspect the repository before assuming implementation, workspace, or build
  commands exist.
- Start with the [ADR index](docs/adr/README.md) for the current architecture,
  ADR set, status, and lifecycle rules.
- For architecture decisions, Accepted ADRs are authoritative and override
  conflicting guidance in this file. Read relevant Accepted ADRs before making
  architecture-facing changes.
- Use the repository's [security policy](SECURITY.md) for security handling.
- Repository tooling configuration is authoritative; do not change it to solve
  a parent workspace's local configuration problem.

## Working in this repository

- Keep diffs task-focused and limited to the requested files.
- Preserve deferred decisions and existing ADR ownership.
- Do not introduce silent violations, speculative paths, or invented tools.
- Keep implementation and documentation deployment-neutral unless an Accepted
  ADR says otherwise.
- Do not add production code, tests, or configuration for a documentation-only
  task.
- Keep Markdownlint clean and use repository-relative links.

## ADRs

- New ADRs MUST use the [ADR template](docs/adr/template.md).
- Follow the index's standard Record Structure without expanding it into a
  copied architecture specification.
- Add every new ADR to the [ADR index](docs/adr/README.md).
- Use the next ADR number; never renumber an adopted ADR.
- A replacement is a new ADR and normally marks the replaced decision
  Superseded.
- Make a new ADR only for a genuine architecture decision, not a small change
  or implementation detail.

## Testing and validation

- The exact Rust toolchain is defined by `rust-toolchain.toml`. Do not override
  it in CI or documentation.
- Before completing an implementation PR, run:

  ```sh
  prek run --all-files --refresh
  cargo fmt --all -- --check
  cargo deny --locked check
  cargo check --workspace --all-targets --all-features --locked
  cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
  cargo test --workspace --all-features --locked
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
  git diff --check
  ```

- Install the exact Renovate-managed `cargo-deny` version from
  `.github/workflows/rust-validation.yaml` before its policy check.
- Add direct Cargo dependencies only when the current change requires them. Pin
  direct dependency versions exactly, commit `Cargo.lock` with manifest changes,
  and use `--locked` for dependency-resolving Cargo commands.
- New workspace crates must inherit the workspace lints.
- Tests must be deterministic and isolated: no public Internet access, real
  external or production services, arbitrary sleeps, wall-clock races, unseeded
  randomness, execution order, persistent shared state, fixed ports, or
  developer-specific state. Prefer controlled time, local fakes and fixtures,
  ephemeral ports, temporary directories, deterministic seeds, explicit
  synchronization, and bounded timeouts. A flaky test is a bug. Never hide it
  with automatic test retries.
- Architecture-specific tests must follow the relevant Accepted ADRs.
- Inspect `git diff` before finishing.
- Optionally inspect `git diff --word-diff` when reviewing wording changes.

## Security

- Never commit credentials, tokens, private keys, secrets, or trust material.
- Do not disable or weaken TLS verification; comply with security requirements
  in Accepted ADRs.
- Use mature, well-maintained libraries for TLS, JWT, OAuth/OIDC,
  cryptography, and signature validation when that work is introduced. Never
  implement cryptographic primitives from scratch.

## Before finishing

- Re-read the relevant Accepted ADRs and confirm no deferred decision was
  silently resolved.
- Confirm only requested files changed.
- Run the allowed checks and inspect the final diff.
- State exact files changed and any validation that was skipped.
