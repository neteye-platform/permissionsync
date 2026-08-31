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
  prek run --all-files
  cargo fmt --all -- --check
  cargo check --workspace --all-targets --all-features --locked
  cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
  cargo test --workspace --all-targets --all-features --locked
  cargo deny --locked check
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
  git diff --check
  ```

- Install the exact Renovate-managed `cargo-deny` version from
  `.github/workflows/rust-validation.yaml` before its policy check.
- Add direct Cargo dependencies only when the current change requires them. Pin
  direct dependency versions exactly, commit `Cargo.lock` with manifest changes,
  and use `--locked` for dependency-resolving Cargo commands.
- Tests must be deterministic and isolated. They must not depend on public
  Internet access; real Keycloak, GLPI, IcingaWeb2, or other production
  services; wall-clock races; arbitrary sleeps; unseeded randomness; execution
  order; persistent state; fixed ports; or developer-specific environment
  state. Use controlled time, local fake or mock servers, ephemeral ports,
  temporary directories, deterministic seeds, explicit synchronization, and
  bounded timeouts. Never retry a failed test; fix the test or production race.
- Inspect `git diff` before finishing.
- Optionally inspect `git diff --word-diff` when reviewing wording changes.
- Future production tests must verify architecture guardrails, not merely build
  a convenient implementation.
- Future tests must cover boundaries, failure isolation, bounded work,
  no-retry behavior, validation-before-mutation, and safe observability.
- Failure isolation is limited to target-local configuration and recoverable
  request failures; those failures isolate to the affected target or request.
- Cancellation is best effort, and detached or background reconciliation is not
  permitted.
- Non-cooperative work, panic, abort, out-of-memory, or unsafe defects can
  affect the whole replica.
- Future tests must not imply dynamic adapter loading or WebAssembly sandbox
  properties for the compile-time Rust architecture.

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
