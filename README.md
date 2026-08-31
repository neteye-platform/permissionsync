# PermissionSync

PermissionSync is an architecture-first service for synchronizing a user's
desired permissions with a selected target. The active constraints are recorded
in the [ADR index](docs/adr/README.md).

The Rust workspace is a production-development foundation. It intentionally
contains no synchronization, HTTP, authentication, Permission Provider, or
target-adapter behavior yet.

## Development

The exact Rust toolchain is defined in
[rust-toolchain.toml](rust-toolchain.toml). Install
[rustup](https://rustup.rs/) and run this from the repository root to install
the selected compiler and required components:

```sh
rustup toolchain install
```

Rustup selects that toolchain automatically for Cargo commands run in this
repository. Build, check, and test the workspace with:

```sh
cargo build --workspace --all-features --locked
cargo check --workspace --all-targets --all-features --locked
cargo test --workspace --all-targets --all-features --locked
```

The dependency-policy check requires the exact, Renovate-managed
`CARGO_DENY_VERSION` in
[the Rust validation workflow](.github/workflows/rust-validation.yaml):

```sh
cargo install --locked --version <CARGO_DENY_VERSION> cargo-deny
```

Run the complete local validation suite before opening an implementation PR:

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

Direct Cargo dependencies must be necessary for the current change, use exact
versions such as `=1.2.3`, and update the committed `Cargo.lock` in the same
change. `deny.toml` enforces advisory, license, source, wildcard, and duplicate
version policy.

Tests must be deterministic and isolated. They must not rely on public Internet
access, production services, timing races, arbitrary sleeps, unseeded
randomness, execution order, retained state, fixed ports, or developer-specific
configuration. Never retry a failed test; fix the defect or race instead. See
[AGENTS.md](AGENTS.md) for the full testing policy.
