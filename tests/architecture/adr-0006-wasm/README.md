# ADR 0006 — WebAssembly Component Target Adapter Feasibility Suite

> **Historical supersession:** This is historical evidence for superseded ADR
> 0006. It proves the former WebAssembly architecture was feasible and
> validated, but does not describe the current selected production architecture
> (ADR 0009).
>
> **Historical architecture validation — not production code.**
>
> This directory is the executable feasibility evidence for **ADR 0006**. It
> exists to record that at least one viable host runtime can uphold the ADR's
> stated boundaries. It is **not** production PermissionSync, **not** a
> reference implementation, and **not** a recommendation of any specific
> runtime, WIT contract, or adapter design.
>
> The host runtime (Wasmtime), the WIT packages/worlds, the entry-point and
> error semantics, and every adapter implementation here are feasibility
> stand-ins. Do not treat them as production choices, and do not let them
> constrain the production implementation.

## What this validates

This suite machine-checks the **11 ADR 0006 feasibility gates** against a real
Wasmtime 48 host carrying WebAssembly Component Model Target Adapters written
in two independent guest toolchains (Rust and TinyGo). It covers independent
lifecycle, admission compatibility, language independence, model fidelity,
context isolation, default-deny capabilities, bounded resources, deadline and
cancellation, invocation accounting, routing isolation, and managed-authority
statelessness.

The recorded, machine-checked evidence lives at
[`../../../docs/adr/evidence/0006-wasm-feasibility.md`](../../../docs/adr/evidence/0006-wasm-feasibility.md).

## Layout

```text
wit/permissions.wit            Single shared WIT contract (world `adapter`)
host/                          Wasmtime 48 host (load, admit, context, egress)
adapters/                      Guest adapters (one per toolchain / scenario)
  rust-adapter/                Rust (wasm32-wasip2) — supports self + descendants
  go-adapter/                  TinyGo (wasip2) — rejects descendants (Gate 4 negative)
  bad-adapter/                 Non-conforming component (Gate 2 admission reject)
  missing-import-adapter/      Correct export shape but an unprovided import
                                (Gate 2)
  egress-adapter/              Valid component that tries egress outside
                                allowlist (Gate 6)
  wasi-adapter/                Valid component that tries env/fs access (Gate 6)
  process-adapter/             Valid component that tries process execution
                                (Gate 6)
  runaway-mem-adapter/         OOM runaway (Gate 7)
  runaway-cpu-adapter/         CPU runaway (Gate 8)
fake-provider/                 Serves canonical desired-permission documents + variants
fake-target/                   In-memory target with managed/unmanaged state
tests/gates.py                 Executable 11-gate suite
Makefile                       Single `make` = build + run all gates
```

## Reproduction

```sh
make            # build host + adapters, then run the 11-gate suite
make build      # build host + adapters only
make test       # run tests/gates.py (self-manages fake-provider + fake-target)
make clean      # remove ALL generated output (bindings, wasm, certs, targets)
```

`make test` ends by printing each gate's PASS/FAIL and an
`OVERALL: ALL 11 GATES PASS` line.

### Toolchain versions

Recorded for reproducibility:

- Host runtime: **Wasmtime `48.0.1`** + `wasmtime-wasi 48.0.1`, ureq2, rustls `0.23`.
- Rust guest: stable rustc, `wasm32-wasip2`, `cargo-component`.
- Non-Rust guest: **TinyGo `0.37.0`** (go `1.24.4`, wit-bindgen-go `v0.7.0`,
  wasm-tools `1.258.0`). `adapter_go.wasm`, the generated Go bindings, and
  `wit-build/permissions.wit` are all generated from source during the build
  (never committed).
- Fake servers: Python `http.server` over TLS.

> **Note on `go-adapter/wit-build/deps/`:** this vendored subtree is
> intentionally retained as the minimum TinyGo WIT resolver dependency tree
> required for reproducible historical validation. The canonical PermissionSync
> WIT (`wit/permissions.wit`) and all generated bindings/artifacts
> (`bindings.rs`, Go `permissionsync/` + `wasi/` packages, `.wasm`, TLS certs)
> are **not** duplicated or committed — they are regenerated from source on
> every build.

Prerequisites: Rust stable + `wasm32-wasip2` target, `cargo-component`,
`wasm-tools`, `openssl` (for ephemeral TLS cert generation), Python 3, and for
the Go adapter a TinyGo + wit-bindgen-go toolchain on `PATH`.

## Contract

`world adapter` imports only `http` (host-mediated, allowlisted HTTPS) and
`runtime` (config/secrets) and exports a single `adapter-api.reconcile` entry
point. It declares **no WASI filesystem, environment, process, or exit imports**
— a guest compiled against this world physically cannot reach those
capabilities (Gate 6 evidence at the contract level).
