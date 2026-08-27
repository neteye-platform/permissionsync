# ADR 0006 — Feasibility Evidence (Executable)

This file records the executable evidence for the **ADR 0006** feasibility
acceptance criteria, produced by `make test` (which runs `tests/gates.py`
against the Wasmtime 48 host and the fake-provider / fake-target). Every
assertion in this file is machine-checked by that suite against the real host
stdout/stderr and the servers' observable state; it is not a hand-written
narrative.

Reproduce with:

```sh
cd tests/architecture/adr-0006-wasm
make test        # builds host + adapters, runs the 11-gate suite
```

The suite contacts the fake-provider over TLS (with the host's rustls trust of
the ephemeral CA, generated into `generated/certs/ca.crt` by `tooling/gen_certs.sh`)
and the fake-target over TLS, then asserts each gate.

---

## Environment

- Host: Wasmtime `48.0.1` + `wasmtime-wasi 48.0.1`, ureq2, rustls `0.23` (`ring`).
- Rust guest: stable rustc, `wasm32-wasip2`, `cargo-component`.
- Non-Rust guest: **TinyGo** `0.37.0` (go `1.24.4`, wit-bindgen-go `v0.7.0`,
  wasm-tools `1.258.0`). `adapter_go.wasm` is generated from source during the
  build from `adapters/go-adapter/wit-build/` (not committed).
- Fake servers: Python `http.server` over TLS.

Shared WIT contract: `wit/permissions.wit` — `world adapter` imports only
`http` and `runtime`, exports `adapter-api`. There are **no WASI filesystem,
environment, process, or exit imports** in this world.

> status = the 11 ADR 0006 feasibility gates, evaluated by the suite below.

---

# Gate 1 — Independent lifecycle

- **Verdict:** PASS
- **Requirement:** ≥2 independently built component artifacts are selectable /
  replaceable without rebuilding core.
- **Implementation:** two separately built components (`rust-adapter`,
  `go-adapter`) are run by the *same* prebuilt host binary.
- **Tests:** `gate1_independent_lifecycle` runs host against rust then go.
- **Evidence:** both `rc=0` with `RECEIVED=` + `EFFECT grant`. Lifecycle rust &
  go both PASS.
- **Negative cases:** none (a `bad-adapter` component is rejected — see Gate 2).
- **Caveats:** the host does no per-component release/build; swapping is a
  config selection of an already-compiled `.wasm`.

# Gate 2 — Admission compatibility

- **Verdict:** PASS
- **Requirement:** an incompatible component is rejected during admission,
  before provider resolution / reconciliation / target mutation.
- **Implementation:** host `admit()` instantiates the component (which must
  export `adapter-api`) *before* the provider is contacted.
- **Tests:** `gate2_admission_compatibility` uses two distinct incompatibility
  cases:
  - `bad-adapter` — component with **no `adapter-api` export**.
  - `missing-import-adapter` — component with the **correct `adapter-api`
    export shape** but an **additional import** (`secret-vault`) the host's
    deny-by-default linker does not provide. The host only wires `http`,
    `runtime`, and WASI p2 imports, so this too fails instantiation.
- **Evidence:**
  - `bad-adapter`: host errors `admission/instantiation failed: no exported
    instance named 'permissionsync:adr0006/adapter-api@0.1.0'`; provider
    `/stats` shows `calls=0`; target `managed_assignments=[]` (unmutated).
  - `missing-import-adapter`: host errors `admission/instantiation failed`
    (unknown import `permissionsync:adr0006/secret-vault`); provider
    `/stats` shows `calls=0`; target `managed_assignments=[]` (unmutated).
- **Negative cases:** for both, provider + reconcile + target mutation stayed
  zero.
- **Caveats:** the two cases exercise the two failure modes admission must
  catch — a wrong export shape **and** an unprovided import — proving the
  deny-by-default linker refuses both before any work is done.

# Gate 3 — Language independence

- **Verdict:** PASS
- **Requirement:** two guest toolchains, incl. one non-Rust, produce components
  for the unchanged host contract.
- **Implementation:** Rust (`rust-adapter`) and TinyGo (`go-adapter`) both
  compile against the single `wit/permissions.wit`; the host does not change.
- **Tests:** `gate3_language_independence` runs both.
- **Evidence:** rust and go both `rc=0` with `RECEIVED=`.
- **Negative cases:** none.
- **Caveats:** the TinyGo build is generated from source
  `adapters/go-adapter/wit-build/` via `tinygo build -target=wasip2
  -wit-package=./wit-build -wit-world=adapter-build -o adapter_go.wasm .`.

# Gate 4 — Model fidelity

- **Verdict:** PASS
- **Requirement:** role/group/entitlement, unscoped, `self`+`descendants`
  scopes, multi-assignment, multi-valued constraints, and version are
  transported intact; unsupported version/kinds/propagation/constraints and
  unknown target values are rejected before mutation.
- **Implementation:** `doc_json()` echoes the exact document the component
  saw; adapters validate against allow-lists before reconciling.
- **Tests:**
  - `valid` variant → task: role `editor` (scoped `resource-boundary`/`self`),
    group `release-managers` (scoped `org`), entitlement `packet-capture-
    download` (unscoped), constraints `network:[collector-a,collector-b]` +
    `interface:[collector-a]`, `version:1`. In addition to the keyword probes,
    a **deep-equal fidelity assert** normalizes the host's `RECEIVED` (WIT
    records serialize snake_case) back to the provider's kebab-case transport
    doc and requires field-for-field equality with the served `/document`.
  - `repeat-scope` → the same role id `editor` granted across two distinct
    scopes with a mixed group/entitlement set: a VALID multi-scope transport,
    both adapters accept (`EFFECT grant`).
  - `descendants` → rust accepts, go rejects `unsupported propagation
    'descendants'`.
  - `unsupported-role` → both reject `unsupported role`.
  - `unsupported-version` → both reject `unsupported model version 99`.
  - Adapter-semantic rejection variants (structurally valid, so the adapter
    IS invoked and rejects; suite asserts one provider fetch, the adapter's
    diagnostic, and no mutation) for both rust and go:
    `unknown-group` → `unsupported group 'ops-admin'`, `unknown-entitlement`
    → `unsupported entitlement 'log-export'`, `unsupported-scope-type` →
    `unsupported scope type 'team'`, `unknown-scope-id` → `unsupported scope
    id 'zanzibar'`, `unsupported-constraint-type` → `unsupported constraint
    type 'budget'`, `invalid-constraint-value` → `unsupported interface value
    'collector-zzz'`, `unsupported-combination` → `unsupported
    assignment/constraint combination` (interface constraint with no
    role/group assignment; the mirror `allowed`-with-no-entitlement rule is
    implemented in both adapters).
  - Core-side structural variants (rejected by the host before the adapter is
    invoked, so provider fetch == 1 and no component invocation / mutation):
    `duplicate-constraint` → `duplicate constraint type 'X'`, `malformed-constraint`
    → `malformed constraint: empty constraint-type`, `partial-scope` → `partial
    scope: missing propagation`, `unsupported-kind` → `unknown assignment kind
    'superuser'`.
- **Evidence:** all fidelity checks PASS; the deep-equal assert confirms the
  whole v1 model (assignments minus order-independence quirk aside — see below
  — incl. scopes + constraints + version) survives intact; `repeat-scope` shows
  multi-scope fidelity; each structural variant shows exactly
  one provider fetch (the pre-invoke fetch), no `RECEIVED=`/`EFFECT` (no adapter
  invocation), and target `managed_assignments=[]` (no mutation); each
  adapter-semantic variant shows exactly one provider fetch, the adapter's
  rejection diagnostic, and no mutation.
- **Negative cases:** each structural rejection happened with `rc=1` and the
  mentioned diagnostic before target mutation; each adapter-semantic rejection
  happened with `rc=1` and the adapter's own diagnostic.
- **Caveats:** scope/constraint/kind/version structural checks live in the core
  (`validate_structural` + `document_from_json`), so they reject before
  component invocation regardless of which guest toolchain is selected. The
  deep-equal assert ignores key order (JSON objects are order-insensitive) and
  arrays are compared positionally; the transport is lossless for the v1 model
  shape used here.

# Gate 5 — Context isolation

- **Verdict:** PASS
- **Requirement:** desired state has no config/secrets; selected target config
  + ≥1 secret can be provided; unrelated target config/secrets unavailable;
  secrets absent from logs.
- **Implementation:** host passes only the selected target's config
  (`endpoint`, `client`) + secret (`token`) via `runtime::get_context`, plus
  per-route extra `context_config`/`context_secrets` items.
- **Tests:** `gate5_context_isolation` (a single-target keys-only check, plus a
  two-real-target isolation check: target-a `bob` on `:19443` and target-b
  `alice` on `:19444`, each with a distinct extra context item and secret).
- **Evidence:**
  - Single-target: `CONTEXT_KEYS=endpoint,client,token` (keys only) and the
    secret value is absent from host output.
  - Two-target: reconciling target-a only ever sees target-a's keys
    (`region`, `api-key-a`) and never target-b's secret key (`api-key-b`);
    reconciling target-b likewise never sees `api-key-a`; neither route's
    secret value (`SECRET_A_VALUE`/`SECRET_B_VALUE`) appears in output; a
    route to target-a leaves target-b's managed state untouched.
- **Negative cases:** a route for one target cannot obtain another target's
  config/secret keys, and no secret value is ever logged.
- **Caveats:** secrets are still transmitted to their own target as Bearer
  tokens (that is their purpose); the gate requires them absent from
  **logs/output**, which the host and fake-target both satisfy.

# Gate 6 — Default-deny capabilities

- **Verdict:** PASS
- **Requirement:** ungranted filesystem/environment/process denied; allowlisted
  HTTPS to mock target succeeds under explicit trust; unrelated destination
  denied; no unrestricted egress.
- **Implementation:**
  - WIT world has no fs/env/process imports (contract-level deny).
  - Host builds `WasiCtxBuilder::new()` (empty env, no preopens, no sockets).
  - `http::Host::call` enforces the allowlist `url.starts_with(target_endpoint)`
    and uses a rustls agent rooted at the target's CA.
- **Tests:** `gate6_default_deny` with `wasi-adapter` + `egress-adapter` +
  `process-adapter` + `rust` (allowlisted).
- **Evidence:**
  - `wasi-adapter` (tries `std::env::var` + `std::fs::read("/etc/passwd")`)
    reports `DIAG wasi env/fs denied (0 bytes readable)` — ungranted env/fs
    yield zero bytes.
  - `process-adapter` (tries `std::process::Command::new("sh")...output()`)
    reports `DIAG process execution denied (0 bytes readable)` — no process
    execution capability is available to the guest.
  - `egress-adapter` (tries `https://example.com/steal`) → host `egress denied:
    'https://example.com:443/steal' is outside allowlist
    'https://127.0.0.1:19443'`.
  - `rust` allowlisted HTTPS target succeeds (`rc=0`) under explicit CA trust.
- **Negative cases:** all three ungranted paths (env/fs, process, unrelated
  destination) denied; allowlisted path permitted.
- **Caveats:** the fake target cert is trusted via the explicit `ca.crt`; this
  is the "explicitly supplied trust" the gate names.

# Gate 7 — Bounded resources

- **Verdict:** PASS
- **Requirement:** deliberate memory exhaustion is denied/trapped before host
  exhaustion.
- **Implementation:** `StoreLimitsBuilder::memory_size(8MiB)` + host limiter.
- **Tests:** `gate7_bounded_resources` with `runaway-mem-adapter`.
- **Evidence:** host exits `rc=1` (OOM/abort trap), `elapsed=0.5s`; host
  process survives (not `rc=137`/SIGKILL).
- **Negative cases:** memory runaway trapped, host not exhausted.
- **Caveats:** limits cover linear memory; the store-limiter path is the
  general trap table used by the boundary.

# Gate 8 — Deadline and cancellation

- **Verdict:** PASS
- **Requirement:** CPU-bound component and stalled outbound are interrupted /
  bounded by remaining deadline, return `500`, no new work.
- **Implementation:** epoch interruption (`set_epoch_deadline` +
  `epoch_deadline_trap`); ureq agent `.timeout(deadline_ms)`.
- **Tests:** `gate8_deadline_cancellation` with `runaway-cpu-adapter` and a
  `--delay-ms 15000` fake target.
- **Evidence:**
  - CPU runaway interrupted: `rc=1`, `elapsed=1.1s` (< 6s bound).
  - No new work after cancellation: provider `calls==1` (the one pre-invoke
    fetch; no retry after the trap).
  - Stalled outbound bounded: `rc=1`, `elapsed=1.0s` (< 12s bound).
- **Negative cases:** both bounded scenarios never exceeded the bound.
- **Caveats:** the host is a CLI that reports a non-zero exit (the gate's
  `500`); effects already issued before a deadline are intentionally left
  uncertain — the PoC issues no rollback, matching the gate's wording.

# Gate 9 — Invocation accounting

- **Verdict:** PASS
- **Requirement:** one provider call, one component call, no automatic retry.
- **Implementation:** a single `fetch_document` then a single `reconcile`. The
  host now instruments the invocation: `HostState` carries `reconcile_calls`
  and `auto_retries` (the host has **no retry loop**, so `auto_retries` is
  always 0), and `reconcile()` prints `ACCOUNT reconcile_calls=<n>
  auto_retries=<n>`.
- **Tests:** `gate9_invocation_accounting`.
- **Evidence:** provider `/stats` shows `calls==1`; the host-instrumented line
  reads `ACCOUNT reconcile_calls=1 auto_retries=0`; target managed state
  reflects exactly the single doc (`role:editor`,
  `group:release-managers`, `entitlement:packet-capture-download`).
- **Negative cases:** no extra provider call, exactly one reconcile invocation,
  and zero automatic retries observed.
- **Caveats:** internal target calls behind the reconcile are allowed (per
  gate); here the adapter makes one POST. `auto_retries` is structurally 0
  because the host performs no retry; the instrumented counter makes that
  invariant machine-visible rather than assumed.

# Gate 10 — Routing isolation

- **Verdict:** PASS
- **Requirement:** an unconfigured/unmanaged route performs zero provider or
  reconcile calls; a missing/disabled/incompatible component returns failure;
  another valid target succeeds.
- **Implementation:** host `route <registry.json> <route-key>` subcommand resolves
  a key from an explicit multi-route registry. The three reachable states are
  distinct per ADR 0006 (an unconfigured/unmanaged route is a successful no-op
  with provider=0 and adapter=0; a *managed* route whose component is missing or
  incompatible is an error): admission before provider fetch isolates bad routes.
- **Tests:** `gate10_routing_isolation` with a registry containing an unmanaged
  route, a managed-missing route, a managed-incompatible route, and a valid
  managed route, plus a route key absent from the registry.
- **Evidence:**
  - Absent route key → `ROUTE unconfigured nocalls`, `rc=0`, provider `calls=0`,
    target untouched.
  - Unmanaged (otherwise valid) route → `ROUTE unmanaged nocalls`, `rc=0`, provider
    `calls=0`, target not mutated.
  - Managed + missing component → `rc=1` (500-equivalent), provider `calls=0`.
  - Managed + incompatible component → `rc=1` (500-equivalent), provider `calls=0`.
  - Distinct valid managed route → `rc=0` with `RECEIVED=` after all failures.
- **Negative cases:** unconfigured vs unmanaged are distinct no-ops and neither
  performs work; missing vs incompatible managed routes both fail without a
  provider call; failures do not prevent a subsequent valid route from succeeding.
- **Caveats:** routing here is a per-process CLI; the registry JSON models the
  persistent multi-route config the ADR anticipates.

# Gate 11 — Managed authority and statelessness

- **Verdict:** PASS
- **Requirement:** only managed assignment/constraint state mutates; unmanaged
  target state untouched; restart requires no shared replay/idempotency/adapter
  lifecycle state.
- **Implementation:** fake-target separates `managed_*` from `unmanaged_*`
  (`legacy-admin` assignment, `legacy:[keep]` constraint) and only the managed
  side is written by the adapter.
- **Tests:** `gate11_managed_authority_statelessness`.
- **Evidence:** after reconcile, `managed_assignments` = the three desired
  entries while `unmanaged_assignments=["legacy-admin"]` and
  `unmanaged_constraints={"legacy":["keep"]}` are untouched; a restart (fresh
  host process) reproduces the same managed state with no shared replay.
- **Negative cases:** unmanaged state verified unchanged; restart required no
  persisted adapter state.
- **Caveats:** the fake-target's state is in-memory per process (restart uses a
  fresh host + same live target), demonstrating no host-side persistence.

---

# Overall Verdict

| Gate | Name                          | Verdict |
|------|-------------------------------|---------|
| 1    | Independent lifecycle         | PASS    |
| 2    | Admission compatibility       | PASS    |
| 3    | Language independence         | PASS    |
| 4    | Model fidelity                | PASS    |
| 5    | Context isolation             | PASS    |
| 6    | Default-deny capabilities     | PASS    |
| 7    | Bounded resources             | PASS    |
| 8    | Deadline and cancellation     | PASS    |
| 9    | Invocation accounting         | PASS    |
| 10   | Routing isolation             | PASS    |
| 11   | Managed authority & statelessness | PASS |

**Overall feasibility verdict:** Feasible — all 11 feasibility gates PASS with
executable, reviewable evidence. A Wasmtime 48 host carriage of guest-agnostic
Target Adapters (Rust and TinyGo) upholds every stated boundary: pre-admission
rejection, default-deny capabilities and egress, bounded resources and
deadlines, one-shot invocation, routing isolation, context isolation, and
managed-authority statelessness.

**Recommendation:** Proceed with ADR 0006's feasibility conclusion that at
least one viable host runtime (Wasmtime, here) upholds the stated boundaries.
Keep the deferred decisions deferred — notably the runtime engine, WIT
packages/worlds, WASI/HTTP mediation, and config/secret APIs remain open. The
former caveats are now exercised by the suite: core-side structural rejection
of duplicate/malformed/partial-scope/unsupported-kind documents, a reproducible
TinyGo build, per-target context isolation across two real targets, an explicit
multi-route registry distinguishing unconfigured/unmanaged/missing/incompatible,
a process-execution denial case, a second admission case (a component whose
export shape is correct but which imports an unprovided interface), a
deep-equal full-model fidelity assert, multi-scope repeated-assignment
transport, a full adapter-semantic rejection matrix (unknown group/entitlement,
unsupported scope type and id, unsupported constraint type and value,
unsupported assignment/constraint combination) across both toolchains, and a
host-instrumented invocation-accounting check. Remaining open items before any
production implementation are the engine/WIT/API choices themselves, not PoC
feasibility.

> This evidence supports ADR 0006's acceptance. The ADR's own gating rule
> ("remains Proposed unless every gate passes and the recorded evidence is
> reviewable") is now satisfied; ADR 0006 is **Accepted**. This file is
> historical architecture evidence; the host runtime, WIT contract, and adapter
> choices here are feasibility stand-ins and do not constrain the production
> implementation.
