# ADR 0008 — Packaging, Distribution, and Lifecycle Validation Evidence

> **Historical supersession:** This is historical evidence for superseded ADR
> 0008. It proves the former independent WASM packaging architecture was
> feasible and validated, but does not describe the current selected production
> architecture ([ADR 0009](../0009-compile-time-rust-target-adapters.md)).

This file records the executable evidence for the **ADR 0008** acceptance
scenarios, produced by `python3 spike.py` (a dependency-free loader model at
[`tests/architecture/adr-0008-packaging/spike.py`](../../../tests/architecture/adr-0008-packaging/spike.py)).
Every scenario below is machine-checked by that spike; it is not a hand-written
narrative.

Reproduce with:

```sh
cd tests/architecture/adr-0008-packaging
python3 spike.py
```

The spike models only the loader-boundary semantics ADR 0008 owns and
intentionally leaves registry product, loader implementation, signing
technology, on-disk layout, and deployment configuration schema deferred (as
ADR 0008 does).

---

## Environment

- Language: Python standard library only (`hashlib`, `shutil`, `tempfile`,
  `dataclasses`, `pathlib`, `typing`); no external packages, no network access.
- The load model: a deployment-local artifact store (`source`) keyed by exact
  content digest, and a `Loader.materialize` that — for the complete selected
  set — obtains every artifact from that local store, verifies each content
  digest matches the exact selected digest, and only then populates the output
  adapter set. Any missing or digest-mismatched artifact fails the whole load
  and leaves the output set empty (no partial set). It never substitutes
  another artifact for the selected one.

> status = the three ADR 0008 acceptance scenarios, evaluated by the spike.

---

## Scenario 1 — Offline replica recovery

- **Verdict:** PASS
- **Requirement:** after successful staging, a fresh replica (including a cold
  node) recovers the complete exact selected artifact set with external
  Internet unavailable and no warm cache.
- **Implementation:** a fresh, empty output set is materialized from a
  deployment-local store that contains exactly the selected artifact. The model
  has no network path at all, so recovery is offline by construction.
- **Evidence:** `scenario [PASS] offline replica recovery`.

## Scenario 2 — Atomic selected-set materialization

- **Verdict:** PASS
- **Requirement:** with two selected artifacts A and B where A is valid and B is
  missing, the loader fails globally; no partial A-only adapter set becomes
  active. Once B is made valid and available, startup succeeds with the full set.
- **Implementation:** `Loader.materialize` verifies every selected artifact
  before populating any output; a missing B returns failure and leaves the
  output empty. Adding B makes the full materialization succeed.
- **Evidence:** `scenario [PASS] atomic selected-set materialization`.

## Scenario 3 — Exact-version and no-fallback enforcement

- **Verdict:** PASS
- **Requirement:** when A@OLD and A@NEW are both available but the deployment
  selects A@NEW, making NEW unavailable while OLD remains must fail startup
  (OLD is not selected automatically). Restoring NEW makes the replica use
  exactly NEW.
- **Implementation:** the selection carries the exact digest; if the exact
  selected artifact is absent, the load fails and the output stays empty even
  though an alternate (OLD) artifact is present. Restoring the exact NEW
  artifact yields exactly the NEW content.
- **Evidence:** `scenario [PASS] exact-version and no-fallback enforcement`.

---

## Summary

```text
scenario [PASS] offline replica recovery
scenario [PASS] atomic selected-set materialization
scenario [PASS] exact-version and no-fallback enforcement
OVERALL: ALL SCENARIOS PASS
```

All three ADR 0008 acceptance scenarios pass. The spike demonstrates that an
atomic, exact-digest, offline materializer upholds the ADR's owned invariants:
deployment configuration is authoritative, the complete selected set
materializes all-or-nothing, and there is no automatic fallback.

> This evidence supports ADR 0008's acceptance. The loader engine, registry
> product, signing/provenance technology, on-disk layout, and deployment
> configuration schema remain deferred; this file is historical architecture
> evidence and does not constrain the production implementation.
