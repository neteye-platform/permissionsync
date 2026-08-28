# ADR 0008 — Target Adapter Packaging, Distribution, and Lifecycle Validation Spike

> **Historical architecture validation — not production code.**
>
> This directory is the small executable validation evidence for **ADR 0008**
> acceptance. It machine-checks the three "Validation Before Acceptance"
> scenarios that ADR 0008 owns. It is **not** production PermissionSync, **not**
> the production loader, and **not** a recommendation of any specific registry
> product, loader implementation, signing technology, or deployment
> configuration schema — all of which ADR 0008 explicitly defers.
>
> The dependency-free loader model here is a feasibility stand-in. Do not treat
> it as a production choice, and do not let it constrain the production
> implementation.

## What this validates

This spike models only the parts of the adapter-loader boundary that ADR 0008
owns, and machine-checks the three scenarios from ADR 0008's
"Validation Before Acceptance":

1. **Offline replica recovery.** After staging, a fresh replica recovers the
   complete exact selected artifact set from deployment-local infrastructure
   with no external network and no warm cache.
2. **Atomic selected-set materialization.** Materializing the complete
   deployment-selected adapter set is all-or-nothing: one missing,
   digest-mismatched, or untrusted artifact fails the loader globally, and no
   partial adapter set (e.g. A alone) becomes active. Startup succeeds only
   once the whole set is valid and available.
3. **Exact-version and no-fallback enforcement.** Deployment configuration is
   authoritative. If the selected digest becomes unavailable while an older one
   remains, the loader fails instead of silently selecting the older artifact;
   when the exact selected artifact is restored, the replica uses exactly that
   digest.

The recorded, machine-checked evidence lives at
[`../../../docs/adr/evidence/0008-packaging-validation.md`](../../../docs/adr/evidence/0008-packaging-validation.md).

## Layout

```text
spike.py          Dependency-free loader model + 3-scenario runner
```

## Reproduction

```sh
python3 spike.py     # or: ./spike.py
```

`spike.py` ends by printing each scenario's PASS/FAIL and an
`OVERALL: ALL SCENARIOS PASS` line and exits `0` only when all scenarios pass.

Requires only the Python standard library (no external packages, no network).
