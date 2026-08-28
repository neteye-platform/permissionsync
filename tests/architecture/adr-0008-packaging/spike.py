#!/usr/bin/env python3
# Copyright (c) 2026 Würth IT Italy S.r.l.
"""ADR 0008 packaging/lifecycle validation spike.

Models the deployment-selected adapter materialization semantics owned by
ADR 0008 and machine-checks the three "Validation Before Acceptance" scenarios:

1. Offline replica recovery
2. Atomic selected-set materialization
3. Exact-version and no-fallback enforcement

This is a *historical architecture validation* stand-in, not production code.
It intentionally does not decide a registry product, loader implementation,
signing technology, on-disk layout, or deployment configuration schema (all
deferred by ADR 0008). It models only the parts of the loader boundary the ADR
owns:

- deployment configuration is the source of truth for adapter identity
  (artifact + exact immutable digest);
- the loader obtains artifacts only from a deployment-local source (offline);
- materialization of the complete selected set is all-or-nothing (atomic, no
  partial set);
- there is no automatic fallback to another digest/version.

Run from anywhere:

    python3 spike.py

Exit code 0 == all scenarios PASS.
"""

from __future__ import annotations

import hashlib
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Iterable

# Real sha256 digests of the distinct fixture artifacts. Computed once so the
# digest checks reflect genuine content hashing (deployment config pins the
# exact digest of the artifact the loader must prove).
DIGESTS: Final = {
    "A": hashlib.sha256(b"adapter A artifact").hexdigest(),
    "B": hashlib.sha256(b"adapter B artifact").hexdigest(),
    "OLD": hashlib.sha256(b"adapter A OLD").hexdigest(),
    "NEW": hashlib.sha256(b"adapter A NEW").hexdigest(),
}


@dataclass(frozen=True)
class Selection:
    """The exact artifact a deployment selects for one adapter (ADR 0008)."""

    name: str
    digest: str


class Loader:
    """The deployment-local materializer with ADR 0008's owning semantics."""

    def __init__(self, source: Path) -> None:
        """Keep the deployment-local store as the only artifact source."""
        # `source` is the durable deployment-local artifact store. The loader
        # reads ONLY from here; no public/external access exists in the model.
        self._source = source

    def materialize(
        self,
        selected: Iterable[Selection],
        out: Path,
    ) -> bool:
        """Materialize the whole selected set atomically, or materialize none.

        Returns True only when EVERY selected artifact was obtained from the
        deployment-local source and its content digest matched the exact
        selected digest. On any missing/mismatched artifact it returns False
        and leaves `out` empty (no partial set).
        """
        planned: list[tuple[Selection, Path]] = []
        for sel in selected:
            blob = self._source / f"{sel.digest}.wasm"
            if not blob.is_file():
                return False  # missing exact artifact -> global failure
            if _sha256(blob) != sel.digest:
                return False  # digest mismatch -> global failure
            planned.append((sel, blob))

        # Only after EVERY artifact verified do we populate the output set.
        out.mkdir(parents=True, exist_ok=True)
        for sel, blob in planned:
            shutil.copyfile(blob, out / f"{sel.name}.wasm")
        return True


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_blob(store: Path, digest: str, content: bytes) -> Path:
    blob = store / f"{digest}.wasm"
    store.mkdir(parents=True, exist_ok=True)
    blob.write_bytes(content)
    return blob


def _scenario_offline_recovery() -> bool:
    """Recover a fresh (cold) replica offline after staging."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        source = root / "deploy-local-source"
        _write_blob(source, DIGESTS["A"], b"adapter A artifact")
        loader = Loader(source)
        out = root / "adapter-set"
        ok = loader.materialize([Selection("A", DIGESTS["A"])], out)
        if not ok:
            return False
        # No warm cache, no network: exact artifact present, cold start works.
        return (out / "A.wasm").is_file()


def _scenario_atomic_selected_set() -> bool:
    """Fail the whole set when an artifact is missing; never start A-only."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        source = root / "deploy-local-source"
        _write_blob(source, DIGESTS["A"], b"adapter A artifact")
        loader = Loader(source)
        out = root / "adapter-set"
        # B is selected but missing -> global failure, NO partial A.
        ok = loader.materialize(
            [Selection("A", DIGESTS["A"]), Selection("B", DIGESTS["B"])],
            out,
        )
        if ok or (out / "A.wasm").exists():
            return False
        # Make B available/valid -> full set now materializes.
        _write_blob(source, DIGESTS["B"], b"adapter B artifact")
        ok = loader.materialize(
            [Selection("A", DIGESTS["A"]), Selection("B", DIGESTS["B"])],
            out,
        )
        return ok and (out / "A.wasm").is_file() and (out / "B.wasm").is_file()


def _scenario_exact_version_no_fallback() -> bool:
    """Select NEW exactly; never auto-fallback to the available OLD."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        source = root / "deploy-local-source"
        _write_blob(source, DIGESTS["OLD"], b"adapter A OLD")
        _write_blob(source, DIGESTS["NEW"], b"adapter A NEW")
        loader = Loader(source)
        out = root / "adapter-set"
        # Selecting NEW... then NEW becomes unavailable while OLD remains.
        (source / f"{DIGESTS['NEW']}.wasm").unlink()
        ok = loader.materialize([Selection("A", DIGESTS["NEW"])], out)
        # Startup must fail and OLD must not have been selected.
        if ok or (out / "A.wasm").exists():
            return False
        # Restore NEW and verify the replica uses exactly NEW, not OLD.
        _write_blob(source, DIGESTS["NEW"], b"adapter A NEW")
        ok = loader.materialize([Selection("A", DIGESTS["NEW"])], out)
        if not ok:
            return False
        materialized = (out / "A.wasm").read_bytes()
        return materialized == b"adapter A NEW"


SCENARIOS: Final = [
    ("offline replica recovery", _scenario_offline_recovery),
    ("atomic selected-set materialization", _scenario_atomic_selected_set),
    (
        "exact-version and no-fallback enforcement",
        _scenario_exact_version_no_fallback,
    ),
]


def main() -> int:
    results: list[tuple[str, bool]] = []
    for name, fn in SCENARIOS:
        try:
            results.append((name, bool(fn())))
        except Exception as e:  # noqa: BLE001 - report, do not abort
            results.append((name, False))
            print(f"  [{name}] ERROR: {e!r}")

    for name, ok in results:
        tag = "PASS" if ok else "FAIL"
        print(f"scenario [{tag}] {name}")

    all_pass = all(ok for _, ok in results)
    verdict = (
        "ALL SCENARIOS PASS"
        if all_pass
        else f"NOT ALL PASS ({sum(ok for _, ok in results)}/3)"
    )
    print(f"OVERALL: {verdict}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
