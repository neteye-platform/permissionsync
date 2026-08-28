#!/usr/bin/env python3
# Copyright (c) 2026 Würth IT Italy S.r.l.
"""ADR 0006 feasibility PoC - executable gate test suite.

Runs the host against the fake-provider / fake-target and asserts each of the
11 ADR 0006 feasibility gates against the *actual* host stdout/stderr and the
servers' observable state (provider call count, target managed/unmanaged).

Exit code 0 == all gates PASS; non-zero otherwise. Prints a per-gate result
table plus a summary line for evidence.md.
"""

import argparse
import contextlib
import http.client
import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from types import TracebackType
from typing import Final, Self, TypedDict

type JsonValue = (
    str | int | float | bool | list["JsonValue"] | dict[str, "JsonValue"] | None
)
type JsonDocument = dict[str, JsonValue]
type HostResult = tuple[int, str, str]
type FixtureProcess = subprocess.Popen[bytes]
type GateResult = tuple[int, str, bool, str]
type CheckValue = JsonValue | list[str]


class TargetStateDocument(TypedDict):
    """Observable managed and unmanaged state returned by the target fixture."""

    managed_assignments: list[str]
    unmanaged_assignments: list[str]
    managed_constraints: dict[str, list[str]]
    unmanaged_constraints: dict[str, list[str]]


POC = Path(__file__).resolve().parents[1]
HOST_BIN = POC / "host" / "target" / "debug" / "permsync-adr0006-host"
PROVIDER_PY = POC / "fake-provider" / "fake_provider.py"
TARGET_PY = POC / "fake-target" / "fake_target.py"
CERT = POC / "generated" / "certs" / "server.crt"
KEY = POC / "generated" / "certs" / "server-pk"
CA = POC / "generated" / "certs" / "ca.crt"

PROV_PORT: Final = 10443
TGT_PORT: Final = 19443
TGT_B_PORT: Final = 19444
CLIENT: Final = "bob"
TOKEN: Final = "-".join(("sekret", "bob", "token"))  # noqa: FLY002
CLIENT_B: Final = "alice"
TOKEN_B: Final = "-".join(("sekret", "alice", "token"))  # noqa: FLY002
DEFAULT_DEADLINE_MS: Final = 5000
DEFAULT_EPOCH_PERIOD_MS: Final = 10
DEFAULT_MEMORY_LIMIT_BYTES: Final = 8 * 1024 * 1024
CPU_DEADLINE_BOUND_SECONDS: Final = 6.0
STALLED_OUTBOUND_BOUND_SECONDS: Final = 12.0
DEFAULT_MANAGED: Final = True
DEFAULT_SECOND_TARGET: Final = False

# Adapter wasm paths (absolute).
ADAPTERS: Final[dict[str, Path]] = {
    "rust": POC / "adapters/rust-adapter/target/wasm32-wasip2/debug/adapter_rust.wasm",
    "go": POC / "adapters/go-adapter/adapter_go.wasm",
    "bad": POC / "adapters/bad-adapter/target/wasm32-wasip2/debug/adapter_bad.wasm",
    "missing-import": POC
    / "adapters/missing-import-adapter/target/wasm32-wasip2/debug/adapter_missing_import.wasm",
    "egress": POC
    / "adapters/egress-adapter/target/wasm32-wasip2/release/adapter_egress.wasm",
    "wasi": POC
    / "adapters/wasi-adapter/target/wasm32-wasip2/release/adapter_wasi.wasm",
    "process": POC
    / "adapters/process-adapter/target/wasm32-wasip2/release/adapter_process.wasm",
    "runaway-mem": POC
    / "adapters/runaway-mem-adapter/target/wasm32-wasip2/debug/adapter_runaway_mem.wasm",
    "runaway-cpu": POC
    / "adapters/runaway-cpu-adapter/target/wasm32-wasip2/debug/adapter_runaway_cpu.wasm",
    "missing": POC / "adapters/does-not-exist.wasm",
}

# ---------------------------------------------------------------------------
# Server lifecycle helpers
# ---------------------------------------------------------------------------


def _free_port(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return False
        else:
            return True


def start_provider(variant: str = "valid") -> FixtureProcess:
    return subprocess.Popen(
        [
            sys.executable,
            str(PROVIDER_PY),
            "--port",
            str(PROV_PORT),
            "--cert",
            str(CERT),
            "--key",
            str(KEY),
            "--variant",
            variant,
        ],
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        start_new_session=True,
    )


def start_target(
    delay_ms: int = 0,
    port: int = TGT_PORT,
    client: str | None = None,
    token: str | None = None,
) -> FixtureProcess:
    target_client = client or CLIENT
    target_token = token or TOKEN
    return subprocess.Popen(
        [
            sys.executable,
            str(TARGET_PY),
            "--port",
            str(port),
            "--cert",
            str(CERT),
            "--key",
            str(KEY),
            "--clients",
            f"{target_client}:{target_token}",
            "--delay-ms",
            str(delay_ms),
        ],
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        start_new_session=True,
    )


def stop(proc: FixtureProcess | None) -> None:
    if proc is None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (PermissionError, ProcessLookupError):
        with contextlib.suppress(PermissionError, ProcessLookupError):
            proc.kill()
    proc.wait(timeout=5)


def _ctx() -> ssl.SSLContext:
    # The fake servers' self-signed cert is intended for the *host's* rustls
    # verification (which IS what Gate 6 tests). The test client here only
    # needs to observe fake-server state, so it uses an unverified context
    # rather than imposing a second, unrelated TLS trust decision.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def get_json(url: str) -> JsonDocument:
    with urllib.request.urlopen(url, context=_ctx(), timeout=10) as r:
        return json.loads(r.read().decode())


def provider_stats() -> JsonDocument:
    return get_json(f"https://127.0.0.1:{PROV_PORT}/stats")


def reset_provider_variant(variant: str) -> None:
    try:
        req = urllib.request.Request(
            f"https://127.0.0.1:{PROV_PORT}/set-variant",
            data=json.dumps({"variant": variant}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, context=_ctx(), timeout=10):
            pass
    except (
        http.client.HTTPException,
        TimeoutError,
        urllib.error.URLError,
    ) as e:
        print(f"  (set-variant {variant}: {e})")


def target_state(
    port: int = TGT_PORT,
    client: str = CLIENT,
) -> TargetStateDocument:
    with urllib.request.urlopen(
        f"https://127.0.0.1:{port}/state?client={client}",
        context=_ctx(),
        timeout=10,
    ) as response:
        return json.loads(response.read().decode())


def reset_target() -> None:
    with (
        contextlib.suppress(
            http.client.HTTPException,
            TimeoutError,
            urllib.error.URLError,
        ),
        urllib.request.urlopen(
            f"https://127.0.0.1:{TGT_PORT}/reset",
            context=_ctx(),
            timeout=10,
        ),
    ):
        pass


def make_config(
    adapter_key: str,
    *,
    deadline_ms: int = DEFAULT_DEADLINE_MS,
    epoch_period_ms: int = DEFAULT_EPOCH_PERIOD_MS,
    mem: int = DEFAULT_MEMORY_LIMIT_BYTES,
    target_endpoint: str | None = None,
    context_config: list[dict[str, str]] | None = None,
    context_secrets: list[dict[str, str]] | None = None,
    client: str | None = None,
    token: str | None = None,
) -> JsonDocument:
    cfg = {
        "adapter": str(ADAPTERS[adapter_key]),
        "provider_endpoint": f"https://127.0.0.1:{PROV_PORT}",
        "target_endpoint": target_endpoint or f"https://127.0.0.1:{TGT_PORT}",
        "client": client or CLIENT,
        "token": token or TOKEN,
        "ca_cert": str(CA),
        "deadline_ms": deadline_ms,
        "epoch_period_ms": epoch_period_ms,
        "memory_limit_bytes": mem,
    }
    if context_config:
        cfg["context_config"] = context_config
    if context_secrets:
        cfg["context_secrets"] = context_secrets
    return cfg


def run_host(cfg: JsonDocument, cwd: str | None = None) -> HostResult:
    tmp = POC / "tests" / "_tmp_cfg.json"
    tmp.write_text(json.dumps(cfg))
    try:
        r = subprocess.run(
            [str(HOST_BIN), "run", str(tmp)],
            capture_output=True,
            text=True,
            timeout=40,
            cwd=cwd or str(POC),
            check=False,
        )
        return r.returncode, r.stdout, r.stderr
    finally:
        tmp.unlink(missing_ok=True)


def make_registry(
    routes: JsonDocument,
    **reg_overrides: JsonValue,
) -> JsonDocument:
    reg = {
        "ca_cert": str(CA),
        "provider_endpoint": f"https://127.0.0.1:{PROV_PORT}",
        "deadline_ms": DEFAULT_DEADLINE_MS,
        "epoch_period_ms": DEFAULT_EPOCH_PERIOD_MS,
        "memory_limit_bytes": DEFAULT_MEMORY_LIMIT_BYTES,
        "routes": routes,
    }
    reg.update(reg_overrides)
    return reg


def make_route(
    adapter_key: str | None,
    *,
    managed: bool = DEFAULT_MANAGED,
    target_endpoint: str | None = None,
    client: str | None = None,
    token: str | None = None,
    context_config: list[dict[str, str]] | None = None,
    context_secrets: list[dict[str, str]] | None = None,
) -> JsonDocument:
    route = {
        "managed": managed,
        "target_endpoint": target_endpoint or f"https://127.0.0.1:{TGT_PORT}",
        "client": client or CLIENT,
        "token": token or TOKEN,
    }
    if adapter_key is not None:
        route["adapter"] = str(ADAPTERS[adapter_key])
    if context_config:
        route["context_config"] = context_config
    if context_secrets:
        route["context_secrets"] = context_secrets
    return route


def run_route(
    reg: JsonDocument,
    key: str,
    cwd: str | None = None,
) -> HostResult:
    tmp = POC / "tests" / "_tmp_reg.json"
    tmp.write_text(json.dumps(reg))
    try:
        r = subprocess.run(
            [str(HOST_BIN), "route", str(tmp), key],
            capture_output=True,
            text=True,
            timeout=40,
            cwd=cwd or str(POC),
            check=False,
        )
        return r.returncode, r.stdout, r.stderr
    finally:
        tmp.unlink(missing_ok=True)


def wait_ready(proc: FixtureProcess, _url: str) -> bool:
    for _ in range(50):
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", 10443), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


# ---------------------------------------------------------------------------
# Results bookkeeping
# ---------------------------------------------------------------------------

RESULTS: list[GateResult] = []  # (gate, name, ok, detail)


def check(gate: int, name: str, ok: CheckValue, detail: str) -> bool:
    RESULTS.append((gate, name, bool(ok), detail))
    return bool(ok)


def ok_text(stdout: str, needle: str) -> bool:
    return needle in stdout


def _snake_to_kebab(obj: JsonValue) -> JsonValue:
    """Recursively normalize keys for fidelity comparisons.

    Rewrite snake_case keys to kebab-case so the host's RECEIVED
    (serialized from the WIT record, snake_case) can be deep-compared against
    the provider's transport doc (kebab-case).
    """
    if isinstance(obj, dict):
        return {k.replace("_", "-"): _snake_to_kebab(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_snake_to_kebab(i) for i in obj]
    return obj


def extract_received(stdout: str) -> JsonValue | None:
    """Parse the RECEIVED=<json> line into the normalized doc for fidelity assert."""
    for line in stdout.splitlines():
        if line.startswith("RECEIVED="):
            return _snake_to_kebab(json.loads(line[len("RECEIVED=") :]))
    return None


def fetch_valid_doc() -> JsonDocument:
    """Fetch the provider's current /document body for the fidelity deep-equal."""
    with urllib.request.urlopen(
        f"https://127.0.0.1:{PROV_PORT}/document",
        context=_ctx(),
        timeout=10,
    ) as r:
        return json.loads(r.read().decode())


# ---------------------------------------------------------------------------
# Server context manager
# ---------------------------------------------------------------------------


class Servers:
    """Manage the provider and target fixture processes for one gate."""

    def __init__(
        self,
        variant: str = "valid",
        delay_ms: int = 0,
        *,
        second_target: bool = DEFAULT_SECOND_TARGET,
    ) -> None:
        """Set fixture configuration before starting its processes."""
        self.variant = variant
        self.delay = delay_ms
        self.second_target = second_target
        self.tgt_b: FixtureProcess | None = None

    def __enter__(self) -> Self:
        """Start and wait for the configured fixture processes."""
        for _ in range(2):
            time.sleep(0.1)
        prov = start_provider(self.variant)
        tgt = start_target(self.delay)
        self.prov = prov
        self.tgt = tgt
        if self.second_target:
            tgt_b = start_target(
                0,
                port=TGT_B_PORT,
                client=CLIENT_B,
                token=TOKEN_B,
            )
            self.tgt_b = tgt_b
        wait_ready(prov, f"https://127.0.0.1:{PROV_PORT}/stats")
        wait_ready(tgt, f"https://127.0.0.1:{TGT_PORT}/state?client=x")
        if self.second_target:
            wait_ready(
                tgt_b,
                f"https://127.0.0.1:{TGT_B_PORT}/state?client=x",
            )
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        """Stop all fixture processes without suppressing test failures."""
        stop(self.prov)
        stop(self.tgt)
        if self.tgt_b is not None:
            stop(self.tgt_b)
        time.sleep(0.3)
        return False


# ---------------------------------------------------------------------------
# Individual gates
# ---------------------------------------------------------------------------


def gate1_independent_lifecycle() -> bool:
    """Two independently built components (rust + go) swap in the same host."""
    ok = True
    with Servers("valid") as _:
        for key in ("rust", "go"):
            rc, out, _ = run_host(make_config(key))
            ok = (
                check(
                    1,
                    f"lifecycle {key}",
                    rc == 0
                    and ok_text(out, "RECEIVED=")
                    and ok_text(out, "EFFECT grant"),
                    f"rc={rc}",
                )
                and ok
            )
    return ok


def gate2_admission_compatibility() -> bool:
    """Incompatible component rejected at admission before provider/reconcile."""
    with Servers("valid") as _:
        rc, _out, err = run_host(make_config("bad"))
        admitted_bad = check(
            2,
            "bad adapter rejected",
            rc != 0 and "admission/instantiation failed" in err,
            f"rc={rc}",
        )
        stats = provider_stats()
        zero_calls = check(
            2,
            "zero provider calls on rejection",
            stats["calls"] == 0,
            f"calls={stats['calls']}",
        )
        st = target_state()
        unmanaged_intact = check(
            2,
            "target not mutated",
            st["managed_assignments"] == []
            and st["unmanaged_assignments"] == ["legacy-admin"],
            json.dumps(st),
        )

        # Second admission case: a component with the CORRECT export shape but an
        # ADDITIONAL import the host does not provide (unknown import). The host
        # linker only wires http/runtime/WASI p2, so this too fails instantiation
        # before provider resolution, reconcile invocation, or target mutation.
        rc, _out, err = run_host(make_config("missing-import"))
        admitted_mi = check(
            2,
            "missing-import adapter rejected (unprovided import)",
            rc != 0 and "admission/instantiation failed" in err,
            f"rc={rc}",
        )
        stats = provider_stats()
        zero_calls_mi = check(
            2,
            "missing-import => zero provider calls",
            stats["calls"] == 0,
            f"calls={stats['calls']}",
        )
        st = target_state()
        no_mutation_mi = check(
            2,
            "missing-import => target not mutated",
            st["managed_assignments"] == []
            and st["unmanaged_assignments"] == ["legacy-admin"],
            json.dumps(st),
        )
        return (
            admitted_bad
            and zero_calls
            and unmanaged_intact
            and admitted_mi
            and zero_calls_mi
            and no_mutation_mi
        )


def gate3_language_independence() -> bool:
    """Rust + non-Rust (TinyGo) toolchains against the unchanged host contract."""
    ok = True
    with Servers("valid") as _:
        for key in ("rust", "go"):
            rc, out, _err = run_host(make_config(key))
            ok = (
                check(
                    3,
                    f"toolchain {key}",
                    rc == 0 and ok_text(out, "RECEIVED="),
                    f"rc={rc}",
                )
                and ok
            )
    return ok


def gate4_model_fidelity() -> bool:
    """Transport intact: roles/groups/entitlements, scopes, unscoped, constraints, version."""
    ok = True
    with Servers("valid") as _:
        rc, out, _ = run_host(make_config("rust"))
        fidelity = check(
            4,
            "valid doc transported intact",
            rc == 0
            and ok_text(out, '"id":"editor"')
            and ok_text(out, '"kind":"role"')
            and ok_text(out, '"scope_type":"resource-boundary"')
            and ok_text(out, '"propagation":"self-only"')
            and ok_text(out, '"id":"packet-capture-download"')
            and ok_text(out, '"kind":"entitlement"')
            and ok_text(
                out,
                '"constraint_type":"network","values":["collector-a","collector-b"]',
            )
            and ok_text(out, '"version":1'),
            "RECEIVED present",
        )
        ok = fidelity and ok

    # descendants: rust accepts, go rejects.
    with Servers("descendants") as _:
        rc, out, _ = run_host(make_config("rust"))
        ok = (
            check(
                4,
                "rust accepts descendants",
                rc == 0 and ok_text(out, "EFFECT grant"),
                f"rc={rc}",
            )
            and ok
        )
        rc, out, err = run_host(make_config("go"))
        ok = (
            check(
                4,
                "go rejects descendants",
                rc != 0 and "unsupported propagation 'descendants'" in err,
                f"rc={rc}",
            )
            and ok
        )

    # unsupported-role: both adapters reject before invocation.
    with Servers("unsupported-role") as _:
        for key in ("rust", "go"):
            rc, _, err = run_host(make_config(key))
            ok = (
                check(
                    4,
                    f"unsupported-role {key} rejected",
                    rc != 0 and "unsupported role" in err,
                    f"rc={rc}",
                )
                and ok
            )

    # unsupported-version: both reject.
    with Servers("unsupported-version") as _:
        for key in ("rust", "go"):
            rc, _, err = run_host(make_config(key))
            ok = (
                check(
                    4,
                    f"unsupported-version {key} rejected",
                    rc != 0 and ("unsupported model version" in err),
                    f"rc={rc}",
                )
                and ok
            )

    # Full-model fidelity as a deep-equal assert (not just keyword probes):
    # normalize the transport's kebab-case keys to the provider's snake_case doc
    # and require the RECEIVED document to equal the provider document exactly.
    # This proves the whole v1 model (assignments incl. scopes + constraints +
    # version) survives the host/adapter boundary field-for-field.
    with Servers("valid") as _:
        rc, out, _ = run_host(make_config("rust"))
        received = extract_received(out)
        provider_doc = fetch_valid_doc()
        fidelity_deep = check(
            4,
            "full-model fidelity: RECEIVED == provider doc (deep-equal)",
            rc == 0 and received == provider_doc,
            f"rc={rc} received={json.dumps(received)} provider={json.dumps(provider_doc)}",
        )
        ok = fidelity_deep and ok

    # Repeated scopes: same role id granted across two distinct scopes is a
    # VALID transport case (multi-scope fidelity), both adapters accept.
    with Servers("repeat-scope") as _:
        for key in ("rust", "go"):
            rc, out, _ = run_host(make_config(key))
            ok = (
                check(
                    4,
                    f"repeat-scope accepted {key}",
                    rc == 0 and "EFFECT grant" in out,
                    f"rc={rc}",
                )
                and ok
            )

    # Adapter-semantic rejection variants: each doc is *structurally valid* (the
    # core admits it), so the adapter IS invoked and rejects on semantic grounds.
    # Suite asserts: structural OK (no structural error), exactly one provider
    # fetch (pre-invoke), the adapter's error string per key, no target mutation.
    semantic = [
        ("unknown-group", "unsupported group 'ops-admin'"),
        ("unknown-entitlement", "unsupported entitlement 'log-export'"),
        ("unsupported-scope-type", "unsupported scope type 'team'"),
        ("unknown-scope-id", "unsupported scope id 'zanzibar'"),
        ("unsupported-constraint-type", "unsupported constraint type 'budget'"),
        (
            "invalid-constraint-value",
            "unsupported interface value 'collector-zzz'",
        ),
        (
            "unsupported-combination",
            "unsupported assignment/constraint combination",
        ),
    ]
    for variant, needle in semantic:
        for key in ("rust", "go"):
            with Servers(variant) as _:
                rc, out, err = run_host(make_config(key))
                rejected = check(
                    4,
                    f"{variant} {key} rejected by adapter",
                    rc != 0 and needle in err,
                    f"rc={rc} needle={needle}",
                )
                adapter_invoked = check(
                    4,
                    f"{variant} {key} => adapter invoked (no structural error)",
                    "admission/instantiation failed" not in err,
                    "adapter reached",
                )
                calls = provider_stats()["calls"]
                exactly_one_fetch = check(
                    4,
                    f"{variant} {key} => exactly one provider fetch",
                    calls == 1,
                    f"calls={calls}",
                )
                st = target_state()
                no_mutation = check(
                    4,
                    f"{variant} {key} => target not mutated",
                    st["managed_assignments"] == [],
                    json.dumps(st),
                )
                ok = (
                    ok
                    and rejected
                    and adapter_invoked
                    and exactly_one_fetch
                    and no_mutation
                )

    # Core-side structural rejection (ADR 0006 Gate 4: the *core* rejects these
    # before the adapter component is invoked). Each must show exactly one
    # provider fetch (the pre-invoke fetch) but NO component invocation
    # (no RECEIVED/effects) and NO target mutation.
    structural = [
        ("duplicate-constraint", "duplicate constraint type"),
        ("malformed-constraint", "malformed constraint"),
        ("partial-scope", "partial scope"),
        ("unsupported-kind", "unknown assignment kind"),
    ]
    for variant, needle in structural:
        with Servers(variant) as _:
            rc, out, err = run_host(make_config("rust"))
            rejected = check(
                4,
                f"core rejects {variant} before invocation",
                rc != 0 and needle in err,
                f"rc={rc} needle={needle}",
            )
            no_invoke = check(
                4,
                f"{variant} => no component invocation",
                "RECEIVED=" not in out and "EFFECT grant" not in out,
                "checked stdout",
            )
            calls = provider_stats()["calls"]
            exactly_one_fetch = check(
                4,
                f"{variant} => exactly one provider fetch (pre-invoke)",
                calls == 1,
                f"calls={calls}",
            )
            st = target_state()
            no_mutation = check(
                4,
                f"{variant} => target not mutated",
                st["managed_assignments"] == [],
                json.dumps(st),
            )
            ok = ok and rejected and no_invoke and exactly_one_fetch and no_mutation
    return ok


def gate5_context_isolation() -> bool:
    """Keys only; per-target context; secret VALUES absent from logs/state."""
    # Baseline/mono-target case (kept for the original "keys not values" proof).
    with Servers("valid") as _:
        rc, out, _err = run_host(make_config("rust"))
        keys = check(
            5,
            "adapter sees keys only",
            rc == 0 and ok_text(out, "CONTEXT_KEYS=endpoint,client,token"),
            f"rc={rc}",
        )
        secret_absent = check(
            5,
            "secret value absent from host output",
            TOKEN not in out and "sekret" not in out.lower(),
            "checked stdout",
        )
        ok = keys and secret_absent

    # Two real target contexts: target-a (bob) and target-b (alice), each with
    # a distinct extra context config item and secret. An adapter for target-a
    # must only ever see target-a's keys, never target-b's, and neither
    # target's secret value may appear in output.
    with Servers("valid", second_target=True) as _:
        ctx_a = {
            "context_config": [{"key": "region", "value": "eu-a"}],
            "context_secrets": [
                {"key": "api-key-a", "value": "SECRET_A_VALUE"},
            ],
        }
        ctx_b = {
            "context_config": [{"key": "region", "value": "us-b"}],
            "context_secrets": [
                {"key": "api-key-b", "value": "SECRET_B_VALUE"},
            ],
        }
        # Route A reconcile against target-a.
        rc, out, _err = run_host(
            make_config(
                "rust",
                target_endpoint=f"https://127.0.0.1:{TGT_PORT}",
                context_config=ctx_a["context_config"],
                context_secrets=ctx_a["context_secrets"],
            ),
        )
        a_sees_own = check(
            5,
            "target-a adapter sees its own key + secret key",
            rc == 0 and "region" in out and "api-key-a" in out,
            f"rc={rc}",
        )
        a_not_b_key = check(
            5,
            "target-a adapter does not see target-b's secret key",
            "api-key-b" not in out,
            "checked stdout",
        )
        a_no_own_value = check(
            5,
            "target-a secret VALUE absent from host output",
            "SECRET_A_VALUE" not in out and "SECRET_B_VALUE" not in out,
            "checked stdout",
        )
        # After route A only, target-b must be untouched (reconcile isolation).
        st_a_after_a = target_state(port=TGT_PORT, client=CLIENT)
        st_b_after_a = target_state(port=TGT_B_PORT, client=CLIENT_B)
        a_isolated = check(
            5,
            "route A does not touch target-b",
            st_a_after_a["managed_assignments"]
            and st_b_after_a["managed_assignments"] == [],
            json.dumps(
                {
                    "a": st_a_after_a["managed_assignments"],
                    "b": st_b_after_a["managed_assignments"],
                },
            ),
        )
        # Route B reconcile against target-b, using a distinct token/endpoint.
        rc, out, _err = run_host(
            make_config(
                "rust",
                target_endpoint=f"https://127.0.0.1:{TGT_B_PORT}",
                client=CLIENT_B,
                token=TOKEN_B,
                context_config=ctx_b["context_config"],
                context_secrets=ctx_b["context_secrets"],
            ),
        )
        b_sees_own = check(
            5,
            "target-b adapter sees its own key + secret key",
            rc == 0 and "api-key-b" in out and "region" in out,
            f"rc={rc}",
        )
        b_not_a_key = check(
            5,
            "target-b adapter does not see target-a's secret key",
            "api-key-a" not in out,
            "checked stdout",
        )
        b_no_value = check(
            5,
            "target-b secret VALUE absent from host output",
            "SECRET_A_VALUE" not in out and "SECRET_B_VALUE" not in out,
            "checked stdout",
        )
        return (
            ok
            and a_sees_own
            and a_not_b_key
            and a_no_own_value
            and a_isolated
            and b_sees_own
            and b_not_a_key
            and b_no_value
        )


def gate6_default_deny() -> bool:
    """Ungranted fs/env/process denied; unrelated destination denied; allowlisted HTTPS works."""
    ok = True
    with Servers("valid") as _:
        # wasi adapter: no env/fs readable.
        rc, out, _ = run_host(make_config("wasi"))
        ok = (
            check(
                6,
                "wasi env/fs denied",
                rc == 0 and ok_text(out, "wasi env/fs denied (0 bytes readable)"),
                f"rc={rc}",
            )
            and ok
        )
        # process adapter: no process execution possible.
        rc, out, _ = run_host(make_config("process"))
        ok = (
            check(
                6,
                "process execution denied",
                rc == 0 and ok_text(out, "process execution denied (0 bytes readable)"),
                f"rc={rc}",
            )
            and ok
        )
        # egress adapter: unrelated destination denied by host.
        rc, _, err = run_host(make_config("egress"))
        ok = (
            check(
                6,
                "egress outside allowlist denied",
                rc != 0 and "egress denied" in err and "outside allowlist" in err,
                f"rc={rc}",
            )
            and ok
        )
        # allowlisted HTTPS to configured mock target succeeds (with explicit CA trust).
        rc, out, _ = run_host(make_config("rust"))
        return (
            check(
                6,
                "allowlisted https target succeeds",
                rc == 0 and ok_text(out, "RECEIVED="),
                f"rc={rc}",
            )
            and ok
        )


def gate7_bounded_resources() -> bool:
    """Runaway memory trapped by StoreLimits before host exhaustion."""
    with Servers("valid", delay_ms=0) as _:
        t0 = time.time()
        rc, _out, err = run_host(
            make_config("runaway-mem", mem=DEFAULT_MEMORY_LIMIT_BYTES),
        )
        elapsed = time.time() - t0
        trapped = check(
            7,
            "mem runaway trapped by store limits",
            rc != 0
            and (
                "allocation" in err.lower()
                or "abort" in err.lower()
                or "oom" in err.lower()
            ),
            f"rc={rc} elapsed={elapsed:.1f}s",
        )
        host_survived = check(
            7,
            "host process survived (not OOM-killed/exit 137)",
            rc not in (-9, 137),
            f"rc={rc}",
        )
        return trapped and host_survived


def gate8_deadline_cancellation() -> bool:
    """Runaway CPU interrupted by epoch deadline; stalled outbound bounded."""
    ok = True
    # runaway-cpu: epoch trap -> no hang, error, no new work.
    with Servers("valid", delay_ms=0) as _:
        t0 = time.time()
        rc, _out, _err = run_host(make_config("runaway-cpu", deadline_ms=800))
        elapsed = time.time() - t0
        ok = (
            check(
                8,
                "cpu runaway interrupted by deadline",
                rc != 0 and elapsed < CPU_DEADLINE_BOUND_SECONDS,
                f"rc={rc} elapsed={elapsed:.1f}s",
            )
            and ok
        )
        # Do not re-fetch after trap: exactly one provider call (the pre-invoke fetch).
        stats = provider_stats()
        ok = (
            check(
                8,
                "no new work after cancellation",
                stats["calls"] == 1,
                f"calls={stats['calls']}",
            )
            and ok
        )

    # stalled outbound target: host must not hang; bounded by agent timeout/deadline.
    with Servers("valid", delay_ms=15000) as _:
        t0 = time.time()
        rc, _out, _err = run_host(make_config("rust", deadline_ms=500))
        elapsed = time.time() - t0
        return (
            check(
                8,
                "stalled outbound bounded",
                rc != 0 and elapsed < STALLED_OUTBOUND_BOUND_SECONDS,
                f"rc={rc} elapsed={elapsed:.1f}s",
            )
            and ok
        )


def gate9_invocation_accounting() -> bool:
    """Exactly one provider fetch + one reconcile, no retry."""
    with Servers("valid") as _:
        rc, out, _err = run_host(make_config("rust"))
        stats = provider_stats()
        once = check(
            9,
            "exactly one provider fetch",
            stats["calls"] == 1,
            f"calls={stats['calls']}",
        )
        # Host-instrumented accounting: the reconcile was invoked exactly once
        # and the host has no retry loop (auto_retries always 0).
        account = check(
            9,
            "host-instrumented accounting (reconcile=1, retries=0)",
            rc == 0 and ok_text(out, "ACCOUNT reconcile_calls=1 auto_retries=0"),
            f"rc={rc} out={out}",
        )
        # Reconcile hits target once: managed state reflects the single doc.
        st = target_state()
        single_reconcile = check(
            9,
            "single reconcile reflected in target state",
            "role:editor" in st["managed_assignments"]
            and "group:release-managers" in st["managed_assignments"]
            and "entitlement:packet-capture-download" in st["managed_assignments"],
            json.dumps(st["managed_assignments"]),
        )
        return once and account and single_reconcile


def gate10_routing_isolation() -> bool:
    """Exercise routing isolation.

    Explicit routing registry: unconfigured vs unmanaged vs missing/incompatible
    adapter are DISTINCT states per ADR 0006 (do not equate 'missing adapter' with
    'unmanaged'). Only configured, managed, valid routes perform work.
    """
    ok = True
    with Servers("valid", second_target=True) as _:
        target_b_ep = f"https://127.0.0.1:{TGT_B_PORT}"
        reg = make_registry(
            {
                "unmanaged-alice": make_route(
                    "rust",
                    managed=False,
                    target_endpoint=target_b_ep,
                    client=CLIENT_B,
                    token=TOKEN_B,
                ),
                "missing-managed": make_route("missing", managed=True),
                "incompat-managed": make_route("bad", managed=True),
                "valid-bob": make_route("rust", managed=True),
            },
        )

        # Route key absent from the registry: unconfigured => noop, exit 0, no calls.
        rc, out, _err = run_route(reg, "ghost-route")
        stats = provider_stats()
        ok = (
            check(
                10,
                "unconfigured route -> 200/noop, no work",
                rc == 0 and ok_text(out, "ROUTE unconfigured") and stats["calls"] == 0,
                f"rc={rc} out={out} calls={stats['calls']}",
            )
            and ok
        )
        st = target_state()
        ok = (
            check(
                10,
                "unconfigured route -> target untouched",
                st["managed_assignments"] == [],
                json.dumps(st),
            )
            and ok
        )

        # Unmanaged (but otherwise valid) target: 200/noop, no work.
        rc, out, _ = run_route(reg, "unmanaged-alice")
        stats = provider_stats()
        ok = (
            check(
                10,
                "unmanaged target -> 200/noop, no work",
                rc == 0 and ok_text(out, "ROUTE unmanaged") and stats["calls"] == 0,
                f"rc={rc} out={out} calls={stats['calls']}",
            )
            and ok
        )
        st_b = target_state(port=TGT_B_PORT, client=CLIENT_B)
        ok = (
            check(
                10,
                "unmanaged target -> not mutated",
                st_b["managed_assignments"] == [],
                json.dumps(st_b),
            )
            and ok
        )

        # Managed target with MISSING component file: error (500), no fetch.
        rc, _, _err = run_route(reg, "missing-managed")
        stats = provider_stats()
        ok = (
            check(
                10,
                "managed + missing component -> 500, no provider call",
                rc != 0 and stats["calls"] == 0,
                f"rc={rc} calls={stats['calls']}",
            )
            and ok
        )

        # Managed target with INCOMPATIBLE component: error (500), no fetch.
        rc, _, _err = run_route(reg, "incompat-managed")
        stats = provider_stats()
        ok = (
            check(
                10,
                "managed + incompatible component -> 500, no provider call",
                rc != 0 and stats["calls"] == 0,
                f"rc={rc} calls={stats['calls']}",
            )
            and ok
        )

        # A distinct VALID managed target still succeeds after the failures.
        rc, out, _ = run_route(reg, "valid-bob")
        return (
            check(
                10,
                "another valid managed target succeeds after failures",
                rc == 0 and ok_text(out, "RECEIVED="),
                f"rc={rc}",
            )
            and ok
        )


def gate11_managed_authority_statelessness() -> bool:
    """Only managed state mutates; unmanaged untouched; restart needs no shared replay."""
    ok = True
    with Servers("valid") as _:
        run_host(make_config("rust"))
        st1 = target_state()
        ok = (
            check(
                11,
                "managed assignments applied",
                sorted(st1["managed_assignments"])
                == sorted(
                    [
                        "role:editor",
                        "group:release-managers",
                        "entitlement:packet-capture-download",
                    ],
                ),
                json.dumps(st1["managed_assignments"]),
            )
            and ok
        )
        ok = (
            check(
                11,
                "unmanaged state untouched",
                st1["unmanaged_assignments"] == ["legacy-admin"]
                and st1["unmanaged_constraints"] == {"legacy": ["keep"]},
                json.dumps(
                    {
                        "u_ass": st1["unmanaged_assignments"],
                        "u_con": st1["unmanaged_constraints"],
                    },
                ),
            )
            and ok
        )
        # Restart (fresh host process, no shared replay) must not require adapter state.
        rc, _out, _ = run_host(make_config("rust"))
        st2 = target_state()
        return (
            check(
                11,
                "restart succeeds idempotently",
                rc == 0 and st2["managed_assignments"] == st1["managed_assignments"],
                f"rc={rc}",
            )
            and ok
        )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

GATES = [
    (1, "Independent lifecycle", gate1_independent_lifecycle),
    (2, "Admission compatibility", gate2_admission_compatibility),
    (3, "Language independence", gate3_language_independence),
    (4, "Model fidelity", gate4_model_fidelity),
    (5, "Context isolation", gate5_context_isolation),
    (6, "Default-deny", gate6_default_deny),
    (7, "Bounded resources", gate7_bounded_resources),
    (8, "Deadline & cancellation", gate8_deadline_cancellation),
    (9, "Invocation accounting", gate9_invocation_accounting),
    (10, "Routing isolation", gate10_routing_isolation),
    (
        11,
        "Managed authority & statelessness",
        gate11_managed_authority_statelessness,
    ),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--only",
        type=int,
        nargs="*",
        help="only run these gate numbers",
    )
    args = ap.parse_args()

    if not HOST_BIN.exists():
        print(
            f"FATAL: host binary not built at {HOST_BIN}. Run `make build` first.",
        )
        return 2

    for key, path in ADAPTERS.items():
        if key != "missing" and not path.exists():
            print(f"FATAL: adapter wasm missing for '{key}': {path}")
            return 2

    gate_ok = {}
    for num, name, fn in GATES:
        if args.only and num not in args.only:
            continue
        try:
            ok = fn()
        except Exception as e:  # noqa: BLE001
            ok = False
            print(f"  [gate {num} {name}] ERROR: {e!r}")
        gate_ok[num] = ok
        tag = "PASS" if ok else "FAIL"
        print(f"gate {num:>2} [{tag}] {name}")

    print()
    print("=== per-check details ===")
    for gate, name, ok, detail in RESULTS:
        print(f"  gate {gate:>2} [{'PASS' if ok else 'FAIL'}] {name}: {detail}")

    all_pass = all(gate_ok.values())
    print()
    verdict = (
        "ALL 11 GATES PASS"
        if all_pass
        else f"NOT ALL PASS ({sum(1 for v in gate_ok.values() if v)}/11)"
    )
    print(f"OVERALL: {verdict}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
