#!/usr/bin/env python3
"""Counted fake provider for the ADR 0006 feasibility PoC.

The conceptual stand-in for PermissionSync's (deferred) provider API. It
serves the ADR 0005 canonical desired-permission document as JSON over HTTPS
so the host can fetch it and hand it to an adapter as a WIT `document`.

It is *counted*: every successful document fetch increments a counter that the
gate suite can read back, which is what makes Gate 9 ("one provider call, one
reconcile call, no automatic retry") executable evidence rather than a claim.

Variant documents let the suite exercise rejection paths:
  - valid          - a normal, accepted document
  - descendants    - a scope carrying `descendants` propagation (Go adapter
                     must reject this; Rust adapter accepts it) -- Gate 4
  - unsupported-role    - role id the adapters reject before any mutation
  - unsupported-version - version the adapters reject
Not a production provider.
"""
import argparse
import copy
import json
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VALID_DOC = {
    "version": 1,
    "assignments": [
        {
            "kind": "role",
            "id": "editor",
            "scope": {
                "scope-type": "resource-boundary",
                "id": "engineering",
                "propagation": "self-only",
            },
        },
        {
            "kind": "group",
            "id": "release-managers",
            "scope": {
                "scope-type": "org",
                "id": "operations",
                "propagation": "self-only",
            },
        },
        {
            "kind": "entitlement",
            "id": "packet-capture-download",
            "scope": None,
        },
    ],
    "constraints": [
        {"constraint-type": "network", "values": ["collector-a", "collector-b"]},
        {"constraint-type": "interface", "values": ["collector-a"]},
    ],
}

# Deep copy, then flip the first scope's propagation to `descendants`. The Go
# adapter must reject it; the Rust adapter accepts it. Must deep-copy so the
# shared VALID_DOC is never corrupted by the mutation (shallow copies alias
# the nested scope dict).
DESCENDANTS_DOC = copy.deepcopy(VALID_DOC)
DESCENDANTS_DOC["assignments"][0]["scope"]["propagation"] = "descendants"

UNSUPPORTED_ROLE_DOC = {
    "version": 1,
    "assignments": [{"kind": "role", "id": "super-user", "scope": None}],
    "constraints": [],
}

UNSUPPORTED_VERSION_DOC = {
    "version": 99,
    "assignments": list(VALID_DOC["assignments"]),
    "constraints": [],
}

# --- Gate 4 (core-side structural) rejection variants -----------------------
# These are structurally malformed *documents* that the core (host) must reject
# before the adapter component is ever invoked and before the target is mutated.
# The suite asserts that each produces a provider fetch (the pre-invoke fetch)
# but zero component invocation and zero target mutation.

# Two constraints with the same type: the core must reject before invocation.
DUPLICATE_CONSTRAINT_DOC = {
    "version": 1,
    "assignments": list(VALID_DOC["assignments"]),
    "constraints": [
        {"constraint-type": "network", "values": ["collector-a"]},
        {"constraint-type": "network", "values": ["collector-b"]},
    ],
}

# A constraint with an empty constraint-type: malformed, rejected by the core.
MALFORMED_CONSTRAINT_DOC = {
    "version": 1,
    "assignments": list(VALID_DOC["assignments"]),
    "constraints": [{"constraint-type": "", "values": ["collector-a"]}],
}

# A scope that is partially specified (no propagation): rejected by the core
# before invocation.
PARTIAL_SCOPE_DOC = {
    "version": 1,
    "assignments": [
        {"kind": "role", "id": "editor",
         "scope": {"scope-type": "resource-boundary", "id": "engineering"}},
    ],
    "constraints": [],
}

# An assignment kind the model does not define: rejected by the core.
UNSUPPORTED_KIND_DOC = {
    "version": 1,
    "assignments": [{"kind": "superuser", "id": "the-boss", "scope": None}],
    "constraints": [],
}

# --- Gate 4 (adapter-semantic) rejection variants ---------------------------
# These documents are *structurally valid* (the core accepts them) but carry a
# value the target adapters refuse on semantic grounds. The suite asserts that
# each produces exactly one provider fetch, that the adapter IS invoked
# (reconcile rejected by adapter), and that the target is never mutated.

# Same role id granted across two different scopes: valid transport of repeated
# assignments (ADR 0005 Gate 4 multi-scope fidelity).
REPEAT_SCOPE_DOC = {
    "version": 1,
    "assignments": [
        {
            "kind": "role",
            "id": "editor",
            "scope": {
                "scope-type": "resource-boundary",
                "id": "engineering",
                "propagation": "self-only",
            },
        },
        {
            "kind": "role",
            "id": "editor",
            "scope": {
                "scope-type": "resource-boundary",
                "id": "north",
                "propagation": "self-only",
            },
        },
        {
            "kind": "group",
            "id": "release-managers",
            "scope": {
                "scope-type": "org",
                "id": "operations",
                "propagation": "self-only",
            },
        },
        {
            "kind": "entitlement",
            "id": "packet-capture-download",
            "scope": None,
        },
    ],
    "constraints": [
        {"constraint-type": "network", "values": ["collector-a", "collector-b"]},
        {"constraint-type": "interface", "values": ["collector-a"]},
    ],
}

# A group id the adapters do not allow-list.
UNKNOWN_GROUP_DOC = {
    "version": 1,
    "assignments": [{"kind": "group", "id": "ops-admin", "scope": None}],
    "constraints": [],
}

# An entitlement id the adapters do not allow-list.
UNKNOWN_ENTITLEMENT_DOC = {
    "version": 1,
    "assignments": [{"kind": "entitlement", "id": "log-export", "scope": None}],
    "constraints": [],
}

# A structurally valid scope whose scope-type the adapters reject.
UNSUPPORTED_SCOPE_TYPE_DOC = {
    "version": 1,
    "assignments": [
        {"kind": "role", "id": "editor",
         "scope": {"scope-type": "team", "id": "engineering",
                   "propagation": "self-only"}},
    ],
    "constraints": [],
}

# A structurally valid scope whose scope id the adapters reject.
UNKNOWN_SCOPE_ID_DOC = {
    "version": 1,
    "assignments": [
        {"kind": "role", "id": "editor",
         "scope": {"scope-type": "resource-boundary", "id": "zanzibar",
                   "propagation": "self-only"}},
    ],
    "constraints": [],
}

# A constraint type the adapters do not allow-list.
UNSUPPORTED_CONSTRAINT_TYPE_DOC = {
    "version": 1,
    "assignments": list(VALID_DOC["assignments"]),
    "constraints": [
        {"constraint-type": "network", "values": ["collector-a"]},
        {"constraint-type": "budget", "values": ["100"]},
    ],
}

# An otherwise-valid constraint whose individual value the adapters reject
# (interface value not in the adapter's interface allow-list).
INVALID_CONSTRAINT_VALUE_DOC = {
    "version": 1,
    "assignments": list(VALID_DOC["assignments"]),
    "constraints": [
        {"constraint-type": "interface", "values": ["collector-zzz"]},
    ],
}

# A constraint type paired with an assignment kind it cannot apply to: an
# `interface`/`network` constraint needs at least one role or group assignment,
# but this document only grants an entitlement. The adapters reject this as an
# unsupported assignment/constraint combination.
UNSUPPORTED_COMBINATION_DOC = {
    "version": 1,
    "assignments": [
        {"kind": "entitlement", "id": "packet-capture-download", "scope": None},
    ],
    "constraints": [
        {"constraint-type": "interface", "values": ["collector-a"]},
    ],
}

VARIANTS = {
    "valid": VALID_DOC,
    "repeat-scope": REPEAT_SCOPE_DOC,
    "descendants": DESCENDANTS_DOC,
    "unsupported-role": UNSUPPORTED_ROLE_DOC,
    "unsupported-version": UNSUPPORTED_VERSION_DOC,
    "unknown-group": UNKNOWN_GROUP_DOC,
    "unknown-entitlement": UNKNOWN_ENTITLEMENT_DOC,
    "unsupported-scope-type": UNSUPPORTED_SCOPE_TYPE_DOC,
    "unknown-scope-id": UNKNOWN_SCOPE_ID_DOC,
    "unsupported-constraint-type": UNSUPPORTED_CONSTRAINT_TYPE_DOC,
    "invalid-constraint-value": INVALID_CONSTRAINT_VALUE_DOC,
    "unsupported-combination": UNSUPPORTED_COMBINATION_DOC,
    "duplicate-constraint": DUPLICATE_CONSTRAINT_DOC,
    "malformed-constraint": MALFORMED_CONSTRAINT_DOC,
    "partial-scope": PARTIAL_SCOPE_DOC,
    "unsupported-kind": UNSUPPORTED_KIND_DOC,
}

# Each served body must be assembled from a deep copy so the in-memory variant
# documents can never be mutated by what a consumer edits or by what we serve.
def document_bytes(variant):
    return json.dumps(copy.deepcopy(VARIANTS[variant])).encode("utf-8")


class ProviderState:
    def __init__(self, default_variant):
        self.lock = threading.RLock()
        self.variant = default_variant
        self.calls = 0

    def serve(self):
        with self.lock:
            self.calls += 1
            return document_bytes(self.variant)

    def set_variant(self, variant):
        with self.lock:
            self.variant = variant
            return variant


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("[fake-provider] %s\n" % (self.path.split("?")[0],))

    def _json(self, code, obj, headers=None):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/document":
            body = self.server.state.serve()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Fake-Provider-Calls", str(self.server.state.calls))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/stats":
            with self.server.state.lock:
                self._json(
                    200,
                    {"calls": self.server.state.calls, "variant": self.server.state.variant},
                )
            return
        if path == "/reset":
            with self.server.state.lock:
                self.server.state.calls = 0
                self.server.state.variant = self.server.default_variant
            self._json(200, {"reset": True})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path == "/set-variant":
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
            except Exception:
                self._json(400, {"error": "bad body"})
                return
            variant = body.get("variant", "")
            if variant not in VARIANTS:
                self._json(400, {"error": "unknown variant", "known": sorted(VARIANTS)})
                return
            with self.server.state.lock:
                self.server.state.variant = variant
            self._json(200, {"variant": variant})
            return
        self._json(404, {"error": "not found"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=10443)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument(
        "--variant", default="valid", choices=sorted(VARIANTS),
        help="document variant served on /document",
    )
    args = ap.parse_args()

    state = ProviderState(args.variant)
    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    httpd.state = state
    httpd.default_variant = args.variant

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    print(
        f"fake-provider listening on https://127.0.0.1:{args.port} "
        f"variant={args.variant}",
        flush=True,
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
