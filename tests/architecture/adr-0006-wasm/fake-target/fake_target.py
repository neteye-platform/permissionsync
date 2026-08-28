#!/usr/bin/env python3
# Copyright (c) 2026 Würth IT Italy S.r.l.
"""Fake target HTTPS server for the ADR 0006 feasibility PoC.

A minimal in-memory "target system" that PermissionSync-style adapters
reconcile against. It is deliberately simple; it exists so the PoC can
produce *executable* evidence for the ADR 0006 gates (managed vs unmanaged
state, secret-bearing authorisation, and a configurable slow mode for the
deadline/cancellation gate).

Not a production target. No real IAM semantics.
"""

import argparse
import contextlib
import json
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TypedDict

type ClientId = str
type BearerToken = str
type Assignments = list[str]
type Constraints = dict[str, list[str]]


class ManagedState(TypedDict):
    """State exclusively owned by an adapter."""

    assignments: Assignments
    constraints: Constraints


class TargetSnapshot(TypedDict):
    """Observable fixture state for one target client."""

    client: ClientId
    managed_assignments: Assignments
    unmanaged_assignments: Assignments
    managed_constraints: Constraints
    unmanaged_constraints: Constraints


DEFAULT_UNMANAGED_ASSIGNMENTS: Assignments = ["legacy-admin"]
DEFAULT_UNMANAGED_CONSTRAINTS: Constraints = {"legacy": ["keep"]}
QUERY_PARTS = 2


class TargetState:
    """Per-client managed and unmanaged state, in memory only."""

    def __init__(self, clients: dict[ClientId, BearerToken]) -> None:
        """Initialize per-client managed and unmanaged fixture state."""
        # clients: dict client_id -> expected bearer token
        self.clients = clients
        self.lock = threading.RLock()
        # managed_assignments: list of "kind:id" strings the adapter owns.
        # unmanaged_assignments: list the adapter must never touch.
        # managed/unmanaged_constraints: dict type -> list of values.
        self.managed: dict[ClientId, ManagedState] = {
            c: {"assignments": [], "constraints": {}} for c in clients
        }
        self.unmanaged_assignments: dict[ClientId, Assignments] = {
            c: list(DEFAULT_UNMANAGED_ASSIGNMENTS) for c in clients
        }
        self.unmanaged_constraints: dict[ClientId, Constraints] = {
            c: {k: list(v) for k, v in DEFAULT_UNMANAGED_CONSTRAINTS.items()}
            for c in clients
        }

    def reset(self) -> None:
        for c in self.clients:
            self.managed[c] = ManagedState(assignments=[], constraints={})
            self.unmanaged_assignments[c] = list(DEFAULT_UNMANAGED_ASSIGNMENTS)
            self.unmanaged_constraints[c] = {
                k: list(v) for k, v in DEFAULT_UNMANAGED_CONSTRAINTS.items()
            }

    def snapshot(self, client: ClientId) -> TargetSnapshot:
        with self.lock:
            return {
                "client": client,
                "managed_assignments": list(
                    self.managed[client]["assignments"],
                ),
                "unmanaged_assignments": list(
                    self.unmanaged_assignments[client],
                ),
                "managed_constraints": {
                    k: list(v) for k, v in self.managed[client]["constraints"].items()
                },
                "unmanaged_constraints": {
                    k: list(v) for k, v in self.unmanaged_constraints[client].items()
                },
            }

    def reconcile(
        self,
        client: ClientId,
        token: BearerToken,
        assignments: Assignments,
        constraints: Constraints,
    ) -> TargetSnapshot | None:
        with self.lock:
            expected = self.clients[client]
            if token != expected:
                return None  # auth failure
            # Adapter owns ONLY managed assignment + managed constraint state.
            self.managed[client]["assignments"] = list(assignments)
            self.managed[client]["constraints"] = {
                k: list(v) for k, v in constraints.items()
            }
            return self.snapshot(client)


class TargetHTTPServer(ThreadingHTTPServer):
    """HTTP server carrying target fixture state and latency configuration."""

    state: TargetState
    delay_ms: int


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: TargetHTTPServer

    def log_message(
        self,
        format: str,
        *args: object,
    ) -> None:
        # Keep logs minimal and secret-free; the host is the auditable side.
        sys.stderr.write(f"[fake-target] {self.path.split('?')[0]}\n")

    def _json(self, code: int, obj: object) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _delay(self) -> None:
        d = self.server.delay_ms
        if d:
            time.sleep(d / 1000.0)

    def _client(self) -> ClientId:
        q = self.path.split("?", 1)
        client = "bob"
        if len(q) == QUERY_PARTS:
            for kv in q[1].split("&"):
                if kv.startswith("client="):
                    client = kv.split("=", 1)[1]
        return client

    def do_GET(self) -> None:
        self._delay()
        path = self.path.split("?", 1)[0]
        if path == "/reset":
            self.server.state.reset()
            self._json(200, {"reset": True})
            return
        if path == "/state":
            client = self._client()
            if client not in self.server.state.clients:
                self._json(404, {"error": "unknown client"})
                return
            self._json(200, self.server.state.snapshot(client))
            return
        if path == "/info":
            self._json(
                200,
                {
                    "clients": sorted(self.server.state.clients),
                    "delay_ms": self.server.delay_ms,
                },
            )
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        self._delay()
        path = self.path.split("?", 1)[0]
        if path != "/state":
            self._json(404, {"error": "not found"})
            return
        client = self._client()
        if client not in self.server.state.clients:
            self._json(404, {"error": "unknown client"})
            return
        auth = self.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ")
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._json(400, {"error": "bad body"})
            return
        assignments = body.get("assignments", [])
        constraints = body.get("constraints", {})
        result = self.server.state.reconcile(
            client,
            token,
            assignments,
            constraints,
        )
        if result is None:
            self._json(403, {"error": "forbidden"})
            return
        self._json(200, result)

    def do_PUT(self) -> None:
        self.do_POST()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9443)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument(
        "--clients",
        required=True,
        help="comma list client:token,client:token",
    )
    ap.add_argument(
        "--delay-ms",
        type=int,
        default=0,
        help="if >0, every request sleeps this long (stalled target)",
    )
    args = ap.parse_args()

    clients: dict[ClientId, BearerToken] = {}
    for pair in args.clients.split(","):
        c, t = pair.split(":", 1)
        clients[c] = t

    state = TargetState(clients)
    with TargetHTTPServer(("127.0.0.1", args.port), Handler) as httpd:
        httpd.state = state
        httpd.delay_ms = args.delay_ms

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

        print(
            f"fake-target listening on https://127.0.0.1:{args.port} "
            f"clients={sorted(clients)} delay_ms={args.delay_ms}",
            flush=True,
        )
        with contextlib.suppress(KeyboardInterrupt):
            httpd.serve_forever()


if __name__ == "__main__":
    main()
