# PermissionSync

PermissionSync is an architecture-first service for synchronizing a user's
desired permissions with a selected target. The active constraints are recorded
in the [ADR index](docs/adr/README.md).

The Rust workspace contains target-neutral Core domain contracts, deterministic
runtime target routing, a concrete Generic REST Permission Provider,
selected-target synchronization orchestration, an internal `permissionsync-auth`
boundary for technical-caller JWT verification and scope target selection,
framework-neutral inbound HTTP request processing, a concrete GLPI Target
Adapter implementing the selected GLPI V1 reconciliation contract, typed runtime
configuration with deterministic application composition, and the executable
service runtime described below: YAML configuration delivery, an Axum listener,
bounded inbound admission and synchronization capacity, health, readiness and
metrics endpoints, graceful shutdown, structured logging, Prometheus metrics,
and optional OTLP trace export.

A real supported-Keycloak deployment contract suite is described below.
OCI and Kubernetes packaging remain future work.

## Running the service

The executable loads exactly one UTF-8 YAML configuration document. Its path
comes only from the required `PERMISSIONSYNC_CONFIG_FILE` environment variable:

```sh
PERMISSIONSYNC_CONFIG_FILE=/etc/permissionsync/permissionsync.yaml permissionsync
```

There are no layered configuration files, command-line overrides, per-value
environment overrides, environment substitution inside the document, include or
merge mechanisms, or runtime reload. Comments are allowed and carry no
semantics. Unknown or misspelled fields are rejected rather than ignored.

A documented example with placeholder values only is in
[docs/permissionsync.example.yaml](docs/permissionsync.example.yaml). Secrets
and private trust material are supplied inline through that external file and
are never built into the binary or image.

### Configuration outline

Every duration is an integer number of whole milliseconds, spelled with a
`_milliseconds` field suffix. These top-level sections are required:

| Section          | Contents                                                                                                                  |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `listener`       | `address` and a non-zero `port`                                                                                           |
| `request`        | Overall deadline, inbound admission limit, synchronization capacity                                                       |
| `shutdown`       | Grace period                                                                                                              |
| `authentication` | Issuer, audience, algorithm allowlist, trusted source, cache policy, metadata timeout, clock skew, optional trust anchors |
| `observability`  | Bounded `log_level`, optional `tracing`                                                                                   |
| `targets`        | Logical target to adapter identifier routes                                                                               |

The `provider` and `glpi` sections are optional. The Provider selects one
supported implementation (`generic_rest`), and `glpi` configures the one
process-wide GLPI backend.

Startup aborts for a global defect: an unreadable, non-UTF-8, empty,
multi-document, or malformed file; an unknown top-level field; an invalid
listener, deadline, admission limit, or capacity; an admission limit or
synchronization capacity whose bounded-concurrency primitives could not be
constructed; a synchronization capacity above the product ceiling of 1024; a
shutdown grace below the overall deadline; invalid authentication configuration;
invalid tracing configuration while export is explicitly enabled; a duplicate or
grammar-invalid logical target; or a listener that cannot be bound.

Startup does **not** abort because a component is unusable. An absent or invalid
`provider` section leaves the Provider unavailable, and an absent or invalid
`glpi` section leaves every configured route selecting `glpi` recognized but
unavailable. Unrelated correctly configured routes stay serviceable, targetless
requests keep working, and a temporarily unreachable Keycloak, Provider, GLPI, or
telemetry backend never prevents startup.

### Endpoints

All four paths are served on the single configured listener:

| Path             | Method | Behaviour                                                                             |
| ---------------- | ------ | ------------------------------------------------------------------------------------- |
| `/api/sync-user` | `POST` | The synchronization contract, with an empty response body                             |
| `/healthz`       | `GET`  | `200` while the process and HTTP runtime are functioning                              |
| `/readyz`        | `GET`  | `200` only while the authenticator has usable trusted verifier state, otherwise `503` |
| `/metrics`       | `GET`  | Prometheus text exposition                                                            |

Readiness means that PermissionSync can currently verify technical callers
safely. It does not require current Keycloak connectivity while still-usable
cached verification material exists, and it never depends on the Provider, GLPI,
a target, or a telemetry backend. It turns false as soon as shutdown begins.

The three operational endpoints take neither an inbound admission permit nor a
place in the admission wait list, and connections are not gated behind either,
so a saturated synchronization workload cannot keep them from being answered.
They expose no secrets, URLs, targets, credentials, trust material, JWT details,
or internal errors, and there is no general status or configuration endpoint.

`inbound_admission_limit` bounds two things: how many synchronization requests
may be admitted at once, and — through a value derived from it — how many further
synchronization requests may be parked waiting for admission. Together those two
values are the complete bound on synchronization requests that are admitted or
waiting anywhere in the process, and only admitted requests buffer a body.

A parked request is woken as soon as a permit frees, so it can still succeed
inside its own overall deadline, and a waiter whose own deadline really does
expire returns the ordinary server-side deadline outcome.

A request that arrives when both bounds are already full is different: it is
never parked, never authenticated, never has its body collected, and receives no
PermissionSync response at all. It was neither cancelled nor expired and was
never processed, so inventing any outcome for it would change the precedence the
synchronization contract fixes. Instead the connection is refused and terminated
at the transport boundary. Saturation therefore adds no `429`, `503`, or other
caller-facing status, and it cannot accumulate waiting requests, buffered bodies,
or permits beyond those two bounds however many connections are open. Such
refusals are counted by `permissionsync_inbound_admission_refused_total`.

The inbound synchronization body has a fixed one-mebibyte product limit. It is
not configurable, and exceeding it is a body-validation outcome in the fixed
processing order rather than an immediate transport rejection.

Connections are additionally bounded by a fixed thirty-second window in which a
client must deliver one complete request head. It applies to an incomplete first
request head and to an idle keep-alive connection waiting for the next request,
so neither can hold a task and a descriptor indefinitely. Like the body limit it
is a fixed product value rather than a deployment knob, and it is unrelated to
the configured overall request deadline, which starts only once a
synchronization request reaches the transport handler.

The *number* of simultaneously accepted connections is not bounded inside the
process. A bound taken when a connection is accepted could not keep the
operational endpoints reachable, because a connection's route is unknown until
its first request head has been read and HTTP/1 keep-alive lets one connection
change route between requests, so no share can be reserved for a class of
request that has not been identified yet. What limits the accepted population is
the process descriptor limit together with the request-head window above.
Descriptor exhaustion is handled rather than fatal: accepting is retried
behind a short backoff, already-established work continues, and the process does
not terminate. A deployment that must bound the population should enforce a
connection limit in front of PermissionSync.

Concurrent synchronization requests are allowed, including requests for the same
synchronized user on the same target. PermissionSync assigns them no ordering
and serializes nothing by identity — `synchronization_capacity` bounds resource
use, not exclusion — so a successful response means the Target Adapter
authoritatively verified its desired state immediately before returning, not
that the target still holds that state afterwards. A caller that needs a settled
outcome for one user must sequence its own deliveries. The exact semantics are
in [ADR-0003](docs/adr/0003-at-most-once-delivery-and-idempotent-reconciliation.md),
[ADR-0007](docs/adr/0007-compile-time-rust-target-adapters.md), and
[ADR-0009](docs/adr/0009-glpi-target-adapter.md).

### Observability

Ordinary runtime events are structured JSON on standard output; startup and
fatal diagnostics go to standard error as fixed, value-free categories.
Configuration selects only the bounded log-level threshold.

Prometheus metrics are always available at `/metrics` and use only closed,
low-cardinality label values. Trace export is an additional optional channel,
disabled unless `observability.tracing.enabled` is `true`. When enabled, spans
are exported over OTLP/HTTP with protobuf encoding to one absolute HTTPS
endpoint, using mandatory certificate and hostname validation, refusing every
redirect, and sending configured exporter credentials only to that endpoint's
origin. Export is asynchronous, batched, and bounded: an unavailable, slow, or
failing backend drops telemetry instead of affecting a synchronization outcome,
readiness, or capacity. Inbound W3C `traceparent` and `tracestate` are accepted
as transport metadata only; a malformed value counts as missing telemetry
context and never changes an outcome. No trace-context header is added to
Provider or Target Adapter requests.

### Shutdown

Listener-accept failures are classified before any of them is treated as fatal.
A per-connection or network error is retried immediately, and local resource
pressure such as descriptor exhaustion is retried behind a short fixed backoff
that shutdown can interrupt; neither is evidence that the listener itself broke,
so neither can terminate the process. Only repeated consecutive failures that do
indicate an unusable listener are fatal: the process then enters the same
shutdown sequence as below and exits reporting failure rather than success.

On `SIGTERM` or `SIGINT` the process marks readiness false, stops accepting,
admits no further synchronization request and releases pending admission waits,
lets already admitted requests finish within the configured grace period, then
cancels the remaining request contexts, terminates and awaits its remaining
tasks, and performs a bounded trace flush when tracing is enabled. Final
telemetry may be lost if the exporter is still unavailable.

## Supported Keycloak

CI exercises exactly one supported Keycloak release, **26.8.0**, pinned by
release tag and immutable digest in
[the disposable Keycloak environment](crates/permissionsync-auth/integration/keycloak/docker-compose.yml).
That is the tested deployment baseline, not a claim that other releases are
broken: PermissionSync's contract is the OIDC and JWT behaviour recorded in
[ADR-0002](docs/adr/0002-receiver-side-jwt-verification.md), and any Keycloak
that satisfies it works. Renovate proposes release and digest updates, and such
an upgrade must pass the contract suite before it can be merged.

The suite proves, against a real Keycloak instance over real HTTPS, that both
supported trusted-source modes work — OIDC discovery, where the discovered
issuer must equal the configured issuer exactly and its `jwks_uri` becomes
trusted only through that chain, and a directly configured `jwks_uri`. It also
proves the token contract: real Client Credentials tokens carry `client_id` and
the configured audience, zero/one/many `permissionsync:<target>` scope tokens
behave as the scope convention requires, and real tokens with the wrong
audience, a different realm, an expired lifetime, or an algorithm outside the
configured allowlist are all refused. One test additionally stops the
configured metadata source and proves that still-usable cached verification
material keeps verifying while an authenticator with no retained state fails
closed.

The Keycloak endpoint is HTTPS with certificate and hostname validation fully
enabled; the disposable CA is supplied through PermissionSync's existing
`additional_trust_anchors_pem` configuration. Nothing in the suite disables
verification, accepts plaintext, or bypasses a host name. Every credential is
generated per run inside the disposable environment and is destroyed with it.

Adversarial parser, cryptographic, and detailed cache-timing cases remain the
job of the hermetic auth tests; this suite covers the wire and deployment
contract.

Run it locally, which needs Docker or Podman:

```sh
source <(crates/permissionsync-auth/integration/keycloak/bootstrap.sh)
set -a
source "$KEYCLOAK_TEST_RUNTIME_ENV"
set +a
cargo test -p permissionsync-auth --test real_keycloak --locked -- --ignored
crates/permissionsync-auth/integration/keycloak/teardown.sh
```

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
cargo test --workspace --all-features --locked
```

Normal Cargo tests remain hermetic and require neither Docker, GLPI, nor
Keycloak. The GLPI adapter has a dedicated disposable
[real-GLPI integration layer](crates/permissionsync-adapter-glpi/integration/glpi/),
and authentication has a dedicated disposable
[real-Keycloak integration layer](crates/permissionsync-auth/integration/keycloak/).
CI executes both, through the
[GLPI adapter test workflow](.github/workflows/glpi-adapter-tests.yaml) and the
[Keycloak authentication test workflow](.github/workflows/keycloak-authentication-tests.yaml).

The dependency-policy check requires the exact, Renovate-managed
`CARGO_DENY_VERSION` in
[the Rust validation workflow](.github/workflows/rust-validation.yaml):

```sh
cargo install --locked --version <CARGO_DENY_VERSION> cargo-deny
```

Run the complete local validation suite before opening an implementation PR:

```sh
prek run --all-files --refresh
cargo fmt --all -- --check
cargo deny --locked check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
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
