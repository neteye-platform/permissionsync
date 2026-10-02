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

It is packaged as a minimal, non-root production OCI image, with a reference
Kubernetes deployment contract and a real supported-Keycloak contract suite,
both described below.

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

`inbound_admission_limit` bounds both how many synchronization requests may be
admitted at once and how many more may be parked waiting, and only admitted
requests buffer a body. A parked request is woken as soon as a permit frees. A
request arriving when both bounds are full is refused at the transport boundary
and receives no PermissionSync response, so saturation adds no `429`, `503`, or
other caller-facing status; such refusals are counted by
`permissionsync_inbound_admission_refused_total`.

Two further bounds are fixed product values rather than deployment knobs: a
one-mebibyte inbound body limit, and a thirty-second window in which a client
must deliver one complete request head.

The number of simultaneously accepted connections is not bounded inside the
process; a deployment that must bound it should enforce a connection limit in
front of PermissionSync. Descriptor exhaustion is retried behind a short backoff
rather than being fatal.

Concurrent synchronization requests are allowed, including requests for the same
user on the same target, and PermissionSync assigns them no ordering:
`synchronization_capacity` bounds resource use, not exclusion. A caller that
needs a settled outcome for one user must sequence its own deliveries. See
[ADR-0003](docs/adr/0003-at-most-once-delivery-and-idempotent-reconciliation.md),
[ADR-0007](docs/adr/0007-compile-time-rust-target-adapters.md), and
[ADR-0009](docs/adr/0009-glpi-target-adapter.md) for why.

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

A per-connection, network, or resource-pressure accept failure is retried and
never terminates the process; only repeated consecutive failures that indicate
an unusable listener are fatal, and the process then shuts down as below and
exits reporting failure.

On `SIGTERM` or `SIGINT` the process marks readiness false, stops accepting,
admits no further synchronization request and releases pending admission waits,
lets already admitted requests finish within the configured grace period, then
cancels the remaining request contexts, terminates and awaits its remaining
tasks, and performs a bounded trace flush when tracing is enabled. Final
telemetry may be lost if the exporter is still unavailable.

## Container image

PermissionSync ships as one generic, immutable, versioned OCI image. It embeds
no deployment URL, credential, permission data, target instance, or environment
trust: the image is identical for every deployment, and everything specific to
one is runtime configuration.

Build it locally from the repository root:

```sh
docker build --file Dockerfile --tag permissionsync:local .
```

The [Dockerfile](Dockerfile) has two stages. The builder is the official Rust
image, pinned by tag and digest, and it installs the toolchain
[rust-toolchain.toml](rust-toolchain.toml) selects. The runtime stage is a
distroless base holding the executable plus the C runtime, OpenSSL, and system
trust store it links against — no shell, package manager, compiler, Cargo
state, source tree, test material, configuration, or trust material.

Run it with the configuration mounted from outside the image:

```sh
docker run --rm \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --publish 127.0.0.1:8443:8443 \
  --env PERMISSIONSYNC_CONFIG_FILE=/etc/permissionsync/permissionsync.yaml \
  --volume /etc/permissionsync/permissionsync.yaml:/etc/permissionsync/permissionsync.yaml:ro \
  permissionsync:local
```

| Property      | Behaviour                                                                                            |
| ------------- | ---------------------------------------------------------------------------------------------------- |
| Entrypoint    | `/usr/local/bin/permissionsync`, exec form, so it is PID 1 and receives `SIGTERM`/`SIGINT` directly  |
| User          | `65532:65532`, a dedicated unprivileged account declared numerically                                 |
| Configuration | Required externally through `PERMISSIONSYNC_CONFIG_FILE`; the image sets no environment value at all |
| Listener      | Whatever `listener.address` and `listener.port` select; no port is baked in, so there is no `EXPOSE` |
| Filesystem    | Nothing is written, so a read-only root filesystem needs no writable path, not even `/tmp`           |
| Private CA    | Only through `additional_trust_anchors_pem` in the mounted configuration                             |
| Health check  | None in the image: Kubernetes is the supported platform and owns the probes below                    |
| Platform      | `linux/amd64`, the only platform published and the only one validated in CI                          |

The image carries the standard `org.opencontainers.image.*` title,
description, source, url, documentation, licenses, and vendor labels. Version,
revision, and creation labels are added by the publishing workflow, so a local
build claims no release identity.

Releases are published to `ghcr.io/neteye-platform/permissionsync` from stable
`vX.Y.Z` tags only. Each release publishes the version tag and also moves the
conventional `latest` tag.

| Reference                         | Mutability                                                                                        |
| --------------------------------- | ------------------------------------------------------------------------------------------------- |
| `…/permissionsync:1.2.3@sha256:…` | Immutable by construction. The reproducible deployment reference.                                 |
| `…/permissionsync:1.2.3`          | Immutable by policy: the release workflow refuses to publish a version that is already published. |
| `…/permissionsync:latest`         | **Mutable by design.** It moves to each new stable release.                                       |

The version tag and the content digest are the release identity. `latest` is a
convenience and discovery reference only and is never part of deployment
correctness, so a deployment that needs reproducibility or offline recovery
MUST reference the immutable digest, which the publishing workflow prints for
every release. Do not pin `latest`.

Normal restart and recovery must not depend on public registry connectivity.
Keeping the selected digest available — mirrored, cached, or on offline
installation media — is the deployment platform's responsibility; this
repository publishes an immutable image and implements no registry or mirror,
so GHCR availability is never part of PermissionSync's runtime correctness.

## Kubernetes

Kubernetes is the only explicitly supported deployment platform, and
PermissionSync still depends on no Kubernetes API, object, discovery, or
configuration semantics. Manifests and Helm charts are deployment-owned
optional artifacts;
[deploy/kubernetes/permissionsync.example.yaml](deploy/kubernetes/permissionsync.example.yaml)
is a small placeholder-only **example** of the contract the platform must
provide, not a mandatory production architecture and not PermissionSync's
configuration API. Copy it, replace every placeholder, and own the result
yourself.

The supported deployment contract is:

| Contract           | Requirement                                                                                 |
| ------------------ | ------------------------------------------------------------------------------------------- |
| Configuration      | Exactly one external YAML document, mounted read-only                                       |
| Configuration path | `PERMISSIONSYNC_CONFIG_FILE` pointing at that mounted file, and no other environment value  |
| Liveness           | `GET /healthz` on the configured listener port                                              |
| Readiness          | `GET /readyz` on the same port                                                              |
| Seccomp            | `seccompProfile.type: RuntimeDefault`                                                       |
| User               | `runAsNonRoot: true` with the image's `runAsUser`/`runAsGroup` of `65532`                   |
| Privileges         | `allowPrivilegeEscalation: false`, not privileged, all capabilities dropped                 |
| Filesystem         | `readOnlyRootFilesystem: true`; no writable path is required                                |
| Host namespaces    | None: no host network, PID, or IPC, and no Kubernetes API token is mounted                  |
| Termination        | `SIGTERM`, with `terminationGracePeriodSeconds` covering the whole bounded shutdown horizon |
| Image              | The published image pinned by immutable digest, kept available locally for restart          |

Any volume source that presents the single document at the mounted path works.
Kubernetes Secrets are **not** required, and PermissionSync neither requires nor
understands a secret backend: a Secret, a ConfigMap, a projected volume, a CSI
secrets-store volume, or an operator-managed volume are all equally valid. The
example shows a Secret only because that document normally carries credentials
and private trust material.

`terminationGracePeriodSeconds` has to cover PermissionSync's whole bounded
shutdown horizon, which is wider than the configured request grace. Once
`shutdown.grace_milliseconds` expires, the process still spends a fixed bounded
window letting already cancelled requests return, and then a bounded final
trace flush when tracing is enabled, before it exits. Both are fixed product
values of a few seconds, not deployment knobs, so budget:

```text
shutdown.grace + fixed post-grace cancellation window
               + bounded final lifecycle and trace cleanup
               + operational margin
```

The example manifest keeps 30 seconds against the example configuration's
20-second grace, which leaves ample headroom for both fixed phases. Choosing
this horizon is the deployment's responsibility; PermissionSync keeps its own
shutdown internally bounded either way, and a horizon that is too short simply
means Kubernetes sends `SIGKILL` before the process finished its own sequence.

Replicas, resource requests and limits, scheduling, Service and Ingress
objects, and TLS termination in front of the listener are deployment concerns.
The example shows resource bounds as placeholders for that reason.

## Supported Keycloak

CI exercises exactly one supported Keycloak release, pinned by release tag and
immutable digest in
[the disposable Keycloak environment](crates/permissionsync-auth/integration/keycloak/docker-compose.yml).
That compose file is the single declaration of the release: the bootstrap and
the contract suite both read it from there, so a Renovate update needs no
second edit, and such an upgrade must pass the contract suite before it can be
merged. That release is the tested deployment baseline, not a claim that other
releases are broken: PermissionSync's contract is the OIDC and JWT behaviour
recorded in [ADR-0002](docs/adr/0002-receiver-side-jwt-verification.md), and
any Keycloak that satisfies it works.

Against a real Keycloak over real HTTPS, the suite covers both supported
trusted-source modes (OIDC discovery and a directly configured `jwks_uri`), the
Client Credentials token and `permissionsync:<target>` scope contract, the
refusal of tokens with a wrong audience, a foreign realm, an expired lifetime or
a disallowed algorithm, behaviour while the metadata source is unreachable, and
a real signing-key rotation. Each case is named and explained in
[real_keycloak.rs](crates/permissionsync-auth/tests/real_keycloak.rs).

Certificate and hostname validation stay fully enabled; the disposable CA is
supplied through `additional_trust_anchors_pem`, and every credential is
generated per run and destroyed with the environment. Adversarial parser,
cryptographic, and cache-timing cases belong to the hermetic auth tests.

Run it locally. The disposable environments drive `docker` and
`docker compose`, so they need Docker Engine with the Compose v2 plugin:

```sh
source <(crates/permissionsync-auth/integration/keycloak/bootstrap.sh)
set -a
source "$KEYCLOAK_TEST_RUNTIME_ENV"
set +a
cargo test -p permissionsync-auth --test real_keycloak --locked -- --ignored
crates/permissionsync-auth/integration/keycloak/teardown.sh
```

## Testing

| Layer                       | What it covers                                                                                                | How to run                                                                |
| --------------------------- | ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| Hermetic workspace tests    | Every contract that needs no external service, including the image and Kubernetes contract checks in `tests/` | `cargo test --workspace --all-features --locked`                          |
| Real GLPI suite             | The production GLPI V1 reconciliation contract against a disposable GLPI                                      | [GLPI adapter test workflow](.github/workflows/glpi-adapter-tests.yaml)   |
| Real Keycloak suite         | The supported-Keycloak authentication and metadata wire contract                                              | [Keycloak workflow](.github/workflows/keycloak-authentication-tests.yaml) |
| OCI and deployment contract | The built production image, its hardening, its signal handling, and the Kubernetes example                    | [OCI workflow](.github/workflows/oci-image-tests.yaml)                    |

The OCI workflow checks the built image itself — hardening, metadata, absence
of build and configuration material, startup without configuration, readiness
while the metadata source is unreachable, and graceful `SIGTERM` — and then runs
that same image against the disposable HTTPS Keycloak. Both checks live in
[integration/oci/](integration/oci/) and take a built image reference, so they
run locally too, against Docker Engine with the Compose v2 plugin:

```sh
docker build --file Dockerfile --tag permissionsync:local .
integration/oci/image-contract.sh permissionsync:local
```

The Kubernetes example is validated by the organization's
[kubeconform hook](https://github.com/neteye-platform/kubeconform-precommit)
configured in [.pre-commit-config.yaml](.pre-commit-config.yaml), which runs in
`prek run --all-files` and in the shared pull-request checks.

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
[real-Keycloak integration layer](crates/permissionsync-auth/integration/keycloak/);
CI executes both, plus the container and deployment contract scripts in
[integration/oci/](integration/oci/), through the workflows listed under
[Testing](#testing).

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
