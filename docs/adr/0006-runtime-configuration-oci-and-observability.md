# ADR-0006: Runtime Configuration, Stateless OCI Operation, and Safe Observability

- **Status:** Accepted
- **Date:** 2026-08-24
- **Deciders:** R&D Team

## Context

PermissionSync must serve distinct deployments without embedding their trust,
network, provider, target, credential, or permission choices. It must remain
portable across OCI runtimes, provide useful operational evidence without
exposing secrets, and recover without deployment-registry access after an
installation or upgrade.

## Decision

### Generic artifact and deployment boundary

PermissionSync is one generic, immutable, versioned binary and OCI image,
reusable across deployments. It embeds no deployment URLs, credentials,
permission data, target instances, or environment trust. After successful
installation or upgrade, normal replica creation and recovery—including
restart, eviction, replacement, node reboot, relocation, and cold-node
scheduling—MUST NOT require public or external registry connectivity. The
selected image MUST therefore be available from deployment-local
infrastructure or equivalent offline installation or upgrade media. Image
availability is deployment infrastructure, not PermissionSync application
state.

Kubernetes is only a deployment target: the service depends on no Kubernetes
API, discovery, object, or configuration semantics and also works with
Podman, Docker, and other OCI runtimes. Helm charts and manifests are
optional deployment artifacts.

### Runtime configuration and validation

All deployment-specific values are runtime configuration:

- **Inbound:** trusted issuer, trusted JWKS source or discovery URL, required
  expected audience, algorithm allowlist, required role or scope (or
  equivalent), and claim location.
- **Provider:** type, endpoint, credentials, TLS or trust settings including
  private CAs, and shorter per-operation timeouts.
- **Target:** `client_id` mapping, managed or unmanaged status, and a logical
  adapter identifier resolved deterministically against adapters compiled into
  the current binary. Endpoint, credentials, TLS or trust settings including
  private CAs, and adapter-specific values are supplied only when required by
  the selected adapter contract.
- **Runtime:** listen address and port, shorter per-operation timeouts,
  bounded synchronization concurrency or capacity, one bounded overall
  synchronization deadline, logging, and metrics.

Secrets are supplied externally; Kubernetes Secrets are not required. All
downstream credentials use least privilege, and TLS verification must not be
disabled. This ADR does not choose a configuration or secret mechanism.

Static configuration is validated at startup and readiness whenever reasonably
possible. Global or core errors prevent startup or readiness, including a
missing or invalid trusted issuer, JWKS or discovery configuration, signing
algorithm allowlist, global authorization configuration, fundamentally invalid
runtime or listener configuration, or ambiguous, contradictory, or
structurally unusable target routing.

Provider configuration, endpoint, authentication or credentials, TLS or trust
settings, and provider-specific configuration are validated eagerly where
practical but are required only for managed synchronization. Missing or
invalid provider dependencies make a selected managed request return `500`.
Unconfigured and unmanaged targets remain `200` no-ops with no provider work;
the service may remain ready when it can authenticate, authorize, validate,
route, and return those outcomes. Provider configuration failures are exposed
safely through logs, metrics, or status where appropriate, without choosing
health or status mechanisms.

Isolated target-local errors are detected eagerly where practical and make
only that managed target unusable. They include a configured adapter
identifier absent from the current compiled-in registry, missing required
endpoint or credentials, malformed endpoint, invalid target TLS or trust
configuration where applicable, and missing or invalid required
adapter-specific configuration. The selected adapter contract determines which
target configuration is required. When an absent adapter key is detectable, no
Permission Provider or Target Adapter work begins for that target. The service
may remain ready; that managed target returns `500`, while other valid managed
targets process normally and unrelated unmanaged or unconfigured targets
remain serviceable as `200` no-ops. Runtime unavailability after valid
configuration is a synchronization failure.

### Statelessness, deadlines, capacity, and delivery

V1 is stateless: any healthy replica can handle a request. There is no shared
persistence, distributed lock, persistent delivery queue, or idempotency
database unless a future ADR accepts one.

Each request has one runtime-configurable overall deadline starting when the
request is accepted and covering all PermissionSync application processing
until the response outcome is ready to emit: authentication, JWKS or
discovery, authorization, strict validation, target resolution, capacity
waiting, provider work, and all Target Adapter reconciliation. It does not
control final HTTP or network transport completion. Every remote
authentication verification, provider operation, and target outbound
operation is individually bounded and consumes the same remaining budget;
child operations may have shorter configured timeouts but must not
intentionally exceed that budget. The overall deadline is configured below
the caller-side HTTP timeout, leaving transport and response margin, without
hardcoding an external timeout. Expiry at any stage is a synchronization
failure returning `500` under [ADR 0001](0001-inbound-synchronization-contract.md),
and no new work intentionally starts after expiry.

Valid managed work obtains bounded synchronization capacity before provider
work. Local saturation, including failure to obtain capacity before the
overall deadline, returns `500`, never a successful no-op, and starts no
provider or adapter work. Capacity and in-flight synchronization remain
bounded so slow downstreams cannot exhaust the runtime; the mechanism and
limits are deferred. Deadline and cancellation pass through authentication,
capacity waits, provider work, and adapter operations on a best-effort basis.
This cannot hard-interrupt arbitrary in-process adapter work. Already-issued
downstream requests or effects remain uncertain, with no rollback or undo
guarantee.

Each inbound request makes at most one Permission Provider resolution
invocation and one selected Target Adapter reconciliation invocation. One
adapter reconciliation may make multiple downstream API calls, but neither
those calls nor failed downstream operations are automatically retried in v1;
the single-attempt, no-retry policy is defined by [ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md).

### Operations, observability, and correlation

The runtime uses reusable outbound HTTP connection pools, graceful shutdown,
health and readiness endpoints, non-root execution, and a minimal runtime
image. Structured stdout and stderr logging and metrics are required
operational capabilities for v1, not optional. Exact metric names, endpoint
paths, the Rust observability library, and the metrics backend or protocol are
deferred and not selected here.

PermissionSync telemetry MUST make it possible to determine at least:
request/synchronization count by coarse outcome; end-to-end request duration;
final or failure stage using bounded categories such as authentication,
authorization, validation, routing, capacity, provider, and adapter; current
in-flight managed synchronization work; local capacity or saturation
rejection; Permission Provider outcome, failure, and latency; and Target
Adapter reconciliation outcome, failure, and latency.

Metric dimensions or labels MUST use bounded, low-cardinality values.
User-derived or otherwise unbounded or sensitive values MUST NOT be metric
labels, including usernames, emails, group values, bearer or JWT data, and
technical caller identities. `client_id` may remain available in safe
structured logs where appropriate, but is not required as a metric label.

Observability may record `client_id`, adapter, result category, stage,
duration or latency, coarse assignment and constraint counts, inbound group
count without group names, and a privacy-conscious technical caller identity.
A username is allowed only when explicitly justified by logging and privacy
policy. It must never record raw request bodies, email, full group paths, raw
bearer tokens, client or provider credentials, target credentials, private
keys, complete JWT claims, full sensitive desired-permission documents or
data, or constraint values such as network ranges, resource selectors, or
internal interface names. Only coarse, non-sensitive summaries are recorded,
and caller-facing errors contain only safe detail.

Distributed tracing and a concrete telemetry protocol or exporter are deferred
and are not required for v1.

Correlation is optional. The runtime supports propagating a future identifier
when it is supplied in an HTTP transport header, but no header or name is
required, and no correlation or request ID is added to the fixed six-field
body. No body field is used for correlation, and current events must not assume
an identifier.

## Alternatives considered

- **Deployment-specific images or embedded configuration:** rejected in favor
  of one reusable generic artifact with external runtime configuration and
  secrets.
- **Kubernetes-specific configuration or secret mechanisms:** rejected to
  preserve OCI and deployment neutrality and because Kubernetes Secrets are
  not required.
- **Stateful delivery, automatic retry, or rollback:** rejected for v1 in
  favor of stateless, single-attempt reconciliation under ADR 0003.

## Consequences

One release supports many deployments while keeping configuration and secrets
outside the artifact. Stateless replicas can scale and recover independently;
offline whole-image availability supports recovery, and bounded downstream
work protects capacity. Adapter changes are full PermissionSync binary and
OCI image releases; there is no independent runtime adapter artifact. Future
specifications must preserve these boundaries and make deferred operational
details explicit.

## References

- [ADR 0001](0001-inbound-synchronization-contract.md)
- [ADR 0002](0002-receiver-side-jwt-verification.md)
- [ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md)
- [ADR 0005](0005-bounded-desired-permission-model.md)
- [ADR 0007](0007-compile-time-rust-target-adapters.md)
