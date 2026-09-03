# ADR-0006: Runtime Configuration, Stateless OCI Operation, and Safe Observability

- **Status:** Accepted
- **Date:** 2026-08-24
- **Deciders:** R&D Team

## Context

PermissionSync must serve distinct deployments without embedding their trust,
network, provider, target, credential, or permission choices. It is packaged as
an OCI image and does not depend on Kubernetes application APIs/semantics,
while providing useful operational evidence without exposing secrets, and must
recover without deployment-registry access after an installation or
upgrade.

## Decision

### Generic artifact and deployment boundary

PermissionSync is one generic, immutable, versioned binary and OCI image,
reusable across deployments. It embeds no deployment URLs, credentials,
permission data, target instances, or environment trust. After successful
installation or upgrade, normal restart and recovery MUST NOT require public or
external registry connectivity. Deployment infrastructure MUST ensure that the
selected PermissionSync image remains available for normal restart and recovery
without public or external registry connectivity, for example from
deployment-local infrastructure or equivalent offline installation or upgrade
media. Image availability is deployment infrastructure, not PermissionSync
application state.

Kubernetes and OpenShift are supported deployment targets: the service depends
on no Kubernetes API, discovery, object, or configuration semantics. Helm
charts and manifests are optional deployment artifacts and are owned by
deployment, not by PermissionSync. Where Kubernetes or OpenShift is used, the
container is configured with the `RuntimeDefault` seccomp profile.

### Runtime configuration and validation

All deployment-specific values are runtime configuration:

- **Inbound:** trusted issuer, trusted JWKS or discovery source, expected
  PermissionSync audience, and algorithm allowlist (see
  [ADR 0002](0002-receiver-side-jwt-verification.md)). Authorization scope is
  not a configurable value: it is derived deterministically from the minimally
  validated target identifier by the convention `permissionsync:<target>`
  under [ADR 0001](0001-inbound-synchronization-contract.md).
- **Provider:** type, endpoint, credentials, TLS or trust settings including
  private CAs, and shorter per-operation timeouts.
- **Target:** a logical adapter identifier resolved deterministically against
  adapters compiled into the current binary. Endpoint, credentials, TLS or
  trust settings including private CAs, and adapter-specific values are
  supplied only when required by the selected adapter contract.
- **Runtime:** listen address and port, shorter per-operation timeouts,
  bounded synchronization concurrency or capacity, one bounded overall
  synchronization deadline, logging, and metrics.

Secrets are supplied externally; Kubernetes Secrets are not required. All
downstream credentials use least privilege, and TLS verification must not be
disabled. The general TLS/trust requirement applies to all credential-bearing
and trust-critical outbound traffic, including Keycloak authentication metadata
retrieval (JWKS and OIDC discovery), Permission Provider requests, and Target
API requests, as specified in
[ADR 0002](0002-receiver-side-jwt-verification.md),
[ADR 0004](0004-generic-rest-permission-provider.md), and
[ADR 0007](0007-compile-time-rust-target-adapters.md). This ADR does not choose
a configuration or secret mechanism.

Static configuration is validated at startup and readiness whenever reasonably
possible. Global or core errors prevent startup or readiness, including a
missing or invalid trusted issuer, JWKS or discovery configuration, signing
algorithm allowlist, fundamentally invalid runtime or listener configuration,
or ambiguous, contradictory, or structurally unusable target routing.
Authorization scope is not runtime configuration, so there is no configurable
authorization mapping or policy to validate; it is derived from the minimally
validated target identifier by convention under
[ADR 0001](0001-inbound-synchronization-contract.md).

Startup and readiness distinguish invalid local authentication configuration
from a temporarily unreachable Keycloak:

- **A. Invalid local configuration** (for example a missing trusted issuer, a
  malformed JWKS or discovery URL, an invalid expected audience configuration,
  or an invalid algorithm allowlist): a global error that may prevent startup
  or readiness.
- **B. Valid local configuration but Keycloak/JWKS/discovery temporarily
  unreachable:** PermissionSync MUST remain alive and MUST NOT enter a
  crash/restart loop. Readiness MUST be false if PermissionSync has no usable
  trusted verification state as defined by
  [ADR 0002](0002-receiver-side-jwt-verification.md). All remote verification,
  discovery, and JWKS
  attempts MUST be bounded by timeouts, and there MUST be no infinite startup
  wait.
- **C. Temporary Keycloak/JWKS outage with usable trusted cached verification
  material as defined by
  [ADR 0002](0002-receiver-side-jwt-verification.md):** PermissionSync may
  remain ready if it can still safely verify callers.

Readiness therefore represents "can PermissionSync currently verify callers
safely?", not "can PermissionSync currently open a connection to Keycloak?".
Fail-closed behavior is preserved, and this adds no persistent application
state or unbounded background work.

Provider configuration, endpoint, authentication or credentials, TLS or trust
settings, and provider-specific configuration are validated eagerly where
practical but are required only when a selected target is reconciled. Missing
or invalid provider dependencies make a selected target's synchronization
return `500`. An authorized caller whose logical target is unknown or
unrecognized by the runtime routing/configuration contract receives `400` under
[ADR 0001](0001-inbound-synchronization-contract.md). Provider configuration
failures are exposed safely through logs, metrics, or status where appropriate,
without choosing health or status mechanisms. The service may remain ready when
it can authenticate, authorize, validate, route, and return those outcomes.

Isolated target-local errors are detected eagerly where practical and make only
that target unusable. A recognized logical target with unavailable or broken
server-side adapter or target configuration is a target-local `500`. Examples
include a configured adapter identifier absent from the current compiled-in
registry, missing required endpoint or credentials, malformed endpoint, invalid
target TLS or trust configuration where applicable, missing or invalid required
adapter-specific configuration, or an equivalent deployment/composition
defect. The selected adapter contract determines which target configuration is
required. When such an error is detectable after logical resolution and before
capacity, no Permission Provider or Target Adapter work begins. The service may
remain ready; that target returns `500`, while other correct targets remain
serviceable. Unknown or unrecognized logical targets return `400`. Runtime
unavailability after valid configuration is a synchronization failure.

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

Valid synchronization work obtains bounded synchronization capacity before
provider work. Local saturation, including failure to obtain capacity before the
overall deadline, returns `500`, never a successful no-op, and starts no
provider or adapter work. Capacity and in-flight synchronization remain
bounded so slow downstreams cannot exhaust the runtime; the mechanism and
limits are deferred. Deadline and cancellation pass through authentication,
capacity waits, provider work, and adapter operations on a best-effort basis.
A COMPLIANT Target Adapter has bounded execution: every remote I/O operation
and every adapter-controlled wait or blocking operation is bounded,
reconciliation cooperates with and observes the overall request deadline and
propagated cancellation, no new downstream work starts after expiry, and
reconciliation returns after its currently executing bounded operation
completes without detaching or backgrounding work; see
[ADR 0007](0007-compile-time-rust-target-adapters.md). The synchronization
capacity slot remains associated with the reconciliation until adapter work has
actually returned and is not released while reconciliation is still running.
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
in-flight synchronization work; local capacity or saturation
rejection; Permission Provider outcome, failure, and latency; and Target
Adapter reconciliation outcome, failure, and latency.

Metric dimensions or labels MUST use bounded, low-cardinality values.
User-derived or otherwise unbounded or sensitive values MUST NOT be metric
labels, including usernames, group values, bearer or JWT data, and technical
caller identities. The technical caller's JWT `client_id` claim may remain
available in safe structured logs where appropriate, but is not required as a
metric label.

Observability may record the technical caller's JWT `client_id` claim, adapter,
result category, stage, duration or latency, coarse `changed`/`unchanged` result
counts, inbound group count without group names, and a privacy-conscious
technical caller identity. A username is allowed only when explicitly justified
by logging and privacy policy. It must never record raw request bodies, full
group paths, raw bearer tokens, client or provider credentials, target
credentials, private keys, complete JWT claims, full sensitive provider payload
documents or data, or target mapping or semantic details. Only coarse,
non-sensitive summaries are recorded, and caller-facing errors contain only
safe detail.

Distributed tracing and a concrete telemetry protocol or exporter are deferred
and are not required for v1.

Correlation is optional. The runtime supports propagating a future identifier
when it is supplied in an HTTP transport header, but no header or name is
required, and no correlation or request ID is added to the fixed five-field
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
- [ADR 0005](0005-versioned-adapter-specific-desired-state-envelope.md)
- [ADR 0007](0007-compile-time-rust-target-adapters.md)
