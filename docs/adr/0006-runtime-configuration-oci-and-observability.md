# Runtime Configuration, Stateless OCI Operation, and Safe Observability

## Status

Accepted

## Context

PermissionSync must serve distinct deployments without embedding their trust,
network, provider, target, credential, or permission choices. It must remain
portable across OCI runtimes and provide useful operational evidence without
exposing secrets or unnecessary sensitive data.

## Decision

PermissionSync is one generic, immutable, versioned binary and OCI image. The
same artifact is reusable across deployments. It must not embed deployment
URLs, credentials, permission data, target instances, or environment trust.

After successful installation or upgrade, normal replica creation and recovery
including restart, eviction, replacement, node reboot, relocation, and
cold-node scheduling MUST NOT require public or external registry connectivity.
Therefore, the selected PermissionSync OCI image MUST be available through
deployment-local infrastructure or equivalent offline installation or upgrade
media. Image availability is deployment infrastructure, not PermissionSync
application state.

All deployment-specific values are runtime configuration:

- Inbound configuration specifies issuer, JWKS or discovery URL, optional
  audience, algorithm allowlist, required role, scope, or equivalent, and the
  claim location.
- Provider configuration specifies type, endpoint, credentials, TLS or trust
  settings including private CAs, and shorter per-operation timeouts.
- Target configuration specifies client_id mapping, managed or unmanaged
  status, and a logical adapter identifier. The identifier is resolved
  deterministically against adapters compiled into the current binary.
  Endpoint, credentials, TLS or trust settings including private CAs, and
  adapter-specific values are included only when required by the selected
  adapter contract.
- Runtime configuration specifies listen address and port, shorter per-operation
  timeouts, bounded synchronization concurrency or capacity, one bounded overall
  synchronization deadline, logging, and metrics.

Secrets are supplied externally, without requiring Kubernetes Secrets. All
downstream credentials use least privilege, and TLS verification must not be
disabled. This ADR does not select a configuration or secret mechanism.

Static configuration is validated at startup and readiness whenever reasonably
possible. Global or core errors prevent startup or readiness: missing or invalid
trusted issuer, JWKS or discovery configuration, signing algorithm allowlist,
or global authorization configuration; fundamentally invalid runtime or
listener configuration; and ambiguous, contradictory, or structurally unusable
target routing.

Permission Provider configuration, endpoint, authentication or credentials,
TLS or trust settings, and provider-specific configuration are validated
eagerly where practical, but are required only for managed synchronization.
Missing or invalid provider dependency causes a selected managed request to
return `500`. Unconfigured and unmanaged targets remain `200` no-ops with no
provider work. The service may remain ready if it can authenticate, authorize,
validate, route, and return those no-op outcomes. Provider configuration failure
is safely visible through logs and metrics or status where appropriate, without
choosing health or status mechanisms.

Isolated target-local errors are detected eagerly where practical, but make only
that managed target unusable. The selected adapter contract determines which
target configuration is required. Errors include a configured adapter
identifier absent from the current compiled-in registry; missing required
target endpoint or credentials; a malformed configured endpoint; invalid
target-specific TLS or trust configuration where applicable; and missing or
invalid required adapter-specific configuration. A target-local adapter
identifier absent from the compiled-in registry is eagerly detected where
practical. When detectable, no Permission Provider or Target Adapter work
begins for that target. The service may remain ready. A selected unusable
managed target returns `500` only for that target; other valid managed
targets process normally, and unrelated unmanaged or unconfigured targets
remain serviceable as `200` no-ops.
Runtime unavailability after valid configuration remains a synchronization
failure.

V1 is stateless. Any healthy replica can handle a request. It has no shared
persistence, distributed locks, persistent delivery queue, or idempotency
database unless a future ADR accepts one.

Each inbound request has one runtime-configurable overall deadline that starts
when the request is accepted and covers all PermissionSync application
processing until the response outcome is ready to be emitted. It covers
authentication, JWKS or discovery work, authorization, strict validation,
target resolution, capacity waiting, provider work, and all Target Adapter
reconciliation work. It does not claim control over final HTTP or network
transport completion. Every remote authentication verification operation is
bounded and consumes the same remaining budget. Every provider and target
outbound operation is also individually bounded. Individual child operations may
have shorter configured timeouts, but their effective timeout must not
intentionally exceed the remaining overall budget. The overall deadline is
configured below the caller-side HTTP timeout, leaving transport and response
margin, without a hardcoded external timeout value. Expiry at any stage is a
synchronization failure and returns `500` under ADR 0001. No new work
intentionally starts after expiry.

Valid managed work acquires bounded synchronization capacity before provider
work. Local saturation, including inability to acquire capacity before the
overall deadline, is a synchronization failure and returns `500`, never a
successful no-op. No Permission Provider or Target Adapter work begins. The
overall deadline and cancellation are passed through authentication
verification, capacity waits, provider work, and adapter operations on a
best-effort basis. This does not promise arbitrary in-process adapter work can
be hard-interrupted. Downstream requests or effects already issued remain
uncertain, with no rollback or undo guarantee.

In-flight synchronization and capacity are bounded so slow downstreams cannot
exhaust the runtime. The capacity mechanism and limits remain deferred.

Each inbound request makes at most one Permission Provider resolution
invocation and one selected Target Adapter reconciliation invocation. One
adapter reconciliation may issue multiple required downstream API operations.
Those operations, and failed downstream operations, are not automatically
retried in v1. The single-attempt, no-retry delivery policy is defined by
[ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md).

The runtime uses reusable outbound HTTP connection pools, graceful shutdown,
health and readiness endpoints, a metrics endpoint where practical, structured
stdout and stderr logging, non-root execution, and a minimal runtime image.
This ADR does not name paths, metrics, or mechanisms.

Kubernetes is a deployment target only. PermissionSync depends on no Kubernetes
API, discovery, object, or configuration semantics. The OCI image also works
with Podman, Docker, and other OCI runtimes. Helm charts and manifests are
optional deployment artifacts.

Observability records may include client_id, adapter, result category, stage,
duration or latency, coarse assignment and constraint counts, and inbound
group count but not group names, plus a privacy-conscious technical caller
identity. They may include a username only
when explicitly justified by logging and privacy policy. They never include a
raw request body, email, full group paths, raw bearer token, client secret,
provider credentials, target credentials, private keys, complete JWT claims,
full sensitive desired-permission documents or data, or constraint values
such as network ranges, resource selectors, or internal interface names.
Only coarse, non-sensitive summaries may be recorded where useful.
Caller-facing errors provide only safe detail.

Correlation is optional. The runtime supports propagating a future identifier
when it is supplied in an HTTP transport header, but does not require a header,
name it, or add correlation or request ID to the fixed six-field body. No body
fields are used for correlation. Current events must not assume an identifier
exists.

## Consequences

One release supports many deployments while keeping configuration and secrets
outside the artifact. Stateless replicas can scale and recover independently,
and bounded downstream work protects runtime capacity. Future specifications
must preserve these boundaries and make the deferred operational details
explicit.

Any adapter change is a new PermissionSync binary and OCI image release; there
is no independent runtime adapter artifact.

## References

- [ADR 0001](0001-inbound-synchronization-contract.md)
- [ADR 0002](0002-receiver-side-jwt-verification.md)
- [ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md)
- [ADR 0005](0005-bounded-desired-permission-model.md)
- [ADR 0007](0007-compile-time-rust-target-adapters.md)
