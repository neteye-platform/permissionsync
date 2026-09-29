# ADR-0011: Executable Runtime, Configuration Delivery, and Operational Lifecycle

- **Status:** Accepted
- **Date:** 2026-09-29
- **Deciders:** R&D Team

## Context

PermissionSync already has semantic runtime configuration, deterministic
composition, authentication, framework-neutral inbound HTTP handling, routing,
selected-target orchestration, a Provider, and a GLPI adapter. It does not yet
have an executable runtime that loads deployment inputs, opens a listener,
limits work, serves operational endpoints, or shuts down predictably.

[ADR-0006](0006-runtime-configuration-oci-and-observability.md) requires
external runtime configuration, bounded deadlines and capacity, safe
observability, health and readiness, and graceful shutdown, but deliberately
defers their mechanisms. This record closes those runtime-level decisions
without changing the inbound, authentication, routing, Provider, or Adapter
contracts.

## Decision

### Configuration delivery

The executable loads exactly one UTF-8 JSON configuration document. Its path is
supplied by the required `PERMISSIONSYNC_CONFIG_FILE` environment variable.
There are no layered file, environment-value, command-line, or remote
configuration overrides, and no implicit environment substitution inside the
document. The file is loaded once during startup; runtime reload is not
supported.

JSON is selected because Serde and `serde_json` are already used throughout the
workspace, and one mounted document is simple for a container deployment.
Secrets, credentials, and private trust material are supplied through this
external runtime file and are never built into the binary or image. The
executable neither requires nor understands Kubernetes Secrets, secret
operators, or another secret backend.

The deserialized executable configuration is a delivery or wire model, not a
replacement for the existing semantic `RuntimeConfiguration`. It contains the
authentication inputs, Provider and GLPI inputs, configured target routes,
listen address and port, overall request deadline, inbound admission limit,
synchronization capacity, authentication, Provider, and GLPI operation
timeouts, shutdown grace period, and observability settings. After
delivery-level validation, it constructs the existing auth configuration and
projects Provider, GLPI, and target values into the existing semantic
`RuntimeConfiguration`.

Configuration failures are split into global and component-local. A global
failure aborts startup: JSON that is malformed as a document, missing or
malformed required top-level runtime structure, invalid authentication,
listener, deadline, admission, or capacity configuration, routing configuration
that cannot form deterministic logical routes, invalid or duplicate logical
targets, and any composition that is globally ambiguous or structurally
unusable. Unknown or misspelled global fields also fail startup rather than
being ignored.

A component-local failure does not abort startup, and strict decoding must not
promote one into a global failure. An absent or invalid Provider section leaves
the Provider unavailable, including a section that cannot be decoded or
validated under the Provider contract. An absent or invalid GLPI section leaves
the GLPI adapter unavailable; because GLPI is process-wide, every configured
route selecting `glpi` stays recognized but unavailable when that section cannot
produce the single usable GLPI instance. Unrelated correctly configured targets
remain serviceable. A schema mistake inside a Provider or Adapter section is
invalid component configuration, never a silently ignored field.

### HTTP runtime and transport adapter

The executable uses the Tokio multi-thread runtime and Axum over Hyper. Axum
provides a small Tokio-compatible server, graceful shutdown support, bounded
body collection, and router tests through its `Service` interface without
opening a real socket.

The synchronization route remains exactly:

```text
POST /api/sync-user
```

The Axum layer is only a transport adapter. It preserves header multiplicity,
converts received headers into `HeaderList`, buffers the bounded request body,
creates one `SynchronizationContext`, invokes the existing `InboundHttpHandler`,
and maps `HttpOutcome` to its existing status code with an empty response body.
It contains no authentication, authorization, scope, routing, Provider,
Adapter, or reconciliation policy.

### Inbound admission, request body, and overall deadline

Before collecting a `POST /api/sync-user` body, the transport obtains one permit
from a process-wide inbound admission limit, a required positive finite runtime
value. It bounds concurrently admitted synchronization requests, and therefore
aggregate application-owned body buffering and concurrent pre-selected-target
processing such as authentication and validation. A permit is held for that
request's complete handling, including cancellation and error paths, without
persistent or distributed coordination. `GET /healthz`, `GET /readyz`, and
`GET /metrics` need no admission permit and stay observable under saturation.
Saturation is transport-level backpressure, never an application outcome: a
waiting request has not yet entered application processing, so a full limit adds
no `429`, `503`, `500`, or other response to the precedence ADR-0001 fixes.
Admission complements the per-request limit below rather than replacing it.

The executable enforces a fixed one-mebibyte product limit on the inbound
synchronization body. The limit belongs at the Axum transport boundary, which
stops accumulating bytes as soon as the limit is exceeded, so buffering is never
unbounded. There is no unbounded mode and no deployment tuning knob.

Exceeding the limit is a body-validation outcome, not an immediate transport
rejection. The transport records the bounded collection failure and passes it to
`permissionsync-inbound-http` in place of a body, which may require a small
representation for "body exceeded the bounded limit". Processing then continues
in the order ADR-0001 fixes: authentication, structural scope validation, scope
cardinality, and suffix validation all resolve first and keep their outcomes. An
invalid credential with an oversized body still returns `401`, and more than one
PermissionSync scope with an oversized body still returns `403`. Only when
processing reaches body validation does an oversized body return `400`. This
adds neither an endpoint nor a body format.

The executable starts one absolute deadline immediately when the request is
admitted, before body collection. Waiting for admission precedes that deadline
and creates no second application deadline. Its duration is required runtime
configuration rather than a deployment-specific value compiled into the
binary. The same absolute deadline is used for body collection and propagated
through authentication, routing, capacity acquisition, Provider work, and
Adapter reconciliation. A child operation may apply its configured shorter
timeout but may never create a later deadline or reset the overall budget.
Expiry at any stage remains `500`.

Configured operation timeouts must be positive and no greater than the overall
request deadline. Body buffering, remote calls, parsing, and capacity waiting
must stop or return when their applicable budget expires. No new application
work intentionally starts after expiry.

### Synchronization capacity

The executable implements `SynchronizationCapacity` with one process-local
Tokio semaphore. The configured permit count must be positive and no greater
than a finite product safety ceiling of 1,024. Invalid values fail startup.

Acquisition checks cancellation and races semaphore acquisition against the
absolute request deadline. Failure to acquire in time follows the existing
capacity-unavailable `500` path and starts no Provider or Adapter work. An
owned semaphore permit implements `SynchronizationPermit` and releases capacity
on drop, including cancellation and error paths. There is no separate work
queue, distributed coordination, persistence, fairness protocol, or retry.
Capacity is independent of inbound admission: admission is taken at the
transport boundary for every synchronization request, while capacity is acquired
later and only for selected-target work.

### Authentication, health, and readiness

The executable converts the authentication section into
`TechnicalCallerAuthenticatorConfig` and constructs
`TechnicalCallerAuthenticator` with its existing constructors. Invalid issuer,
audience, source, algorithm allowlist, cache policy, clock skew, timeout, TLS,
or trust-anchor configuration fails startup. Construction performs no mandatory
remote connectivity check.

Valid configuration with unreachable JWKS or discovery does not fail startup.
The process binds and serves with readiness false. A bounded, non-gating
verifier warm-up may begin only after the listener is serving, and readiness
evaluation may initiate at most one bounded refresh when no usable state
exists. Both use the authenticator's existing trusted source, cache policy, and
failure rules; there is no second verifier and no change to token inputs,
authentication outcomes, or failure mapping.

The executable exposes these paths on the same listener:

- `GET /healthz` returns `200` while the process and HTTP runtime are functioning.
- `GET /readyz` returns `200` only while the authenticator has usable trusted
  verification state under ADR-0002; otherwise it returns `503`.
- `GET /metrics` exposes Prometheus text-format metrics.

Readiness means that PermissionSync can currently verify technical callers
safely. It does not require current Keycloak connectivity when still-usable
cached state exists. It never depends on Provider, GLPI, target, or other
downstream reachability. These endpoints expose no secrets, URLs, targets,
credentials, trust material, JWT details, or internal errors. There is no
general status or configuration endpoint. Requests that select no configured
target retain their existing behavior and do not depend on Provider or GLPI
availability.

### Startup and shutdown

Startup proceeds in this order:

1. Resolve and read the single configuration file.
2. Parse it and validate required global and static values.
3. Construct the technical-caller authenticator.
4. Project semantic configuration and compose the Provider and targets.
5. Construct the inbound admission limit and semaphore-backed capacity.
6. Wire orchestration, inbound handling, and the Axum transport adapter.
7. Bind the configured listener.
8. Begin serving and allow bounded verifier warm-up.

Startup aborts for an unreadable or syntactically malformed required
configuration file, invalid global authentication configuration, invalid
listener or runtime values, globally invalid target composition, impossible
admission, capacity, or deadline configuration, or listener bind failure.

Startup does not abort because the Provider is absent or invalid where existing
ADRs make it selected-target unavailable, a target-local Adapter cannot be
constructed, JWKS or discovery is unreachable, or the Provider or GLPI endpoint
is unreachable. Composition performs no mandatory downstream connectivity
probe.

On Linux, the executable handles `SIGTERM` and `SIGINT`. It first marks
readiness false and stops accepting new requests. Existing bounded requests may
finish during the configured grace period. The grace period must be positive
and at least the overall request deadline, so every compliant request accepted
before shutdown has time to return. At grace expiry, remaining request contexts
are cancelled, their tasks are terminated and awaited, and connections are
closed. Reconciliation is never detached or continued after process exit. No
lifecycle framework is introduced.

### Observability

Structured logging uses `tracing` with `tracing-subscriber` JSON output.
Ordinary events go to standard output; startup and fatal failures may go to
standard error. Runtime configuration selects a bounded log-level threshold,
while JSON format and redaction rules are fixed.

Metrics use the `metrics` facade with `metrics-exporter-prometheus` and are
exposed at `/metrics`. The bounded categories and prohibited dimensions in
ADR-0006 remain authoritative. Distributed tracing is optional and is not
required for this executable.

### Non-goals

This decision does not design Helm charts, Kubernetes manifests or APIs, secret
operators, Vault, service discovery, dynamic adapters or plugins, distributed
capacity, persistent queues, retries, databases, registry strategy beyond
ADR-0006, OCI image construction details, or CI/CD pipelines.

## Alternatives considered

- **Layered file, environment, and command-line overrides:** rejected because
  precedence and partial overrides make sensitive configuration harder to
  reason about. One external JSON document provides one inspectable input.

- **A hand-written Hyper server:** rejected because it would recreate routing,
  extraction, body-limit, graceful-shutdown, and test-support facilities that
  Axum already provides over the Hyper and Tokio ecosystem.

- **Distributed capacity or a persistent queue:** rejected because v1 is
  stateless and single-attempt. A local semaphore directly implements the
  existing capacity port without adding coordination or delivery semantics.

- **Readiness based on Provider, GLPI, or target reachability:** rejected because
  transient downstream outages must not remove otherwise functioning replicas
  or cause restart loops. Readiness represents safe caller verification only.

- **Dynamic component discovery:** rejected because Provider and Adapter
  composition is explicit and adapters are statically linked. Discovery would
  add hidden configuration, lifecycle, and trust paths.

## Consequences

PermissionSync has one runtime delivery model and keeps deployment values,
secrets, and private trust outside the image. Invalid local global
configuration fails deterministically, while transient authentication metadata
or downstream outages do not create startup crash loops.

A fixed body limit, bounded inbound admission, one absolute deadline, and
bounded local concurrency protect the process from unbounded request work.
Readiness reports authentication safety rather than downstream health. Later
Kubernetes-focused packaging can supply the external file and probes without
coupling application semantics to Kubernetes APIs.

## References

- [ADR-0001](0001-inbound-synchronization-contract.md)
- [ADR-0002](0002-receiver-side-jwt-verification.md)
- [ADR-0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md)
- [ADR-0006](0006-runtime-configuration-oci-and-observability.md)
- [ADR-0007](0007-compile-time-rust-target-adapters.md)
- [ADR-0010](0010-runtime-target-configuration-and-composition-root.md)
- [ADR index](README.md)
