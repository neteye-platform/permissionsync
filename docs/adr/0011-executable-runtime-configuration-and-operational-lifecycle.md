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
listen address and port, overall request deadline, synchronization capacity,
authentication, Provider, and GLPI operation timeouts, shutdown grace period,
and observability settings. After delivery-level validation, it constructs the
existing auth configuration and projects Provider, GLPI, and target values into
the existing semantic `RuntimeConfiguration`.

Malformed JSON, unreadable configuration, and invalid required global fields
fail startup. Provider and target-local sections are decoded independently
enough to preserve existing semantics: an absent or locally invalid Provider
remains unavailable for selected-target requests, and failed target-local
Adapter construction leaves recognized routes unavailable. Such local defects
do not become whole-document parse failures. Unknown fields are rejected so
misspelled global settings cannot be silently ignored.

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

### Request body and overall deadline

The executable enforces a fixed one-mebibyte product limit on the inbound
synchronization body. The limit belongs at the Axum transport boundary, before
the body is fully buffered or passed to `permissionsync-inbound-http`.
`Content-Length` may permit early rejection, but streamed bytes are counted as
they are collected, so a missing or misleading length cannot bypass the limit.
An oversized body returns `400`; there is no unbounded mode or deployment
tuning knob. This adds neither an endpoint nor a body format.

The executable starts one absolute deadline immediately when the request is
accepted, before body collection. Its duration is required runtime
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
5. Construct the semaphore-backed capacity implementation.
6. Wire orchestration, inbound handling, and the Axum transport adapter.
7. Bind the configured listener.
8. Begin serving and allow bounded verifier warm-up.

Startup aborts for an unreadable or syntactically malformed required
configuration file, invalid global authentication configuration, invalid
listener or runtime values, globally invalid target composition, impossible
capacity or deadline configuration, or listener bind failure.

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

A fixed body limit, one absolute deadline, and bounded local concurrency protect
the process from unbounded request work. Readiness reports authentication
safety rather than downstream health. Later Kubernetes-focused packaging can
supply the external file and probes without coupling application semantics to
Kubernetes APIs.

## References

- [ADR-0001](0001-inbound-synchronization-contract.md)
- [ADR-0002](0002-receiver-side-jwt-verification.md)
- [ADR-0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md)
- [ADR-0006](0006-runtime-configuration-oci-and-observability.md)
- [ADR-0007](0007-compile-time-rust-target-adapters.md)
- [ADR-0010](0010-runtime-target-configuration-and-composition-root.md)
- [ADR index](README.md)
