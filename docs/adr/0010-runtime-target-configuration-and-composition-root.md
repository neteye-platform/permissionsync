# ADR-0010: Runtime Target Configuration and Composition Root

- **Status:** Accepted
- **Date:** 2026-09-25
- **Deciders:** R&D Team

## Context

The accepted inbound, Provider, adapter, and GLPI contracts define selected-target
work, but leave deterministic application composition open. The application must
distinguish an unknown logical target from a configured route whose adapter cannot
be constructed, without selecting a deployment or configuration-delivery model.

This record owns semantic runtime target and Provider configuration and the
composition root. It selects no serialization format, parser, configuration
library, or delivery mechanism, including environment, files, CLI arguments,
Kubernetes objects, Vault, or another external source.

## Decision

### Provider and target configuration

V1 configures one Permission Provider instance for the process, not one Provider
per logical target. The supported v1 Provider is the Generic REST Permission
Provider; configuration selects and configures that supported model. Its
construction values include a complete HTTPS endpoint, bounded timeout, private
trust anchors where required, and its applicable Provider-specific values. The
raw inbound bearer JWT remains request-scoped, not configuration. The Provider
continues to decide what desired permissions to return for the target it derives
from that JWT.

A logical target is exactly the suffix selected by the existing
`permissionsync:<target>` scope-token grammar in
[ADR 0001](0001-inbound-synchronization-contract.md). It is case-sensitive and
exact; composition does not normalize or alias it. An adapter identifier is also
an opaque exact value: it has no generic grammar, normalization, case folding, or
aliases. It need not have a successful registration to appear in a route; lookup
decides whether it is available. `glpi` is the stable GLPI adapter identifier.

The root receives typed construction inputs and supplies them when constructing
a Provider or adapter. Secrets and trust material are never logical targets or
adapter identifiers, and never appear in diagnostics, desired state, URLs, logs,
or metrics. This record selects no secret or trust-material delivery mechanism.

### Compiled adapters, registrations, and routes

The binary has a compiled adapter set. `TargetRoute` is independently configured
as an exact logical target to adapter identifier mapping. Separately, a compiled
adapter implementation, plus any configuration required by its contract, is
constructed into a usable adapter instance and `AdapterRegistration`. A route
points to an identifier, not an existing registration. If construction fails, the
route remains with no usable registration, so selection returns `500` rather than
unknown-target `400`.

The root reuses these routing concepts; it introduces no new registry framework.
With unambiguous configuration, each compiled adapter identifier has zero or one
usable registration, and only successfully configured instances are registered.
Duplicate adapter configuration or registration definitions for the same
identifier are invalid static configuration and fail startup, regardless of
construction success. No usable registration for a route's identifier does not
erase that route.

An invalid configured logical target that violates the ADR 0001 grammar or a
duplicate logical route is invalid or ambiguous static configuration and fails
startup; neither is ignored. At request time, an unknown logical target returns
`400`. A recognized route with an unavailable selected adapter registration or
invalid selected-adapter configuration returns target-local `500`; valid routes
selecting other valid registrations remain serviceable.

The adapter set is compiled into the product. Composition has no plugins, dynamic
loading, discovery, downloads, sidecars, independent adapter-version selection,
runtime feature selection, or deployment feature matrix.

### GLPI registration

ADR 0009 requires one `glpi` adapter instance and one GLPI backend per
PermissionSync process. The root configures that one instance from its HTTPS
`apirest.php` endpoint, application token, service-account User Token, bounded
timeout, private trust anchors where required, and independently optional
`authtype` and `auths_id` user-provisioning fields.

Multiple logical targets may route to `glpi`, but all use that same instance and
backend. There are no independently configured per-route GLPI instances or
values. A failed `glpi` registration leaves every route selecting `glpi`
recognized but unavailable: it returns target-local `500` when selected, while
routes selecting other valid registrations remain serviceable. This GLPI decision
does not choose instance models for future adapters. Composition does not pass a
logical target in an adapter request or put registration values in Provider
requests or desired-state payloads.

### Composition, ordering, and failures

The root binary/application owns construction and wiring. It may depend on Core
and supported concrete adapter crates; Core depends on no concrete adapter; and
adapters use only Core's public contract, not Core internals or other adapters.
These dependencies remain acyclic. Composition is deterministic from the compiled
adapter set and explicit runtime configuration. Components do not independently
discover hidden PermissionSync application configuration or use global
registration side effects. This does not alter normal platform DNS resolution or
system trust facilities used by explicit HTTPS/TLS client configuration.

After authentication, scope processing, and strict body validation, a valid
zero-target request returns `204` before routing, capacity, Provider, adapter, or
target configuration work. This is true with zero routes and with unavailable
Provider or adapter configuration.

For one grammar-valid selected target, route resolution precedes capacity and
Provider work. An unavailable selected adapter registration/configuration returns
`500` before capacity, Provider, or adapter work. Invalid or unavailable Provider
construction/configuration likewise does not prevent a valid targetless `204`,
but selected-target synchronization returns `500` before Provider work. The
Provider's availability is considered only after route resolution, so it cannot
hide ADR 0001's unknown-target `400` precedence. The current synchronizer uses a
concrete Provider; later composition must preserve this unavailable-Provider
behavior. This ADR does not prescribe its exact Rust representation. A
runtime Provider failure after invocation remains an explicit selected-target
server-side failure and never becomes empty desired state or success.

### Deferred details and follow-up

This ADR does not reopen or select formats, loaders, Kubernetes, Helm, OCI,
listener configuration, capacity limits, deadline values, shutdown, connection
pools, health paths, an observability library, metric names, telemetry, tracing,
or signals. Those categories remain governed by existing decisions or need their
own decision; this record makes no deployment-specific configuration model.

Later implementation can add typed configuration and a composition root; delivery
formats and platform integration remain separate.

## Alternatives considered

- **Dynamic plugins or runtime adapter discovery:** rejected because they add
  loading, trust, lifecycle, and version-selection mechanisms outside the
  compiled adapter model.
- **A GLPI instance per logical target:** rejected because ADR 0009 defines one
  `glpi` instance and backend per process.
- **Globally failing startup for every unavailable registration:** rejected
  because routes must retain recognized target-local `500` behavior while valid
  registrations remain serviceable.
- **A deployment-specific configuration model:** rejected to keep semantic
  configuration independent of formats, loaders, platforms, and secret delivery.
- **A new registry framework:** rejected because the existing routing concepts
  provide the required deterministic composition.

## Consequences

Composition has a clear distinction: invalid or ambiguous static configuration
fails startup; an unknown request target returns `400`; and a recognized route
without a usable selected adapter returns `500`. The process can still handle
valid targetless requests despite unavailable downstream configuration. GLPI
routes share one configured backend without leaking routing or construction values
into Provider payloads or adapter requests.

## References

- [ADR 0001](0001-inbound-synchronization-contract.md)
- [ADR 0004](0004-generic-rest-permission-provider.md)
- [ADR 0006](0006-runtime-configuration-oci-and-observability.md)
- [ADR 0007](0007-compile-time-rust-target-adapters.md)
- [ADR 0008](0008-generic-rest-permission-provider-wire-and-transport-contract.md)
- [ADR 0009](0009-glpi-target-adapter.md)
- [ADR index](README.md)
