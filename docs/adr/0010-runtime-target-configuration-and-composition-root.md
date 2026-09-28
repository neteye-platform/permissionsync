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
aliases. `glpi` is the stable GLPI adapter identifier.

The root receives typed construction inputs and supplies them when constructing
a Provider or adapter. Secrets and trust material are never logical targets or
adapter identifiers, and never appear in diagnostics, desired state, URLs, logs,
or metrics. This record selects no secret or trust-material delivery mechanism.

### Compiled implementations and configured targets

The binary contains a compiled adapter implementation registry: an exact adapter
identifier maps to one statically linked implementation. Separately, configured
targets map each exact logical target to an adapter identifier and the target
configuration required by that adapter's contract. Composition turns each
configured target into either a usable configured instance or a target-local
unavailable state. Thus, a route remains recognized when its compiled
implementation is absent or its configuration or instance cannot be constructed;
it returns `500`, not unknown-target `400`.

Adapter contracts, not this ADR, choose configuration cardinality, instance
cardinality, and sharing. For example, `target-a` may select `adapter-x` with
configuration A and `target-b` may select `adapter-x` with configuration B when
that adapter permits it. Different configurations for one adapter identifier are
not generically invalid, and this ADR does not impose one runtime adapter
instance per adapter identifier.

Startup fails for a duplicate logical target, a configured logical target invalid
under the ADR 0001 routing grammar, duplicate compiled implementation
registrations for one adapter identifier, or globally ambiguous or structurally
unusable composition. These failures are neither ignored nor converted into
target-local states. Other errors isolated to a recognized target, including a
missing compiled implementation or failed target configuration/instance
construction, remain target-local. At request time, an unknown logical target
returns `400`; a recognized unavailable target returns `500`; and unrelated
usable targets remain serviceable.

The registry and route terms state semantics, not a required current
`AdapterIdentifier -> AdapterRegistration` API. Later implementation may evolve
the routing or registration representation if needed while preserving exact,
deterministic routing and these outcomes. The adapter set is static: there are no
plugins, dynamic loading, discovery, downloads, sidecars, independent adapter
version selection, runtime feature selection, or deployment feature matrix.

### GLPI registration

ADR 0009 requires exactly one configured GLPI backend and one registered `glpi`
adapter instance per PermissionSync process. Multiple logical targets may select
`glpi` and share it. There is no independent per-target GLPI endpoint,
credentials, trust, or authentication-source configuration. The one-instance rule
is specific to the GLPI adapter and does not choose another adapter's model.

GLPI authentication-source provisioning configuration may be absent when relying
on applicable GLPI defaults. When an explicit source is configured, `authtype`
and `auths_id` form one coherent selection under the GLPI adapter contract.
Failed GLPI construction leaves every target selecting `glpi` recognized but
unavailable and therefore target-local `500`; usable targets remain serviceable.
Composition does not pass logical-target configuration in an adapter request or
put adapter construction values in Provider requests or desired-state payloads.

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
targetless request returns `204` before routing, capacity, Provider, adapter, or
target configuration work. It requires neither Provider nor target configuration,
including when either is unavailable.

For one grammar-valid selected target, route resolution precedes capacity and
Provider availability. An unknown target therefore returns `400` even when the
Provider is unavailable. A recognized unavailable target returns `500` before
capacity, Provider, or adapter work. Unavailable Provider construction or
configuration does not prevent a targetless `204`, but selected-target
synchronization returns `500` before Provider work. A runtime Provider failure
after invocation remains a selected-target server-side failure, never empty
desired state or success. This ADR does not prescribe the Provider's exact Rust
representation.

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
- **Globally failing startup for every unavailable target:** rejected
  because routes must retain recognized target-local `500` behavior while valid
  targets remain serviceable.
- **A deployment-specific configuration model:** rejected to keep semantic
  configuration independent of formats, loaders, platforms, and secret delivery.
- **A new registry framework:** rejected because the existing routing concepts
  provide the required deterministic composition.

## Consequences

Composition has a clear distinction: invalid or ambiguous static configuration
fails startup; an unknown request target returns `400`; and a recognized route
without a usable selected target instance returns `500`. The process can still
handle valid targetless requests despite unavailable downstream configuration.
GLPI routes share one configured backend without leaking routing or construction
values into Provider payloads or adapter requests.

## References

- [ADR 0001](0001-inbound-synchronization-contract.md)
- [ADR 0004](0004-generic-rest-permission-provider.md)
- [ADR 0006](0006-runtime-configuration-oci-and-observability.md)
- [ADR 0007](0007-compile-time-rust-target-adapters.md)
- [ADR 0008](0008-generic-rest-permission-provider-wire-and-transport-contract.md)
- [ADR 0009](0009-glpi-target-adapter.md)
- [ADR index](README.md)
