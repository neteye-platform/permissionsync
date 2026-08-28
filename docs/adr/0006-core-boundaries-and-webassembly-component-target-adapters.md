# Core Boundaries and WebAssembly Component Target Adapters

## Status

Accepted

## Context

PermissionSync synchronizes access with different target systems while
remaining a generic service. The core must not learn target authorization
semantics, API payload shapes or versions, target mappings, or
reconciliation logic.

The established boundary remains: the Permission Provider decides WHAT access
is desired, the Target Adapter decides HOW to apply it, and the core only
orchestrates their interaction. ADR 0005 defines the desired-permission model;
this ADR does not change that model.

Compile-time target crates couple target implementation changes to the
PermissionSync build and release lifecycle. They also limit compatible adapter
implementations to Rust. PermissionSync needs an adapter boundary that permits
an independently versioned target implementation without embedding it in the
core binary.

The WebAssembly Component Model defines language-interoperable components with
WIT worlds, imports, exports, canonical ABI interoperation, and semver-qualified
package identities. It does not itself define component distribution, semantic
compatibility, HTTP policy, resource limits, or timely interruption and
cancellation. Those properties need runtime design and evidence.

## Decision

PermissionSync remains a stateless, OCI-friendly orchestration service and is
the Component Model host. Custom and reusable Target Adapters are independently
versioned WebAssembly Components. They use a stable, versioned WIT contract so
the core, component, and target can evolve on separate lifecycles. Any language
or toolchain that can produce a compatible component may implement an adapter;
Rust is not required.

The core remains responsible only for orchestration. It authenticates and
authorizes the technical caller, strictly validates the request under ADR 0001,
resolves `client_id`, resolves generic target state, and admits bounded managed
work. It calls the Permission Provider once, structurally validates the ADR 0005
model, invokes one selected component reconciliation, and returns the HTTP
result.
It emits safe operational signals without interpreting target meaning.

The core must not know target authorization semantics, target API payloads or
versions, target mappings, or target-specific reconciliation logic. It must
not contain target-specific branches. Target-specific configuration is opaque
to the core where practical.

An adapter owns target-side desired-state reconciliation, including user
lookup, any allowed user creation, assignments and removals, managed
constraints, mappings, and target API communication. It validates target
semantics, including roles, groups, entitlements, scopes, propagation,
constraints, constraint values, and their supported combinations before
mutation. Unsupported semantics fail synchronization;
they are never silently ignored, weakened, rewritten, or defaulted.

The WIT contract carries ADR 0005's versioned desired-permission model
without changing its semantics; ADR 0005 owns that model's definition. The
core performs structural validation of the whole canonical model before
component invocation. The component performs target-semantic validation of
the whole canonical model before mutation. Exact WIT packages, worlds,
functions, types, and errors remain deferred.

Desired state is distinct from adapter runtime context. Desired state contains
no target endpoint, target-specific configuration, credentials or secrets,
TLS or trust material, target API version configuration, adapter runtime
options, deadline context, logging configuration, or diagnostics.
Document-level constraints are desired authorization state, not deployment
configuration. Deployment configures PermissionSync itself, not arbitrary
host-process access for each component: the PermissionSync host consumes
deployment configuration from whatever mechanisms a deployment chooses, such
as environment variables, configuration files, mounted secrets,
secret-management integrations, or deployment tooling, and constructs a
least-privilege runtime context for the selected adapter. A component never
implicitly inherits the PermissionSync process environment, all environment
variables, the host filesystem, mounted secrets, or all target credentials or
configuration merely because it executes inside PermissionSync. The selected
component receives only the configuration, secrets, and capabilities
explicitly projected for its selected target. The exact WIT or WASI APIs used
to provide them remain deferred; `config.get`-style or `secrets.get`-style
names in this ADR are conceptual examples only.

Integration preference is target-native integration first, then a reusable
standard integration where appropriate, then a PermissionSync adapter only when
those options are insufficient. Product-specific adapters are not required. A
future standards integration, such as SCIM, uses this same adapter boundary, but
SCIM is not required or selected by this ADR.

Whenever PermissionSync performs reconciliation through a reusable
standards-based or target-specific adapter, this Component Model and WIT
mechanism applies. Target-native integration need not imply a PermissionSync
adapter.

Rust `.so` or ABI plugins, compile-time target crates, target implementations
linked into PermissionSync, rebuild or release coupling, and target-specific
core branches are rejected.

### Routing and Invocation

`client_id` resolves target routing. An unconfigured `client_id` and an
explicitly unmanaged target return `200` as no-ops, with no provider or
component call. A selected managed component that is unavailable, disabled,
incompatible, or misconfigured returns `500`, with no provider or component
call when the condition is detectable before admission. Unrelated targets remain
serviceable. Global ambiguous routing remains governed by ADR 0007.

Selected target-local component or configuration failures may leave the service
ready. They do not disable unrelated valid managed, unmanaged, or unconfigured
no-op routes.

For valid managed work, the core acquires bounded runtime capacity before
provider or component work. It calls the provider once and the selected
component reconciliation once, with no automatic retry. One component
invocation may make multiple target API calls. Provider or component failure is
`500`; it does not become an empty desired state or successful no-op.

The ADR 0007 overall deadline and remaining budget govern component execution
and component-mediated target operations. Cancellation is best effort. Expiry
returns `500`, starts no new work, and makes already-issued effects uncertain;
there is no rollback claim. The runtime must make non-cooperative or blocked
component execution interruptible for the deadline. Its exact mechanism is
deferred to the proof of concept and runtime specification.

An adapter may mutate or reconcile only within its explicitly configured managed
boundary. An absent boundary or empty desired state is not authority outside the
managed space. PermissionSync stays stateless: it has no shared replay,
idempotency, or adapter lifecycle state.

### Capabilities and Containment

Components receive explicit, least-privilege capabilities only. There is no
implicit or unrestricted filesystem, environment, process, network, arbitrary
host-resource, or access to all PermissionSync secrets. The host grants only
the selected adapter's stated requirements.
Examples include restricted outbound HTTP, selected target configuration and
credentials, time or remaining-deadline awareness, and controlled diagnostics;
none is automatic or unrestricted.

Target business configuration may remain opaque to the core where practical,
but information the host requires to enforce security policy cannot be
completely opaque. To enforce an adapter's outbound communication policy, the
host must know or derive the permitted destination or origin for the selected
target and its applicable TLS or trust posture. The host still does not
interpret target roles, permissions, API payload semantics, or business
mappings.

Outbound HTTP is host-controlled or practically restricted to configured target
destinations. Components do not require unrestricted egress: an adapter that
may access its configured target may not access arbitrary unrelated
destinations, and another adapter's permitted destinations grant it nothing.
Component resources
and containment are bounded, but this ADR does not select the sandbox, limit,
interruption, or HTTP mediation mechanism. WIT alone does not guarantee these
properties.

## Feasibility Acceptance Criteria

This ADR remains Proposed unless every gate passes and the recorded evidence is
reviewable. Any failed gate keeps the ADR Proposed.

1. **Independent lifecycle.** PASS: at least two independently built and
   versioned compatible component artifacts can be selected and replaced without
   rebuilding, relinking, or releasing the core. FAIL: replacing a component
   with another host-compatible version requires a core build, link, or release.
2. **Admission compatibility.** PASS: incompatible WIT or a missing required
   import or export is rejected during admission before provider resolution,
   reconciliation invocation, or target mutation. FAIL: any of those starts
   before rejection.
3. **Language independence.** PASS: two guest toolchains, including one
   non-Rust toolchain, produce components for the unchanged host contract.
   FAIL: either requires a changed host contract or only Rust works.
4. **Model fidelity.** PASS: role, group, and entitlement assignments;
   unscoped assignments; scopes with `self` and with `descendants`
   propagation; multiple assignments; repeated assignments across scopes; and
   document-level constraints, including a constraint type carrying multiple
   values, are transported intact. The core rejects unsupported model versions
   or kinds, partial scopes, unsupported propagation, malformed or duplicated
   constraint types, and other structural invalidity before invocation. The
   component rejects unknown or unsupported roles, groups, entitlements,
   scope types or IDs, `descendants` propagation, constraint types, individual
   constraint values, and unsupported assignment or constraint combinations
   before mutation. No value is silently dropped, rewritten, weakened, or
   defaulted; a fake or test adapter is sufficient evidence. FAIL: any value
   changes or disappears, or invalidity reaches the wrong stage.
5. **Context isolation.** PASS: desired state contains no deployment
   configuration or secrets; required configuration and at least one secret
   belonging to the selected target can be explicitly provided to the
   selected component; unrelated target configuration and secrets are
   unavailable; and secrets are absent from logs. FAIL: any forbidden value
   is present, reachable, or logged.
6. **Default-deny capabilities.** PASS: ungranted filesystem, environment,
   process, and host resources are denied; allowed HTTPS communication to a
   configured mock target succeeds using explicitly supplied trust or
   configuration; an unrelated destination is denied; and unrestricted egress
   is not granted. FAIL: any ungranted access works, or a disallowed
   destination succeeds.
7. **Bounded resources.** PASS: deliberate memory, table, instance, handle, or
   equivalent exhaustion is denied or trapped before host exhaustion. FAIL: it
   exhausts host resources or escapes the configured bound.
8. **Deadline and cancellation.** PASS: a CPU-bound component and stalled
   outbound operation are interrupted or bounded by the remaining deadline,
   return `500`, and start no new work. Effects already issued remain uncertain
   and no rollback is claimed. FAIL: either case exceeds the deadline or starts
   new work after expiry.
9. **Invocation accounting.** PASS: instrumentation proves one provider call,
   one component reconciliation call, and no automatic retry; multiple internal
   target calls remain allowed. FAIL: an extra provider or component call, or an
   automatic retry, occurs.
10. **Routing isolation.** PASS: unconfigured and unmanaged routes return
    `200` with zero provider or component reconciliation calls; a selected
    missing, disabled, or incompatible component returns `500`; another valid
    target succeeds. FAIL: a no-op invokes work, or one target failure prevents
    the valid target from succeeding.
11. **Managed authority and statelessness.** PASS: only managed assignment
    and managed constraint state mutate; unmanaged target state remains
    untouched; and a restart requires no shared replay, idempotency, or
    adapter lifecycle state. FAIL: unmanaged assignment or constraint state
    changes, or shared persistence is required for correctness.

## Validation

All eleven feasibility gates above pass with executable, reviewable evidence.
An executable suite (`tests/architecture/adr-0006-wasm/`) runs a Wasmtime 48
host carriage of guest-agnostic Target Adapters across two independent guest
toolchains (Rust and TinyGo) and machine-checks every gate against the real host
stdout/stderr and the fake servers' observable state.

The recorded evidence is at
[`evidence/0006-wasm-feasibility.md`](evidence/0006-wasm-feasibility.md). It is
historical architecture evidence: the host runtime, WIT contract, and adapter
implementations there are feasibility stand-ins and do not constrain the
production implementation. The deferred decisions remain open.

## Consequences

Adapters can be built, tested, versioned, distributed, and replaced separately
from PermissionSync. Compatible implementations can come from multiple language
toolchains, while the core keeps its generic orchestration boundary.

The approach adds runtime, contract, sandbox, compatibility, operational, and
testing complexity. The feasibility gates establish that at least one viable
host runtime (Wasmtime, here) can uphold the stated boundaries, and the ADR is
accepted on that basis; it still does not select the production runtime engine.

## Deferred Decisions

This ADR defers:

- exact WIT packages, worlds, functions, types, and errors;
- runtime or engine choice;
- WASI and HTTP mediation;
- sandbox, resource-limit, and interruption mechanisms;
- configuration and secret APIs;
- component discovery, distribution, signing, trust, update, rollback,
  hot-reload, caching, and instantiation;
- compatibility and version-negotiation mechanics;
- observability details;
- repository organization, including one repository per adapter or a shared
  repository;
- concrete adapter implementations; and
- any SCIM decision.

## References

- [ADR 0001](0001-inbound-synchronization-contract.md)
- [ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md)
- [ADR 0004](0004-generic-rest-permission-provider.md)
- [ADR 0005](0005-bounded-desired-permission-model.md)
- [ADR 0007](0007-runtime-configuration-oci-and-observability.md)
- [ADR index](README.md)
- [WebAssembly Component Model](https://component-model.bytecodealliance.org/)
- [WebAssembly Interface Types][wit]

[wit]: https://component-model.bytecodealliance.org/design/wit.html
