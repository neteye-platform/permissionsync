# Core Boundaries and Compile-Time Rust Target Adapters

## Status

Accepted

This ADR supersedes ADR 0006 and ADR 0008.

## Context

PermissionSync must reconcile users with different target systems without
putting target authorization semantics, API payloads, mappings, or
reconciliation logic in generic Core. The boundary is:

```text
Identity Context -> Permission Provider -> DesiredPermissionState
                -> Core-owned TargetAdapter contract
                -> linked concrete adapter crate -> target application
```

The **Permission Provider** owns **WHAT** access the user should have. It
resolves its source authorization model and produces the desired state. The
**Target Adapter** owns **HOW** that state is validated and reconciled against
the target, including target lookup, permitted user creation, assignments,
managed constraint application and removal, mappings, and target API calls.
**Core** owns orchestration: caller authentication and authorization, strict
request validation, target routing, capacity and deadline handling, structural
model validation, one provider invocation, one adapter invocation, and the HTTP
outcome. Core does not interpret target semantics.

The desired state remains the bounded, versioned model from ADR 0005: desired
assignments and document-level constraints with opaque provider-defined values
and target-defined semantic interpretation. Desired permissions are
authoritative only inside explicitly managed assignment and constraint
boundaries; absent desired state does not authorize changes to unmanaged state.
Desired state contains no endpoint, credentials, trust material, deployment
configuration, adapter options, deadlines, or logging configuration. Core
performs structural validation of the complete model before target work. The
adapter performs complete target-semantic validation before mutation and owns
the target mappings and combinations. Unsupported or invalid target semantics
must fail rather than being silently dropped, rewritten, weakened, or
defaulted.

## Decision

### Compile-time crate boundary

Core owns the public `TargetAdapter` trait and its contract, together with
public domain types for identity context and desired permission state. The
names `TargetAdapter`, `DesiredPermissions`, and `DesiredPermissionState` are
conceptual; their exact Rust names, trait signature, error and result types,
versioning details, and workspace paths are deferred. Runtime target context
is a contract-provided runtime value, not necessarily a pure domain type. The
contract must provide the selected adapter with only its selected,
least-privilege target context and credentials, desired state,
deadline/cancellation context, and no secrets in the desired state.

Each concrete adapter is a distinct Rust crate. Adapter crates are statically
linked into one generic PermissionSync binary and its OCI image. Core depends
on no concrete adapter crate. An adapter crate's dependency on Core is limited
to Core's public contract and public types; it may also use its own
third-party dependencies, but not Core internals or other adapter crates. The
composition root depends on Core and the supported adapter crates in a product
release and deterministically maps each logical adapter ID to its compiled-in
implementation. There is one generic product image containing all supported
adapters; deployment does not require a cargo-feature deployment matrix. The
product image identity includes the complete linked adapter set.

Runtime configuration selects only among those compiled-in adapters. A
configuration cannot download, install, load, or select an implementation
that is absent from the binary. There is no dynamic loading, WebAssembly,
WIT, `.so`, sidecar, microservice, adapter OCI artifact, loader, independent
adapter-artifact digest or version selection, hot load, or independent
adapter release mechanism. This does not reject product OCI image digests;
the product image, including its complete linked adapter set, may be
identified and deployed by its normal image identity.

Target-native integration is preferred first, then a reusable standard
integration where appropriate, then a PermissionSync adapter only when those
options are insufficient. This ADR does not select SCIM.

### Request order, routing, and invocation

For every request, the complete order is:

1. Authenticate the technical caller under ADR 0002.
2. Authorize the technical caller under ADR 0002.
3. Strictly validate the request.
4. Route the target from the request.
5. If the target is unconfigured or explicitly unmanaged, immediately return
   `200` as a no-op, with no capacity, provider, or adapter work.
6. If a configured managed target names an adapter key absent from the
   compiled-in registry and that error is detectable, return target-local
   `500` without capacity, provider, or adapter work. Unrelated routes remain
   serviceable.
7. Obtain bounded capacity.
8. Invoke the Permission Provider once.
9. Structurally validate the resulting DesiredPermissions.
10. Invoke the selected Target Adapter reconciliation once.
11. Return the resulting HTTP outcome.

Globally ambiguous or structurally unusable routing remains a global startup or
readiness error under ADR 0007. A target-local managed configuration error may
be detected eagerly where practical without making unrelated routes
unavailable.

Adapter reconciliation owns target lookup, permitted user creation, assignment
and managed-constraint application and removal, target mappings, target API
calls, and target-semantic validation of the complete desired state before
mutation. Where the target contract makes it meaningful, an adapter may report
resource creation information relevant to ADR 0001's `201` response behavior;
no adapter is required to do so. There is no automatic retry or rollback. One
reconciliation may make multiple target calls.

The overall deadline and cancellation propagate through provider and adapter
work. Core starts no new work after it observes expiry. A compliant adapter
uses bounded operations, propagates and checks cancellation, and must not
start detached or background reconciliation. Cancellation is best effort:
non-cooperative or defective in-process code may continue or block despite
Core's observation, and its effects may be uncertain.

The failure model has three stages:

- Build compilation and compile-time and unit/integration tests enforce trait
  compatibility and catch defects exercised by those tests; they cannot catch
  every adapter defect.
- Startup or readiness rejects global invalid configuration. A target-local
  invalid managed adapter selection or target configuration may instead leave
  the service ready while that target returns `500`.
- Returned or recoverable provider and adapter failures during a request return
  `500`; they never become an empty desired state or a successful no-op. A
  panic, abort, out-of-memory condition, unsafe defect, or non-cooperative
  blocking may affect, stall, or terminate the whole replica and is not
  target-local isolation.

### Deployment, restart, and upgrades

The image already contains every supported adapter. ADR 0007 owns
whole-product-image availability. Because all adapter code is linked into that
image, satisfying ADR 0007 also makes adapter code available. No extra adapter
artifact, registry, loader, or download path exists.

Upgrades and rollbacks are whole-product-image operations. There is no
adapter-specific rollback and no runtime adapter-version selection. During a
rolling rollout, old and new replicas may run different image versions; each
replica deterministically uses the adapters linked into its own image. An
operator or deployment system may explicitly roll back the whole product
image, but PermissionSync does not choose or remember a prior adapter version.
There is no lifecycle manager, and no shared adapter lifecycle, version, or
replay state is required for routing or correctness. Core remains stateless.

### Security boundary

Concrete adapter crates are trusted in-process code. They have the authority
of the PermissionSync process, so this design does **not** provide the
security properties previously sought from a WebAssembly sandbox. In
particular, it loses WebAssembly isolation, WIT admission, capability
linking, default runtime denial of filesystem/environment/process access,
host-enforced egress, and independent memory isolation. No sandbox or
capability-isolation claim may be inferred from the Rust trait boundary or
static linking.

Core passes only the selected target context and credentials through the public
contract, but that is code-level discipline, not a confidentiality or
security boundary: linked code has process authority. The process and
deployment must still enforce least privilege operationally. Downstream
credentials use least privilege, TLS verification is required, and trust
material is supplied externally as deployment policy requires.
`DesiredPermissionState` contains no secrets. Logs and diagnostics must not
contain credentials, tokens, private keys, raw request bodies, or sensitive
desired-permission data.

Trust therefore shifts to the product build and release pipeline. Adapter
source and dependencies use the same review, provenance, vulnerability,
build, and release controls as Core. The exact controls are deferred; static
selection alone does not prove that adapter code was reviewed or is safe.

## Consequences

Core remains generic and has a small, explicit Rust contract. Adapters can be
implemented and tested independently at the crate level, while composition
and the set of supported targets are deterministic at build time. Runtime
selection cannot introduce code absent from the product build, but static
selection does not itself establish that the code was reviewed or is safe.

The trade-off is deliberate coupling of adapter source, compilation, and
release to the product image. Every supported adapter is present in every
image, and an adapter change requires a full image rollout. In return, the
system avoids the operational and compatibility complexity of a component
runtime, dynamic ABI, loader, or separate service.

The technically feasible Wasm approach from ADR 0006 could have supplied
isolation and independent artifacts, but its runtime, WIT, admission,
capability, distribution, and lifecycle machinery is no longer justified by
the product's simplicity and trust model. Native dynamic libraries would add
ABI and loading complexity with weak isolation. Microservices would add
network, deployment, availability, and latency overhead. Putting target logic
in Core would destroy genericity and make every target change a Core change.

The lost sandbox properties are a material security cost, not an accidental
omission. Adapter code must therefore be reviewed and trusted as product
code, and process/deployment privileges must be constrained outside this
in-process boundary.

## Alternatives

- **Compile-time Rust crates (chosen):** statically linked, deterministic,
  simple, and strongly typed, at the cost of full-image coupling and trusted
  in-process code.
- **WebAssembly components (prior ADR 0006):** technically feasible and
  capable of language independence and stronger isolation, but no longer
  justified by the added runtime, WIT, capability, admission, and artifact
  lifecycle complexity.
- **Native dynamic libraries:** independently replaceable, but require an ABI,
  loader, compatibility policy, and trust machinery while providing weak
  isolation.
- **Microservices:** provide process isolation and independent deployment, but
  impose service discovery or routing, network failure modes, operational
  overhead, and additional latency.
- **Target logic in Core:** avoids an adapter boundary, but destroys Core's
  genericity and couples the central service to every target's semantics.

## Testing Expectations

Testing must verify, without requiring a proof of concept, that:

- Core builds without depending on any concrete adapter, adapter crates use
  only the public Core contract/types for their Core dependency, and the
  composition root links every declared supported adapter exactly once and
  maps logical IDs deterministically.
- The complete desired-permission model, structural validation, target-semantic
  validation-before-mutation, managed boundaries, and absence of secret or
  sensitive logging are covered.
- Unconfigured and unmanaged requests return `200` with zero provider/adapter
  calls; a configured adapter key absent from the compiled-in registry returns
  target-local `500`; global routing ambiguity fails startup/readiness;
  unrelated routes remain serviceable.
- Managed requests make at most one provider and one adapter reconciliation
  call, do not retry or roll back automatically, propagate deadlines and
  cancellation, and return `500` for returned/recoverable provider, adapter,
  or expiry failures. Tests cover the prohibition on detached/background
  reconciliation and the possibility that non-cooperative defects affect the
  whole replica.
- A built image contains all supported adapters, so satisfying ADR 0007's
  image-availability requirement needs no additional adapter artifact,
  registry, loader, or download dependency. Rolling image revisions can operate
  with old and new replicas. No test should imply dynamic loading, Wasm
  isolation, WIT admission, capability linking, host-enforced egress, or
  independent memory isolation for these in-process crates.

## Deferred Decisions

This ADR defers the exact workspace paths; crate names and repository layout;
the exact `TargetAdapter` trait signature, associated types, errors, and
versioning; the precise composition-root registration API; runtime
configuration schema and logical adapter-ID grammar; target context and
credential projection details; and concrete target API contracts. It also
defers implementation-level capacity, timeout, observability, trust-material
and secret-delivery mechanisms. None of these deferrals permits a dynamic
adapter mechanism or changes the static-linking and security boundary chosen
here.

## References

- [ADR 0001](0001-inbound-synchronization-contract.md)
- [ADR 0002](0002-receiver-side-jwt-verification.md)
- [ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md)
- [ADR 0004](0004-generic-rest-permission-provider.md)
- [ADR 0005](0005-bounded-desired-permission-model.md)
- [ADR 0007](0007-runtime-configuration-oci-and-observability.md)
- [ADR 0006 (historical)](0006-core-boundaries-and-webassembly-component-target-adapters.md)
- [ADR 0008 (historical)](0008-target-adapter-packaging-distribution-and-lifecycle.md)
- [ADR index](README.md)
