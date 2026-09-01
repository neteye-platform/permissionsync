# ADR-0007: Core Boundaries and Compile-Time Rust Target Adapters

- **Status:** Accepted
- **Date:** 2026-08-31
- **Deciders:** R&D Team

## Context

PermissionSync must reconcile users with different target systems without
putting target authorization semantics, API payloads, mappings, or
reconciliation logic in generic Core. The boundary is:

```text
Identity Context -> Permission Provider -> DesiredPermissionState
                -> Core-owned TargetAdapter contract
                -> linked concrete adapter crate -> target application
```

The Permission Provider owns **WHAT** access the user should have: it resolves
its source authorization model and produces desired state. The Target Adapter
owns **HOW** that state is validated and reconciled against the target,
including target lookup, permitted-user creation, assignments, managed
constraint application and removal, mappings, and target API calls. Core owns
orchestration: caller authentication and authorization, strict request
validation, target routing, capacity and deadline handling, structural model
validation, one provider invocation, one adapter invocation, and the HTTP
outcome. Core does not interpret target semantics.

The desired state is the bounded, versioned model from [ADR 0005](0005-bounded-desired-permission-model.md):
desired assignments and document-level constraints with opaque
provider-defined values and target-defined semantic interpretation. It is
authoritative only inside explicitly managed assignment and constraint
boundaries; absent desired state does not authorize changes to unmanaged state.
It contains no endpoint, credentials, trust material, deployment
configuration, adapter options, deadlines, or logging configuration. Core
validates the complete model structurally before target work; the adapter
performs complete target-semantic validation before mutation and owns target
mappings and combinations. Unsupported or invalid target semantics fail
rather than being silently dropped, rewritten, weakened, or defaulted.

## Decision

### Public boundary and compile-time composition

Core owns the public `TargetAdapter` trait and contract, with public domain
types for identity context and desired permission state. `TargetAdapter`,
`DesiredPermissions`, and `DesiredPermissionState` are conceptual names; exact
Rust names, trait signature, result and error types, versioning, and workspace
paths are deferred. Runtime target context is a contract-provided value, not
necessarily a pure domain type. The contract supplies only the selected
adapter's least-privilege target context and credentials, desired state,
deadline/cancellation context, and no secrets in desired state.

Each concrete adapter is a distinct Rust crate, statically linked into one
generic PermissionSync binary and OCI image. Core depends on no concrete
adapter crate. An adapter may depend on Core only through Core's public
contract and public types; it may use its own third-party dependencies, but
not Core internals or other adapter crates. The composition root depends on
Core and supported adapter crates and deterministically maps each logical
adapter ID to its compiled implementation. One generic product image
contains all supported adapters; deployment has no cargo-feature matrix, and
the image identity includes the complete linked adapter set.

Runtime configuration selects only a compiled-in adapter. It cannot download,
install, load, or select an implementation absent from the binary. There is no
dynamic loading, `.so`, sidecar, microservice, adapter OCI artifact, loader,
independent adapter-artifact digest or version selection, hot loading, or
independent adapter release mechanism. Product OCI image digests remain valid
for identifying the complete product image.

Target-native integration is preferred first, then a reusable standard
integration where appropriate, then a PermissionSync adapter only when those
options are insufficient. This ADR does not select SCIM.

### Request order and failure model

For every request, the complete order is:

1. Authenticate the technical caller under ADR 0002.
2. Authorize the technical caller under ADR 0002.
3. Strictly validate the request.
4. Route the target from the request.
5. If the target is unconfigured or explicitly unmanaged, immediately return
   `200` as a no-op, with no capacity, provider, or adapter work.
6. If a configured managed target names an adapter key absent from the
   compiled-in registry and that error is detectable, return target-local
   `500` with no capacity, provider, or adapter work; unrelated routes remain
   serviceable.
7. Obtain bounded capacity.
8. Invoke the Permission Provider once.
9. Structurally validate the resulting DesiredPermissions.
10. Invoke the selected Target Adapter reconciliation once.
11. Return the resulting HTTP outcome.

Globally ambiguous or structurally unusable routing is a global startup or
readiness error under [ADR 0006](0006-runtime-configuration-oci-and-observability.md).
A target-local managed adapter-selection or target-configuration error may be
detected eagerly where practical while leaving the service ready and returning
`500` only for that target; unrelated routes remain available.

Adapter reconciliation owns target lookup, permitted-user creation, assignment
and managed-constraint application and removal, target mappings, target API
calls, and target-semantic validation of the complete desired state before
mutation. Where meaningful, it may report resource creation information
relevant to ADR 0001's `201` behavior, but need not. One reconciliation may
make multiple target calls; there is no automatic retry or rollback.

The overall deadline and cancellation propagate through provider and adapter
work. Core starts no new work after observing expiry. A compliant adapter uses
bounded operations, propagates and checks cancellation, and starts no
detached or background reconciliation. Cancellation is best effort:
non-cooperative or defective in-process code may continue or block, and its
effects may be uncertain.

Build compilation and compile-time and unit/integration tests enforce trait
compatibility and catch exercised defects, but not every adapter defect.
Returned or recoverable provider and adapter failures return `500`; they
never become an empty desired state or successful no-op. A panic, abort,
out-of-memory condition, unsafe defect, or non-cooperative block may affect,
stall, or terminate the whole replica and is not target-local isolation.

### Deployment, lifecycle, and security

The image already contains every supported adapter. [ADR 0006](0006-runtime-configuration-oci-and-observability.md)
owns whole-product-image availability; satisfying it also makes adapter code
available. No extra adapter artifact, registry, loader, or download path
exists.

Upgrades and rollbacks are whole-product-image operations. There is no
adapter-specific rollback or runtime adapter-version selection. During a
rolling rollout, old and new replicas may run different image versions and
each uses the adapters linked into its own image. Operators or deployment
systems may roll back the whole image, but PermissionSync does not choose or
remember a prior adapter version. There is no lifecycle manager or shared
adapter lifecycle, version, or replay state required for routing or
correctness; Core remains stateless.

Concrete adapter crates are trusted in-process code with the authority of the
PermissionSync process. The Rust crate/trait boundary and static linking are
not a sandbox or isolation boundary; linked code has process authority.

Core's selected target context and credentials are passed through the public
contract as code-level discipline, not as a confidentiality or security
boundary, because linked code has process authority. Process and deployment
must enforce least privilege operationally; downstream credentials use least
privilege, TLS verification is required, and trust material is supplied
externally as deployment policy requires. `DesiredPermissionState` contains no
secrets. Logs and diagnostics contain no credentials, tokens, private keys,
raw request bodies, or sensitive desired-permission data. Trust therefore
rests with the product build and release pipeline: adapter source and
dependencies receive the same review, provenance, vulnerability, build, and
release controls as Core. Exact controls are deferred; static selection alone
does not prove review or safety.

### Deferred details and testing expectations

Deferred details are the workspace paths, crate names and repository layout,
exact `TargetAdapter` signature and associated types/errors/versioning,
composition-root registration API, runtime configuration schema and logical
adapter-ID grammar, target context and credential projection, concrete target
API contracts, and implementation-level capacity, timeout, observability,
trust-material, and secret-delivery mechanisms. These deferrals permit no
dynamic adapter mechanism or change to the static-linking and security
boundary decision.

Tests must verify Core's independence from concrete adapters; adapters' use of
only public Core contract/types; exactly-once composition-root linking and
deterministic ID mapping; complete desired-permission and structural and
target-semantic validation before mutation; managed boundaries; and absence
of secret or sensitive logging. They must cover `200` zero-call outcomes for
unconfigured/unmanaged requests, target-local `500` for an absent compiled
adapter key, global startup/readiness failure for ambiguous routing,
serviceability of unrelated routes, at most one provider and adapter call,
no retry or rollback, deadline/cancellation propagation, `500` for returned or
recoverable provider, adapter, or deadline-expiry failures, no detached
reconciliation, and whole-replica impact from non-cooperative defects. Image
tests must confirm all supported adapters are present and no dynamic loader,
separate adapter artifact, or download path is implied; rolling image revisions
may coexist.

## Alternatives considered

- **Compile-time Rust crates (chosen):** static, deterministic, simple, and
  strongly typed, at the cost of full-image coupling and trusted in-process
  code.
- **WebAssembly components:** evaluated during design, technically feasible,
  and language-independent with stronger isolation, but rejected because its
  runtime, WIT, capability, admission, and artifact-lifecycle complexity is
  not justified here.
- **Native dynamic libraries:** independently replaceable, but require an ABI,
  loader, compatibility policy, and trust machinery while providing weak
  isolation.
- **Microservices:** process isolation and independent deployment, but service
  discovery or routing, network failure modes, operational overhead, and
  latency are additional costs.
- **Target logic in Core:** avoids an adapter boundary but destroys Core's
  genericity and couples the central service to every target's semantics.

## Consequences

Core remains generic with a small, explicit Rust boundary. Adapters can be
implemented and tested independently at crate level, while composition and
the supported-target set are deterministic at build time. Runtime selection
cannot introduce code absent from the product build, but static selection does
not establish that code was reviewed or is safe.

Adapter source, compilation, and release are deliberately coupled to the
product image: every supported adapter is present in every image, and any
adapter change requires a full image rollout. The system avoids runtime
components, dynamic ABIs, loaders, and separate services, at the cost of
independent adapter release and the lost sandbox properties. Adapter code must
be reviewed and trusted as product code, with process and deployment
privileges constrained outside this in-process boundary.

## References

- [ADR 0001](0001-inbound-synchronization-contract.md)
- [ADR 0002](0002-receiver-side-jwt-verification.md)
- [ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md)
- [ADR 0004](0004-generic-rest-permission-provider.md)
- [ADR 0005](0005-bounded-desired-permission-model.md)
- [ADR 0006](0006-runtime-configuration-oci-and-observability.md)
- [ADR index](README.md)
