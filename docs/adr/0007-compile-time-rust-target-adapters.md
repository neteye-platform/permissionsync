# ADR-0007: Core Boundaries and Compile-Time Rust Target Adapters

- **Status:** Accepted
- **Date:** 2026-08-31
- **Deciders:** R&D Team

## Context

PermissionSync must reconcile users with different target systems without
putting target authorization semantics, API payloads, mappings, or
reconciliation logic in generic Core. The boundary is:

```text
Identity Context -> Permission Provider -> versioned payload envelope
                -> Core-owned TargetAdapter contract
                -> linked concrete adapter crate -> target application
```

The Permission Provider owns **WHAT** access the user should have: it resolves
its source authorization model and returns the versioned adapter-specific
envelope from
[ADR
0005](0005-versioned-adapter-specific-desired-state-envelope.md). The Target
Adapter owns **HOW** that state is validated and reconciled against the target,
including adapter-specific payload and target-semantic validation, target
mappings, and target API calls. Core owns orchestration: caller authentication
and authorization, strict request validation, target routing, capacity and
deadline handling, structural envelope validation, one provider invocation, one
adapter invocation, and the HTTP outcome. Core does not interpret target
semantics and owns neither WHAT nor HOW.

The desired state is the versioned adapter-specific payload envelope from
[ADR
0005](0005-versioned-adapter-specific-desired-state-envelope.md): a common
`{version, payload}` envelope whose payload is opaque to Core and whose
semantics are owned by the selected adapter. It contains no endpoint,
credentials, trust material, deployment configuration, adapter options,
deadlines, or logging configuration.
Core validates only the envelope structure before adapter work; the adapter
performs complete target-semantic validation of its payload before mutation and
owns target mappings and combinations. Unsupported or invalid target semantics
fail rather than being silently dropped, rewritten, weakened, or defaulted.

## Decision

### Public boundary and compile-time composition

Core owns the public `TargetAdapter` trait and contract, with public domain
types for identity context and the versioned payload envelope. `TargetAdapter`,
`Envelope`, and `Payload` are conceptual names; exact Rust names, trait
signature, result and error types, versioning, and workspace paths are deferred.
Runtime target context is a contract-provided value, not necessarily a pure
domain type. The contract supplies only the selected adapter's least-privilege
target context and credentials, the payload envelope, deadline/cancellation
context, and no secrets in desired state.

Each concrete adapter is a distinct Rust crate, statically linked into one
generic PermissionSync binary and OCI image. Core depends on no concrete
adapter crate. An adapter may depend on Core only through Core's public
contract and public types; it may use its own third-party dependencies, but
not Core internals or other adapter crates. The composition root depends on
Core and supported adapter crates and deterministically maps each adapter
identifier to its compiled adapter implementation. One generic product image
contains all supported adapters; deployment has no cargo-feature matrix, and
the image identity includes the complete linked adapter set.

Runtime configuration for a recognized logical target selects an adapter
identifier. That identifier is resolved only against the compiled-in adapter
registry; PermissionSync cannot download, install, load, or select an
implementation absent from the binary. There is no dynamic loading, `.so`,
sidecar, microservice, adapter OCI artifact, loader, independent adapter-artifact
digest or version selection, hot loading, or independent adapter release
mechanism. Product OCI image digests remain valid for identifying the complete
product image.

Target-native integration is preferred first, then a reusable standard
integration where appropriate, then a PermissionSync adapter only when those
options are insufficient. This ADR does not select SCIM.

### Request order and failure model

For every request, the complete order is:

1. Authenticate the technical caller JWT under ADR 0002.
2. Parse and validate the request only enough to obtain a usable `target`
   value: the body must be parseable enough to read `target`, `target` must be
   present, `target` must be a non-null string, and `target` must match the v1
   target identifier grammar under ADR 0001. If this minimal target extraction
   or grammar validation cannot be performed, return `400`.
3. Derive the required authorization scope deterministically:
   `permissionsync:<target>`.
4. Authorize the authenticated caller for that derived scope. A valid caller
   lacking the required scope returns `403`. This authorization check happens
   before full strict request validation, before target resolution, and before
   any check of whether the logical target is recognized or configured.
5. Perform full strict validation of the fixed four-field request body. An
   invalid request returns `400`.
6. Resolve the target. If the caller was authorized for the derived target
   scope but the logical target is unknown or unrecognized by the runtime
   routing/configuration contract, return `400` under ADR 0001.
7. If the recognized logical target names an adapter key absent from the
   compiled-in registry, or has another unavailable or broken server-side
   adapter/configuration defect that is detectable, return target-local `500`
   with no capacity, provider, or adapter work; unrelated correct targets
   remain serviceable.
8. Obtain bounded capacity.
9. Invoke the Permission Provider once.
10. Structurally validate the resulting payload envelope (`{version, payload}`).
11. Invoke the selected Target Adapter reconciliation once.
12. Return `200` when reconciliation changed target state, `204` when it was
    already in the desired state, or the appropriate error status.

Authorization for the derived scope precedes target resolution, so an
authenticated caller who lacks `permissionsync:<target>` for a target name
receives `403` before PermissionSync determines whether that target is
recognized or configured. Target existence and server-side configuration are
not revealed to unauthorized callers. An authenticated and authorized caller
who requests a logical target that is unknown or unrecognized by the runtime
routing/configuration contract receives `400`; a recognized logical target with
an unavailable or broken server-side adapter/configuration receives target-local
`500`. An unauthorized caller receives neither the unknown-target `400` nor the
target-local `500`. No Permission Provider or Target Adapter work begins before
authentication, authorization, full strict request validation, and target
resolution succeed.

Globally ambiguous or structurally unusable routing is a global startup or
readiness error under [ADR 0006](0006-runtime-configuration-oci-and-observability.md).
A target-local adapter-selection or target-configuration error for a recognized
logical target may be detected eagerly where practical while leaving the
service ready and returning `500` only for that target; unrelated correct
targets remain available.

Adapter reconciliation owns target lookup, adapter-specific payload and
target-semantic validation of the complete envelope before mutation, target
mappings, target API calls, and adaptation of the desired state to the target.
It converges the target to the desired state idempotently under the adapter
idempotent-convergence contract in
[ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md).
It reports whether reconciliation changed target state (`changed`) or left it
unchanged (`unchanged`) without exposing exactly what resource was created or
modified. One reconciliation may make multiple target calls; there is no
automatic retry or rollback.

Adapter-specific payload or target-semantic validation failures for a
recognized logical target are server-side failures and return target-local
`500`; they are not unknown-target `400` responses.

The overall deadline and cancellation propagate through provider and adapter
work; a COMPLIANT Target Adapter has bounded execution. Each compliant adapter:

- MUST cooperate with the overall request deadline under
  [ADR 0006](0006-runtime-configuration-oci-and-observability.md);
- MUST give every remote I/O operation a bounded timeout no greater than the
  remaining request budget;
- MUST bound every adapter-controlled wait or blocking operation;
- MUST observe propagated cancellation/deadline signals;
- MUST NOT start new downstream work after observing cancellation/deadline
  expiry, and MUST return after its currently executing bounded operation
  completes;
- MUST NOT detach or background reconciliation work.

Core starts no new work after observing expiry. The synchronization capacity
slot remains associated with the reconciliation until adapter work has actually
returned; capacity is not released while reconciliation is still running.

Cancellation is best effort for non-cooperative code: because adapters are
trusted in-process Rust code, PermissionSync cannot safely hard-interrupt
arbitrary defective or non-cooperative code. A buggy adapter that spins, blocks
forever, panics, OOMs, or otherwise violates the `TargetAdapter` contract may
still impair or terminate the whole replica. This is a defective-adapter
condition, not supported normal behavior.

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
externally as deployment policy requires. Every outbound Target API request
that carries any of the following MUST use HTTPS: credentials; synchronized-user
identity; desired-state / permission payload; or permission mappings or other
sensitive target data. An HTTPS URI is required for such sensitive Target
requests, with TLS certificate validation and hostname validation; TLS
verification MUST NOT be disabled, and plaintext `http://` MUST NOT be used for
sensitive Target API traffic. Private or internal CAs remain supported through
configured trust material. The concrete TLS implementation and library, and the
concrete adapter authentication scheme, are implementation decisions and are not
chosen in this ADR. The payload envelope contains no
secrets. Logs and diagnostics contain no credentials, tokens, private keys,
raw request bodies, or sensitive provider payload data. Trust therefore
rests with the product build and release pipeline: adapter source and
dependencies receive the same review, provenance, vulnerability, build, and
release controls as Core. Exact controls are deferred; static selection alone
does not prove review or safety.

### Deferred details and testing expectations

Deferred details are the workspace paths, crate names and repository layout,
exact `TargetAdapter` signature and associated types/errors/versioning,
composition-root registration API, runtime configuration schema and adapter
identifier grammar, target context and credential projection, concrete target
API contracts, and implementation-level capacity, timeout, observability,
trust-material, and secret-delivery mechanisms. These deferrals permit no
dynamic adapter mechanism or change to the static-linking and security
boundary decision.

Tests must verify Core's independence from concrete adapters; adapters' use of
only public Core contract/types; `400` for an unknown or unrecognized logical
target and target-local `500` for a recognized target with unavailable or broken
server-side adapter/configuration; adapter-specific payload or target-semantic
failures remain target-local `500`, not unknown-target `400`;
exactly-once composition-root linking and deterministic ID mapping; complete
envelope-structure and target-semantic payload validation before mutation; and
absence of secret or sensitive logging. They must cover the `200`/`204`
`changed`/`unchanged` distinction, target-local `500` for an absent compiled
adapter key, global startup/readiness failure for ambiguous routing,
serviceability of unrelated routes, at most one provider and adapter call,
no retry or rollback, deadline/cancellation propagation, `500` for returned or
recoverable provider, adapter, or deadline-expiry failures, no detached
reconciliation, and whole-replica impact from non-cooperative defects. Every
supported adapter is compiled and tested on every PR; image tests must confirm
all supported adapters are present and no dynamic loader, separate adapter
artifact, or download path is implied; rolling image revisions may coexist.

If a shared target HTTP client or common transport owns target TLS policy, that
layer MUST have hermetic, deterministic tests that verify:

- a sensitive `http://` endpoint is rejected before any sensitive traffic;
- configuration that disables certificate validation is rejected;
- configuration that disables hostname validation is rejected;
- a local TLS server using an explicitly configured test/private CA succeeds
  when certificate and hostname validation succeed; and
- an untrusted certificate is rejected.

These tests use only local fake or test TLS endpoints, deterministic
certificates and fixtures, and never weaken production validation. They do not
use the public internet or real GLPI/Grafana. An adapter that owns its own
target transport requires equivalent coverage; an adapter using the tested
shared transport need not duplicate it. Adapter-specific tests remain focused
on adapter behavior.

Target-identifier grammar tests under
[ADR 0001](0001-inbound-synchronization-contract.md) MUST cover at least:

- a one-character alphanumeric target is accepted;
- a valid 64-character target is accepted;
- a 65-character target is rejected;
- a leading separator is rejected;
- a trailing separator is rejected; and
- internal `.`, `_`, and `-` characters are accepted.

For every adapter, where the target behavior can be represented by a
deterministic fake/test double, idempotent-convergence must be tested for at
least:

A. Reconcile the desired state -> `changed`.
B. Reconcile the same desired state again -> `unchanged`, with no duplicate or
   unintended additional effects.
C. Simulate a recoverable partial failure after an observable target mutation
   -> a later legitimate reconciliation observes the current target state,
   converges to the desired state, and produces no duplicate or unintended
   additional effect.
D. Simulate a downstream timeout/cancellation -> the adapter returns within its
   bounded contract, and no detached or background reconciliation continues.

These tests use deterministic, hermetic fakes and require no real downstream
service in PR CI. They assume no automatic caller retry and provide no
exactly-once guarantee when downstream effects are genuinely unobservable or
ambiguous.

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
- [ADR 0005](0005-versioned-adapter-specific-desired-state-envelope.md)
- [ADR 0006](0006-runtime-configuration-oci-and-observability.md)
- [ADR index](README.md)
