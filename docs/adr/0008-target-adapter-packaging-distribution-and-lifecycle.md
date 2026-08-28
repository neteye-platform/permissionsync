# Target Adapter Packaging, Distribution, and Lifecycle

## Status

Proposed

## Context

ADR 0006 defines independently versioned WebAssembly Component Target Adapters
and makes PermissionSync their in-process host. ADR 0007 defines one generic,
immutable OCI-friendly service with external deployment configuration. Both
records defer adapter repository organization, distribution, trust, updates,
caching, and lifecycle mechanics.

Some deployments permit external connectivity only during installation or
upgrade. Pods and replicas must still recover after a restart, eviction,
replacement, node reboot, or relocation when public or external connectivity is
unavailable. Artifact availability therefore cannot depend on a public registry
or service at PermissionSync startup.

## Decision

The intended production organization is one repository per Target Adapter. Each
repository owns its adapter source, tests, WIT compatibility checks, pipeline,
version, release, and artifact. Repository independence and release
independence are distinct properties, but an independent build, version, and
release lifecycle is required. Target-specific implementation must never move
into the PermissionSync core for packaging convenience.

Adapter CI emits an immutable, compatible WebAssembly Component `.wasm`
artifact. Deployment endpoints, credentials, target instances and
configuration, private CAs, provider configuration, and secrets remain external
runtime or deployment configuration. Adapters are not containers or services.

Adapter artifacts use OCI-compatible distribution. Each release is identified
by an immutable content digest and may also have a human-friendly tag or
version. Deployment selects an exact artifact version and its digest. Exact OCI
media types and annotations remain deferred.

Deployment configuration is the source of truth for adapter identity. For every
selected Target Adapter, the deployment declares the exact artifact that must be
used: the artifact, its pinned version, and its immutable content digest. The
exact configuration schema remains deferred, but the rule is fixed:
PermissionSync MUST use the exact selected immutable artifact. There MUST be no
automatic fallback to a previous adapter version, a previous digest, another
locally cached artifact, another tag, `latest`, the newest available version, or
the closest compatible version. If the deployment selects digest BBB, a newly
created replica must either use BBB or fail to start. A cache may satisfy the
request only if it contains the exact selected artifact; it never silently
substitutes another artifact.

Authoritative upstream or release distribution is distinct from deployment-local
runtime availability. Before use, deployment tooling must make every selected,
verified artifact available from a deployment-local OCI registry, source, or
mirror by digest. External connectivity may be used during installation or
upgrade, but a rollout is not successfully staged until that condition holds.
Cache use is an optimization, not a correctness condition. A cold node with an
empty cache must start offline from the durable deployment-local source.

Once installation or upgrade completes successfully, recreating PermissionSync
through restart, eviction, replacement, node reboot, or relocation MUST NOT
require public or external network access. All images, loaders, and selected
adapter artifacts must already be deployment-locally available. No public
registry or service is a startup dependency.

The generic requirement is that deployment tooling makes selected, verified
artifacts available before use. A recommended Kubernetes realization is a
startup-only adapter-loader initContainer that places selected components on a
shared adapter volume. This is not a long-running sidecar, execution service,
network proxy, or Core-adapter transport. After startup, only the
PermissionSync application container runs, and its Component host executes
components in process. This recommendation does not require Kubernetes, and
PermissionSync makes no Kubernetes API calls.

Before an artifact is eligible for materialization, the loader verifies its
selected content digest and any signature or provenance evidence required by
deployment trust policy. The loader's verification does not admit a component
for execution. PermissionSync remains the authoritative admission point: before
provider resolution, reconciliation, or target mutation, its Component host
must verify Component and WIT import/export compatibility and grant only the
selected adapter's configured capabilities.

The adapter loader MUST treat the complete deployment-selected adapter set as
an atomic startup requirement. Before PermissionSync starts, the loader must
successfully obtain and verify EVERY exact selected artifact. Failure of any
single selected artifact — missing, digest mismatch, or failing artifact
trust/signature/provenance policy — fails the loader globally. When any selected
artifact fails, the PermissionSync application container MUST NOT start. A Pod
MUST NOT start with a partial deployment-selected adapter set: materializing
adapters A and C and starting without B is not permitted.

Materialization is atomic with respect to the deployment-selected adapter set.
PermissionSync MUST NOT start a new replica unless every selected adapter
artifact has been obtained from deployment-local infrastructure, matches its
selected immutable identity, and satisfies the deployment's artifact trust
policy. A new replica MUST NOT silently substitute any other adapter artifact
when the selected artifact is unavailable or invalid.

The loader owns artifact-delivery validation only: the exact selected artifact
is available; the exact selected immutable digest matches; the required artifact
trust, signature, and provenance policy passes; and the artifact can be safely
materialized. Failure of any selected artifact at this stage fails the loader
globally. This is intentional. The loader's verification does not admit a
component for execution, and WebAssembly/WIT admission does not move into the
loader. After the complete artifact set has been successfully materialized, the
PermissionSync Component host inspects and admits the selected Components,
validates Component and WIT import/export compatibility and available host
capabilities, and enforces runtime capability boundaries.

ADR 0006 failure isolation has two distinct phases. Phase 1, deployment and
materialization, is all-or-nothing: any selected artifact that cannot be
obtained or fails artifact integrity or trust verification fails the loader, and
a new PermissionSync Pod does not start. This is a deployment-revision failure,
not a target-runtime failure. Phase 2, PermissionSync admission and runtime,
applies only after the complete exact artifact set has been successfully
materialized. Target-local failures then remain isolated according to ADR 0006:
a component rejected during PermissionSync admission makes that selected target
unavailable, and a reconciliation or runtime failure for one adapter fails only
that adapter's synchronization while unrelated targets remain serviceable.
Unmanaged and unconfigured routes remain their existing successful `200` no-op
behavior. This target-local runtime isolation does NOT permit the loader to
start with missing artifacts.

Loader credentials are separate from target credentials. A loader may receive
only credentials and trust material required to access the deployment-local OCI
source. Those loader credentials and trust material MUST NOT reach any adapter,
any target context, DesiredPermissions, provider configuration, or
PermissionSync's post-startup runtime context, logs, or failure output. Target
configuration and credentials remain subject to ADR 0006's least-privilege host
projection.

V1 updates select a new pinned version and digest, then replace PermissionSync
Pods or replicas through a rolling deployment. A compatible adapter update never
rebuilds or releases the core. Rolling replacement is distinct from fallback.
During a rolling update from a deployment revision selecting Adapter A@ digest
AAA to a new revision selecting A@ digest BBB, an existing old replica may
temporarily continue running AAA while a replacement replica attempts to start
with BBB. The replacement replica MUST use BBB; it does not fall back to AAA,
and PermissionSync does not select AAA. If BBB cannot be materialized, the
replacement replica fails startup and the rollout does not converge, while
existing healthy replicas from the previous deployment revision may remain
available according to deployment rollout policy. The deployment remains visibly
not converged to its declared desired revision. An old replica retires only
after its replacement starts and is admitted under deployment rollout policy,
without selecting exact Kubernetes mechanics.

PermissionSync performs no rollback decision. The architecture MUST NOT
automatically revert from a selected digest BBB to a previously approved digest
AAA because BBB cannot be fetched, verified, loaded, or used. If an operator or
deployment system explicitly changes the desired configuration from BBB back to
AAA, that is simply a new explicit deployment revision selecting AAA.
PermissionSync itself does not remember a previous adapter version, does not
choose a previous working artifact, and does not automatically revert a failed
rollout to the previous digest. There is no automatic rollback mechanism, and
previous artifacts are not retained specifically to support one. ADR 0003 and
the uncertain-effect semantics in ADR 0006 and ADR 0007 govern target-side
reconciliation outcomes; this is not an automatic rollback capability.

PermissionSync remains stateless. It has no shared database for adapter
versions, rollout, replay, lifecycle, or idempotency. The selected adapter set
comes from deployment or runtime configuration and locally staged immutable
artifacts. Deployment-local artifact infrastructure and storage are not
PermissionSync application state.

## Consequences

Adapters can be independently built, tested, released, and replaced without a
core rebuild. Exact deployment state is deterministic: because deployment
configuration is the authoritative source of truth and fallback is prohibited,
the actual adapter identity cannot silently diverge from the declared state.
Configuration drift caused by fallback is impossible. Startup either realizes
the complete deployment-selected adapter set or fails; it never comes up with a
subset. Offline replica recovery remains deterministic, and admitted runtime
target failures remain isolated after successful materialization.

The approach requires one unavailable, invalid, or untrusted selected artifact
to prevent a new replica from starting, so deployment-local artifact
infrastructure must be reliable. A rollout can stall if the declared artifact
cannot be materialized. There is no automatic fallback: operators must
explicitly change deployment configuration to select a different artifact. This
deliberately sacrifices availability of a new revision in favor of configuration
correctness and determinism; partial startup is not an acceptable availability
mechanism.

The approach also adds staging and mirroring work, deployment-local source
infrastructure, trust operations, loader and per-target status complexity, and
artifact retention work, and requires two-stage coordination between artifact
release and deployment staging. Rolling replacement is simpler and more
auditable than hot reload.

## Validation Before Acceptance

Before ADR activation, a small deployment spike validates operational
realizability. Acceptance follows architecture and team review plus confirmation
of these scenarios; this is not a new feasibility-gate framework.

- **Offline replica recovery.** After successful staging, with external Internet
  unavailable and deployment-local infrastructure available, recreate a fresh
  Pod or replica, including cold-node scheduling. The loader obtains the exact
  selected artifacts only from the deployment-local source, and PermissionSync
  starts without public or external access or a warm cache.
- **Atomic selected-set materialization.** Configure at least two selected
  artifacts, A and B. A is available and valid; B is missing, digest-mismatched,
  or untrusted. Expected result: the loader fails, the PermissionSync
  application container does not start, and no partial A-only adapter set
  becomes active. Then make B valid and available and confirm startup succeeds.
- **Exact-version and no-fallback enforcement.** Make two versions or digests of
  one adapter available locally, A@sha256:OLD and A@sha256:NEW. Configure the
  deployment to select A@sha256:NEW, then make NEW unavailable or invalid while
  OLD remains available. Expected result: startup fails and OLD is not selected
  automatically. Restore NEW and verify that the replica starts using exactly
  NEW. This proves that deployment configuration is authoritative and that no
  previous version or digest is selected automatically.

## Deferred Decisions

This ADR defers:

- exact OCI media types and annotations;
- registry product and deployment-local implementation;
- signing technology, provenance format, and trust-root distribution and
  rotation;
- loader implementation and on-disk or shared-volume layout;
- per-adapter status format;
- exact deployment configuration schema and adapter selection representation;
- retention and garbage-collection policy as an operational and deployment
  concern (not an architectural rollback mechanism; previous artifacts need not
  be retained to support automatic rollback);
- compatibility metadata and version-negotiation mechanics; and
- hot reload.

## References

- [ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md)
- [ADR 0006](0006-core-boundaries-and-webassembly-component-target-adapters.md)
- [ADR 0007](0007-runtime-configuration-oci-and-observability.md)
- [ADR index](README.md)
- [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec/blob/main/spec.md)
- [OCI Image Specification, descriptor and content digest](https://github.com/opencontainers/image-spec/blob/main/descriptor.md)
- [WebAssembly Component Model](https://component-model.bytecodealliance.org/)
