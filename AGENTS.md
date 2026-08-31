# Coding Agent Guide

## Repository purpose

- PermissionSync is an architecture-first repository.
- No production implementation currently exists.
- The repository records the service contract, boundaries, security properties,
  and deployment constraints that a future implementation must preserve.
- Treat the architecture records as executable constraints for future code.

## Sources of truth

- The [ADR index](docs/adr/README.md) is the source for ADR status and status
  conventions.
- Its status meanings are normative: Accepted decisions guide the architecture;
  Superseded decisions remain for history and do not guide new work.
- The [accepted inbound contract](docs/adr/0001-inbound-synchronization-contract.md)
  defines the inbound outcome and caller-owned workflow contract.
- The [accepted JWT decision](docs/adr/0002-receiver-side-jwt-verification.md)
  defines receiver-side JWT authentication and authorization.
- The [accepted delivery decision](docs/adr/0003-at-most-once-delivery-and-idempotent-reconciliation.md)
  defines at-most-once delivery and idempotent reconciliation boundaries.
- The [accepted Permission Provider decision](docs/adr/0004-generic-rest-permission-provider.md)
  defines the Provider's WHAT: resolving the desired access state.
- The [accepted desired-permission model](docs/adr/0005-bounded-desired-permission-model.md)
  defines the bounded, target-neutral DesiredPermissions model.
- The [accepted runtime decision](docs/adr/0007-runtime-configuration-oci-and-observability.md)
  defines runtime configuration, stateless operation, OCI image behavior, and
  safe observability.
- The [active adapter decision](docs/adr/0009-compile-time-rust-target-adapters.md)
  defines the compile-time Rust Target Adapter architecture.
- The repository tooling configuration, including
  [pre-commit configuration](.pre-commit-config.yaml),
  [editor settings](.editorconfig), and
  [codespell settings](.codespellrc), is authoritative for local checks.
- Do not commit configuration changes merely to solve a parent workspace's
  local configuration or tooling problem.

## Active architecture

- ADR 0009 is the active Target Adapter architecture.
- Each concrete adapter is a distinct Rust crate linked into one generic
  PermissionSync binary and one generic OCI product image.
- Runtime configuration selects only among adapters compiled into that binary.
- The complete linked adapter set is part of the product image identity.
- Core owns orchestration, authentication and authorization, strict request
  validation, routing, capacity, deadlines, structural model validation, one
  Provider invocation, one adapter invocation, and the HTTP outcome.
- Core sequences every request as authentication, authorization, strict request
  validation, then routing.
- An unconfigured or explicitly unmanaged route returns `200` as a no-op with no
  capacity, Provider, or adapter work.
- A detectable configured managed route whose adapter key is absent from the
  compiled-in registry returns target-local `500` with no downstream work.
- Globally ambiguous or structurally unusable routing prevents startup or
  readiness.
- The Provider owns WHAT access the user should have.
- A Target Adapter owns HOW desired state is validated and reconciled against its
  target, including target lookup, mappings, and target API calls.
- An adapter mutates only configured managed assignments and constraints;
  unmanaged target state remains untouched.
- Provider failure must not become an empty desired state or a successful no-op.
- Core must not depend on concrete adapter crates.
- Concrete adapters may depend only on Core's public contract and public types
  for their Core dependency.
- Adapters must not depend on Core internals or on other adapter crates.
- Do not move target-specific behavior into Core just for packaging convenience.
- The composition root maps logical adapter identifiers deterministically to
  compiled implementations.
- A configured adapter identifier absent from the compiled-in registry is a
  target-local configuration failure when detectable.
- There is no dynamic loading, WebAssembly runtime, WIT admission, shared
  adapter artifact, adapter loader, adapter-specific registry, or download path.
- There is no independent adapter release, adapter version selection, or hot
  loading mechanism.
- A product image may have its normal OCI image identity and digest.
- Deployment does not require a cargo-feature matrix for target selection.
- PermissionSync must remain deployment-neutral and must not depend on
  Kubernetes APIs, objects, discovery, or configuration semantics.

## Cross-ADR guardrails

- [ADR 0001](docs/adr/0001-inbound-synchronization-contract.md) governs the
  inbound synchronization outcome and caller-owned workflow policy.
- [ADR 0002](docs/adr/0002-receiver-side-jwt-verification.md) requires
  receiver-side JWT authentication and authorization.
- [ADR 0003](docs/adr/0003-at-most-once-delivery-and-idempotent-reconciliation.md)
  requires at-most-once delivery and permits no automatic retry.
- ADR 0003 also excludes delivery queues, deduplication, replay, and idempotency
  persistence unless a later accepted ADR explicitly introduces them.
- [ADR 0004](docs/adr/0004-generic-rest-permission-provider.md) makes the
  Permission Provider responsible for WHAT, not target-specific reconciliation.
- [ADR 0005](docs/adr/0005-bounded-desired-permission-model.md) keeps
  DesiredPermissions bounded and target-neutral.
- Core performs structural validation of the complete DesiredPermissions model.
- Adapters perform complete target-semantic validation before mutation.
- Unsupported or invalid target semantics must fail.
- They must not be silently dropped, weakened, rewritten, or defaulted.
- [ADR 0007](docs/adr/0007-runtime-configuration-oci-and-observability.md)
  requires stateless runtime operation.
- ADR 0007 keeps deployment configuration and externally supplied secrets out
  of the generic binary and image.
- ADR 0007 requires TLS verification and deployment-specific trust settings.
- After successful installation or upgrade, normal replica creation and
  recovery must not require public or external registry connectivity.
- The selected whole PermissionSync OCI image must be available through
  deployment-local infrastructure or equivalent offline installation or
  upgrade media.
- Whole-image availability is deployment infrastructure, not application state.
- Keep one generic image; do not introduce a product-specific deployment image.
- Do not select a cache, mirror, or loader architecture as a workaround.

## Historical architecture evidence

- [ADR 0006](docs/adr/0006-core-boundaries-and-webassembly-component-target-adapters.md)
  is superseded and historical only.
- [ADR 0008](docs/adr/0008-target-adapter-packaging-distribution-and-lifecycle.md)
  is superseded and historical only.
- The [ADR 0006 evidence](docs/adr/evidence/0006-wasm-feasibility.md) is a
  historical feasibility record, not an active architecture requirement.
- The [ADR 0008 evidence](docs/adr/evidence/0008-packaging-validation.md) records
  historical packaging scenarios and their passed results.
- The [ADR 0006 proof of concept](tests/architecture/adr-0006-wasm/README.md)
  and [ADR 0008 proof of concept](tests/architecture/adr-0008-packaging/README.md)
  are historical artifacts.
- The [ADR 0008 spike](tests/architecture/adr-0008-packaging/spike.py) is not a
  product implementation or product validation.
- ADR 0006 and ADR 0008 evidence and POCs never validate ADR 0009.
- Do not revive their WebAssembly, dynamic-artifact, loader, or independent
  adapter-lifecycle requirements through incidental implementation choices.

## Working in the repository

- Read the relevant Accepted ADRs before changing architecture-facing material.
- Use the [ADR index](docs/adr/README.md) to confirm whether a record is active
  or superseded.
- Preserve each ADR's owned decision; reference another ADR instead of copying
  its full policy.
- Do not create a new ADR for a small clarification or implementation detail.
- Create a new ADR only for a genuine architecture decision.
- Keep documentation concise, direct, and deployment-neutral.
- Do not add a Kubernetes-specific product or deployment contract.
- Do not add production code, tests, or configuration when the requested change
  is documentation-only.
- Keep changes limited to the requested files.
- Use repository-relative Markdown links for repository sources.
- Keep Markdownlint clean: use valid headings, list indentation, links, and
  fenced code blocks.

## Testing and validation

- The repository's assigned validation command is `prek run --all-files
  --refresh`.
- Also run `git diff --check` for whitespace errors.
- Inspect `git diff` before finishing.
- Optionally inspect `git diff --word-diff` when reviewing wording changes.
- Do not invent Cargo, test-runner, Docker, Make, or build commands.
- Historical POCs may document local commands, but those commands are not
  product validation and do not establish ADR 0009 compliance.
- Future production tests must verify architecture guardrails, not merely build
  a convenient implementation.
- Future tests must cover boundaries, failure isolation, bounded work,
  no-retry behavior, validation-before-mutation, and safe observability.
- Failure isolation is limited to target-local configuration and recoverable
  request failures; those failures isolate to the affected target or request.
- Cancellation is best effort, and detached or background reconciliation is not
  permitted.
- Non-cooperative work, panic, abort, out-of-memory, or unsafe defects can
  affect the whole replica.
- Future tests must not imply dynamic adapter loading or WebAssembly sandbox
  properties for the compile-time Rust architecture.

## Security

- Follow the repository [security policy](SECURITY.md) for vulnerability
  reporting and handling.
- Never commit credentials, tokens, private keys, secrets, or trust material.
- DesiredPermissions contains no credentials, endpoints, deployment settings,
  trust material, or other secrets.
- Logs and diagnostics must not expose credentials, tokens, private keys, raw
  request bodies, or sensitive desired-permission data.
- Do not disable TLS verification.
- Use least privilege for downstream credentials and target context.
- Treat linked adapter crates as trusted in-process code with process authority.
- Static linking is not a sandbox, confidentiality boundary, or capability
  isolation boundary.
- Do not claim WebAssembly isolation, WIT admission, host-enforced egress, or
  independent memory isolation for compile-time Rust adapters.

## Before finishing

- Confirm the implementation follows the active ADRs, especially ADR 0007 and
  ADR 0009.
- Confirm superseded ADR 0006 and ADR 0008 were not treated as requirements.
- Confirm no unrelated file changed.
- Run the assigned repository checks and inspect the resulting diff.
- Report skipped checks accurately rather than substituting invented commands.
