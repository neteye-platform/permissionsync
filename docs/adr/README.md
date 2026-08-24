# Architecture Decision Records

Architecture Decision Records (ADRs) capture durable architecture decisions
and their trade-offs. They record why a direction was chosen so later work
can understand the decision in context.

ADRs do not replace future API or configuration specifications. Those
specifications define detailed contracts when they are needed.

## Record Structure

Each ADR uses these sections:

- **Status**: The current standing of the decision.
- **Context**: The problem, constraints, and relevant background.
- **Decision**: The chosen approach and its scope.
- **Consequences**: The expected benefits, costs, and follow-up
  implications.
- **References**: Links to related ADRs, specifications, or external
  material.

## Writing Principles

- Each ADR directly states the essential decision and invariants it owns.
- Cross-ADR references provide additional context or detail; they are never
  required to understand an ADR's own decision.
- Avoid duplicating decisions owned by other ADRs.
- An Accepted ADR may reference a Proposed ADR for context, but must not
  normatively depend on a Proposed ADR for its own meaning.

## Status Meanings

- **Accepted**: The decision is active and guides the architecture.
- **Proposed**: The decision is under consideration and does not yet guide
  the architecture.
- **Superseded**: A newer ADR replaces the decision. The record remains for
  history.
- **Deprecated**: The decision should no longer be used, but no replacement
  ADR is named.

## Index

1. [0001](0001-inbound-synchronization-contract.md) Inbound Synchronization
   Contract and Caller-Owned Workflow Policy (Accepted)
2. [0002](0002-receiver-side-jwt-verification.md) Caller Authentication and
   Authorization (Accepted)
3. [0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md)
   At-Most-Once Delivery and Idempotent Reconciliation (Accepted)
4. [0004](0004-generic-rest-permission-provider.md) Generic REST Permission
   Provider for v1 (Accepted)
5. [0005](0005-bounded-desired-permission-model.md) Bounded Desired-Permission
   Model (Accepted)
6. [0006](0006-core-boundaries-and-webassembly-component-target-adapters.md)
   Core Boundaries and WebAssembly Component Target Adapters (Proposed)
7. [0007](0007-runtime-configuration-oci-and-observability.md) Runtime
   Configuration, Stateless OCI Operation, and Safe Observability (Accepted)
