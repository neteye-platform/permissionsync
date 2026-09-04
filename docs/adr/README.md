# Architecture Decision Records

This directory is the entry point for PermissionSync Architecture Decision
Records (ADRs). ADRs capture durable architecture decisions, ownership,
constraints, trade-offs, and rationale. They do not replace detailed API or
configuration specifications.

New ADRs MUST use the [ADR template](template.md).

## Record Structure

Every ADR uses this standard structure:

- **Status**: The current standing of the decision.
- **Date**: The decision record date in `YYYY-MM-DD` form.
- **Deciders**: The roles or people responsible for the decision.
- **Context**: The problem, constraints, and relevant background.
- **Decision**: The chosen approach and its scope.
- **Alternatives considered**: Material options considered and why they were
  not chosen.
- **Consequences**: Expected benefits, costs, and follow-up implications.
- **References**: Related ADRs, specifications, or external material.

## Statuses

PermissionSync uses these statuses:

- **Proposed**: Under consideration; it does not guide the architecture.
- **Accepted**: Active; it guides the architecture.
- **Superseded**: Replaced by a newer ADR; retained for its decision history.
- **Deprecated**: No longer to be used; no replacement ADR is named.

## Lifecycle and numbering

- Follow the standard structure and add every new ADR to this index.
- Use the next available number; once assigned, never reuse or renumber it.
- A replacement is a new ADR and normally marks the replaced Accepted decision
  Superseded.
- A design discarded before acceptance may be omitted from the architecture
  baseline; retain useful rationale in the selected ADR's Alternatives.
- Cross-references provide context; an ADR must state the decision it owns.

## Index

1. [0001](0001-inbound-synchronization-contract.md) Inbound Synchronization
   Contract and Caller-Owned Workflow Policy (Accepted)
2. [0002](0002-receiver-side-jwt-verification.md) Caller Authentication and
   Authorization (Accepted)
3. [0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md)
   At-Most-Once Delivery and Idempotent Reconciliation (Accepted)
4. [0004](0004-generic-rest-permission-provider.md) Generic REST Permission
   Provider for v1 (Accepted)
5. [0005](0005-versioned-adapter-specific-desired-state-envelope.md) Versioned Adapter-Specific
   Desired-State Envelope (Accepted)
6. [0006](0006-runtime-configuration-oci-and-observability.md) Runtime
   Configuration, OCI Packaging, and Safe Observability (Accepted)
7. [0007](0007-compile-time-rust-target-adapters.md) Core Boundaries and
   Compile-Time Rust Target Adapters (Accepted)
