# ADR-0003: At-Most-Once Delivery and Idempotent Reconciliation

- **Status:** Accepted
- **Date:** 2026-08-24
- **Deciders:** R&D Team

## Context

PermissionSync receives logical delivery attempts from callers and synchronizes
desired access with a target. Timeout, I/O, and HTTP failures can leave callers
uncertain whether downstream work occurred.

The inbound request has no idempotency key. Its fixed body contains no event
ID, request ID, or correlation ID. PermissionSync does not infer any such
identifier.

## Decision

At-most-once end-to-end delivery applies to the current compatibility caller:
it submits one logical delivery and does not retry a timeout, I/O failure, 4xx
response, or 5xx response. A failed delivery may never be replayed, and
PermissionSync must not assume eventual delivery.

PermissionSync cannot control all callers. If any caller submits the same
logical synchronization again, PermissionSync processes it as a new legitimate
request.

For each inbound request, PermissionSync invokes Permission Provider resolution
at most once and selected Target Adapter reconciliation at most once. It does
not replay work or deduplicate requests. It must never merge requests by
byte-identical bodies, username and target and timestamp tuples, caller
identity, or inferred fingerprints. Identical bodies can represent separate,
valid login events.

One adapter reconciliation can make multiple required downstream API
operations, such as lookup, create, read, or update. These are not multiple
adapter invocations. Failed downstream operations are not automatically retried
in v1.
A future retry policy requires an explicit ADR and supporting evidence.

PermissionSync v1 is stateless. It has no persistent replay queue and adds no
persistence solely to provide delivery guarantees.

This decision makes no exactly-once promise and introduces no automatic retry.
The single-attempt, no-retry policy applies to both Permission Provider and
Target Adapter invocations. The adapter idempotent-convergence contract is:
each Target Adapter reconciles toward the desired state idempotently, comparing
current target state with desired state rather than making blind additive
changes, so that repeated legitimate desired-state synchronizations converge the
target to the desired state. Adapters must tolerate uncertain downstream effects
from a previous attempt. This convergence contract does not create any delivery
or exactly-once guarantee, and it does not add automatic retry; see
[ADR 0007](0007-compile-time-rust-target-adapters.md) for how the contract
applies to adapter reconciliation.

## Alternatives considered

No material alternatives were recorded for this decision.

## Consequences

This keeps latency low and state simple, but failed work can be lost.

Adapters still need to reconcile safely when a downstream effect is uncertain.

## References

- [ADR 0001](0001-inbound-synchronization-contract.md)
- [ADR 0002](0002-receiver-side-jwt-verification.md)
- [ADR index](README.md)
