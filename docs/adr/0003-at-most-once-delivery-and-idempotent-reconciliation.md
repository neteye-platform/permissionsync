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

The v1 caller contract is single-attempt: one logical delivery is submitted,
and a timeout, I/O failure, 4xx response, or 5xx response is not automatically
retried. A failed delivery may never be replayed, and PermissionSync must not
assume eventual delivery.

PermissionSync cannot control all callers. If any caller submits the same
logical synchronization again, PermissionSync processes it as a new legitimate
request.

Those repeated legitimate requests may also overlap in time, including requests
for the same adapter, the same backend, and the same synchronized identity.
PermissionSync allows that overlap and assigns no ordering between them. It
neither deduplicates nor merges nor serializes them: no request identity, no
username-and-target tuple, no caller identity, and no body fingerprint is used
as an exclusion key, and Core does not serialize logical delivery attempts by
identity. There is no "last request wins" rule and no request that owns the
resulting durable state. Configured synchronization concurrency bounds resource
consumption only; it is not an ordering or exclusion primitive, and
[ADR 0006](0006-runtime-configuration-oci-and-observability.md)'s stateless
multiple-replica model means no process-local mechanism could provide one.

For each inbound request, PermissionSync invokes Permission Provider resolution
at most once and selected Target Adapter reconciliation at most once. It does
not replay work or deduplicate requests. It must never merge requests by
byte-identical bodies, a username-and-target tuple, caller identity, or inferred
fingerprints. Identical bodies can represent separate, valid login events.

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
from a previous attempt and concurrent effects of another legitimate
reconciliation running at the same time, and a later reconciliation must still
converge from any safely representable intermediate state either of those left
behind. This convergence contract does not create any delivery, ordering, or
exactly-once guarantee, and it does not add automatic retry; see
[ADR 0007](0007-compile-time-rust-target-adapters.md) for the concurrency
requirements this places on adapter reconciliation, including the authoritative
final-state verification a successful reconciliation must perform.

Allowing overlap does not weaken the at-most-once invocation rule above. One
inbound request still causes at most one Provider resolution and at most one
Target Adapter reconciliation invocation. Resolving the outcome of a target
mutation the adapter itself performed, re-reading authoritative target state,
and verifying the final state belong to that one invocation and are not
retries.

## Alternatives considered

No material alternatives were recorded for this decision.

## Consequences

This keeps latency low and state simple, but failed work can be lost.

Adapters still need to reconcile safely when a downstream effect is uncertain,
and now also when another legitimate reconciliation is mutating the same target
subject concurrently. A successful reconciliation states what the adapter
authoritatively verified before returning, not that the target still holds that
state afterwards; a concurrent legitimate request may change it immediately
after. Callers that need a settled outcome for one identity must sequence their
own deliveries.

## References

- [ADR 0001](0001-inbound-synchronization-contract.md)
- [ADR 0002](0002-receiver-side-jwt-verification.md)
- [ADR index](README.md)
