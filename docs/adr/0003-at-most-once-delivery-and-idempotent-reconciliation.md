# At-Most-Once Delivery and Idempotent Reconciliation

## Status

Accepted

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
byte-identical bodies, username and client and timestamp tuples, caller
identity, or inferred fingerprints. Identical bodies can represent separate,
valid login events.

One adapter reconciliation can make multiple required downstream API
operations, such as lookup, create, read, or update. These are not multiple
adapter invocations. Failed downstream operations are not automatically retried
in v1.
A future retry policy requires an explicit ADR and supporting evidence.

PermissionSync v1 is stateless. It has no persistent replay queue and adds no
persistence solely to provide delivery guarantees.

This decision makes no exactly-once promise. Where practical, Target Adapters
should reconcile idempotently by comparing current managed state with desired
managed state, rather than making blind additive changes. They must tolerate
repeated legitimate desired-state synchronizations and uncertain downstream
effects.

## Consequences

This keeps latency low and state simple, but failed work can be lost.

Adapters still need to reconcile safely when a downstream effect is uncertain.

## References

- [ADR 0001](0001-inbound-synchronization-contract.md)
- [ADR 0002](0002-receiver-side-jwt-verification.md)
- [ADR index](README.md)
