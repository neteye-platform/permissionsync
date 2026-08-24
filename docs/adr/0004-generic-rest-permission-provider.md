# Generic REST Permission Provider for v1

## Status

Accepted

## Context

PermissionSync needs a configurable source of desired permissions without
coupling the service to a particular permission backend or target API contract.
The service is an orchestration boundary, not a universal identity and access
management system.

The transport choice must leave room for a later wire-contract specification.
It must preserve a clear boundary: the Permission Provider decides WHAT is
desired, the Target Adapter decides HOW to apply it, and the core owns neither
responsibility.

## Decision

Use a generic REST Permission Provider as the v1 desired-permission boundary.
PermissionSync calls the configured provider with synchronized-user identity
context, relevant inbound group membership and login metadata, and an explicit
target or client identifier. The provider resolves the desired permissions for
that user.

Runtime configuration supplies the provider type, endpoint, authentication or
credentials, TLS and trust settings, including private or internal CA trust,
and a bounded timeout. Provider credentials use least privilege. TLS
certificate verification must not be disabled as a workaround. The same OCI
image can therefore use different permission backends. This ADR does not select
an authentication mechanism, configuration library, timeout value, or number.
Its request and response wire contract, including exact fields, versions, and
error representation, remains deferred to a separate specification.

The provider owns the decision about WHAT desired permissions the synchronized
user should have. The Target Adapter owns HOW to apply them, including mappings,
user creation policy, lookups, and target API behavior. The core orchestrates
their interaction, transports the model without interpreting its business
meaning or target mappings, and owns neither WHAT nor HOW.

PermissionSync makes one bounded provider attempt in v1 and does not retry. The
current compatibility caller uses single-attempt, at-most-once delivery under
[ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md).
Provider failure is explicit, fails synchronization, and must never become an
empty desired-permission set. The provider does not perform target
reconciliation, and neither adapters nor the core make permission decisions.
The caller only owns what to do with the returned synchronization result.

## Consequences

The REST Permission Provider can be configured independently from adapters while
the implementation remains portable across targets. A future wire specification
can evolve without changing this boundary decision.

This choice does not define a universal IAM ontology, target-specific property
bags, runtime libraries, or a target API schema. The accepted bounded
desired-permission model is recorded in
[ADR 0005](0005-bounded-desired-permission-model.md). The detailed provider
REST wire specification remains deferred elsewhere.

## References

- [ADR 0001](0001-inbound-synchronization-contract.md)
- [ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md)
- [ADR 0005](0005-bounded-desired-permission-model.md)
- [ADR 0006](0006-core-boundaries-and-webassembly-component-target-adapters.md)
- [ADR 0007](0007-runtime-configuration-oci-and-observability.md)
