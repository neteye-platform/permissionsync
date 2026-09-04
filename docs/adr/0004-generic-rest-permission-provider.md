# ADR-0004: Generic REST Permission Provider for v1

- **Status:** Accepted
- **Date:** 2026-08-24
- **Deciders:** R&D Team

## Context

PermissionSync needs a configurable source of desired permissions without
coupling the service to a particular permission backend or target API contract.
It is an orchestration boundary, not a universal identity and access
management system. The transport must also leave room for a later wire-contract
specification.

## Decision

Use a generic REST Permission Provider as the v1 desired-state boundary.
PermissionSync calls the configured provider with synchronized-user identity
context, relevant inbound group membership, and the logical target selected by
the caller's authorized `permissionsync:<target>` JWT scope (see
[ADR 0002](0002-receiver-side-jwt-verification.md)). The provider resolves and
returns the versioned adapter-specific envelope for that user and target. The
synchronized-user identity context is information about the end user whose
desired permissions are being resolved; it is not an authentication identity or
context and must not be confused with the technical caller authenticated by
PermissionSync.

The provider returns a common envelope containing a versioned, target-specific
payload (`{version, payload}`). The envelope is defined by
[ADR
0005](0005-versioned-adapter-specific-desired-state-envelope.md). The provider
must know which target is being requested and return the payload contract
expected by that target's adapter; it keeps no universal permission
vocabulary.

Runtime configuration supplies the provider type, endpoint, authentication or
credentials, TLS and trust settings (including private or internal CA trust),
and a bounded timeout. Provider credentials use least privilege, and TLS
certificate verification must not be disabled as a workaround. One reusable
OCI image can therefore serve different permission backends.

Every outbound Permission Provider API request always carries synchronized-user
identity context, relevant inbound group membership, and the logical target
selected from the caller's authorized JWT scope. Therefore ALL HTTP Permission
Provider requests in v1 MUST use HTTPS, not only
requests that happen to carry authentication credentials. An
HTTPS URI is required for all Provider requests, with TLS certificate validation
and hostname validation; TLS verification MUST NOT be disabled, and plaintext
`http://` MUST NOT be used for a Provider request. Private or internal CAs
remain supported through configured trust material. Provider credentials use
least privilege. The concrete TLS implementation and library, and the concrete
provider authentication scheme, are implementation decisions and are not chosen
in this ADR.

The authentication mechanism, configuration library, configuration values and
timeout value remain deferred. The request and response wire contract,
including exact fields, versions and error representation, is also deferred to
a separate specification.

The provider owns WHAT desired permissions the user should have. The Target
Adapter owns HOW to apply them, including mappings, user-creation policy,
lookups and target API behavior. The core strictly orchestrates this boundary,
transports the model without interpreting its business meaning or target
mappings, and owns neither WHAT nor HOW.

PermissionSync makes at most one bounded provider attempt per inbound
request and does not retry. Provider failure is explicit and fails
synchronization; it never means an empty desired-permission set. The provider
does not reconcile the target, and neither adapters nor the core make
permission decisions. The caller owns
what to do with the returned synchronization result. The current compatibility
caller uses single-attempt, at-most-once delivery under [ADR
0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md).

## Alternatives considered

No material alternatives were recorded for this decision.

## Consequences

The REST Permission Provider can be configured independently from adapters,
while the implementation remains portable across targets and the same image
can support different backends. A future wire specification can evolve without
changing this boundary.

This decision does not define a universal IAM ontology, target-specific
property bags, runtime libraries or a target API schema. The versioned
adapter-specific payload envelope is defined by
[ADR
0005](0005-versioned-adapter-specific-desired-state-envelope.md); the detailed
provider REST wire specification remains deferred.

## References

- [ADR 0001](0001-inbound-synchronization-contract.md)
- [ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md)
- [ADR 0005](0005-versioned-adapter-specific-desired-state-envelope.md)
- [ADR 0006](0006-runtime-configuration-oci-and-observability.md)
- [ADR 0007](0007-compile-time-rust-target-adapters.md)
