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

Use a generic REST Permission Provider as the v1 desired-state boundary. Only a
request that selects exactly one grammar-valid logical target under
[ADR 0002](0002-receiver-side-jwt-verification.md) can invoke the configured
provider. PermissionSync calls it with the synchronized user's `username`,
relevant inbound `groups`, and the exact raw inbound technical-caller JWT as
Bearer authentication. Before the invocation, PermissionSync independently
derives and validates the `LogicalTarget` from that JWT's scope and uses it for
routing. The Provider independently validates the same forwarded JWT as its
own resource server and derives the same target from its
`permissionsync:<target>` scope.
The Provider resolves and returns the versioned adapter-specific envelope for
that user and derived target. A targetless successful no-op does not invoke the
Provider or resolve desired state. The synchronized-user identity context is
information about the end user whose desired permissions are being resolved; it
is not an authentication identity or context and must not be confused with the
technical caller authenticated by PermissionSync.

The provider returns a common envelope containing a versioned, target-specific
payload (`{version, payload}`). The envelope is defined by
[ADR
0005](0005-versioned-adapter-specific-desired-state-envelope.md). The provider
uses the target it derives from the forwarded JWT scope to return the payload
contract expected by that target's adapter; it keeps no universal permission
vocabulary.

Runtime configuration supplies the provider type, endpoint, TLS and trust
settings (including private or internal CA trust), a bounded timeout, and other
applicable Provider-specific values. The forwarded raw inbound JWT is
request-scoped sensitive material, not runtime configuration, and is never
persisted. The Provider owns its resource-server validation configuration. TLS
certificate verification must not be disabled as a workaround. One reusable OCI
image can therefore serve different permission backends.

Every outbound Permission Provider API request always carries synchronized-user
identity context, relevant inbound group membership, and the exact raw inbound
technical-caller JWT as Bearer authentication. PermissionSync has already
selected the logical target for routing, and the Provider derives the same
target from the forwarded JWT scope. Therefore ALL HTTP Permission Provider
requests in v1 MUST use HTTPS. An HTTPS URI is required for all Provider
requests, with TLS certificate validation and hostname validation; TLS
verification MUST NOT be disabled, and plaintext `http://` MUST NOT be used for
a Provider request. Private or internal CAs remain supported through configured
trust material. The concrete TLS implementation and library remain
implementation decisions and are not chosen in this ADR.

The configuration library, configuration values, and timeout value remain
deferred. The exact Provider wire, forwarded-JWT authentication, target
derivation, response, and error contract is defined by
[ADR 0008](0008-generic-rest-permission-provider-wire-and-transport-contract.md).

The provider owns WHAT desired permissions the user should have. The Target
Adapter owns HOW to apply them, including mappings, user-creation policy,
lookups and target API behavior. The core strictly orchestrates this boundary,
transports the model without interpreting its business meaning or target
mappings, and owns neither WHAT nor HOW.

For selected-target synchronization, PermissionSync makes at most one bounded
provider attempt and does not retry. A targetless successful no-op makes zero
Provider attempts. Provider failure is explicit and fails selected-target
synchronization; it never means an empty desired-permission set. The provider
does not reconcile the target, and neither adapters nor the core make
permission decisions. The caller owns what to do with the returned
synchronization result. Inbound delivery follows the single-attempt,
at-most-once contract defined by [ADR
0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md).

## Alternatives considered

No material alternatives were recorded for this decision.

## Consequences

The REST Permission Provider can be configured independently from adapters,
while the implementation remains portable across targets and the same image
can support different backends. The Provider independently enforces its own
resource boundary while PermissionSync retains target selection and routing.

This decision does not define a universal IAM ontology, target-specific
property bags, runtime libraries or a target API schema. The versioned
adapter-specific payload envelope is defined by
[ADR
0005](0005-versioned-adapter-specific-desired-state-envelope.md); the detailed
Provider REST wire specification is defined by
[ADR 0008](0008-generic-rest-permission-provider-wire-and-transport-contract.md).

## References

- [ADR 0001](0001-inbound-synchronization-contract.md)
- [ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md)
- [ADR 0005](0005-versioned-adapter-specific-desired-state-envelope.md)
- [ADR 0006](0006-runtime-configuration-oci-and-observability.md)
- [ADR 0007](0007-compile-time-rust-target-adapters.md)
- [ADR 0008](0008-generic-rest-permission-provider-wire-and-transport-contract.md)
