# ADR-0005: Bounded Desired-Permission Model

- **Status:** Accepted
- **Date:** 2026-08-24
- **Deciders:** R&D Team

## Context

PermissionSync needs a small, canonical representation of desired permissions
resolved by a Permission Provider and passed among the provider, core and
Target Adapter. It must not attempt to describe every identity and access
management system.

Reconciliation is authoritative only within an explicitly configured managed
boundary. Unrelated local or administrative permissions already held by a
target user must remain untouched, separately for managed assignment state and
managed constraint state.

## Decision

The v1 model contains a document `version`, `assignments` and document-level
`constraints`. The supported version is 1. Each assignment expresses one
desired grant and contains:

- `kind`: exactly `role`, `group` or `entitlement`;
- `id`: a stable, provider-defined opaque logical identifier; and
- an optional `scope`.

A present scope is complete and contains opaque `type`, opaque `id` and
explicit `propagation`. Propagation is only `self` or `descendants`; a partial
scope is invalid. With no scope, propagation is absent and meaningless. An
assignment has no scope array: multiple scopes are represented by multiple
assignments, including repeated or different grants at different scopes.

The following is conceptual JSON, not a REST or serialization schema:

```json
{
  "version": 1,
  "assignments": [
    { "kind": "role", "id": "reader" },
    {
      "kind": "role",
      "id": "editor",
      "scope": {
        "type": "resource-boundary",
        "id": "engineering",
        "propagation": "descendants"
      }
    },
    {
      "kind": "group",
      "id": "release-managers",
      "scope": {
        "type": "resource-boundary",
        "id": "operations",
        "propagation": "self"
      }
    },
    { "kind": "entitlement", "id": "packet-capture-download" }
  ],
  "constraints": [
    { "type": "network", "values": ["10.0.0.0/8", "192.168.0.0/16"] },
    { "type": "interface", "values": ["collector-a"] }
  ]
}
```

A `role` is a logical named bundle of permissions or privileges understood by
the selected target integration; names such as `viewer`, `editor`,
`administrator` and `technician` are illustrative only. The core treats its
identifier as opaque and the adapter validates and maps it. A `group` is
desired membership in a target-side user collection, whether called a group,
team or user group; `team` is not a separate canonical kind.

An `entitlement` is an independently assignable target-side capability or
right, neither a named permission bundle nor target-side user-collection
membership. The core does not interpret its identifier. The adapter determines
whether it exists or is supported, how it maps to target state, whether it may
be scoped and whether combinations with other assignments are valid. It may
use the same optional scope representation when target semantics require it
and introduces no additional fields.

`team` and `organization` are not v1 kinds. No kinds, propagation values or
scope changes are added speculatively. Such evolution requires explicit
versioning and compatibility work across Provider, PermissionSync and Adapter;
each must support the document model version, and the selected Adapter must
support the model's semantics and capabilities. Compatibility is not automatic.

The Permission Provider owns WHAT access a user should have. It resolves the
source representation and authorization schema it owns and emits only
assignments and constraints intentionally meant as desired target state.
Source-local roles, groups, entitlements and restrictions are inputs, not
automatically forwarded state.

The core transports the complete canonical model and performs complete
structural validation before target mutation: supported version, required
fields, assignment shape, allowed kinds, scope shape and propagation, and
constraint shape with `type` and string `values`, including at most one
occurrence of each constraint `type` per document. It rejects malformed or
unsupported documents before target mutation. The core does not determine
whether target IDs, scope types or IDs, propagation, entitlement scoping,
constraint values, mappings or combinations are supported or meaningful.

The selected Target Adapter owns HOW desired target state is reconciled and
performs complete semantic validation of the model before target mutation. It
checks roles, groups, entitlements, scope types and IDs, propagation,
constraint types, individual values, mappings, target support and unsupported
assignment or constraint combinations. Unsupported or semantically invalid
values fail synchronization and must not be silently dropped, rewritten,
weakened or defaulted. This pre-mutation validation rule does not change the
uncertain downstream-effect behavior for valid target operations under [ADR
0006](0006-runtime-configuration-oci-and-observability.md).

A document-level constraint expresses a desired access restriction applying to
the synchronized user or document rather than one assignment. It contains
exactly `type` and `values`: `type` is a stable provider-defined opaque logical
identifier, and `values` is an array of opaque strings. Values can be CIDRs,
names, paths, selectors or other logical values, not only identifiers. The
examples `network` and `interface` are not canonical built-in types.

The core gives constraint types and values no business interpretation; it only
validates their complete structure. The adapter interprets them and rejects
unsupported types or invalid values before mutation. Each constraint `type`
appears at most once per document, while multiple values for one type are in
that constraint's single `values` array. An absent constraint and a present
constraint with an empty `values` array are distinct. Empty `values` is
structurally valid, has no universal core meaning, and may mean clearing,
deny-all, unsupported or invalid according to the adapter. Neither state is
silently normalized into the other.

Assignments and constraints describe desired authorization state, not
deployment configuration. URLs, API tokens, usernames, passwords, TLS or CA
material, target API version configuration, adapter runtime options, deadlines
and logging configuration do not appear in the model; they belong to runtime
context.

The model is authoritative only within the explicitly configured managed
boundary. Absence from desired assignments authorizes removal only inside
managed assignment authority; absence from desired constraints authorizes
clearing or removal only for explicitly delegated constraint types. Empty
assignment or constraint collections do not grant authority over unrelated
target state. Unmanaged target permissions and unmanaged constraint dimensions
remain untouched. The exact runtime representation of this boundary is
deferred; the invariant is required.

This is a generic, reusable open-source boundary, not a universal IAM ontology,
and it has no target-specific property bags. Exact Rust types, JSON and REST
schemas, serialization and version encoding, capability-negotiation mechanics,
and target API contracts are deferred.

## Alternatives considered

No material alternatives were recorded for this decision.

## Consequences

Providers and adapters share a precise, small desired-state boundary. It covers
unscoped and scoped roles, hierarchical `self` and `descendants` propagation,
target-side user-collection membership, independently assignable capabilities,
document-level restrictions and multiple assignments across scopes.

Adapters must reject unsupported model values before mutation and reconcile
removal only within their configured managed authority. Valid target operations
retain the uncertain downstream-effect behavior defined by [ADR
0006](0006-runtime-configuration-oci-and-observability.md).

## References

- [ADR 0001](0001-inbound-synchronization-contract.md)
- [ADR 0004](0004-generic-rest-permission-provider.md)
- [ADR 0006](0006-runtime-configuration-oci-and-observability.md)
