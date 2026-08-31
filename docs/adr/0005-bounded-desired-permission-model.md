# Bounded Desired-Permission Model

## Status

Accepted

## Context

PermissionSync needs a small, canonical representation of the desired
permissions resolved by a Permission Provider. The representation passes among
the provider, core, and Target Adapter without attempting to describe every
identity and access management system.

Reconciliation must be safe. Only delegated permission space within an
explicitly configured managed boundary is authoritative. Unrelated local or
administrative permissions already held by a target user must remain untouched.

## Decision

The v1 desired-permission model is a version, a collection of assignments,
and a collection of document-level constraints. An assignment expresses one
desired grant. It has:

- `kind`, either `role`, `group`, or `entitlement`;
- `id`, a stable, provider-defined opaque logical identifier; and
- zero or one scope.

A present scope contains all three fields: opaque `type`, opaque `id`, and
explicit `propagation`; a partial scope is structurally invalid. `propagation`
is either `self` or `descendants`. The core treats scope type and identifier as
opaque. When no scope exists, propagation is absent and has no meaning. An
assignment has no array of scopes. Multiple scopes are expressed as multiple
assignments, so the same or different grants may be represented at different
scopes.

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
    {
      "type": "network",
      "values": ["10.0.0.0/8", "192.168.0.0/16"]
    },
    {
      "type": "interface",
      "values": ["collector-a"]
    }
  ]
}
```

A `role` is a logical named bundle of permissions or privileges understood by
the selected target integration, such as the concepts behind `viewer`,
`editor`, `administrator`, or `technician`; those names are illustrative
only. The core treats the identifier as opaque. The adapter validates and maps
it. A `group` is desired membership in a target-side user collection. A target
may call that collection a group, team, or user group, but `team` is not a
separate canonical kind.

An `entitlement` is an independently assignable target-side capability or
right that is neither a named permission bundle (`role`) nor membership in a
target-side user collection (`group`). Real target integrations have
demonstrated this need. Conceptually,
`{ "kind": "entitlement", "id": "packet-capture-download" }`
means that the synchronized user
should possess that independently assignable target-side capability.
PermissionSync Core does not interpret the meaning of an entitlement
identifier. The selected adapter determines whether that entitlement exists or
is supported, how it maps to target state, whether it may be scoped, and
whether its combination with other assignments is valid. An entitlement may
use the same optional assignment-local `scope` representation as other kinds
when target semantics require it. Entitlements introduce no additional fields.

`team` and `organization` are not v1 kinds. No additional kinds are added
speculatively. New kinds, propagation values, or scope changes require
explicit versioned evolution and compatibility work across the Provider,
PermissionSync, and selected Adapter.
Each must support the document's model version. The selected Adapter must also
support the semantics and capabilities used by the document. Compatibility is
not automatic.

The Permission Provider owns WHAT access a user should have. It reads the
source representation it owns, resolves its source authorization schema, and
emits only assignments and constraints intentionally intended as desired
target state. Source-local roles, groups, entitlements, and restrictions are
inputs; they are not automatically forwarded.

The core transports and performs structural validation of the whole canonical
model only: supported version, assignment shape, allowed kinds (`role`,
`group`, `entitlement`), scope shape, propagation value, required fields,
constraint shape with `type` and string `values`, and at most one occurrence
of each constraint `type` per document. It rejects malformed or unsupported
documents before target mutation. It does not decide whether role, group, or
entitlement IDs exist or are meaningful for the target, whether a scope type
or ID exists, whether a target supports propagation or scoping of an
entitlement, whether a constraint value is valid, or whether mappings,
combinations, or constraint semantics are correct.

The selected Target Adapter owns HOW the desired target state is reconciled.
It completes target-semantic checks for the whole canonical model before
target mutation:
unknown or unsupported roles, groups, entitlements, scope types or IDs,
propagation, constraint types, individual constraint values, and unsupported
assignment or constraint combinations. It owns mappings and target support.
Unsupported or semantically invalid model values fail synchronization
and must not be made to appear supported by silently dropping, rewriting,
weakening, or defaulting semantics. This pre-mutation model-validation rule
does not change the uncertain downstream-effect behavior for valid target
operations under
[ADR 0006](0006-runtime-configuration-oci-and-observability.md).

A constraint expresses a desired access restriction that applies at the
synchronized-user or document level rather than to one assignment, such as a
target-wide user visibility or access restriction. A constraint contains
exactly `type` and `values`. The `type` is a stable provider-defined opaque
logical identifier; `values` is an array of opaque strings. Values may be
CIDRs, names, paths, selectors, or other logical values rather than
identifiers, which is why the field is named `values` and not `ids`. The
conceptual examples above are illustrative only: `network` and `interface`
are not canonical built-in constraint types.

PermissionSync Core does not interpret the business meaning of constraint
types or values. Structural validation is the core's only role here; it does
not decide whether `10.0.0.0/8` is a valid network value. The selected
adapter performs semantic interpretation and rejects unsupported constraint
types or invalid values before target mutation. In v1 each constraint `type`
may appear at most once in one desired-permission document, so ambiguous
union or intersection semantics never arise; multiple values for one type are
expressed inside that single constraint's `values`.

An absent constraint and a present constraint with an empty `values` array
are distinct states. An empty `values` array is structurally valid in the
canonical v1 model: PermissionSync Core accepts the structure and assigns it
no universal business meaning. The selected Target Adapter determines
whether, for its target, an empty values list means clearing a restriction,
deny-all, unsupported, semantically invalid, or something else. Neither form
is silently normalized into the other.

Constraints are desired authorization state, not deployment configuration.
A target URL, API token, username and password, TLS or CA material, target
API version configuration, adapter runtime options, deadline, or logging
configuration never appears in `assignments`, `scope`, or `constraints`;
such values belong to adapter runtime context.

The model is authoritative only within the explicitly configured managed
boundary, separately for managed assignment state and managed constraint
state. Absence from desired assignments authorizes removal only for
assignment state inside managed assignment authority. Likewise, absence from
desired constraints authorizes clearing or removal only for constraint types
explicitly delegated to PermissionSync. Empty assignment or constraint
collections do not grant authority over unrelated target state. Unmanaged
target permissions and unmanaged constraint dimensions remain untouched. The
exact runtime configuration representation of that boundary is deferred; this
ADR requires only the invariant.

This is a generic, reusable open-source boundary, not a universal IAM ontology.
It has no target-specific property bags. Exact Rust types, JSON and REST
schemas, serialization and version encoding, capability-negotiation mechanics,
and target API contracts are deferred.

## Consequences

Providers and adapters share a precise, small desired-state boundary.
The model has now been validated against materially different real
authorization shapes: multiple unscoped roles; scoped roles; hierarchical
`self` and `descendants` propagation; target-side user-collection membership;
independently assignable capabilities or rights; target-wide user visibility
or access restrictions expressed as document-level constraints; and multiple,
including repeated, assignments across scopes.

Adapters must reject model values they cannot support before mutation. They
must reconcile removal only within their configured managed authority.

## References

- [ADR 0001](0001-inbound-synchronization-contract.md)
- [ADR 0004](0004-generic-rest-permission-provider.md)
- [ADR 0006](0006-runtime-configuration-oci-and-observability.md)
