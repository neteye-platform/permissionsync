# ADR-0001: Inbound Synchronization Contract and Caller-Owned Workflow Policy

- **Status:** Accepted
- **Date:** 2026-08-24
- **Deciders:** R&D Team

## Context

PermissionSync receives a synchronous request to reconcile one user's desired
permissions with a selected target. The technical caller is distinct from the
synchronized user. The caller retains its own authentication and workflow
decisions.

## Decision

PermissionSync exposes this synchronous request:

    POST /api/sync-user
    Authorization: Bearer <technical-service-jwt>
    Content-Type: application/json

The JSON body has exactly these three fields and no others:

- `event_type`: string, exactly `LOGIN`.
- `username`: non-null string, the canonical NetEye user key.
- `groups`: array of strings supplied as full group-path values.

PermissionSync validates the body strictly; it rejects invalid JSON and unknown
JSON fields rather than ignoring them. At minimum, `400` applies to malformed
JSON, a missing required field, an unknown extra field, or a wrong JSON type. It
also applies to `event_type` other than `LOGIN`, an illegal null for a
non-nullable field, `groups` that is not an array, or a non-string group member.

`username` requires a non-null string, with no additional grammar imposed.
Group strings are preserved as provided, with no new path grammar imposed.

The logical target is extracted from exactly one authorized
`permissionsync:<target>` JWT scope token under
[ADR 0002](0002-receiver-side-jwt-verification.md), which is the sole source of
the logical target and the sole target-routing selector. The v1 `target`
identifier grammar governs that extracted suffix:

    ^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$

The match is ASCII-only, lowercase, 1..64 characters long, and starts and ends
with an alphanumeric character; a one-character alphanumeric target is valid.
Internal characters are limited to `a-z`, `0-9`, `.`, `_`, and `-`. No leading
or trailing separator, spaces, colons, quotes, backslashes, control characters,
or arbitrary Unicode are allowed. An extracted target that violates this
grammar is an unusable authorization grant and returns `403` under
[ADR 0002](0002-receiver-side-jwt-verification.md), not `400`: a caller cannot
force arbitrary routing input this way. An extracted target that matches this
grammar passes minimal validation; recognized target routing is target
resolution under
[ADR 0006](0006-runtime-configuration-oci-and-observability.md), not scope
parsing.

    {
      "event_type": "LOGIN",
      "username": "jdoe",
      "groups": ["/staff", "/staff/engineering"]
    }

The body must not gain request, event, or correlation IDs, idempotency keys,
retry metadata, or arbitrary metadata without an explicit contract revision.
Future correlation should be transport metadata, owned by
[ADR 0006](0006-runtime-configuration-oci-and-observability.md).

The processing order for every request is fixed:

1. Authenticate the technical caller's JWT under
   [ADR 0002](0002-receiver-side-jwt-verification.md). A missing or malformed
   bearer token, an invalid signature, or a missing or malformed authentication
   claim returns `401`.
2. Validate the `scope` claim's shape and, if nonempty, its RFC 6749 syntax
   under [ADR 0002](0002-receiver-side-jwt-verification.md). A wrong-shaped
   `scope`, or a nonempty `scope` string that violates RFC 6749 syntax, returns
   `401`.
3. Require exactly one scope token with the exact, case-sensitive prefix
   `permissionsync:`. An absent or empty `scope`, a syntactically valid `scope`
   with no such token, or more than one such token, returns `403`.
4. Extract the suffix of that one token as the logical target identifier and
   validate it against the v1 target identifier grammar. A suffix that
   violates the grammar is an unusable authorization grant and returns `403`.
5. Perform full strict validation of the fixed three-field request body. An
   invalid request body returns `400`.
6. Resolve the extracted logical target. If it is unknown or unrecognized by
   the runtime routing/configuration contract, return `400`. A recognized
   logical target whose server-side adapter or required target configuration
   is unavailable or broken returns target-local `500` as described by ADR
   0006 and ADR 0007.
7. Obtain bounded synchronization capacity.
8. Invoke the Permission Provider once, passing the extracted logical target.
9. Structurally validate the `{version, payload}` envelope.
10. Invoke the selected Target Adapter once.
11. Return `200` when reconciliation changed target state, `204` when the
    target was already in the desired state, or the appropriate error status.

Authentication, scope validation and target extraction, full strict request
validation, and target resolution all occur before Permission Provider or
Target Adapter work. Target resolution remains compatible with
[ADR 0006](0006-runtime-configuration-oci-and-observability.md).
Delivery and reconciliation behavior is defined by
[ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md).

Scope validation and target extraction precede full strict body validation and
target resolution: a caller without exactly one valid-grammar
`permissionsync:<target>` scope token is rejected with `401` or `403` before
PermissionSync evaluates the request body or checks whether any candidate
target is recognized or configured, so an unauthorized caller cannot learn
whether any target name exists. Only once a caller holds exactly one such
valid token does PermissionSync resolve the extracted target: an unknown or
unrecognized logical target receives `400`, and a recognized logical target
with an unavailable or broken server-side adapter or target configuration
receives target-local `500`.

Response semantics are:

- `200`: successful reconciliation and target state changed.
- `204`: successful reconciliation but target state was already in the desired
  state.
- `400`: invalid request body, or an unknown or unrecognized logical target
  extracted from an authorized scope.
- `401`: caller credential validation failure, including a wrong-shaped or
  syntactically invalid `scope` claim.
- `403`: authenticated, but the JWT `scope` does not grant exactly one valid
  `permissionsync:<target>` authorization for a grammar-valid target.
- `500`: synchronization, internal, provider, adapter, or other server-side
  failure, including unavailable or broken configuration for a recognized
  logical target.

PermissionSync is a reconciliation service. Target-side resource creation is an
implementation detail of reconciliation and does not control the public HTTP
status; `201` is not part of this contract.

The Target Adapter must provide enough internal result information to
distinguish `changed` from `unchanged` reconciliation. It need not expose
exactly what resource was created or modified, and no response body is required
for this distinction. Internal models may be richer, but cannot replace these
wire semantics.

The caller alone decides whether a result affects authentication or its
workflow. PermissionSync does not decide authentication success.

Changes to the public wire contract require an explicit contract revision.

## Alternatives considered

No material alternatives were recorded for this decision.

## Consequences

Callers have one exact, synchronous wire contract and retain workflow policy.
PermissionSync keeps caller identity distinct from synchronized user identity,
and can evolve internal reconciliation models without changing the contract.

## References

- [ADR 0002](0002-receiver-side-jwt-verification.md)
- [ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md)
- [ADR 0006](0006-runtime-configuration-oci-and-observability.md)
- [ADR index](README.md)
