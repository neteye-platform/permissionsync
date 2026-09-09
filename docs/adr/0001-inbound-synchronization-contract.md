# ADR-0001: Inbound Synchronization Contract and Caller-Owned Workflow Policy

- **Status:** Accepted
- **Date:** 2026-08-24
- **Deciders:** R&D Team

## Context

PermissionSync receives a synchronous request to reconcile one user's desired
permissions with a selected target. A request that selects no PermissionSync
target completes as a targetless successful no-op; it does not reconcile a
target. The technical caller is distinct from the synchronized user. The caller
retains its own authentication and workflow decisions.

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

After successful authentication and structural `scope` validation,
PermissionSync counts exact `permissionsync:<target>` scope tokens under
[ADR 0002](0002-receiver-side-jwt-verification.md). Exactly one such token
selects a logical target: its suffix is the sole source of the logical target
and the sole target-routing selector. Zero such tokens select no logical target
and grant no authorization to any target. More than one such token is an
authorization failure. The v1 `target` identifier grammar governs the suffix of
the exactly one selected token:

    ^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$

The match is ASCII-only, lowercase, 1..64 characters long, and starts and ends
with an alphanumeric character; a one-character alphanumeric target is valid.
Internal characters are limited to `a-z`, `0-9`, `.`, `_`, and `-`. No leading
or trailing separator, spaces, colons, quotes, backslashes, control characters,
or arbitrary Unicode are allowed. A suffix from exactly one token that violates
this grammar is an unusable authorization grant and returns `403` under
[ADR 0002](0002-receiver-side-jwt-verification.md), not `400`: a caller cannot
force arbitrary routing input this way. It is not a zero-token request. A suffix
that matches this grammar passes minimal validation; recognized target routing
is target resolution under
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
3. Count scope tokens with the exact, case-sensitive `permissionsync:` prefix.
   An absent or empty `scope`, or a syntactically valid scope string with no
   such token, has a count of zero. Other OAuth scopes do not affect the count.
4. If the count is more than one, return `403`, including when the tokens are
   duplicates.
5. If the count is exactly one, extract its suffix as the logical target
   identifier and validate it against the v1 target identifier grammar. A suffix
   that violates the grammar is an unusable authorization grant and returns
   `403`.
6. Perform full strict validation of the fixed three-field request body. An
   invalid request body returns `400`.
7. If the count is zero, return `204` as a targetless successful no-op. Do not
   create or resolve a logical target, obtain synchronization capacity, inspect
   target-specific configuration, invoke the Permission Provider, invoke a
   Target Adapter, or construct an empty desired state.
8. If the count is exactly one with a grammar-valid target, resolve that logical
   target. If it is unknown or unrecognized by the runtime routing/configuration
   contract, return `400`. A recognized logical target whose server-side adapter
   or required target configuration is unavailable or broken returns target-local
   `500` as described by ADR 0006 and ADR 0007.
9. Obtain bounded synchronization capacity for the selected-target
   synchronization.
10. Invoke the Permission Provider as the request's single permitted Provider
    attempt, passing the selected logical target.
11. Structurally validate the `{version, payload}` envelope.
12. Invoke the selected Target Adapter as the request's single permitted Adapter
    reconciliation.
13. Return `200` when the selected Adapter reports that reconciliation changed
    target state, `204` when it reports unchanged, or the appropriate error
    status.

Authentication, structural scope validation, token cardinality, suffix
validation where applicable, and full strict request validation occur before
Permission Provider or Target Adapter work. Target resolution remains compatible
with [ADR 0006](0006-runtime-configuration-oci-and-observability.md). Delivery
and reconciliation behavior is defined by
[ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md).

Once a request enters the selected-target synchronization path, a successful
`200` or selected-target `204` requires successful completion of both the
Permission Provider invocation and the selected Target Adapter invocation.
Earlier failures, including invalid bodies, target resolution or target-local
configuration failures, capacity or deadline failures, Provider failures, and
invalid desired-state envelopes, can prevent Adapter invocation. No layer before
the selected Adapter may manufacture a successful selected-target `200` or
`204`; the selected Adapter is the sole authority for `changed` versus
`unchanged` reconciliation.

After successful authentication and structural scope validation, the public
scope-selection outcomes are:

| PermissionSync scope count | Fixed body | Result |
| --- | --- | --- |
| 0 | valid | Targetless `204`; no target work |
| 0 | invalid | `400` |
| 1, valid suffix | valid | Target path: `200` or Adapter `204` |
| 1, valid suffix | invalid | `400` |
| 1, invalid suffix | any | `403` |
| More than 1 | any | `403` |

More than one PermissionSync scope plus a malformed body returns `403`, because
cardinality rejection precedes body validation. Exactly one PermissionSync scope
with an invalid suffix plus a malformed body likewise returns `403`. Zero
PermissionSync scopes plus a malformed body returns `400`, because the
targetless successful no-op occurs only after strict body validation.

Structural scope failures remain `401` before this matrix. More than one exact
PermissionSync token, and exactly one token with a grammar-invalid suffix, are
rejected before PermissionSync evaluates the request body or checks whether a
target is recognized or configured. A zero-token request does validate its body,
but performs no target resolution or target-specific lookup, so it cannot reveal
whether any target name exists. Only after exactly one grammar-valid target
token and a valid body does PermissionSync resolve that target: an unknown or
unrecognized logical target receives `400`, and a recognized logical target
with an unavailable or broken server-side adapter or target configuration
receives target-local `500`.

Response semantics are:

- `200`: successful selected-target reconciliation and target state changed.
- `204`: either a targetless successful no-op after a valid request selected no
  PermissionSync target and performed no reconciliation, or successful
  selected-target reconciliation whose Target Adapter reported `unchanged`.
- `400`: invalid request body, or an unknown or unrecognized logical target
  extracted from an authorized scope.
- `401`: caller credential validation failure, including a wrong-shaped or
  syntactically invalid `scope` claim.
- `403`: authenticated with a structurally valid `scope`, but it contains more
  than one exact `permissionsync:` token or exactly one such token with a
  grammar-invalid target suffix.
- `500`: synchronization, internal, provider, adapter, or other server-side
  failure, including unavailable or broken configuration for a recognized
  logical target.

PermissionSync is a reconciliation service. Target-side resource creation is an
implementation detail of reconciliation and does not control the public HTTP
status; `201` is not part of this contract.

The Target Adapter must provide enough internal result information to
distinguish `changed` from `unchanged` selected-target reconciliation. It need
not expose exactly what resource was created or modified, and no response body
is required for this distinction. A targetless successful no-op is not an
Adapter result and does not imply reconciliation. Internal models may be richer,
but cannot replace these wire semantics.

The caller alone decides whether a result affects authentication or its
workflow. PermissionSync does not decide authentication success.

Changes to the public wire contract require an explicit contract revision.

## Alternatives considered

No material alternatives were recorded for this decision.

## Consequences

Callers have one exact, synchronous wire contract and retain workflow policy.
PermissionSync keeps caller identity distinct from synchronized user identity,
can complete a valid targetless delivery without granting access to a target,
and can evolve internal reconciliation models without changing the contract.

## References

- [ADR 0002](0002-receiver-side-jwt-verification.md)
- [ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md)
- [ADR 0006](0006-runtime-configuration-oci-and-observability.md)
- [ADR index](README.md)
