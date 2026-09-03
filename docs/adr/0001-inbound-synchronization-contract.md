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

The JSON body has exactly these five fields and no others:

- `event_type`: string, exactly `LOGIN`.
- `target`: non-null string identifying the requested target/adapter, matching
  the v1 target identifier grammar.
- `username`: non-null string, the canonical NetEye user key.
- `groups`: array of strings supplied as full group-path values.
- `timestamp`: ISO-8601 UTC string truncated to whole seconds.

PermissionSync validates the body strictly; it rejects invalid JSON and unknown
JSON fields rather than ignoring them. At minimum, `400` applies to malformed
JSON, a missing required field, an unknown extra field, or a wrong JSON type. It
also applies to `event_type` other than `LOGIN`, an illegal null for a
non-nullable field, `groups` that is not an array, a non-string group member, or
a timestamp that is not ISO-8601 UTC with whole-second precision. An unknown or
unsupported `target` is rejected with `400`.

The v1 `target` identifier grammar is:

    ^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$

The match is ASCII-only, lowercase, 1..64 characters long, and starts and ends
with an alphanumeric character; a one-character alphanumeric target is valid.
Internal characters are limited to `a-z`, `0-9`, `.`, `_`, and `-`. No leading
or trailing separator, spaces, colons, quotes, backslashes, control characters,
or arbitrary Unicode are allowed. Because `target` is used directly to derive
`permissionsync:<target>`, it is NOT an arbitrary non-null string; a `target`
that violates this grammar is rejected with `400` during the minimal target
validation that precedes scope derivation, so a caller cannot force arbitrary
input into an OAuth scope name.

`username` requires a non-null string, with no additional grammar imposed.
Group strings are preserved as provided, with no new path grammar imposed. A
`target` matching the identifier grammar passes minimal validation; recognized
target routing is target resolution under
[ADR 0006](0006-runtime-configuration-oci-and-observability.md), not JSON
validation.

    {
      "event_type": "LOGIN",
      "target": "glpi",
      "username": "jdoe",
      "groups": ["/staff", "/staff/engineering"],
      "timestamp": "2026-08-24T09:15:32Z"
    }

The body must not gain request, event, or correlation IDs, idempotency keys,
retry metadata, or arbitrary metadata without an explicit contract revision.
Future correlation should be transport metadata, owned by
[ADR 0006](0006-runtime-configuration-oci-and-observability.md).

The processing order for every request is fixed:

1. Authenticate the technical caller's JWT under
   [ADR 0002](0002-receiver-side-jwt-verification.md).
2. Parse and validate the request only enough to obtain a usable `target`
   value: the body must be parseable enough to read `target`, `target` must be
   present, `target` must be a non-null string, and `target` must match the v1
   target identifier grammar. If this minimal target extraction or grammar
   validation cannot be performed, return `400`.
3. Derive the required authorization scope deterministically:
   `permissionsync:<target>`.
4. Authorize the authenticated technical caller for that derived scope. If the
   caller lacks the required scope, return `403`. This authorization check
   intentionally happens BEFORE full strict validation of the remaining
   request fields, before target resolution, and before any check of whether
   the target is actually supported or configured: an authenticated caller who
   is not authorized for a target name must not be able to determine whether
   that target exists or is supported.
5. Perform full strict validation of the fixed five-field request body. An
   invalid request returns `400`.
6. Resolve the target. If the caller was authorized for the derived target
   scope but the target is unknown or unsupported, return `400`.
7. Obtain bounded synchronization capacity.
8. Invoke the Permission Provider once.
9. Structurally validate the `{version, payload}` envelope.
10. Invoke the selected Target Adapter once.
11. Return `200` when reconciliation changed target state, `204` when the
    target was already in the desired state, or the appropriate error status.

Authentication, authorization, full strict request validation, and target
resolution all occur before Permission Provider or Target Adapter work. Target
resolution remains compatible with
[ADR 0006](0006-runtime-configuration-oci-and-observability.md).
Delivery and reconciliation behavior is defined by
[ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md).

Because authorization for the derived scope precedes target resolution, an
authenticated caller who lacks `permissionsync:<target>` for a given target name
receives `403` before PermissionSync determines whether that target exists or is
supported. PermissionSync does not reveal target existence to unauthorized
callers. An authenticated and authorized caller who requests a target that is
unknown or unsupported receives `400`.

Response semantics are:

- `200`: successful reconciliation and target state changed.
- `204`: successful reconciliation but target state was already in the desired
  state.
- `400`: invalid request, or an unknown or unsupported target.
- `401`: caller credential validation failure.
- `403`: authenticated but not authorized for the requested target.
- `500`: synchronization, internal, provider, adapter, or server-side failure.

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

`/api/sync-user` may be provisional during 0.x. Any route, body, or status
change requires explicit compatibility work and a caller contract revision.

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
