# Inbound Synchronization Contract and Caller-Owned Workflow Policy

## Status

Accepted

## Context

PermissionSync receives a synchronous request to reconcile one user's desired
permissions with a selected target. The technical caller is distinct from the
synchronized user. The caller retains its own authentication and workflow
decisions.

## Decision

PermissionSync exposes this synchronous request:

```http
POST /api/sync-user
Authorization: Bearer <technical-service-jwt>
Content-Type: application/json
```

The JSON body has exactly these six fields and no others:

- `event_type`: string, exactly `LOGIN`.
- `client_id`: non-null string OIDC client and target selector.
- `username`: non-null string.
- `email`: nullable string.
- `groups`: array of strings supplied as full group-path values.
- `timestamp`: ISO-8601 UTC string truncated to whole seconds.

PermissionSync validates the body strictly; it rejects invalid JSON and unknown
JSON fields rather than ignoring them. At minimum, `400` applies to malformed
JSON, a missing required field, an unknown extra field, or a wrong JSON type,
including for `email`. It also applies to `event_type` other than `LOGIN`, an
illegal null for a non-nullable field, `groups` that is not an array, a
non-string group member, or a timestamp that is not ISO-8601 UTC with
whole-second precision.

`client_id` and `username` require non-null strings, with no additional grammar
imposed. Group strings are preserved as provided, with no new path grammar
imposed. A non-null string `client_id` passes wire-schema validation; configured
target recognition is target resolution under
[ADR 0007](0007-runtime-configuration-oci-and-observability.md),
not JSON validation.

```json
{
  "event_type": "LOGIN",
  "client_id": "example-client",
  "username": "alex",
  "email": "alex@example.test",
  "groups": ["/engineering/platform", "/engineering/security"],
  "timestamp": "2026-08-25T12:34:56Z"
}
```

The body must not gain request, event, or correlation IDs, idempotency keys,
retry metadata, or arbitrary metadata without an explicit contract revision.
Future correlation should be transport metadata, owned by
[ADR 0007](0007-runtime-configuration-oci-and-observability.md).

The technical caller is authenticated and authorized under
[ADR 0002](0002-receiver-side-jwt-verification.md). Authentication and
authorization occur first, followed by strict request validation. All occur
before target resolution, Permission Provider, or Target Adapter work. Target
resolution remains compatible with
[ADR 0007](0007-runtime-configuration-oci-and-observability.md).
Delivery and reconciliation behavior is defined by
[ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md).

Response semantics are:

- `200`: successful synchronization.
- `201`: successful synchronization when PermissionSync can meaningfully
  report creation of target-side resources.
- `400`: invalid request.
- `401`: caller credential validation failure.
- `403`: authenticated but unauthorized.
- `500`: synchronization, internal, provider, or adapter failure.

PermissionSync does not define a response body or mandatory public outcome
enum. Both `200` and `201` are valid success responses; adapter or API
specifications may refine their selection. Internal models may be richer, but
cannot replace these wire semantics. An internal adapter result may optionally
expose creation information when its target contract can determine it
meaningfully, without defining a public type or enum. No Target Adapter is
required to expose or determine creation state.
The caller alone decides whether a result affects authentication or its
workflow. PermissionSync does not decide authentication success.

`/api/sync-user` may be provisional during 0.x. Any route, body, or status
change requires explicit compatibility work and a caller contract revision.

## Consequences

Callers have one exact, synchronous wire contract and retain workflow policy.
PermissionSync keeps caller identity distinct from synchronized user identity,
and can evolve internal reconciliation models without changing the contract.

## References

- [ADR 0002](0002-receiver-side-jwt-verification.md)
- [ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md)
- [ADR 0007](0007-runtime-configuration-oci-and-observability.md)
- [ADR index](README.md)
