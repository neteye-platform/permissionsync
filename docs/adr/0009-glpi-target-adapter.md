# ADR-0009: GLPI Target Adapter

- **Status:** Accepted
- **Date:** 2026-09-21
- **Deciders:** R&D Team

## Context

PermissionSync needs a concrete Target Adapter for GLPI 11. The Provider
decides which permissions a user should have. The adapter must turn that desired
state into GLPI's user, entity, profile, and recursive-assignment model without
putting GLPI concepts into Core or routing.

In GLPI, the relevant relationship is `Profile_User`. One assignment links a
user, entity, and profile, and carries `is_recursive`. A GLPI permission state
is therefore the complete set of those assignments for one user.

This record defines the adapter contract only. It does not add the future
`permissionsync-adapter-glpi` crate, runtime configuration, registration, or
HTTP implementation.

## Decision

### Identity, scope, and ownership

The adapter is named **GLPI Target Adapter**. Its runtime adapter identifier is
`glpi`; its future crate is `permissionsync-adapter-glpi`.

It targets GLPI 11 and owns reconciliation of one user's complete
`Profile_User` assignment set. The authoritative permission key is:

| Field | GLPI relationship field |
| --- | --- |
| user | `users_id` |
| entity | `entities_id` |
| profile | `profiles_id` |
| recursive | `is_recursive` |

The adapter may create a missing user and may create or delete `Profile_User`
assignments. It does not create or modify entities or profiles, and it does not
manage unrelated GLPI configuration or user attributes. Numeric GLPI IDs are
adapter-internal resolution results; they are not a Provider contract.

With the current unchanged Core and routing contracts, this adapter has one
configured GLPI target per PermissionSync process. `TargetAdapterRequest` has
no logical-target or target-configuration selector, and `glpi` identifies one
registered adapter instance. Supporting several independently configured GLPI
instances requires a later architecture decision; this record does not define
that mechanism.

### Desired-state payload v1

The Provider sends the versioned envelope from
[ADR 0005](0005-versioned-adapter-specific-desired-state-envelope.md). The GLPI
adapter supports only version `1`.

```json
{
  "version": 1,
  "payload": {
    "user": {
      "username": "jdoe"
    },
    "permissions": [
      {
        "entity": "Root Entity > IT",
        "profile": "Technician",
        "recursive": true
      },
      {
        "entity": "Root Entity > IT > Operations",
        "profile": "Read-Only",
        "recursive": false
      }
    ]
  }
}
```

The payload is one object with exactly `user` and `permissions`. `user` is one
object with exactly the non-empty string `username`; it selects exactly one
GLPI user. `permissions` is an array of zero or more objects. Every permission
object has exactly the non-empty strings `entity` and `profile`, and the boolean
`recursive`.

The adapter rejects unsupported versions, unknown or duplicate JSON members,
wrong types, empty selectors, extra user shapes, and duplicate or contradictory
permissions. Two permissions conflict when they name the same entity and
profile, including when their `recursive` values differ. The adapter does not
trim, normalize, default, or otherwise rewrite selectors or recursive values.

An empty list is an authoritative empty state:

```json
{
  "version": 1,
  "payload": {
    "user": {
      "username": "jdoe"
    },
    "permissions": []
  }
}
```

It means: create `jdoe` if missing, remove every existing `Profile_User`
assignment for that user, and finish with no assignments.

### User, entity, and profile resolution

`user.username` is the Provider-supplied selector for the PermissionSync user.
The adapter receives no `IdentityContext` and does not compare it with the
inbound username. It matches the selector exactly against the GLPI `User.name`
login and fails if lookup returns more than one exact match.

GLPI's search `equals` operator is not a strict-string guarantee and is
paginated. The adapter must retrieve all relevant pages, then perform its own
exact, case-sensitive string comparison for user, entity, and profile
selectors. It must reject a username that GLPI would reject as a login before
any mutation.

If no matching user exists, the adapter creates a User whose only
Provider-controlled value is exactly that `name`. It does not set a password,
default profile, default entity, or any other user attribute. GLPI may apply its
own defaults, rules, or dynamic assignment during creation; the subsequent
authoritative `Profile_User` reconciliation removes any assignment not desired.

`entity` is the exact full entity path stored by GLPI as `Entity.completename`,
such as `Root Entity > IT`. It is not a numeric ID or a path that the adapter
parses, normalizes, or creates. Each entity selector must resolve to exactly one
existing entity.

`profile` is the exact GLPI `Profile.name`. A profile name is a semantic
selector, not a numeric ID. Each selector must resolve to exactly one existing
profile; a missing or ambiguous profile is an error. This deliberate
single-match rule makes a non-unique GLPI profile name safe for the Provider
contract without leaking GLPI IDs.

After structural validation, the adapter resolves every entity and profile
reference before it changes GLPI. If any reference is missing or ambiguous,
reconciliation fails before user creation, assignment deletion, or assignment
creation. Entities and profiles are never created as a fallback.

### Authoritative reconciliation

After user lookup or creation, the adapter reads every page of that user's
current `Profile_User` assignments. The service account must have an active
GLPI profile and entity access that makes this read complete; incomplete ACL
visibility is invalid target configuration, not a partial reconciliation mode.

The adapter compares the resolved `(entity, profile, recursive)` tuples with
the desired set. `is_dynamic`, `is_default_profile`, and other relationship
metadata are not desired-state fields; the adapter does not create or update
them separately. It nevertheless owns every `Profile_User` row for the
synchronized user. GLPI rules, LDAP synchronization, or another writer must
not concurrently manage those assignments.

- One desired tuple already present is retained.
- A desired tuple not present is missing and must be added.
- A current tuple not desired is stale and must be removed.
- A different `recursive` value is both a stale tuple and a missing tuple.
- Extra current rows with the same desired tuple are stale and must be removed.
- An empty desired list removes all current assignments for the user.

The adapter must delete every stale assignment before it creates any missing
assignment. It must not update an assignment in place to change `recursive`.
It uses one mutation per request and verifies that each response represents the
requested successful mutation before beginning the next one. A failed removal,
including a mixed-status response, stops reconciliation; the add phase does not
start.

| Stage | Example assignment |
| --- | --- |
| Current | `Root Entity > IT` / `Technician` / `true` |
| Current | `Root Entity > Legacy` / `Read-Only` / `false` |
| Desired | `Root Entity > IT` / `Technician` / `true` |
| Desired | `Root Entity > IT > Operations` / `Read-Only` / `false` |
| Plan | **REMOVE** `Root Entity > Legacy` / `Read-Only` / `false` |
| Plan | **ADD** `Root Entity > IT > Operations` / `Read-Only` / `false` |

The final state is exactly the desired state. Successful reconciliation returns
`Unchanged` only when the user already existed and its assignment set exactly
matched the desired set. It returns `Changed` when it creates the user or
successfully adds or removes an assignment. These are the existing
`ReconciliationOutcome` values; no GLPI detail is returned to the caller.

### GLPI API and authentication

The adapter uses GLPI 11's V1 REST API at the configured HTTPS
`apirest.php` endpoint. This is the only selected API contract; there is no
V1/V2 fallback. GLPI 11.0.0 is the verified compatibility baseline. A later
GLPI 11.x implementation update must validate the same contract before it is
supported.

The V1 API exposes the `Profile_User` item type and its
`users_id`, `profiles_id`, `entities_id`, and `is_recursive` fields. Its generic
itemtype endpoints provide the reads, creates, and deletes needed for
reconciliation. The verified GLPI 11.0.0 High-Level API inventory has no
equivalent `Profile_User` operation. V2 is therefore not selected for this
contract.

| Need | V1 REST operation |
| --- | --- |
| Begin authentication | `GET /apirest.php/initSession/` |
| Resolve users, entities, profiles, assignments | `GET /apirest.php/search/:itemtype/` and item reads |
| Create missing user or assignment | `POST /apirest.php/:itemtype/` |
| Remove stale assignment | `DELETE /apirest.php/Profile_User/:id` |
| End the request-scoped session | `GET /apirest.php/killSession/` |

Authentication is request-scoped GLPI session authentication. The adapter
starts a session with the configured least-privilege service account's
long-lived GLPI user token in `Authorization: user_token <token>` and the
configured `App-Token`. GLPI returns a session token. Subsequent API requests
use `Session-Token` and `App-Token`; the adapter ends the session with
`killSession` on every path after a successful session start when the remaining
budget permits. It does not persist, share, or log user tokens or session
tokens. Cleanup never starts after observed cancellation or expiry. A
`killSession` failure after otherwise successful reconciliation is an adapter
failure; after an earlier failure, it does not replace the primary failure.

Endpoint, user token, App-Token, TLS trust material, and operation timeouts are
runtime target configuration. They are not part of the desired state.

### Failure, partial state, and request bounds

Invalid payloads, unresolved references, ambiguous user lookup, and GLPI/API
failures are adapter failures on the existing target-local server-side path.
They never become an empty state, a successful no-op, or an alternate user
selection.

Once a mutation has succeeded, later failure can leave a partial GLPI state.
The adapter performs no rollback and no automatic retry. A later legitimate
reconciliation reads the current assignment set and converges toward the same
desired state. This follows the single-attempt and idempotent-convergence
contract in [ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md).

Every GLPI request, including session work, is bounded by the remaining overall
`SynchronizationContext` budget. The adapter observes propagated cancellation,
does not start new target work after observed cancellation or expiry, and does
not detach work. HTTPS with certificate and hostname verification is required;
configured private CA trust remains supported. Credentials, tokens, usernames,
full desired state, mapping details, and raw GLPI responses must not appear in
ordinary errors, logs, or metric labels. These requirements apply as specified
by [ADR 0006](0006-runtime-configuration-oci-and-observability.md) and
[ADR 0007](0007-compile-time-rust-target-adapters.md).

### Implementation test contract

The implementation PR must use deterministic, hermetic local GLPI V1 fakes or
fixtures. It must not use public Internet, production GLPI, fixed ports,
arbitrary sleeps, or retries. At minimum, it must prove:

- strict payload validation: only version 1, no unknown fields or invalid user
  shapes, no duplicate or contradictory permissions, and every desired reference
  validated before mutation;
- exact username lookup, missing-user creation, ambiguous-user failure, and
  missing user plus an empty desired state creating no assignments after final
  reconciliation;
- exact full-path entity resolution and exact profile-name resolution, including
  nested paths, missing and ambiguous references, pagination, lookalike or
  selector-metacharacter values, and no entity/profile creation;
- authoritative additions, removals, empty-state removal, recursive differences,
  duplicate current rows, dynamic/default assignment created by GLPI, and an
  exact final assignment set;
- observable operation order proving removals happen before additions;
- idempotency: an intentionally divergent first reconciliation is `Changed`,
  the same desired state is `Unchanged`, and no duplicate effects occur;
- partial failure after user creation, during deletion, and during the add phase
  after removals: no rollback or automatic retry, then later legitimate
  convergence; including mixed-status mutation responses;
- deadline and cancellation: bounded return, no operation starts after observed
  expiry/cancellation, and no detached work remains; and
- the selected V1 endpoints plus `Authorization`, `App-Token`, `Session-Token`,
  `initSession`, `killSession`, cleanup, and primary-failure semantics;
- complete-assignment access required of the configured GLPI service account;
  and
- transport and redaction safety: reject HTTP, redirects, and disabled
  certificate or hostname verification; accept an explicitly configured private
  CA; reject untrusted certificates; and keep sentinel tokens, usernames,
  selectors, and raw GLPI responses out of ordinary errors and telemetry.

An optional real-GLPI compatibility check may be added outside required PR CI.

## Alternatives considered

- **Provider supplies GLPI numeric IDs:** rejected because IDs are deployment
  internals and would couple the Provider to a GLPI instance.
- **Additive-only synchronization:** rejected because the payload is the user's
  complete authoritative assignment state.
- **Create missing entities or profiles:** rejected because they are outside the
  adapter's permission-assignment ownership.
- **Add assignments before removing stale ones:** rejected in favor of the
  explicit remove-before-add plan.
- **GLPI V2, or runtime V1/V2 fallback:** rejected because the verified GLPI
  11.0.0 V2 inventory has no equivalent `Profile_User` operation, and fallback
  would make the API contract non-deterministic.

## Consequences

The subsequent implementation has one GLPI 11 API and session contract, a
Provider payload free of GLPI IDs and credentials, and an explicit authoritative
set-reconciliation algorithm. It must use a service account with only the GLPI
rights needed to find/create users and manage their `Profile_User` assignments.

Implementation, crate creation, registration, runtime configuration schema,
HTTP client choice, concrete timeout values, and target credential/trust
delivery remain deferred to the implementation/runtime PR.

## References

- [ADR 0001](0001-inbound-synchronization-contract.md)
- [ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md)
- [ADR 0005](0005-versioned-adapter-specific-desired-state-envelope.md)
- [ADR 0006](0006-runtime-configuration-oci-and-observability.md)
- [ADR 0007](0007-compile-time-rust-target-adapters.md)
- [GLPI REST API documentation](https://github.com/glpi-project/glpi/blob/11.0.0/apirest.md)
- [GLPI `Profile_User` source](https://github.com/glpi-project/glpi/blob/11.0.0/src/Profile_User.php)
- [GLPI `User` source](https://github.com/glpi-project/glpi/blob/11.0.0/src/User.php)
- [GLPI V2 OpenAPI generator](https://github.com/glpi-project/glpi/blob/11.0.0/src/Glpi/Api/HL/OpenAPIGenerator.php)
- [GLPI High-Level API documentation](https://glpi-developer-documentation.readthedocs.io/en/master/devapi/hlapi/index.html)
