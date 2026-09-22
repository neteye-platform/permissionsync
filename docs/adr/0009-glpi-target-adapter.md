# ADR-0009: GLPI Target Adapter

- **Status:** Accepted
- **Date:** 2026-09-21
- **Deciders:** R&D Team

## Context

PermissionSync needs a concrete Target Adapter for GLPI. The Provider decides
which permissions a user should have. The adapter must turn that desired state
into GLPI's user, entity, profile, and recursive-assignment model without
putting GLPI concepts into Core or routing.

In GLPI, the relevant relationship is `Profile_User`. One assignment links a
user, entity, and profile, and carries `is_recursive`. A GLPI permission state
is therefore the complete set of those assignments for one user.

## Decision

### Identity, scope, and ownership

The adapter is named **GLPI Target Adapter**. Its runtime adapter identifier is
`glpi`; its crate identifier is `permissionsync-adapter-glpi`. These identifiers
remain stable across GLPI release and major-version changes.

It targets GLPI and owns reconciliation of one user's complete `Profile_User`
assignment set. For the synchronized user, `(entity, profile, recursive)` is a
complete desired or current GLPI assignment. `(entity, profile)` is solely the
normalization and grouping identity; a physical `Profile_User` row may also
carry GLPI metadata. The GLPI relationship fields are:

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

This adapter has one configured GLPI backend per PermissionSync process.
`TargetAdapterRequest` conceptually carries the synchronized `IdentityContext`
separately from the desired-state envelope and `SynchronizationContext`; it has
no logical-target or target-configuration selector. `glpi` identifies one
registered adapter instance.

### Desired-state payload v1

The Provider sends the versioned envelope from
[ADR 0005](0005-versioned-adapter-specific-desired-state-envelope.md). The GLPI
adapter supports only version `1`.

```json
{
  "version": 1,
  "payload": {
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

The payload is one object with exactly `permissions`; it contains no `user`,
`username`, `identity`, or `subject` field. `permissions` is an array of zero or
more objects. Every permission object has exactly the non-empty strings `entity`
and `profile`, and the boolean `recursive`.

The adapter rejects unsupported versions, unknown JSON members, wrong types, and
empty selectors. As GLPI-specific payload validation, it rejects duplicate
`permissions` members in the payload object and duplicate `entity`, `profile`,
or `recursive` members in a permission object before any GLPI request. This is
separate from ADR 0008's common envelope handling of duplicate `version` and
`payload` members.

The Provider supplies every valid permission entry and its requested `recursive`
value. The adapter structurally validates every permission entry, then groups
valid entries by the exact `(entity, profile)` pair. Repeated complete permission
objects and mixed `recursive` values for one pair are valid. The canonical
`recursive` value is `true` when any entry in the group is `true`; otherwise it
is `false`. The adapter does not independently choose an input `recursive`
value. It owns only deterministic representation normalization: selector strings
are never altered, and normalization removes only semantic repetition. This
canonicalization is owned by the GLPI adapter, not Core.

Repeated complete objects in the `permissions` array are valid Provider intent:

```json
{
  "permissions": [
    {"entity": "Root Entity > IT", "profile": "Technician", "recursive": false},
    {"entity": "Root Entity > IT", "profile": "Technician", "recursive": false}
  ]
}
```

This is accepted and normalizes to one complete desired assignment for `Root
Entity > IT` / `Technician` / `false`.

```json
{
  "permissions": [
    {"entity": "Root Entity > IT", "profile": "Technician", "recursive": false},
    {"entity": "Root Entity > IT", "profile": "Technician", "recursive": true}
  ]
}
```

This is accepted and normalizes to one complete desired assignment for `Root
Entity > IT` / `Technician` / `true`.

These are not repeated member names within JSON objects. For example, this
permission object is contract-invalid because `entity` appears twice:

```json
{
  "entity": "Root Entity > IT",
  "entity": "Root Entity > IT",
  "profile": "Technician",
  "recursive": false
}
```

The adapter rejects this GLPI-specific duplicate-member form before any GLPI
request. It does not normalize invalid repeated entries.

The Permission Provider resolves the envelope for the synchronized
`IdentityContext`. The generic adapter request carries that identity separately
from the envelope. Core does not inspect GLPI payload or compare it with
identity, and the GLPI adapter uses identity as its sole synchronized-subject
source.

An empty list is an authoritative empty state:

```json
{
  "version": 1,
  "payload": {
    "permissions": []
  }
}
```

When the synchronized `IdentityContext` username is `jdoe` and `permissions` is
empty, the adapter validates the payload with no entity or profile references,
looks up `jdoe` by GLPI `User.name`, creates it if absent, removes every
`Profile_User` assignment, and finishes with an empty set. Creating the user
returns `Changed`.

### User, entity, and profile resolution

The adapter derives the username from `IdentityContext` under the inbound
identity contract and preserves it exactly. No username exists in the payload.
The adapter matches the username exactly against the GLPI `User.name` login and
fails if lookup returns more than one exact match. It uses a result only when
exactly one exact match exists.

GLPI's search `equals` operator is not a strict-string guarantee and is
paginated. The adapter must retrieve all relevant pages, then perform its own
exact, case-sensitive string comparison for user, entity, and profile
selectors. Complete visibility of GLPI User records relevant to the adapter is
required target and service-account configuration before it decides a user is
absent. An empty or filtered zero-result lookup proves absence only under that
guarantee; otherwise reconciliation MUST fail closed before creation and MUST
NOT treat the user as absent.

If no matching user exists, GLPI, not PermissionSync, decides whether the exact
username may be created. The adapter makes `POST /apirest.php/User/` as a
separate mutation request before any `Profile_User` mutation. It sends the
preserved username as `name` and only the target-configuration user-provisioning
fields required for the deployment-selected GLPI authentication source,
including `authtype` and `auths_id` when needed. Those fields are never
Provider payload. The adapter never creates a password and does not synchronize
unrelated user attributes. If creation fails, reconciliation fails, no
`Profile_User` mutation starts, and there is no automatic retry or fallback.
GLPI may apply its own defaults, rules, or dynamic assignment during creation;
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

The conceptual order is: parse; complete structural validation of the payload
and every permission entry; semantic normalization of only valid entries;
entity/profile resolution; GLPI user lookup/creation; complete current
`Profile_User` read; authoritative reconciliation. No GLPI request starts before
complete GLPI-specific structural validation. Invalid repeated entries fail
rather than being hidden by normalization. If any entity or profile reference is
missing or ambiguous, reconciliation fails before user creation, assignment
deletion, or assignment creation. Entities and profiles are never created as a
fallback.

### Authoritative reconciliation

After user lookup or creation, the adapter reads every page of that user's
current `Profile_User` assignments. The service account must have an active
GLPI profile and entity access that makes this read complete; incomplete ACL
visibility is invalid target configuration, not a partial reconciliation mode.

The normalization identity for desired permission entries is `(entity, profile)`.
The adapter canonicalizes each grouped identity to `true` if any entry is `true`,
otherwise to `false`.
Physical current rows may be duplicate or have mixed `is_recursive` values. The
GLPI represents duplicate `Profile_User` rows, and recursive access includes an
entity and its descendants and semantically subsumes non-recursive access.
`is_dynamic`, `is_default_profile`, and other relationship metadata are not
desired-state fields; the adapter does not create or update them separately. It
nevertheless owns every `Profile_User` row for the synchronized user. GLPI rules,
LDAP synchronization, or another writer must not concurrently manage those
assignments.

The canonical final state contains exactly one physical row for every desired
`(entity, profile)` pair, with `is_recursive` set to its canonical value.

- One current row with a desired pair's canonical value is retained.
- Every additional current row for that pair, and every row with its
  noncanonical `is_recursive` value, is stale and must be removed.
- If no current row has a desired pair's canonical value, that canonical row is
  missing and must be added after stale rows are removed.
- Every row for an undesired `(entity, profile)` pair is stale and must be
  removed.
- An empty desired list removes all current assignments for the user.

The adapter MUST NOT update any `Profile_User` row in place. It resolves every
divergence through removals and creations, deleting every stale assignment before
creating any missing assignment. Each `POST /apirest.php/Profile_User/`
assignment creation is its own request and is never combined with the
missing-user `POST /apirest.php/User/` request. It uses one
permission-assignment mutation per request and verifies that each response
represents the requested successful mutation before beginning the next one. The
first failed mutation stops reconciliation. If a removal fails, the add phase
does not start.

| Stage | Example assignment |
| --- | --- |
| Current | `Root Entity > IT` / `Technician` / `true` |
| Current | `Root Entity > Legacy` / `Read-Only` / `false` |
| Desired | `Root Entity > IT` / `Technician` / `true` |
| Desired | `Root Entity > IT > Operations` / `Read-Only` / `false` |
| Plan | **REMOVE** `Root Entity > Legacy` / `Read-Only` / `false` |
| Plan | **ADD** `Root Entity > IT > Operations` / `Read-Only` / `false` |

The final state is exactly the canonical desired state. Successful reconciliation
returns `Unchanged` only when the user already existed and its physical
assignment set already had exactly one canonical row for each desired pair. It
returns `Changed` when it creates the user or successfully adds or removes an
assignment. These are the existing `ReconciliationOutcome` values; no GLPI
detail is returned to the caller.

### GLPI API and authentication

The adapter selects GLPI V1 REST API at the configured HTTPS `apirest.php`
endpoint. This is the only selected API contract; there is no V1/V2 fallback.

The V1 API exposes the `Profile_User` item type and its
`users_id`, `profiles_id`, `entities_id`, and `is_recursive` fields. Its generic
itemtype endpoints provide the reads, creates, and deletes needed for
reconciliation. V2 has no equivalent `Profile_User` operation and is not
selected for this contract.

| Need | V1 REST operation |
| --- | --- |
| Begin authentication | `GET /apirest.php/initSession/` |
| Resolve GLPI objects | `GET /apirest.php/search/:itemtype/` and item reads |
| Create missing user | `POST /apirest.php/User/` |
| Create one missing assignment | `POST /apirest.php/Profile_User/` |
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
Authenticated GLPI API requests MUST NOT follow HTTP redirects.

Every GLPI V1 `GET` request used by the adapter, including `initSession`, search,
item reads, `killSession`, and any other `GET`, MUST have an empty request body
and place request parameters in the URL or query. `Authorization`, `App-Token`,
and `Session-Token` remain request headers. This is distinct from JSON mutation
requests, which have the following `Content-Type` requirement.

Every GLPI mutation request with a JSON body, including missing-user and
`Profile_User` creation, MUST send `Content-Type: application/json`.

Endpoint, user token, App-Token, TLS trust material, and operation timeouts are
runtime target configuration. The authentication-source provisioning fields
needed for missing-user creation are also target configuration. None of these
values are part of the desired state.

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

### Conformance test contract

Conformance tests use deterministic, hermetic local GLPI V1 fakes or fixtures.
They do not use public Internet, production GLPI, fixed ports, arbitrary sleeps,
or retries. At minimum, they must prove:

- strict v1 payload validation: the payload has exactly `permissions`, has no
  username, and rejects unknown payload members, wrong-type or incomplete
  permission fields, and empty selectors; repeated complete permission objects
  and mixed `recursive` values for the same entity/profile are valid;
- before ANY GLPI request, GLPI-specific payload validation rejects duplicate
  `permissions` members in the payload object and duplicate `entity`, `profile`,
  or `recursive` members in a permission object. This is separate from ADR
  0008's common envelope handling of duplicate `version` and `payload` members;
- no GLPI request starts before complete payload validation, and every desired
  reference is resolved before mutation;
- the generic request carries identity separately from payload, and exact
  `IdentityContext`-driven `User.name` lookup covers existing, missing, and
  ambiguous users;
- deterministic fake coverage of incomplete User lookup visibility failing closed
  with no user creation;
- a missing user plus an empty desired state is created and finishes with no
  assignments;
- GLPI-rejected missing-user creation is an adapter failure with no
  `Profile_User` mutation;
- failed missing-user creation has no automatic retry or fallback;
- exact full-path entity resolution and exact profile-name resolution, including
  nested paths, missing and ambiguous references, pagination, lookalike or
  selector-metacharacter values, and no entity/profile creation;
- authoritative additions, removals, empty-state removal, recursive differences,
  duplicate current rows, dynamic/default assignment created by GLPI, and an
  exact final assignment set;
- desired normalization and canonical reconciliation, including:
  - one desired `false`, one desired `true`, duplicate `false`, duplicate `true`,
    `false` then `true`, `true` then `false`, and three or more mixed values for
    one entity/profile pair;
  - multiple independent pairs where only some repeat, the same entity with
    different profiles, the same profile with different entities, and
    order-independent input;
  - duplicate Provider desired entries with an already canonical current row
    returning `Unchanged`;
  - strict-validation interaction: duplicate complete objects are valid;
    duplicate JSON members and unknown fields are invalid; structurally invalid
    repeated entries fail before normalization; and every invalid input makes
    zero GLPI requests;
  - cleanup for desired canonical `false`: one `false`, duplicate `false`, one
    `true`, `true` plus `false`, and `false` plus `false` plus `true` current
    rows;
  - cleanup for desired canonical `true`: one `true`, duplicate `true`, one
    `false`, `false` plus `true`, and `true` plus `true` plus `false` current
    rows;
  - undesired-pair cleanup with one, duplicate, mixed, and several current rows;
  - pagination of duplicate current rows, independent plans, and exactly one
    canonical physical row per desired pair;
  - remove-before-add recursive changes; cleanup failure blocking addition with
    no rollback; partial duplicate cleanup followed by later convergence;
    dirty-row cleanup returning `Changed`, followed by a second successful
    reconciliation returning `Unchanged`; no automatic retry; and no unnecessary
    `POST` when a canonical acceptable row already exists;
- observable operation order proving removals happen before additions;
- idempotency: an intentionally divergent first reconciliation is `Changed`,
  the same desired state is `Unchanged`, and no duplicate effects occur;
- partial failure after user creation, during deletion, and during the add phase
  after removals: no rollback or automatic retry, then later legitimate
  convergence;
- deadline and cancellation: bounded return, no operation starts after observed
  expiry/cancellation, and no detached work remains; and
- the selected V1 endpoints plus `Authorization`, `App-Token`, `Session-Token`,
  `initSession`, `killSession`, cleanup, primary-failure semantics, and
  `Content-Type: application/json` on JSON mutation bodies;
- V1 `GET` request construction: empty request bodies, request parameters in the
  URL or query, and no JSON body on `GET` requests;
- complete-assignment access required of the configured GLPI service account;
  and
- transport and redaction safety: reject HTTP, redirects, and disabled
  certificate or hostname verification; accept an explicitly configured private
  CA; reject untrusted certificates; and keep sentinel tokens, usernames,
  selectors, and raw GLPI responses out of ordinary errors and telemetry.

### Two-layer test policy

A compliant GLPI adapter MUST have both this deterministic, hermetic
fake-based conformance suite and a real GLPI integration suite. Both MUST run
for every pull request. Normal `cargo test --workspace --all-features --locked`
remains hermetic and MUST NOT require a real GLPI instance.

The fake-based suite MUST remain deterministic and exhaustive, and MUST NOT use
a real instance. Its conformance cases cover strict parsing, including duplicate
members; structurally invalid desired state; ambiguity; pagination; operation
order and request construction; targeted failure injection and partial
mutation; no retry or rollback; deadline and cancellation; transport, TLS, redirects,
redaction, and idempotency; and malformed GLPI responses. The detailed
conformance requirements above remain mandatory; no real GLPI test can replace
this suite.

Before adapter scenarios, the real integration suite MUST automatically bootstrap
wholly within its disposable integration environment. The bootstrap MUST make
the selected V1 `apirest.php` API available; provision ephemeral `App-Token`,
service-account and user-token credentials, required profile and entity access,
complete User lookup visibility, and deterministic entities, profiles, users,
and scenario fixtures; and verify readiness before adapter tests.
It MUST NOT use shared, staging, manually configured, external, or long-lived
state, credentials, or databases. It MUST use the disposable, pinned database
service required by the exact GLPI image, capture useful failure diagnostics
while redacting secrets, and tear down the entire environment. Bootstrap may use
a local administrative mechanism in that environment where necessary, but it is
test infrastructure: adapter tests still exercise the selected production
`apirest.php` V1 contract.

At minimum, the real integration suite MUST cover:

- session establishment and `App-Token`, user-token, and `Session-Token`
  behavior, including session cleanup;
- exact `User.name` lookup and missing-user creation;
- entity and profile lookup;
- `Profile_User` reads, creation, and deletion, including `is_recursive`, exact
  duplicate current rows, and mixed current values;
- duplicate and mixed desired input, all true-wins desired variants, exactly one
  canonical final row per desired pair, and authoritative and empty
  reconciliation; and
- cleanup returning `Changed`, followed by the same reconciliation returning
  `Unchanged`.

These real-GLPI tests are the mandatory key-normalization baseline. The fake
suite remains exhaustive and irreplaceable.

Exactly one GLPI release is supported at a time, selected by the exact release
tag and immutable `sha256` digest used by the mandatory real integration
environment. This release selection does not affect the `glpi` or
`permissionsync-adapter-glpi` identifiers.

The integration environment MUST reference the official `glpi/glpi` image with
an exact release tag and immutable digest. The database image MUST use an exact
version or tag and an immutable digest.

An automated dependency-update mechanism MUST open pull requests for newer GLPI
releases/tags and digest changes and newer database versions/tags and digest
changes. Each such pull request requires the complete fake suite and complete
real integration suite against the proposed release, normal human review, and no
automatic merge.

CI implementation MUST follow repository conventions for immutable GitHub Action
SHA pins with version comments, least-privilege permissions, and explicit
timeouts.

A GLPI major upgrade changes neither the adapter identifier nor the crate and
requires a new ADR only when an API or semantic incompatibility prevents
conformance to this ADR.

## Alternatives considered

- **Provider supplies GLPI numeric IDs:** rejected because IDs are deployment
  internals and would couple the Provider to a GLPI instance.
- **Additive-only synchronization:** rejected because the payload is the user's
  complete authoritative assignment state.
- **Create missing entities or profiles:** rejected because they are outside the
  adapter's permission-assignment ownership.
- **Add assignments before removing stale ones:** rejected in favor of the
  explicit remove-before-add plan.
- **GLPI V2, or runtime V1/V2 fallback:** rejected because V2 has no equivalent
  `Profile_User` operation, and fallback would make
  the API contract non-deterministic.

## Consequences

This decision defines one selected GLPI V1 API and session contract, a Provider
payload free of GLPI IDs, credentials, and identity, and an explicit
authoritative set-reconciliation algorithm. It requires a service account with
only the GLPI rights needed to find/create users and manage their `Profile_User`
assignments.

Crate layout, registration, runtime configuration schema, HTTP client choice,
concrete timeout values, and target credential/trust delivery are not prescribed
by this ADR. Implementation choices must preserve this ADR's GLPI decisions and
the runtime, adapter-boundary, and security requirements in
[ADR 0006](0006-runtime-configuration-oci-and-observability.md) and
[ADR 0007](0007-compile-time-rust-target-adapters.md).

## References

- [ADR 0001](0001-inbound-synchronization-contract.md)
- [ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md)
- [ADR 0005](0005-versioned-adapter-specific-desired-state-envelope.md)
- [ADR 0006](0006-runtime-configuration-oci-and-observability.md)
- [ADR 0007](0007-compile-time-rust-target-adapters.md)
- [ADR 0008](0008-generic-rest-permission-provider-wire-and-transport-contract.md)
- [GLPI REST API documentation](https://github.com/glpi-project/glpi/blob/11.0.0/apirest.md)
- [GLPI `Session` source](https://github.com/glpi-project/glpi/blob/11.0.0/src/Session.php)
- [GLPI `Profile_User` source](https://github.com/glpi-project/glpi/blob/11.0.0/src/Profile_User.php)
- [GLPI `User` source](https://github.com/glpi-project/glpi/blob/11.0.0/src/User.php)
- [GLPI `DbUtils` source](https://github.com/glpi-project/glpi/blob/11.0.0/src/DbUtils.php)
- [GLPI empty database schema](https://github.com/glpi-project/glpi/blob/11.0.0/install/mysql/glpi-empty.sql)
- [GLPI V2 OpenAPI generator](https://github.com/glpi-project/glpi/blob/11.0.0/src/Glpi/Api/HL/OpenAPIGenerator.php)
- [GLPI High-Level API documentation](https://glpi-developer-documentation.readthedocs.io/en/master/devapi/hlapi/index.html)
