# ADR-0002: Caller Authentication and Authorization

- **Status:** Accepted
- **Date:** 2026-08-24
- **Deciders:** R&D Team

## Context

The synchronization endpoint in
[ADR 0001](0001-inbound-synchronization-contract.md) is a trust boundary.
PermissionSync must verify the technical caller and its permission before any
provider or adapter work begins. That caller is not the synchronized end user.

## Decision

PermissionSync expects the technical caller's bearer JWT in the HTTP
`Authorization` header. The JWT is an OAuth2 Client Credentials access token
issued by Keycloak and represents the caller, not the synchronized end user.
Technical caller access tokens should be short-lived.

PermissionSync uses these JWT claims:

Authentication:

    iss
    aud
    exp
    iat
    client_id

Authorization and target selection:

    scope

Authentication and authorization use these claims with distinct
responsibilities:

- **Authentication** validates `signature`, `iss`, `aud`, `exp`, `iat`, and
  `client_id`.
- **Authorization** uses `scope`.

Authentication validation semantics:

- `iss` MUST exist and match the configured trusted Keycloak issuer.
- `aud` MUST exist and contain the configured expected PermissionSync audience;
  additional audience values are permitted.
- `exp` MUST exist and the token MUST NOT be expired.
- `iat` MUST exist and be temporally valid with bounded clock skew.
- `client_id` MUST exist and identifies the authenticated technical caller.
- Signature verification MUST use the trusted Keycloak JWKS source and an
  explicit algorithm allowlist.

Authorization semantics:

- When present, `scope` MUST be a JSON string. A `null`, array, object, number,
  or boolean `scope` is wrong-shaped and returns `401`.
- After successful authentication, an absent `scope` or an empty string
  `scope` returns `403`.
- A nonempty `scope` string MUST use the RFC 6749 section 3.3 syntax:
  `scope = scope-token *( SP scope-token)` and
  `scope-token = 1*( %x21 / %x23-5B / %x5D-7E )`. A nonempty string that
  violates this syntax returns `401`.
- A valid scope string consists of space-delimited scope tokens. Other,
  non-PermissionSync OAuth scope tokens MAY also be present and have no effect
  on PermissionSync authorization or routing.
- PermissionSync identifies scope tokens with the exact, case-sensitive prefix
  `permissionsync:`. Matching is exact-token only: prefix, suffix, and
  substring lookalikes do not count.
- PermissionSync requires exactly one scope token with that exact prefix. A
  syntactically valid scope string with no such token, or with more than one
  such token (including exact duplicates), returns `403`: zero is insufficient
  authorization and more than one is an ambiguous target selection, and
  neither is a usable authorization grant. Token order and the presence of
  other, non-PermissionSync scope tokens do not affect this count.
- The single required token has the form `permissionsync:<target>`. Its suffix
  after the `permissionsync:` prefix is the logical target identifier and MUST
  match the v1 target identifier grammar defined in
  [ADR 0001](0001-inbound-synchronization-contract.md). An exact single token
  whose suffix violates that grammar is an unusable authorization grant and
  returns `403`.
- That single valid `permissionsync:<target>` token both authorizes the caller
  and identifies the request's logical target; it is the only source of the
  logical target, and PermissionSync uses no other claim or request value to
  select one. Scope insufficiency, ambiguity, or an invalid extracted target
  does not invalidate an already established technical caller identity.

Examples:

- `scope = "permissionsync:glpi"` is valid: exactly one PermissionSync token,
  extracting target `glpi`.
- `scope = "service_account permissionsync:glpi"` is valid: exactly one
  PermissionSync token among other, non-PermissionSync OAuth scopes.
- `scope = "permissionsync:glpi permissionsync:grafana"` returns `403`: more
  than one PermissionSync target scope is an ambiguous target selection.
- `scope = "service_account"` returns `403`: no PermissionSync target scope is
  present.

Ordering matters: authentication verifies the signature and `iss`, `aud`,
`exp`, `iat`, and `client_id`; authorization is separate and, after successful
authentication, evaluates `scope`.

Failure semantics:

- A missing or malformed bearer token or JWT, an invalid signature, or a
  missing or malformed claim required for authentication (`iss`, `aud`, `exp`,
  `iat`, or `client_id`) returns `401`.
- A structurally malformed or wrong-shaped `scope` claim, or a nonempty `scope`
  string that violates RFC 6749 syntax, makes the token structurally invalid
  and returns `401`.
- After successful authentication with a syntactically valid token, an absent
  `scope`, an empty `scope`, a `scope` with no exact `permissionsync:` token, a
  `scope` with more than one exact `permissionsync:` token, or a single exact
  `permissionsync:` token whose extracted target suffix violates the v1 target
  identifier grammar, all return `403`.

The `client_id` claim requires supported deployment provisioning. Keycloak
provisioning MUST guarantee that service-account / Client Credentials access
tokens contain the `client_id` claim, using the Keycloak built-in
service-account Client Id claim/mapper appropriate to the Keycloak version used
by the deployment. The exact supported Keycloak version belongs to the NetEye
deployment/support matrix and is not pinned in this ADR, and PermissionSync
introduces no custom Keycloak protocol mapper. The architecture requirement is:
a supported Keycloak deployment, with the service account enabled and built-in
provisioning emitting `client_id`, produces access tokens that PermissionSync
requires to contain `client_id`.

The `aud` claim also requires supported deployment provisioning. Keycloak
provisioning MUST use Keycloak's standard OIDC Audience protocol-mapper
capability to ensure that Client Credentials / service-account access tokens
presented to PermissionSync contain the configured expected PermissionSync
audience as one `aud` value. The exact supported mapper placement — for example,
a dedicated client scope or another supported provisioning location — is a
deployment detail. PermissionSync introduces no custom protocol mapper, does not
choose the concrete audience string, and does not pin a Keycloak version. The
architecture requirement is: a supported Keycloak deployment, with Client
Credentials / service account, standard Audience mapper or client-scope
provisioning, and the configured PermissionSync audience, issues an access token
whose `aud` contains that expected audience.

Integration/contract testing against the supported Keycloak configuration MUST
verify that representative Client Credentials tokens:

- contain `client_id` with the expected technical caller identity;
- contain the configured expected PermissionSync audience in `aud`; and
- cover the complete PermissionSync-required token contract defined by this
  ADR;
- have an absent `scope` and return `403` after otherwise successful
  authentication;
- have an empty string `scope` and return `403`;
- have a valid scope string with no `permissionsync:` token and return `403`;
- have exactly one exact `permissionsync:<target>` scope token and authorize,
  extracting `<target>` as the logical target;
- have that one token among other, non-PermissionSync scopes and authorize;
- have the same scopes in changed order and produce the same result;
- have two distinct `permissionsync:<target>` scope tokens and return `403`;
- have two duplicate identical `permissionsync:<target>` scope tokens and
  return `403`;
- have exactly one exact `permissionsync:` token whose suffix violates the v1
  target identifier grammar and return `403`;
- have a wrong-shaped `scope` and return `401`;
- have a nonempty malformed scope string and return `401`;
- have a case-different `permissionsync:` prefix (for example
  `Permissionsync:glpi`) and not match, returning `403`; and
- have prefix, suffix, or substring lookalikes of `permissionsync:` and not
  match, returning `403`.

These cases belong at the supported-Keycloak integration/contract layer. A
real Keycloak instance is not required in every unit test.

The audience assertion MUST accept standards-compliant `aud` representations
while requiring the configured PermissionSync audience to be present; it MUST
NOT require `aud` to equal exactly one audience value.

PermissionSync does NOT depend on `sub`, `nbf`, `azp`, `jti`, `acr`, or other
claims for its required authentication or authorization contract. These claims
are not forbidden from appearing in the JWT; they are simply not required by
PermissionSync.

The `client_id` claim is the explicit technical caller identity. PermissionSync
does not assume the `sub` claim equals the technical caller identity. The
required `aud` provides resource binding to PermissionSync and contains the
configured expected PermissionSync audience, without requiring it to be the
only audience value.

Token-controlled URLs, algorithms, or other token content must never expand
trust.

All remote Keycloak authentication metadata retrieval — direct JWKS retrieval
and OIDC discovery where used — MUST use HTTPS. This requires an HTTPS URI,
TLS certificate validation, and hostname validation. TLS verification MUST NOT
be disabled. Private or internal CA trust remains supported through explicitly
configured trusted CA material; public certificate authorities are not
required. Redirects MUST NOT downgrade HTTPS to HTTP or otherwise weaken the
configured trust or TLS boundary, and token-controlled URLs or redirects MUST
NOT expand trust. The concrete Rust HTTP/TLS library is an implementation
decision and is not chosen in this ADR. The bounded-timeout, JWKS caching,
rotation, and fail-closed rules defined in this ADR apply.

A `usable cached trusted verification state` (including its verification key
or other verification material) MUST satisfy all of these conditions:

- It was previously obtained through the configured trusted Keycloak JWKS or
  discovery path.
- Its original retrieval satisfied this ADR's HTTPS and trust requirements.
- It is applicable under normal trusted key selection, including `kid` and the
  allowed algorithm where relevant.
- Its material is not expired or invalid and is not beyond a configured,
  bounded stale-cache or verification-material grace policy. Stale-cache
  acceptance is never indefinite.
- It does not conflict with subsequently observed trusted key-rotation state.
- It successfully verifies the token while normal authentication validation
  succeeds.

This ADR does not choose a cache duration, library, or new configuration
schema. A JWKS or discovery source failure never causes acceptance by itself.
During a temporary source outage, a request may proceed only when still-usable
cached trusted verification material successfully verifies the token and all
normal claim and authorization checks succeed. If no usable cached trusted
verification state exists, token validity cannot be established and the request
returns `500`; readiness is false while no usable verifier state exists under
[ADR 0006](0006-runtime-configuration-oci-and-observability.md).

Permission for a target is granted by scope, and that same scope identifies
the target: the logical target and the authorization decision both come from
the single exact `permissionsync:<target>` scope token, whose suffix is
validated against the v1 target identifier grammar under
[ADR 0001](0001-inbound-synchronization-contract.md) so a caller cannot force
arbitrary routing through an unvalidated value. There is no configured role or
claim-location indirection: this single scope token is both the technical
caller's authorization grant and the sole logical-target selector. Other,
non-PermissionSync OAuth scopes MAY be present and have no effect on
authorization or routing. Exactly one `permissionsync:<target>` token is
required; zero such tokens, more than one, or one with a grammar-invalid
suffix all return `403`, as specified above.

JWT parsing, signature verification, standards handling, and cryptographic
operations MUST use a mature, maintained, standards-compliant library. The
concrete library is an implementation decision and is not chosen in this ADR.

Authentication, JWT verification, and authorization logic is isolated behind an
internal reusable Rust crate boundary inside the PermissionSync workspace. It is
used internally first, is reusable and target-independent, and may later be
extracted into a shared NetEye crate if useful. The exact crate name and path,
and the concrete JWT library, are implementation decisions and are not chosen in
this ADR.

Return `401` when credentials cause rejection: a missing or malformed bearer
token, invalid JWT structure, expiry or not-yet-valid time, invalid signature,
wrong issuer, an `aud` that does not contain the configured expected
PermissionSync audience, disallowed algorithm, a missing signing key after a
successful trusted JWKS refresh, or another cryptographically unverifiable token
after the trusted source was successfully consulted.

If a metadata refresh times out or its source fails, that failure alone does not
return `500`. If still-usable cached trusted verification state safely verifies
the signature and normal authentication claims, processing continues through
normal authorization. If existing cached state definitively proves the token
invalid, return `401` even when the refresh also failed.

Return `403` only after successful authentication when a syntactically valid
`scope` is absent, empty, contains no exact `permissionsync:` token, contains
more than one exact `permissionsync:` token, or contains exactly one such
token whose extracted target suffix violates the v1 target identifier
grammar. Wrong-shaped scope, or a nonempty scope string that violates RFC 6749
syntax, returns `401` as specified above. Return `500` when PermissionSync
cannot
establish validity because verifier infrastructure is unavailable and no
still-usable cached trusted verification state can establish validity. This
includes unavailable JWKS or required discovery, including a refresh timeout,
when no such cached state exists, or unexpectedly unavailable trusted
verification configuration. A usable cached trusted verification state may
verify a token during a temporary JWKS or discovery outage only when all the
conditions above succeed. A source failure never accepts a token by itself.

Remote JWKS and discovery verification operations have bounded timeouts and
consume the remaining overall request budget under
[ADR 0006](0006-runtime-configuration-oci-and-observability.md). Provider or
adapter work runs only after successful authentication, authorization, and
request validation.

External authentication or authorization responses MUST NOT reveal the precise
token validation failure; the caller receives only the appropriate HTTP
outcome. Never log a bearer token, complete claims, or secrets. Diagnostics use
only a minimal, privacy-conscious caller identity. Detailed diagnostics may
exist internally only when they are safe and privacy-conscious, and must never
expose bearer tokens, complete claims, secrets, or sensitive verification
material.

## Alternatives considered

No material alternatives were recorded for this decision.

## Consequences

Configured trust inputs, authorization scope, and the required audience must be
managed deliberately: the trusted issuer, expected audience, JWKS source, the
Keycloak realm/client provisioning that grants each technical caller exactly
one `permissionsync:<target>` scope, and the reusable auth crate. Provisioning
a technical caller with more than one `permissionsync:<target>` scope makes
every synchronization request for that caller return `403`, because
PermissionSync requires exactly one such token per request. PermissionSync can
support normal signing-key rotation without accepting an unverifiable token,
while distinguishing caller credential failures, authorization failures, and
verifier infrastructure failures.

## References

- [ADR 0001](0001-inbound-synchronization-contract.md)
- [ADR 0006](0006-runtime-configuration-oci-and-observability.md)
- [ADR index](README.md)
