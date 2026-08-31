# Caller Authentication and Authorization

## Status

Accepted

## Context

The synchronization endpoint in
[ADR 0001](0001-inbound-synchronization-contract.md) is a trust boundary.
PermissionSync must verify the technical caller and its permission before any
provider or adapter work begins. That caller is not the synchronized end user.

## Decision

PermissionSync expects the technical caller's bearer JWT in the HTTP
`Authorization` header. The JWT comes from OAuth2 Client Credentials and
represents the caller, not the synchronized end user.
Technical caller access tokens should be short-lived.

Authentication requires:

- A configured, trusted JWKS and configured, trusted issuer validation.
- Signature validation with an algorithm allowlist.
- A required `exp` claim and `nbf` validation when present.
- Validation of other meaningful temporal claims with bounded clock skew.
- Safe JWKS caching and rotation, with fail-closed behavior.

Token-controlled URLs, algorithms, or other token content must never expand
trust. Validate an expected `aud` only when an audience is configured.

Authorization is separate from, and required after, authentication. It requires
a configured least-privilege role, scope, or equivalent trusted claim. Runtime
configuration owns the required value, claim location, and optional audience.

Return `401` when credentials cause rejection: a missing or malformed bearer
token, invalid JWT structure, expiry or not-yet-valid time, invalid signature,
wrong issuer or configured audience, disallowed algorithm, a missing signing
key after a successful trusted JWKS refresh, or another cryptographically
unverifiable token after the trusted source was successfully consulted.

Return `403` only when a valid, authenticated technical caller lacks the
configured role, scope, or equivalent claim. Return `500` when PermissionSync
cannot establish validity because verifier infrastructure is unavailable. This
includes unavailable JWKS with no usable cached trusted key, required discovery
with no usable cached metadata, refresh timeout, or unexpectedly unavailable
trusted verification configuration. A usable cached trusted key may verify a
token during a temporary JWKS outage. A source failure never accepts a token.

Remote JWKS and discovery verification operations have bounded timeouts and
consume the remaining overall request budget under
[ADR 0006](0006-runtime-configuration-oci-and-observability.md). Provider or
adapter work runs only after successful authentication, authorization, and
request validation.

Never log a bearer token, complete claims, or secrets. Diagnostics use only a
minimal, privacy-conscious caller identity.

## Consequences

Configured trust inputs, authorization policy, and optional audience must be
managed deliberately. PermissionSync can support normal signing-key rotation
without accepting an unverifiable token, while distinguishing caller credential
failures, authorization failures, and verifier infrastructure failures.

## References

- [ADR 0001](0001-inbound-synchronization-contract.md)
- [ADR 0006](0006-runtime-configuration-oci-and-observability.md)
- [ADR index](README.md)
