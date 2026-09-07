# ADR-0008: Generic REST Permission Provider Wire and Transport Contract

- **Status:** Accepted
- **Date:** 2026-09-07
- **Deciders:** R&D Team

## Context

[ADR 0004](0004-generic-rest-permission-provider.md) selects a Generic REST
Permission Provider for v1, but deliberately defers its exact wire and
transport contract. A concrete Provider implementation must not invent that
contract, especially because it transports synchronized-user identity, group
membership, logical-target selection, desired-state payloads, and optionally a
Provider credential.

This record refines only that deferred Provider boundary. It applies only after
inbound processing has selected exactly one valid logical target; a targetless
successful no-op never invokes the Provider. It does not change inbound HTTP,
caller JWT processing, target routing, Core orchestration, adapter semantics,
runtime-configuration loading, or deployment behavior.

## Decision

### Endpoint and request

Runtime configuration supplies one complete Provider request URI. It MUST be
an absolute `https` URI with an authority containing a non-empty host. Its path
and optional port are used as configured; an empty path is requested as `/`.
PermissionSync owns no appended Provider path.

The URI MUST NOT be relative, contain userinfo, a query component, or a
fragment, and MUST NOT use URI-template processing. PermissionSync MUST NOT
interpolate a username, group, logical target, credential, or other dynamic
value into the URI. There is no Provider endpoint discovery or service
discovery protocol.

For selected-target synchronization, PermissionSync makes at most one `POST`
request to the configured URI. It may make no request when invalid Provider
configuration, deadline expiry, or cancellation prevents outbound I/O. It sends
these request headers:

```text
Content-Type: application/json
Accept: application/json
Accept-Encoding:
```

The empty `Accept-Encoding` value communicates that v1 does not accept response
content coding.

The UTF-8 JSON request body is one object with exactly these required members:

```json
{
  "username": "jdoe",
  "groups": ["/staff", "/staff/engineering"],
  "target": "glpi"
}
```

`username` is a JSON string, `groups` is an array of JSON strings, and
`target` is the already validated logical-target string. Member order has no
meaning. PermissionSync serializes the Core username, groups, and target
values without trimming, Unicode normalization, sorting, deduplication, group
path interpretation, or target transformation. Group order and duplicates are
preserved. JSON serialization uses a standards-compliant serializer; it is not
constructed through string concatenation or manual escaping.

No other top-level request member is part of v1. In particular, the request
does not include `event_type`, the inbound technical caller JWT, `client_id`,
request identifiers, retry metadata, adapter identifiers, inbound HTTP details,
or credentials. A Provider MUST NOT require such a member.

### Successful response and failures

Only a final `200 OK` response is successful. It MUST use `application/json`
and UTF-8 JSON. If a `charset` parameter is present, it MUST NOT contradict
UTF-8. An `application/*+json` media type is unsupported in v1 and is a
Provider failure.

The successful body is one complete JSON object with exactly one `version` and
one `payload` member. Unknown or duplicate envelope members are a Provider
failure. `version` is an unquoted unsigned JSON integer in the range
`0..=u64::MAX`; Core does not require it to equal `1` or decide adapter support.
`payload` is required and may be any one syntactically valid JSON value,
including `null`, a scalar, an array, or an object. Payload schema, member
handling, version support, and semantics remain the selected Target Adapter's
responsibility under [ADR 0005](0005-versioned-adapter-specific-desired-state-envelope.md).

Every final status other than `200`, including every other `2xx`, is a Provider
failure. PermissionSync MUST disable automatic redirects; every `3xx` response
is a Provider failure, and its `Location` is not followed. Provider error
responses, including their bodies and `WWW-Authenticate` fields, have no
semantic role. They MUST NOT be parsed, retained, exposed, or logged. A remote
Provider status never determines PermissionSync's public inbound HTTP status.

### Response bounds and content coding

Every Provider response body that PermissionSync may buffer is subject to the
effective response-body limit. The effective response-body limit is always
positive and finite; there is no unbounded mode.

PermissionSync MUST have one concrete positive, finite absolute product safety
ceiling for Provider response bodies. This product-owned ceiling is the maximum
that configuration can never raise. ADR 0008 deliberately does not select its
numeric value. The Generic REST Permission Provider implementation PR MUST
select and document that concrete value with rationale before it can be merged
or Provider response buffering can ship. It MUST NOT use an effectively
unbounded platform maximum as that ceiling.

A deployment-specific response-body limit MAY be supported. If supported, it
MUST be positive and finite, MAY only make the effective response-body limit
stricter, and MUST NOT exceed or raise the absolute product safety ceiling. Its
semantic ownership is
deployment/runtime configuration; its source, file/env/secret mechanism, parsing
library, and exact representation remain deferred under
[ADR 0006](0006-runtime-configuration-oci-and-observability.md).

The effective response-body limit is the absolute product safety ceiling when
no deployment-specific limit exists. When a deployment-specific limit exists,
the effective response-body limit is `min(absolute product safety ceiling,
deployment-specific limit)`.

For a candidate `200` response, a declared `Content-Length` greater than the
effective response-body limit is a Provider failure before body reading starts.
`Content-Length` alone is insufficient: it can be absent, be used with streamed
responses, or be misleading. The transport MUST count body bytes incrementally
before fully buffering them and fail as soon as the effective response-body
limit would be exceeded. No body may be fully buffered beyond the effective
response-body limit. The byte count is measured after HTTP message framing. A
body exactly equal to the effective response-body limit is allowed.

V1 expects an unencoded Provider response. The implementation MUST NOT silently
enable or advertise response content codings, and transparent decompression MUST
NOT bypass the effective response-body limit. A coded successful response is a
Provider failure. Therefore the bounded bytes are the UTF-8 JSON bytes that Core
can later validate, with no compressed-versus-decompressed size bypass. No
response body is passed to `OpaquePayload` until after the effective
response-body limit has been enforced and the full envelope has been validated.

Non-`200` response bodies are not buffered. If an implementation drains one to
reuse a connection, it MUST apply the effective response-body limit; otherwise
it closes or drops the response stream.

### Attempts, deadline, and cancellation

[ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md)
owns the single-attempt policy. The Provider implementation MUST also prevent
an HTTP client, middleware, redirect handler, credential refresh, or connection
replay from sending another Provider request. There are no automatic retries
for DNS, connection, TLS, timeout, status, media-type, body-limit, JSON, or
other Provider failures.

The Provider operation uses the existing `SynchronizationContext`. Its effective
budget is no greater than the minimum of the remaining overall synchronization
budget and the configured shorter Provider operation timeout. DNS, connection,
TLS, request write, response headers, bounded body reading, and response parsing
all consume that budget. If cancellation or deadline expiry is already observed,
no Provider request starts. In-flight work cooperates with the existing
cancellation signal and returns after its currently executing bounded operation;
it MUST NOT detach or background Provider work. This decision adds no
runtime-specific cancellation type to Core.

### TLS, authentication, and ambient environment

All Provider requests use HTTPS with certificate validation and hostname
validation. TLS verification MUST NOT be disabled, and there is no plaintext
fallback. Configured trust material MUST support private or internal CAs. The
TLS library, trust-material delivery, and configuration format remain deferred
under [ADR 0006](0006-runtime-configuration-oci-and-observability.md).

Optional bearer authentication is the sole v1 Provider authentication mechanism.
When no Provider credential is configured, PermissionSync sends no
`Authorization` header. When a configured credential is present, PermissionSync
sends `Authorization: Bearer <opaque credential>`. The credential is distinct
from the inbound technical caller JWT and is never forwarded, derived, or
exchanged from it. Credentials MUST NOT appear in the URI, query, JSON body,
logs, errors, or ordinary `Debug` or `Display` output.

V1 has no generic authentication framework, HTTP Basic authentication,
arbitrary API-key or custom-header map, mTLS authentication, or token
acquisition or refresh subsystem. Provider traffic MUST NOT implicitly inherit
ambient proxy configuration. This record does not define proxy support; a
Provider implementation must explicitly disable proxy-from-environment behavior.

### Observability and error boundary

[ADR 0006](0006-runtime-configuration-oci-and-observability.md) owns the
observability system. Provider diagnostics may use bounded coarse categories
and record Provider outcome and latency, but MUST NOT log raw request,
response, or error bodies; usernames; group names; payloads; bearer credentials;
or full endpoint URIs. These values MUST NOT be metric labels.

`PermissionProviderError` remains the non-HTTP Core boundary error. A Provider
failure is explicit and cannot mean an empty desired state or a successful
no-op. Its conversion to the public synchronization outcome remains owned by
Core orchestration and the inbound contract.

## Alternatives considered

- **Base URI plus a PermissionSync-owned path:** rejected because it invents a
  universal Provider deployment layout. One complete configured URI is smaller
  and deployment-neutral.
- **Query, userinfo, fragments, or dynamic URI interpolation:** rejected to
  avoid a second data or credential channel, ambiguous endpoint behavior, and
  sensitive URI disclosure.
- **GET, inbound-event forwarding, or technical-caller propagation:** rejected
  because Provider resolution needs only synchronized-user identity, groups,
  and the selected logical target, and those values belong in the JSON body.
- **Permissive envelopes, `version == 1`, object-only payloads, other `2xx`
  successes, or a generic remote-error schema:** rejected because they either
  weaken structural validation or steal envelope and target semantics from
  [ADR 0005](0005-versioned-adapter-specific-desired-state-envelope.md).
- **Redirect following, automatic retry, or a fresh Provider deadline:**
  rejected because they can replay sensitive work, change trust boundaries, or
  exceed the one overall synchronization budget.
- **Unbounded buffering or response compression:** rejected because the
  transport must enforce a bound before allocation and parsing, without a
  decompression bypass. A Provider implementation cannot be complete until it
  selects and documents a concrete absolute product safety ceiling; an optional
  stricter deployment limit cannot raise it.
- **No Provider authentication only, HTTP Basic, arbitrary custom headers,
  mTLS authentication, or a pluggable authentication strategy:** rejected in
  favor of one optional standard Bearer header without an authentication
  framework or credential lifecycle subsystem.
- **Implicit ambient proxy behavior:** rejected because sensitive Provider
  traffic must not acquire an undocumented machine-dependent route.

## Consequences

The subsequent Provider implementation has one deterministic HTTP contract and
can be tested with local, hermetic endpoints for exact request serialization,
strict response validation, redirect refusal, streaming size limits, content
coding refusal, no retry, deadline/cancellation propagation, configured private
CA trust, and credential redaction.

Deployment configuration must supply an endpoint, shorter Provider timeout,
trust material where needed, and optionally a least-privilege Bearer credential.
The Provider implementation PR must select and document the concrete absolute
product safety ceiling with rationale before it can merge. A deployment-specific
limit remains optional; if supported, it can only lower the effective
response-body limit. This record does not select how those values are loaded or
stored, the numeric ceiling, its implementation mechanism, or any optional
stricter deployment configuration.

This decision changes no Rust public API, Core contract, routing behavior,
adapter contract, Cargo dependency, or deployment mechanism.

## References

- [ADR 0001](0001-inbound-synchronization-contract.md)
- [ADR 0002](0002-receiver-side-jwt-verification.md)
- [ADR 0003](0003-at-most-once-delivery-and-idempotent-reconciliation.md)
- [ADR 0004](0004-generic-rest-permission-provider.md)
- [ADR 0005](0005-versioned-adapter-specific-desired-state-envelope.md)
- [ADR 0006](0006-runtime-configuration-oci-and-observability.md)
- [ADR 0007](0007-compile-time-rust-target-adapters.md)
- [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986)
- [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750)
- [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259)
- [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110)
