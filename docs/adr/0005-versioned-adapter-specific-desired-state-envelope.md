# ADR-0005: Versioned Adapter-Specific Desired-State Envelope

- **Status:** Accepted
- **Date:** 2026-08-24
- **Deciders:** R&D Team

## Context

PermissionSync needs a common way for the Permission Provider to return desired
state that Core can transport without interpreting, while each target has its
own permission semantics. Core must not become target-specific, and must not
silently weaken or rewrite unknown semantics.

## Decision

The Permission Provider returns a common envelope whose payload is versioned and
adapter-specific:

    {
      "version": 1,
      "payload": { ... }
    }

Core treats the payload as opaque and does NOT interpret its business meaning.

Core responsibilities:

- Verify that the provider returned the required envelope.
- Verify that `version` is present and structurally valid.
- Verify that `payload` is present and structurally valid.
- Carry the opaque payload to the selected Target Adapter.

The selected Target Adapter responsibilities:

- Validate whether it supports the `version`.
- Fully validate the payload schema before any mutation.
- Validate every permission type, value, and semantic rule required by that
  target.
- Reject unsupported or malformed payloads.
- Never silently ignore, weaken, rewrite, or default unsupported semantics.
- Reconcile only after complete adapter-specific validation succeeds.
- Distinguish whether reconciliation left target state `changed` or `unchanged`,
  per the response semantics in
  [ADR 0001](0001-inbound-synchronization-contract.md).

Different adapters use different payload shapes; their payloads do NOT need a
common internal permission structure. The Permission Provider must know which
target is being requested and return the payload contract expected by that
target's adapter (see
[ADR 0004](0004-generic-rest-permission-provider.md)); the adapter owns the
version and semantics for its own target.

When a concrete Target Adapter is introduced, its supported payload contract
MUST be documented as part of that adapter's design. This documentation covers at
least: the supported envelope version(s); the adapter-specific payload schema;
the supported permission concepts and fields; the semantic validation rules; and
the compatibility and versioning expectations. Normally this is captured in an
adapter-specific ADR or equivalent architecture decision. Concrete payload
schemas are not specified in this ADR.

## Alternatives considered

A universal bounded desired-permission model was considered but not accepted.
Its promise of a single normalized vocabulary cannot hold across targets with
fundamentally different permission semantics, and normalizing would risk
silently weakening or reinterpreting target-specific rules.

## Consequences

Core stays target-neutral and trusts adapters to validate their own payload
semantics. Providers and adapters must define and keep compatible per-target
payload contracts. Substituting a new adapter or payload schema requires explicit
versioning and compatibility work.

## References

- [ADR 0001](0001-inbound-synchronization-contract.md)
- [ADR 0004](0004-generic-rest-permission-provider.md)
- [ADR 0007](0007-compile-time-rust-target-adapters.md)
- [ADR index](README.md)
