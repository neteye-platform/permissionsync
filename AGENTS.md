# Coding Agent Guide

## Sources of truth

- Inspect the repository before assuming implementation, workspace, or build
  commands exist.
- Start with the [ADR index](docs/adr/README.md) for the current architecture,
  ADR set, status, and lifecycle rules.
- For architecture decisions, Accepted ADRs are authoritative and override
  conflicting guidance in this file. Read relevant Accepted ADRs before making
  architecture-facing changes.
- Use the repository's [security policy](SECURITY.md) for security handling.
- Repository tooling configuration is authoritative; do not change it to solve
  a parent workspace's local configuration problem.

## Working in this repository

- Keep diffs task-focused and limited to the requested files.
- Preserve deferred decisions and existing ADR ownership.
- Do not introduce silent violations, speculative paths, or invented tools.
- Keep implementation and documentation deployment-neutral unless an Accepted
  ADR says otherwise.
- Do not add production code, tests, or configuration for a documentation-only
  task.
- Keep Markdownlint clean and use repository-relative links.

## ADRs

- New ADRs MUST use the [ADR template](docs/adr/template.md).
- Follow the index's standard Record Structure without expanding it into a
  copied architecture specification.
- Add every new ADR to the [ADR index](docs/adr/README.md).
- Use the next ADR number; never renumber an adopted ADR.
- A replacement is a new ADR and normally marks the replaced decision
  Superseded.
- Make a new ADR only for a genuine architecture decision, not a small change
  or implementation detail.

## Testing and validation

- Run only `prek run --all-files` as the repository-native validation command.
- Run `git diff --check` for whitespace errors.
- Inspect `git diff`; optionally inspect `git diff --word-diff` for wording.
- Do not invent Cargo, test-runner, Docker, Make, build, or other commands.
- Do not speculate about paths or validation that the repository does not
  establish.
- Report skipped checks accurately.

## Security

- Never commit credentials, tokens, private keys, secrets, or trust material.
- Do not disable or weaken TLS verification; comply with security requirements
  in Accepted ADRs.

## Before finishing

- Re-read the relevant Accepted ADRs and confirm no deferred decision was
  silently resolved.
- Confirm only requested files changed.
- Run the allowed checks and inspect the final diff.
- State exact files changed and any validation that was skipped.
