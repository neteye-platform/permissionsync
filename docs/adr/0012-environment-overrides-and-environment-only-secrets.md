# ADR-0012: Environment Overrides and Environment-Only Secrets

- **Status:** Accepted
- **Date:** 2026-11-04
- **Deciders:** R&D Team

## Context

[ADR-0011](0011-executable-runtime-configuration-and-operational-lifecycle.md)
delivers the executable configuration as one external YAML file. Its path comes
from `PERMISSIONSYNC_CONFIG_FILE`. ADR-0011 also states that there are no
environment-value overrides and that secrets are supplied through the same file.

This has two costs. First, the file mixes ordinary deployment values with
credentials, so the whole document must be handled as a secret. Second, a
deployment cannot change one value, such as a port or a log level, without a
new copy of the file. Most deployment platforms and secret managers can supply
environment variables, and many of them supply secrets only in that form.

[ADR-0006](0006-runtime-configuration-oci-and-observability.md) requires that
secrets are supplied from outside the artifact and that PermissionSync has no
Kubernetes dependency. It selects no secret mechanism. This record keeps both
constraints.

## Decision

### Scope

This record replaces two statements of the ADR-0011 "Configuration delivery"
section: that there are no environment-value overrides, and that secrets are
supplied through the file. It also replaces the environment part of the
ADR-0011 alternative "Layered file, environment, and command-line overrides".
All other ADR-0011 decisions stay in force, including one YAML document, no
layered files, no command-line overrides, no environment substitution inside
the document, no runtime reload, and the split between global and
component-local configuration failures. ADR-0006 does not change.

### The file is the base, the environment replaces single values

The file named by `PERMISSIONSYNC_CONFIG_FILE` stays the required base document.
`PERMISSIONSYNC_CONFIG_FILE` selects the file and is not an override.

One environment variable replaces exactly one scalar value of the file. Every
scalar value can come from the environment. Lists stay in the file only:
`targets`, `authentication.algorithms`, and every
`additional_trust_anchors_pem`. The environment cannot replace an absent,
empty, or malformed file.

### Names

A variable name is `PERMISSIONSYNC_` followed by the path of the key in the
file, in uppercase, with `__` between two levels. A single `_` already occurs
inside keys, so it cannot separate levels. Examples:

- `PERMISSIONSYNC_REQUEST__OVERALL_DEADLINE_MILLISECONDS`
- `PERMISSIONSYNC_PROVIDER__GENERIC_REST__ENDPOINT`
- `PERMISSIONSYNC_OBSERVABILITY__LOG_LEVEL`
- `PERMISSIONSYNC_GLPI__APP_TOKEN`

Variable names are public interface, like the file keys. A change to a name is
a change to the configuration contract.

### Secrets come only from the environment

Secrets come only from the environment, in every deployment. The file has no
secret field. When the file contains a secret key, whatever its value, startup
stops with a fixed failure category that contains no value. The secrets are:

- `glpi.app_token`, from `PERMISSIONSYNC_GLPI__APP_TOKEN`;
- `glpi.user_token`, from `PERMISSIONSYNC_GLPI__USER_TOKEN`;
- the OTLP exporter headers `observability.tracing.headers`, which can carry
  exporter credentials.

A future secret configuration value is also environment-only and is marked as a
secret in the schema below.

### Tracing exporter headers

The exporter headers are a map, so one variable supplies one header:

```text
PERMISSIONSYNC_OBSERVABILITY__TRACING__HEADERS__<NAME>
```

`<NAME>` is one or more groups of uppercase ASCII letters and digits, separated
by a single `_`. The header name is `<NAME>` in lowercase, with every `_`
replaced by `-`. For example, `..._HEADERS__AUTHORIZATION` supplies
`authorization`, and `..._HEADERS__X_API_KEY` supplies `x-api-key`. Any other
`<NAME>` is an unknown variable.

This shape continues the naming pattern: the map key is one more level of the
path. HTTP header names are case-insensitive, so the uppercase form loses
nothing. Portable environment variable names cannot contain `-`, and HTTP header
names use `-` where the name has a separator, so `_` maps to `-`. Each header is
a separate variable, so each credential can come from its own secret reference.
The cost is that a header name that contains `_` cannot be supplied. Such names
are rare, and many proxies drop them.

### Merge and validation

The runtime parses the file into one YAML tree. A YAML tag anywhere in the file,
on a key, a mapping, a list element, or a scalar, makes the document structure
invalid and stops startup. No configuration value uses a tag, and a tagged key
would otherwise hide from the secret check and from the merge while typed
decoding still accepts it. Then the runtime checks the file for secret keys.
Then it decodes each recognized environment value with the declared type of its
key and inserts it into the tree, creating missing mappings and treating a null
mapping as missing. Then the existing strict decoding and validation run on the
merged tree.

- An unsigned integer is decimal digits only, with no leading `0` unless the
  value is exactly `0`, so a value such as `08080` is rejected, as it is in the
  file. A signed integer is the same, with an optional leading `-`. A boolean
  is exactly `true` or `false`. A string is any UTF-8 text.
- A value that cannot be decoded with its declared type makes its section
  invalid, exactly as a wrongly typed file value does.
- The merge never repairs the file. When a node on the path exists and is not a
  mapping, the value is not inserted, and strict decoding reports that node.
- Validation uses exactly the same rules for file values and environment
  values. The ADR-0011 global-versus-component decoding is unchanged: a wrong
  value in a global section stops startup, and a wrong value in the `provider`
  or `glpi` section leaves only that component unavailable.
- A variable creates its missing section. That section then needs its other
  required keys, exactly as in the file.

### Unknown variables

An unknown `PERMISSIONSYNC_*` variable does not stop startup. Startup emits one
warning for each such variable. The warning contains only the variable name.
The names depend only on the environment, so the runtime collects them before
it reads the file. Configuration is loaded before logging exists, so the
runtime keeps the names and emits the warnings through the normal structured
log once logging is set up.

The warning must stay visible when the structured log cannot show it. In two
cases, PermissionSync also writes one line per name to standard error, in the
same value-free form as the other startup diagnostics:

- startup stops before logging is set up, for example because a global
  section is invalid; the lines come before the fatal failure category;
- the configured log level is `error`, which filters warnings.

A misspelled override is often the reason for a startup failure, so the name
must reach the operator in exactly that case.

### Values are never exposed

PermissionSync never logs, prints, or puts in an error the value of an
environment variable. Configuration failures stay fixed, value-free categories.

### One schema

One static table in the code lists every variable: its name, its file key path,
its type, its default (or that it is required or has none), and whether it is a
secret. The merge, the secret check, and the documentation use this table. The
documentation contains a table of every variable that is generated from the
schema, and a test checks that the documented table is equal to the generated
table. The runtime reads the process environment in one place at startup; every
other function receives the captured variables, so tests inject them and never
change the process environment.

## Alternatives considered

- **Keep the ADR-0011 delivery model:** rejected because the whole file must be
  handled as a secret, and a single deployment value cannot change without a
  new file.
- **Secrets from the file or the environment:** rejected because two sources
  need a precedence rule, and a secret can still reach a file that is shared or
  committed. One source is easier to audit.
- **Secret file references, such as an `app_token_file` key:** rejected because
  they add a second file mechanism and new keys, while every supported
  deployment platform can already supply environment variables.
- **Environment substitution inside the document:** rejected for the reasons in
  ADR-0011: template syntax and hidden indirection inside the one document.
- **A single `_` between levels:** rejected because keys already contain `_`,
  so names would be ambiguous.
- **Lists from the environment:** rejected because a list value needs a second
  syntax and partial-list semantics.
- **All exporter headers in one structured variable:** rejected because it
  needs a second value syntax, and one header cannot come from its own secret
  reference.
- **Startup failure for an unknown variable:** rejected because deployment
  tooling can set variables that an older or newer release does not know, and a
  failure would break such a rollout or rollback. The warning keeps the
  mistake visible.

## Consequences

Deployments can keep the file free of credentials and handle it as ordinary
configuration, and they can change single values without a new file. Every
deployment supplies secrets through the environment. A Kubernetes deployment
can use a Secret through `secretKeyRef`, but PermissionSync still has no
Kubernetes dependency.

Operators now have two inputs to inspect: the file and the `PERMISSIONSYNC_*`
variables. The generated documentation table lists every variable, and the
unknown-variable warning reports misspelled names. Environment values are
visible to the process owner and to the platform that sets them, so deployments
must protect them as they protect any secret delivery.

Each new scalar configuration key needs a schema entry, which also gives it a
public variable name. A test reads the field names of every delivery struct
from its derived decoding and checks that each field is a nested section, a
list, the exporter header map, or a schema entry, and that each schema entry is
such a field. A new field that is not a list or a section therefore fails the
test until it has a variable. Another test checks the documented table against
the schema.

## References

- [ADR-0006](0006-runtime-configuration-oci-and-observability.md)
- [ADR-0011](0011-executable-runtime-configuration-and-operational-lifecycle.md)
- [Environment variables](../environment-variables.md)
- [Example configuration](../permissionsync.example.yaml)
- [ADR index](README.md)
