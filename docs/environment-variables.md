# Environment Variables

PermissionSync reads one YAML configuration file. Its path comes from the
required `PERMISSIONSYNC_CONFIG_FILE` environment variable. The file is the base
document. Other `PERMISSIONSYNC_*` variables replace single values of that file,
and they supply every secret. [ADR-0012](adr/0012-environment-overrides-and-environment-only-secrets.md)
records this decision.

## Rules

- **Names.** A variable name is `PERMISSIONSYNC_` followed by the path of the
  key in the file, in uppercase, with `__` between two levels. A single `_`
  stays part of a key. For example, `request.overall_deadline_milliseconds` is
  `PERMISSIONSYNC_REQUEST__OVERALL_DEADLINE_MILLISECONDS`. Variable names are
  public interface, like the file keys.
- **One value.** One variable replaces exactly one scalar value of the file.
  The other values stay the file values.
- **Lists.** Lists stay in the file only: `targets`, `authentication.algorithms`,
  and every `additional_trust_anchors_pem`. No variable sets a list.
- **Types.** The value is decoded with the declared type of its key. An unsigned
  integer is decimal digits only, with no leading `0` unless the value is
  exactly `0`. A signed integer is the same, with an optional leading `-`. A
  boolean is exactly `true` or `false`. A string is any
  UTF-8 text, and an empty string is an empty value.
- **Validation.** Validation runs after the merge, with the same rules as file
  values. A wrong value in a global section stops startup. A wrong value in the
  `provider` or `glpi` section leaves only that component unavailable.
- **Missing sections.** A variable creates its missing section. The section then
  needs its other required keys, exactly as in the file. For example, GLPI
  secrets without a `glpi` section give an invalid GLPI section, and a tracing
  variable without `observability.tracing.enabled` stops startup.
- **Secrets.** Secrets come only from the environment, in every deployment. A
  secret key in the file stops startup with a fixed message that contains no
  value.
- **Tracing headers.** One variable
  `PERMISSIONSYNC_OBSERVABILITY__TRACING__HEADERS__<NAME>` supplies one OTLP
  exporter header. `<NAME>` is one or more groups of uppercase ASCII letters
  and digits, separated by a single `_`. The header name is `<NAME>` in
  lowercase, with every `_` replaced by `-`. For example,
  `PERMISSIONSYNC_OBSERVABILITY__TRACING__HEADERS__X_API_KEY` supplies the
  `x-api-key` header. A header name that contains `_` cannot be supplied.
- **Unknown names.** An unknown `PERMISSIONSYNC_*` variable gives one structured
  log warning that contains only its name, and startup continues. When startup
  stops before logging is set up, or when the log level is `error`, which
  filters warnings, PermissionSync also writes one line per name to standard
  error. The line contains only the name.
- **YAML tags.** No configuration value uses a YAML tag. A tag anywhere in the
  file stops startup.
- **No exposure.** PermissionSync never logs, prints, or puts in an error the
  value of an environment variable.

In the table, **required** means that the key must be present when its section
is present. The `provider`, `glpi`, `observability.tracing`, and
`glpi.authentication_source` sections are optional. **none** means that the key
is optional and has no default value. The
[example configuration](permissionsync.example.yaml) explains the conditions
between keys, for example that exactly one trusted source is required.

## Variables

The table is generated from the schema in the code. A test checks that this
table is equal to the generated table.

<!-- BEGIN GENERATED ENVIRONMENT VARIABLE TABLE -->

| Variable                                                                 | File key                                                 | Type                                         | Default  | Secret |
| ------------------------------------------------------------------------ | -------------------------------------------------------- | -------------------------------------------- | -------- | ------ |
| `PERMISSIONSYNC_LISTENER__ADDRESS`                                       | `listener.address`                                       | string                                       | required | no     |
| `PERMISSIONSYNC_LISTENER__PORT`                                          | `listener.port`                                          | unsigned integer                             | required | no     |
| `PERMISSIONSYNC_REQUEST__OVERALL_DEADLINE_MILLISECONDS`                  | `request.overall_deadline_milliseconds`                  | unsigned integer                             | required | no     |
| `PERMISSIONSYNC_REQUEST__INBOUND_ADMISSION_LIMIT`                        | `request.inbound_admission_limit`                        | unsigned integer                             | required | no     |
| `PERMISSIONSYNC_REQUEST__SYNCHRONIZATION_CAPACITY`                       | `request.synchronization_capacity`                       | unsigned integer                             | required | no     |
| `PERMISSIONSYNC_SHUTDOWN__GRACE_MILLISECONDS`                            | `shutdown.grace_milliseconds`                            | unsigned integer                             | required | no     |
| `PERMISSIONSYNC_AUTHENTICATION__ISSUER`                                  | `authentication.issuer`                                  | string                                       | required | no     |
| `PERMISSIONSYNC_AUTHENTICATION__AUDIENCE`                                | `authentication.audience`                                | string                                       | required | no     |
| `PERMISSIONSYNC_AUTHENTICATION__SOURCE__JWKS_URI`                        | `authentication.source.jwks_uri`                         | string                                       | none     | no     |
| `PERMISSIONSYNC_AUTHENTICATION__SOURCE__OIDC_DISCOVERY_URI`              | `authentication.source.oidc_discovery_uri`               | string                                       | none     | no     |
| `PERMISSIONSYNC_AUTHENTICATION__CACHE__FRESHNESS_MILLISECONDS`           | `authentication.cache.freshness_milliseconds`            | unsigned integer                             | required | no     |
| `PERMISSIONSYNC_AUTHENTICATION__CACHE__STALE_IF_ERROR_MILLISECONDS`      | `authentication.cache.stale_if_error_milliseconds`       | unsigned integer                             | required | no     |
| `PERMISSIONSYNC_AUTHENTICATION__METADATA_OPERATION_TIMEOUT_MILLISECONDS` | `authentication.metadata_operation_timeout_milliseconds` | unsigned integer                             | required | no     |
| `PERMISSIONSYNC_AUTHENTICATION__CLOCK_SKEW_MILLISECONDS`                 | `authentication.clock_skew_milliseconds`                 | unsigned integer                             | required | no     |
| `PERMISSIONSYNC_OBSERVABILITY__LOG_LEVEL`                                | `observability.log_level`                                | `error`, `warn`, `info`, `debug`, or `trace` | required | no     |
| `PERMISSIONSYNC_OBSERVABILITY__TRACING__ENABLED`                         | `observability.tracing.enabled`                          | `true` or `false`                            | required | no     |
| `PERMISSIONSYNC_OBSERVABILITY__TRACING__ENDPOINT`                        | `observability.tracing.endpoint`                         | string                                       | none     | no     |
| `PERMISSIONSYNC_OBSERVABILITY__TRACING__EXPORT_TIMEOUT_MILLISECONDS`     | `observability.tracing.export_timeout_milliseconds`      | unsigned integer                             | none     | no     |
| `PERMISSIONSYNC_OBSERVABILITY__TRACING__HEADERS__<NAME>`                 | `observability.tracing.headers.<name>`                   | string (one header value)                    | none     | yes    |
| `PERMISSIONSYNC_PROVIDER__GENERIC_REST__ENDPOINT`                        | `provider.generic_rest.endpoint`                         | string                                       | required | no     |
| `PERMISSIONSYNC_PROVIDER__GENERIC_REST__OPERATION_TIMEOUT_MILLISECONDS`  | `provider.generic_rest.operation_timeout_milliseconds`   | unsigned integer                             | required | no     |
| `PERMISSIONSYNC_GLPI__ENDPOINT`                                          | `glpi.endpoint`                                          | string                                       | required | no     |
| `PERMISSIONSYNC_GLPI__APP_TOKEN`                                         | `glpi.app_token`                                         | string                                       | required | yes    |
| `PERMISSIONSYNC_GLPI__USER_TOKEN`                                        | `glpi.user_token`                                        | string                                       | required | yes    |
| `PERMISSIONSYNC_GLPI__OPERATION_TIMEOUT_MILLISECONDS`                    | `glpi.operation_timeout_milliseconds`                    | unsigned integer                             | required | no     |
| `PERMISSIONSYNC_GLPI__AUTHENTICATION_SOURCE__AUTHTYPE`                   | `glpi.authentication_source.authtype`                    | signed integer                               | required | no     |
| `PERMISSIONSYNC_GLPI__AUTHENTICATION_SOURCE__AUTHS_ID`                   | `glpi.authentication_source.auths_id`                    | signed integer                               | required | no     |

<!-- END GENERATED ENVIRONMENT VARIABLE TABLE -->
