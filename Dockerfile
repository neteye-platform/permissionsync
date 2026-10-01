# Production PermissionSync OCI image.
#
# Two stages: a pinned Rust builder that compiles exactly the PermissionSync
# executable from the locked workspace, and a minimal distroless runtime that
# contains that executable and nothing else the service does not need.
#
# The runtime stage deliberately carries no configuration: ADR-0011 requires
# exactly one external UTF-8 YAML document whose path comes only from
# PERMISSIONSYNC_CONFIG_FILE, so the image sets neither that variable nor a
# default document. Secrets, private trust material, deployment URLs, and
# target configuration stay outside the artifact (ADR-0006).
#
# Base images are pinned by readable tag and immutable digest so Renovate can
# propose both together. The builder tag's Rust version is deliberately the
# same value as rust-toolchain.toml's channel; tests/oci_packaging.rs fails
# when the two drift, so a base-image bump cannot silently change the
# toolchain contract.

FROM docker.io/library/rust:1.98.1-trixie@sha256:a8a5f0a1e5fe7dfe1d352591e4a1c7dd2c08fd70475cae872cf3458ba0df0546 AS build

WORKDIR /src

# The toolchain contract is copied and installed first so the exact compiler
# and components it names are used for the build below, and so editing sources
# does not reinstall it.
COPY rust-toolchain.toml ./
RUN rustup toolchain install

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY src ./src

# Only the executable and the workspace crates it actually depends on are
# built; no test, bench, or example target is compiled into this stage.
RUN cargo build --release --locked --bin permissionsync

# The runtime base provides glibc, libgcc, OpenSSL 3, zlib, and the system
# trust store that the native-tls/OpenSSL stack this binary links against
# needs. It contains no shell, package manager, compiler, or Cargo state.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:54df941ed0d06a1bd95ef5e0ce391fd8d9f94b64782dc9a60062727849ee3f97 AS runtime

# Only statically true metadata is baked in. Version, revision, and creation
# metadata are supplied by the publishing workflow, so a local build never
# claims a release identity it does not have.
LABEL org.opencontainers.image.title="permissionsync" \
      org.opencontainers.image.description="PermissionSync service" \
      org.opencontainers.image.source="https://github.com/neteye-platform/permissionsync" \
      org.opencontainers.image.url="https://github.com/neteye-platform/permissionsync" \
      org.opencontainers.image.documentation="https://github.com/neteye-platform/permissionsync/blob/main/README.md" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.vendor="neteye-platform"

COPY --from=build /src/target/release/permissionsync /usr/local/bin/permissionsync

# The dedicated unprivileged distroless account, declared numerically so
# Kubernetes can enforce runAsNonRoot without resolving a user name. The
# service writes nothing to the filesystem, so a read-only root filesystem
# needs no writable path.
USER 65532:65532

# Exec form with no shell wrapper: the executable is PID 1 and receives
# SIGTERM and SIGINT directly, which is what its bounded graceful shutdown
# depends on.
ENTRYPOINT ["/usr/local/bin/permissionsync"]
