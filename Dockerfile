# Production PermissionSync OCI image.
#
# The runtime stage deliberately carries no configuration: ADR-0011 requires
# exactly one external UTF-8 YAML document whose path comes only from
# PERMISSIONSYNC_CONFIG_FILE, so the image sets neither that variable nor a
# default document. Secrets, private trust material, deployment URLs, and
# target configuration stay outside the artifact (ADR-0006).
#
# Both base images are pinned by readable tag and immutable digest so Renovate
# can propose both together. The builder tag is only a rustup bootstrap: the
# compiler actually used is whichever one rust-toolchain.toml selects below, so
# that file stays the single declaration of the toolchain and a base-image bump
# cannot change it.

FROM docker.io/library/rust:1.99.0-trixie@sha256:cb1b90b0ce00f9eb950c4de62cc1bb89c7bf8a3577de6600d10e31fb15f876de AS build

WORKDIR /src

# Installs the exact compiler and components rust-toolchain.toml names, which
# cargo then selects for the build below. Copied before the sources so editing
# them does not reinstall it.
COPY rust-toolchain.toml ./
RUN rustup toolchain install

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY src ./src

RUN cargo build --release --locked --bin permissionsync

# The runtime base provides glibc, libgcc, OpenSSL 3, zlib, and the system
# trust store that the native-tls/OpenSSL stack this binary links against
# needs. It contains no shell, package manager, compiler, or Cargo state.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:54df941ed0d06a1bd95ef5e0ce391fd8d9f94b64782dc9a60062727849ee3f97 AS runtime

# Only statically true metadata. Version, revision, and creation metadata come
# from the publishing workflow, so a local build claims no release identity.
LABEL org.opencontainers.image.title="permissionsync" \
      org.opencontainers.image.description="PermissionSync service" \
      org.opencontainers.image.source="https://github.com/neteye-platform/permissionsync" \
      org.opencontainers.image.url="https://github.com/neteye-platform/permissionsync" \
      org.opencontainers.image.documentation="https://github.com/neteye-platform/permissionsync/blob/main/README.md" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.vendor="neteye-platform"

COPY --from=build /src/target/release/permissionsync /usr/local/bin/permissionsync

# Numeric so Kubernetes can enforce runAsNonRoot without resolving a name.
USER 65532:65532

# Exec form, so the executable is PID 1 and its bounded graceful shutdown
# receives SIGTERM and SIGINT directly rather than through a shell wrapper.
ENTRYPOINT ["/usr/local/bin/permissionsync"]
