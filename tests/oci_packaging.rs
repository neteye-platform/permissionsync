//! Hermetic checks for the production OCI image and the reference Kubernetes
//! deployment contract.
//!
//! These tests read only files that are checked into the repository. They
//! require neither a container engine nor a Kubernetes cluster, so they keep
//! the deployment contract's invariants in the ordinary workspace test run,
//! while `integration/oci/` owns the properties that can only be proved by
//! actually building and running the image.

use std::{fs, path::PathBuf, time::Duration};

use yaml_serde::Value;

fn repository_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read(relative: &str) -> String {
    let path = repository_path(relative);
    fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("{} could not be read: {error}", path.display());
    })
}

#[test]
fn every_base_image_is_pinned_by_tag_and_immutable_digest() {
    let dockerfile = read("Dockerfile");
    let references: Vec<&str> = dockerfile
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("FROM "))
        .collect();
    assert_eq!(
        references.len(),
        2,
        "the image is built in exactly two stages"
    );
    for line in references {
        let reference = line
            .split_whitespace()
            .nth(1)
            .expect("every FROM names an image");
        let (tagged, digest) = reference
            .split_once('@')
            .unwrap_or_else(|| panic!("{reference} is not pinned by digest"));
        assert!(
            digest.starts_with("sha256:") && digest.len() == "sha256:".len() + 64,
            "{reference} does not carry a complete sha256 digest"
        );
        let tag = tagged
            .split_once(':')
            .unwrap_or_else(|| panic!("{reference} carries no readable tag"))
            .1;
        assert!(
            !tag.is_empty() && tag != "latest",
            "{reference} must carry a meaningful, non-floating tag"
        );
    }
}

/// Returns one stage's instructions, with comments, blank lines, and line
/// continuations folded away, so assertions inspect what the builder executes
/// rather than what the file happens to mention in prose.
fn stage_instructions(dockerfile: &str, stage: &str) -> Vec<String> {
    let mut instructions: Vec<String> = Vec::new();
    let mut inside = false;
    let mut continued = false;
    for line in dockerfile.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !continued && line.starts_with("FROM ") {
            inside = line.ends_with(&format!(" AS {stage}"));
        }
        if !inside {
            continued = line.ends_with('\\');
            continue;
        }
        let folded = line.trim_end_matches('\\').trim_end();
        if continued {
            let last = instructions
                .last_mut()
                .expect("a continuation follows an instruction");
            last.push(' ');
            last.push_str(folded);
        } else {
            instructions.push(folded.to_owned());
        }
        continued = line.ends_with('\\');
    }
    instructions
}

/// The runtime stage must stay a minimal, non-root, configuration-free
/// artifact with a direct executable entrypoint.
#[test]
fn the_runtime_stage_declares_the_expected_execution_contract() {
    let dockerfile = read("Dockerfile");
    let runtime = stage_instructions(&dockerfile, "runtime");
    let directive = |keyword: &str| -> Vec<String> {
        runtime
            .iter()
            .filter(|instruction| instruction.starts_with(&format!("{keyword} ")))
            .cloned()
            .collect()
    };

    assert_eq!(
        directive("USER"),
        vec!["USER 65532:65532".to_owned()],
        "the runtime stage must select its unprivileged account numerically, so Kubernetes \
         can enforce runAsNonRoot without resolving a user name"
    );
    assert_eq!(
        directive("ENTRYPOINT"),
        vec!["ENTRYPOINT [\"/usr/local/bin/permissionsync\"]".to_owned()],
        "the entrypoint must be the executable itself in exec form, with no shell wrapper"
    );
    assert_eq!(
        directive("COPY"),
        vec![
            "COPY --from=build /src/target/release/permissionsync /usr/local/bin/permissionsync"
                .to_owned()
        ],
        "the runtime stage must contain the executable and nothing else"
    );

    // No preset configuration path, and no runtime stage environment at all:
    // the configuration contract is one externally supplied variable.
    assert!(
        directive("ENV").is_empty(),
        "the image must not preset any environment value, including the configuration path"
    );
    // An application-level health check would only duplicate the Kubernetes
    // probes the supported platform already defines.
    for forbidden in ["HEALTHCHECK", "VOLUME", "CMD", "RUN", "WORKDIR", "EXPOSE"] {
        assert!(
            directive(forbidden).is_empty(),
            "the runtime stage must not declare {forbidden}"
        );
    }

    let labels = directive("LABEL").join(" ");
    for label in [
        "org.opencontainers.image.source",
        "org.opencontainers.image.licenses",
        "org.opencontainers.image.title",
    ] {
        assert!(
            labels.contains(label),
            "the image must carry the standard OCI label {label}"
        );
    }
    // Version, revision, and creation metadata belong to the publishing
    // workflow. A normal local build must not claim a release identity.
    for release_label in [
        "org.opencontainers.image.version",
        "org.opencontainers.image.revision",
        "org.opencontainers.image.created",
    ] {
        assert!(
            !labels.contains(release_label),
            "{release_label} must come from CI-generated metadata, not a hardcoded label"
        );
    }
}

/// The builder must take its compiler from `rust-toolchain.toml` rather than
/// from whatever the base image happens to ship, so the toolchain version is
/// declared in exactly one place and a base-image bump cannot change it.
#[test]
fn the_builder_stage_installs_the_repository_toolchain_before_building() {
    let builder = stage_instructions(&read("Dockerfile"), "build");
    let position = |needle: &str| {
        builder
            .iter()
            .position(|instruction| instruction.contains(needle))
            .unwrap_or_else(|| panic!("the builder stage is missing {needle}"))
    };
    assert!(
        position("COPY rust-toolchain.toml") < position("rustup toolchain install"),
        "rust-toolchain.toml must be present before the toolchain is installed"
    );
    assert!(
        position("rustup toolchain install") < position("cargo build"),
        "the toolchain that file selects must be installed before the build"
    );
    assert!(
        builder
            .iter()
            .any(|instruction| instruction.contains("cargo build --release --locked")),
        "the executable must be built from the locked workspace in release mode"
    );
}

/// Nothing deployment-specific may enter the build context in the first place.
#[test]
fn the_builder_stage_copies_only_the_locked_workspace() {
    let dockerfile = read("Dockerfile");
    let copied: Vec<String> = stage_instructions(&dockerfile, "build")
        .iter()
        .filter(|instruction| instruction.starts_with("COPY "))
        .cloned()
        .collect();
    assert!(!copied.is_empty(), "the builder stage copies the workspace");
    for instruction in &copied {
        for forbidden in [
            "docs/",
            "deploy/",
            "integration/",
            ".git",
            ".yaml",
            ".yml",
            ".pem",
            ".crt",
            ".env",
        ] {
            assert!(
                !instruction.contains(forbidden),
                "{instruction} must not bring {forbidden} into the image build"
            );
        }
    }
}

/// The build context is an allowlist, so a developer-local file or a newly
/// added top-level artifact cannot reach the builder by accident. That is only
/// safe if everything the locked build genuinely needs is restored.
#[test]
fn the_build_context_allowlist_keeps_every_file_the_locked_build_needs() {
    let ignore = read(".dockerignore");
    let rules: Vec<&str> = ignore
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();

    assert_eq!(
        rules.first().copied(),
        Some("*"),
        ".dockerignore must exclude everything before restoring what is required"
    );
    for required in [
        "!Cargo.toml",
        "!Cargo.lock",
        "!rust-toolchain.toml",
        "!crates",
        "!src",
    ] {
        assert!(
            rules.contains(&required),
            ".dockerignore must restore {required} for the locked release build"
        );
    }
    // Nothing may re-exclude a restored requirement.
    for rule in &rules {
        assert!(
            !matches!(
                *rule,
                "Cargo.toml" | "Cargo.lock" | "rust-toolchain.toml" | "crates" | "src"
            ),
            "{rule} is required by the locked build and must not be excluded"
        );
    }
}

fn kubernetes_example() -> Value {
    let manifest = read("deploy/kubernetes/permissionsync.example.yaml");
    yaml_serde::from_str(&manifest).expect("the deployment contract example parses as YAML")
}

fn field<'a>(value: &'a Value, path: &[&str]) -> &'a Value {
    let mut current = value;
    for segment in path {
        current = current
            .get(segment)
            .unwrap_or_else(|| panic!("the deployment example has no {} field", path.join(".")));
    }
    current
}

fn pod_spec(example: &Value) -> &Value {
    field(example, &["spec", "template", "spec"])
}

fn container(example: &Value) -> &Value {
    pod_spec(example)
        .get("containers")
        .and_then(Value::as_sequence)
        .and_then(|containers| containers.first())
        .expect("the deployment example declares a container")
}

/// Every security property ADR-0006 and the image's own execution contract
/// require, asserted structurally rather than by reading the file.
#[test]
fn the_deployment_contract_example_is_hardened() {
    let example = kubernetes_example();
    let pod = pod_spec(&example);
    let container = container(&example);

    assert_eq!(field(&example, &["kind"]).as_str(), Some("Deployment"));

    // Non-root, with the image's own dedicated numeric account.
    for context in [
        field(pod, &["securityContext"]),
        field(container, &["securityContext"]),
    ] {
        assert_eq!(field(context, &["runAsNonRoot"]).as_bool(), Some(true));
        assert_eq!(field(context, &["runAsUser"]).as_u64(), Some(65532));
        assert_eq!(
            field(context, &["seccompProfile", "type"]).as_str(),
            Some("RuntimeDefault"),
            "ADR-0006 requires the RuntimeDefault seccomp profile"
        );
    }

    let container_context = field(container, &["securityContext"]);
    assert_eq!(
        field(container_context, &["allowPrivilegeEscalation"]).as_bool(),
        Some(false)
    );
    assert_eq!(
        field(container_context, &["privileged"]).as_bool(),
        Some(false)
    );
    assert_eq!(
        field(container_context, &["readOnlyRootFilesystem"]).as_bool(),
        Some(true),
        "the service writes nothing, so the root filesystem stays read-only"
    );
    let dropped: Vec<&str> = field(container_context, &["capabilities", "drop"])
        .as_sequence()
        .expect("dropped capabilities are a sequence")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        dropped,
        vec!["ALL"],
        "no Linux capability is required by the service"
    );
    assert!(
        container_context
            .get("capabilities")
            .and_then(|capabilities| capabilities.get("add"))
            .is_none(),
        "no capability may be added back"
    );

    // No host namespace and no Kubernetes API credential is required.
    for host_namespace in ["hostNetwork", "hostPID", "hostIPC"] {
        assert_eq!(
            field(pod, &[host_namespace]).as_bool(),
            Some(false),
            "{host_namespace} must be explicitly disabled"
        );
    }
    assert_eq!(
        field(pod, &["automountServiceAccountToken"]).as_bool(),
        Some(false),
        "PermissionSync calls no Kubernetes API, so it needs no API credential"
    );

    // Deployment sizing is shown as a deployment concern, not omitted.
    for bound in ["requests", "limits"] {
        assert!(
            field(container, &["resources", bound])
                .as_mapping()
                .is_some(),
            "resource {bound} belong in the deployment contract example"
        );
    }
}

/// The example must demonstrate exactly the application configuration
/// contract: one externally mounted file named by one environment variable.
#[test]
fn the_deployment_contract_example_mounts_exactly_one_external_configuration_file() {
    let example = kubernetes_example();
    let container = container(&example);

    let variables = field(container, &["env"])
        .as_sequence()
        .expect("the container declares environment variables");
    assert_eq!(
        variables.len(),
        1,
        "the configuration contract is exactly one environment variable"
    );
    let variable = &variables[0];
    assert_eq!(
        field(variable, &["name"]).as_str(),
        Some("PERMISSIONSYNC_CONFIG_FILE")
    );
    let configuration_path = field(variable, &["value"])
        .as_str()
        .expect("the variable names a file path");
    assert!(
        configuration_path.ends_with(".yaml"),
        "PERMISSIONSYNC_CONFIG_FILE must name one YAML document"
    );

    let mounts = field(container, &["volumeMounts"])
        .as_sequence()
        .expect("the container mounts the configuration");
    assert_eq!(
        mounts.len(),
        1,
        "only the configuration document is mounted"
    );
    let mount = &mounts[0];
    assert_eq!(field(mount, &["readOnly"]).as_bool(), Some(true));
    let mount_path = field(mount, &["mountPath"])
        .as_str()
        .expect("the mount declares a path");
    assert!(
        configuration_path.starts_with(&format!("{mount_path}/")),
        "PERMISSIONSYNC_CONFIG_FILE must point inside the mounted volume"
    );

    let volumes = field(pod_spec(&example), &["volumes"])
        .as_sequence()
        .expect("the pod declares the configuration volume");
    assert_eq!(volumes.len(), 1);
    assert_eq!(
        field(&volumes[0], &["name"]).as_str(),
        field(mount, &["name"]).as_str(),
        "the mount and the volume must refer to the same name"
    );
}

/// Liveness and readiness must use the existing operational endpoints with
/// their existing semantics, on the configured listener port.
#[test]
fn the_deployment_contract_example_probes_the_operational_endpoints() {
    let example = kubernetes_example();
    let container = container(&example);

    let port_name = field(container, &["ports"])
        .as_sequence()
        .and_then(|ports| ports.first())
        .map(|port| field(port, &["name"]))
        .and_then(Value::as_str)
        .expect("the container names its listener port");

    for (probe, path) in [("livenessProbe", "/healthz"), ("readinessProbe", "/readyz")] {
        let request = field(container, &[probe, "httpGet"]);
        assert_eq!(
            field(request, &["path"]).as_str(),
            Some(path),
            "{probe} must use {path}"
        );
        assert_eq!(
            field(request, &["port"]).as_str(),
            Some(port_name),
            "{probe} must target the configured listener port"
        );
        assert!(
            request.get("scheme").and_then(Value::as_str) != Some("HTTPS"),
            "{probe} speaks plain HTTP; TLS termination is a deployment concern"
        );
    }
}

/// Graceful termination has to be compatible with the shutdown grace the
/// mounted configuration selects, otherwise Kubernetes would kill the process
/// while a compliant request was still allowed to finish.
#[test]
fn the_deployment_contract_example_allows_the_configured_shutdown_grace() {
    let example = kubernetes_example();
    let grace_period = Duration::from_secs(
        field(pod_spec(&example), &["terminationGracePeriodSeconds"])
            .as_u64()
            .expect("the pod declares a termination grace period"),
    );

    let documented: Value = yaml_serde::from_str(&read("docs/permissionsync.example.yaml"))
        .expect("the documented example configuration parses as YAML");
    let configured_grace = Duration::from_millis(
        field(&documented, &["shutdown", "grace_milliseconds"])
            .as_u64()
            .expect("the example configuration declares a shutdown grace"),
    );

    assert!(
        grace_period >= configured_grace,
        "terminationGracePeriodSeconds ({grace_period:?}) must be at least the configured \
         shutdown grace ({configured_grace:?})"
    );
}

/// The published artifact is immutable and offline-recoverable only if the
/// deployment pins it by digest; the example has to show that.
#[test]
fn the_deployment_contract_example_pins_the_image_by_digest() {
    let example = kubernetes_example();
    let image = field(container(&example), &["image"])
        .as_str()
        .expect("the container names an image");
    assert!(
        image.starts_with("ghcr.io/neteye-platform/permissionsync:"),
        "the example must reference the published image repository, found {image}"
    );
    assert!(
        image.contains("@sha256:"),
        "the example must pin the selected image by immutable digest, found {image}"
    );
    assert!(
        image.contains("REPLACE_WITH_"),
        "the example must stay a placeholder rather than pinning a real release"
    );
}
