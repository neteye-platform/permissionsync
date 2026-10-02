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

/// Headroom the checked-in example must keep above the configured request
/// grace.
///
/// Kubernetes' termination horizon has to cover more than
/// `shutdown.grace_milliseconds`: once that expires the runtime still spends a
/// fixed bounded window letting cancelled requests return, and then a bounded
/// final trace flush, before it exits. Those are private runtime constants, so
/// this file does not pretend to know them. It asserts only that the example
/// keeps a real margin, which is what makes the example safe to copy, instead
/// of codifying the weaker claim that equalling the configured grace is always
/// enough.
const MINIMUM_TERMINATION_HEADROOM: Duration = Duration::from_secs(5);

#[test]
fn the_deployment_contract_example_keeps_headroom_above_the_configured_grace() {
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

    let required = configured_grace + MINIMUM_TERMINATION_HEADROOM;
    assert!(
        grace_period >= required,
        "terminationGracePeriodSeconds ({grace_period:?}) must cover the configured shutdown \
         grace ({configured_grace:?}) plus headroom for the runtime's bounded post-grace \
         phases, so at least {required:?}"
    );
}

/// Overlapping workflow runs for one release ref must not race each other
/// through the preflight and publish path, and a later run must never cancel a
/// release that is already publishing.
#[test]
fn the_release_workflow_serializes_releases_per_ref() {
    let workflow: Value = yaml_serde::from_str(&read(".github/workflows/release-image.yaml"))
        .expect("the release workflow parses as YAML");
    let concurrency = field(&workflow, &["concurrency"]);
    let group = field(concurrency, &["group"])
        .as_str()
        .expect("the concurrency group is a string");
    assert!(
        group.contains("github.ref"),
        "the concurrency group must be per release ref, found {group:?}"
    );
    assert_eq!(
        field(concurrency, &["cancel-in-progress"]).as_bool(),
        Some(false),
        "a later release run must not cancel one that is already publishing"
    );
}

/// The published tag set is a release decision, and documentation that claims
/// the opposite is worse than none. Stable releases really do move `latest`,
/// so the documentation has to describe it and still direct deployments at the
/// immutable references.
#[test]
fn the_release_documentation_describes_latest_as_mutable() {
    let readme = read("README.md");
    assert!(
        readme.contains("`latest`"),
        "the README must document the latest tag that stable releases move"
    );
    assert!(
        readme.contains("Mutable by design"),
        "the README must say plainly that latest is mutable"
    );
    assert!(
        readme.contains("@sha256:"),
        "the README must keep recommending the immutable digest"
    );
    for source in [
        "README.md",
        ".github/workflows/release-image.yaml",
        "deploy/kubernetes/permissionsync.example.yaml",
    ] {
        let text = read(source);
        for stale in ["no mutable `latest`", "no `latest`", "publishes no mutable"] {
            assert!(
                !text.contains(stale),
                "{source} still claims {stale:?}, which is not what the release workflow does"
            );
        }
    }
}

/// The scanner policy for the deployment contract is configuration, not
/// suppression: KSV0125 stays enabled for every workload in this repository
/// and only its generic trusted-registry data is replaced. This asserts the
/// checked-in policy stays that narrow; it deliberately does not reimplement
/// Trivy's own rule, which `integration` scanning in CI evaluates for real.
#[test]
fn the_trivy_policy_narrows_ksv0125_instead_of_suppressing_it() {
    assert!(
        !repository_path(".trivyignore").exists(),
        ".trivyignore must not exist: KSV0125 is configured, never suppressed"
    );

    let configuration: Value =
        yaml_serde::from_str(&read("trivy.yaml")).expect("trivy.yaml parses as YAML");
    assert_eq!(
        configuration
            .as_mapping()
            .expect("trivy.yaml is a mapping")
            .len(),
        1,
        "trivy.yaml must configure nothing beyond the Rego data path"
    );

    let data_paths: Vec<&str> = field(&configuration, &["rego", "data"])
        .as_sequence()
        .expect("rego.data is a sequence")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        data_paths.len(),
        1,
        "exactly one repository-owned data path is loaded, found {data_paths:?}"
    );

    // The trusted-registry data has to live under the path trivy.yaml really
    // loads, not merely at a filename this test happens to know.
    let data_directory = repository_path(data_paths[0]);
    assert!(
        data_directory.is_dir(),
        "{} must be the repository's Trivy data directory",
        data_directory.display()
    );
    let trusted: Vec<String> = fs::read_dir(&data_directory)
        .expect("the Trivy data directory is readable")
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read_to_string(entry.path()).ok())
        .filter_map(|text| yaml_serde::from_str::<Value>(&text).ok())
        .filter_map(|document| {
            document
                .get("ksv0125")
                .and_then(|check| check.get("trusted_registries"))
                .and_then(Value::as_sequence)
                .map(|registries| {
                    registries
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect::<Vec<String>>()
                })
        })
        .flatten()
        .collect();

    // Both assertions below deliberately carry fixed messages: the values come
    // from repository configuration and printing them buys nothing.
    assert!(
        trusted.iter().any(|registry| registry == "ghcr.io"),
        "KSV0125 must trust ghcr.io"
    );
    assert!(
        trusted.iter().all(|registry| {
            !registry.is_empty()
                && !registry.contains('*')
                && !registry.contains('/')
                && !registry.contains("://")
        }),
        "KSV0125 trusted registries must be non-empty plain registry hosts, with no wildcard, \
         scheme, or path"
    );
}

/// `latest` is expected to exist from the first stable release onward and to
/// move on every later one, so its presence must never block a release.
#[test]
fn the_release_preflight_checks_the_version_tag_rather_than_latest() {
    let workflow: Value = yaml_serde::from_str(&read(".github/workflows/release-image.yaml"))
        .expect("the release workflow parses as YAML");
    let steps = field(&workflow, &["jobs", "unpublished-version", "steps"])
        .as_sequence()
        .expect("the preflight job declares steps");
    let script = steps
        .iter()
        .filter_map(|step| step.get("run"))
        .filter_map(Value::as_str)
        .collect::<String>();
    assert!(
        !script.is_empty(),
        "the preflight job must run a registry check"
    );
    assert!(
        script.contains("manifests/${version}"),
        "the preflight must request the immutable version manifest"
    );
    assert!(
        !script.contains("manifests/latest"),
        "the preflight must not consult the mutable latest tag"
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
