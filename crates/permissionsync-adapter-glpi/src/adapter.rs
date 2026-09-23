//! The GLPI Target Adapter: orchestrates the mandatory operation order from
//! ADR 0009 end to end. See the crate-level documentation for the full
//! contract.

use std::time::{Duration, Instant};

use permissionsync_core::{
    BoxFuture, ReconciliationOutcome, SynchronizationContext, TargetAdapter, TargetAdapterError,
    TargetAdapterRequest,
};

use crate::{
    config::{GlpiAdapterConfig, ValidatedConfig, validate},
    error::{GlpiAdapterConfigError, GlpiFailure},
    mutation, payload, plan,
    search::{
        self, REQUIRED_ENTITY_UIDS, REQUIRED_PROFILE_UIDS, REQUIRED_PROFILE_USER_UIDS,
        REQUIRED_USER_UIDS, SearchOptions,
    },
    session::{self, GlpiSession},
};

/// The GLPI Target Adapter. Reconciles one synchronized user's complete
/// `Profile_User` assignment set against a v1 desired-state payload.
pub struct GlpiAdapter {
    config: ValidatedConfig,
}

impl GlpiAdapter {
    /// Validates the given adapter-local configuration and constructs a new
    /// adapter instance. All static configuration is validated eagerly;
    /// no GLPI request is made during construction.
    pub fn new(config: GlpiAdapterConfig) -> Result<Self, GlpiAdapterConfigError> {
        Ok(Self {
            config: validate(config)?,
        })
    }
}

impl TargetAdapter for GlpiAdapter {
    fn reconcile<'a>(
        &'a self,
        request: TargetAdapterRequest<'a>,
    ) -> BoxFuture<'a, Result<ReconciliationOutcome, TargetAdapterError>> {
        Box::pin(async move {
            reconcile(&self.config, request)
                .await
                .map_err(TargetAdapterError::new)
        })
    }
}

pub(crate) fn effective_deadline(
    context: &SynchronizationContext<'_>,
    operation_timeout: Duration,
) -> Result<Instant, GlpiFailure> {
    if context.cancellation().is_cancelled() {
        return Err(GlpiFailure::Cancelled);
    }
    let now = Instant::now();
    if context.deadline() <= now {
        return Err(GlpiFailure::DeadlineExceeded);
    }
    let operation_deadline = now
        .checked_add(operation_timeout)
        .unwrap_or(context.deadline());
    Ok(context.deadline().min(operation_deadline))
}

pub(crate) fn check_context(
    context: &SynchronizationContext<'_>,
    deadline: Instant,
) -> Result<(), GlpiFailure> {
    if context.cancellation().is_cancelled() {
        return Err(GlpiFailure::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(GlpiFailure::DeadlineExceeded);
    }
    Ok(())
}

async fn reconcile(
    config: &ValidatedConfig,
    request: TargetAdapterRequest<'_>,
) -> Result<ReconciliationOutcome, GlpiFailure> {
    let context = request.context();
    check_context(context, context.deadline())?;

    if request.desired_state().version().get() != 1 {
        return Err(GlpiFailure::UnsupportedEnvelopeVersion);
    }

    let desired = payload::parse_and_normalize(request.desired_state().payload().as_json())?;

    // Each outbound operation gets its own freshly recomputed
    // `min(overall_deadline, now+operation_timeout)` window immediately
    // before it is issued, rather than a single deadline threaded unchanged
    // through the whole reconciliation. See `effective_deadline`.
    let init_session_deadline = effective_deadline(context, config.operation_timeout)?;
    let session = session::init_session(config, init_session_deadline).await?;
    let outcome = reconcile_with_session(
        config,
        &session,
        request.identity().username(),
        &desired,
        context,
    )
    .await;
    // Cleanup must never start after observed cancellation or expiry (ADR
    // 0009 "Cleanup never starts after observed cancellation or expiry").
    // The naive form of this check re-observes cancellation/deadline via
    // `effective_deadline` immediately before `kill_session`, but discarding
    // that second observation with `.unwrap_or(...)` re-introduces exactly
    // the race it exists to close: cancellation/expiry becomes true between
    // the first check and the second, `effective_deadline` returns `Err`,
    // and the fallback deadline lets `kill_session` start anyway. The
    // `Err(_)` arm below is therefore load-bearing: it suppresses cleanup
    // entirely rather than falling back to any prior deadline.
    let cleanup_allowed =
        !context.cancellation().is_cancelled() && Instant::now() < context.deadline();

    if cleanup_allowed {
        match effective_deadline(context, config.operation_timeout) {
            Ok(cleanup_deadline) => {
                let cleanup_result =
                    session::kill_session(config, &session, cleanup_deadline).await;
                return match (outcome, cleanup_result) {
                    (Ok(outcome), Ok(())) => Ok(outcome),
                    (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
                    (Err(primary_error), _) => Err(primary_error),
                };
            }
            Err(_) => {
                // Cancellation or expiry was observed between the first
                // check and this one: no cleanup request may start.
            }
        }
    }

    outcome
}

async fn reconcile_with_session(
    config: &ValidatedConfig,
    session: &GlpiSession,
    username: &str,
    desired: &[payload::CanonicalAssignment],
    context: &SynchronizationContext<'_>,
) -> Result<ReconciliationOutcome, GlpiFailure> {
    let deadline = effective_deadline(context, config.operation_timeout)?;
    session::force_all_entities(config, session, deadline).await?;
    let deadline = effective_deadline(context, config.operation_timeout)?;
    session::verify_complete_visibility(config, session, deadline).await?;

    let entity_options = if desired.is_empty() {
        None
    } else {
        Some(
            resolve_search_options(config, session, "Entity", REQUIRED_ENTITY_UIDS, context)
                .await?,
        )
    };
    let profile_options = if desired.is_empty() {
        None
    } else {
        Some(
            resolve_search_options(config, session, "Profile", REQUIRED_PROFILE_UIDS, context)
                .await?,
        )
    };
    let user_options =
        resolve_search_options(config, session, "User", REQUIRED_USER_UIDS, context).await?;
    let profile_user_options = resolve_search_options(
        config,
        session,
        "Profile_User",
        REQUIRED_PROFILE_USER_UIDS,
        context,
    )
    .await?;

    // Resolve every unique desired entity/profile reference before any user
    // lookup, creation, or mutation. When there is no desired assignment at
    // all, no Entity or Profile GLPI request is issued: `entity_options`/
    // `profile_options` above are never populated in that case, and the
    // loop below runs zero times regardless.
    let mut resolved_entities: Vec<(String, u64)> = Vec::new();
    let mut resolved_profiles: Vec<(String, u64)> = Vec::new();

    for assignment in desired {
        check_context(context, context.deadline())?;
        if !resolved_entities
            .iter()
            .any(|(selector, _)| selector == &assignment.entity)
        {
            let entity_options = entity_options
                .as_ref()
                .expect("entity_options is populated whenever desired is non-empty");
            let id = search::resolve_entity_id(
                config,
                session,
                entity_options,
                &assignment.entity,
                context,
            )
            .await?;
            resolved_entities.push((assignment.entity.clone(), id));
        }

        check_context(context, context.deadline())?;
        if !resolved_profiles
            .iter()
            .any(|(selector, _)| selector == &assignment.profile)
        {
            let profile_options = profile_options
                .as_ref()
                .expect("profile_options is populated whenever desired is non-empty");
            let id = search::resolve_profile_id(
                config,
                session,
                profile_options,
                &assignment.profile,
                context,
            )
            .await?;
            resolved_profiles.push((assignment.profile.clone(), id));
        }
    }

    let existing_user_id =
        search::resolve_user_id(config, session, &user_options, username, context).await?;

    let (user_id, mut changed) = match existing_user_id {
        Some(id) => (id, false),
        None => {
            let deadline = effective_deadline(context, config.operation_timeout)?;
            let id = mutation::create_user(
                config,
                session,
                username,
                &config.authentication_source,
                deadline,
            )
            .await?;
            (id, true)
        }
    };

    let current = search::read_current_assignments(
        config,
        session,
        &profile_user_options,
        username,
        user_id,
        context,
    )
    .await?;

    let desired_resolved: Vec<plan::DesiredAssignment> = desired
        .iter()
        .map(|assignment| {
            let entities_id = resolved_entities
                .iter()
                .find(|(selector, _)| selector == &assignment.entity)
                .map(|(_, id)| *id)
                .expect("every desired entity was resolved above");
            let profiles_id = resolved_profiles
                .iter()
                .find(|(selector, _)| selector == &assignment.profile)
                .map(|(_, id)| *id)
                .expect("every desired profile was resolved above");
            plan::DesiredAssignment {
                entities_id,
                profiles_id,
                recursive: assignment.recursive,
            }
        })
        .collect();

    let reconciliation_plan = plan::compute(&current, &desired_resolved);
    if !reconciliation_plan.is_empty() {
        changed = true;
    }

    for assignment_id in &reconciliation_plan.removals {
        let deadline = effective_deadline(context, config.operation_timeout)?;
        mutation::delete_assignment(config, session, *assignment_id, deadline).await?;
    }

    for addition in &reconciliation_plan.additions {
        let deadline = effective_deadline(context, config.operation_timeout)?;
        mutation::create_assignment(
            config,
            session,
            user_id,
            addition.profiles_id,
            addition.entities_id,
            addition.recursive,
            deadline,
        )
        .await?;
    }

    if changed {
        Ok(ReconciliationOutcome::Changed)
    } else {
        Ok(ReconciliationOutcome::Unchanged)
    }
}

async fn resolve_search_options(
    config: &ValidatedConfig,
    session: &GlpiSession,
    itemtype: &str,
    required_uids: &[&'static str],
    context: &SynchronizationContext<'_>,
) -> Result<SearchOptions, GlpiFailure> {
    let deadline = effective_deadline(context, config.operation_timeout)?;
    search::resolve_search_options(config, session, itemtype, required_uids, deadline).await
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use permissionsync_core::{CancellationSignal, SynchronizationContext};

    use super::effective_deadline;
    use crate::error::GlpiFailure;

    struct NeverCancelled;

    impl CancellationSignal for NeverCancelled {
        fn is_cancelled(&self) -> bool {
            false
        }
    }

    /// Operation timeout shorter than the overall deadline: the effective
    /// deadline must be `now + operation_timeout`, not the overall deadline.
    #[test]
    fn effective_deadline_uses_operation_timeout_when_shorter_than_overall_deadline() {
        let cancellation = NeverCancelled;
        let overall_deadline = Instant::now() + Duration::from_secs(60);
        let context = SynchronizationContext::new(overall_deadline, &cancellation);
        let operation_timeout = Duration::from_millis(50);

        let before = Instant::now();
        let deadline =
            effective_deadline(&context, operation_timeout).expect("deadline is computed");
        let after = Instant::now();

        assert!(deadline >= before + operation_timeout);
        assert!(deadline <= after + operation_timeout);
        assert!(deadline < overall_deadline);
    }

    /// Overall deadline shorter than the operation timeout: the effective
    /// deadline must be capped at the overall deadline.
    #[test]
    fn effective_deadline_caps_at_overall_deadline_when_shorter_than_operation_timeout() {
        let cancellation = NeverCancelled;
        let overall_deadline = Instant::now() + Duration::from_secs(30);
        let context = SynchronizationContext::new(overall_deadline, &cancellation);
        let operation_timeout = Duration::from_secs(60);

        let deadline =
            effective_deadline(&context, operation_timeout).expect("deadline is computed");

        assert_eq!(deadline, overall_deadline);
    }

    /// Calling `effective_deadline` again later, for an unrelated subsequent
    /// operation, must yield a fresh `now + operation_timeout` window rather
    /// than a value shrunk by time already consumed by a prior operation.
    #[test]
    fn effective_deadline_is_recomputed_fresh_for_each_call() {
        let cancellation = NeverCancelled;
        let overall_deadline = Instant::now() + Duration::from_secs(60);
        let context = SynchronizationContext::new(overall_deadline, &cancellation);
        let operation_timeout = Duration::from_millis(200);

        let first = effective_deadline(&context, operation_timeout).expect("first deadline");
        let before_second = Instant::now();
        let second = effective_deadline(&context, operation_timeout).expect("second deadline");

        // A new call creates a full new operation window, rather than reusing
        // the first operation's deadline. No wall-clock sleep is needed to
        // establish that lower bound.
        assert!(second >= before_second + operation_timeout);
        assert!(second >= first);
    }

    /// No operation may start after the overall deadline: `effective_deadline`
    /// must return an error once `context.deadline()` is already in the past.
    #[test]
    fn effective_deadline_fails_once_overall_deadline_has_passed() {
        let cancellation = NeverCancelled;
        let elapsed_deadline = Instant::now() - Duration::from_millis(10);
        let context = SynchronizationContext::new(elapsed_deadline, &cancellation);
        let operation_timeout = Duration::from_secs(60);

        let result = effective_deadline(&context, operation_timeout);

        assert!(matches!(result, Err(GlpiFailure::DeadlineExceeded)));
    }

    #[test]
    fn effective_deadline_fails_when_cancelled() {
        struct AlwaysCancelled;

        impl CancellationSignal for AlwaysCancelled {
            fn is_cancelled(&self) -> bool {
                true
            }
        }

        let cancellation = AlwaysCancelled;
        let overall_deadline = Instant::now() + Duration::from_secs(60);
        let context = SynchronizationContext::new(overall_deadline, &cancellation);

        let result = effective_deadline(&context, Duration::from_secs(1));

        assert!(matches!(result, Err(GlpiFailure::Cancelled)));
    }
}

/// Private, crate-internal-only coverage proving the *concrete* primary
/// `GlpiFailure` variant survives a concrete `GlpiFailure::CleanupFailed`
/// cleanup failure (ADR 0009: "after an earlier failure, [a `killSession`
/// failure] does not replace the primary failure"). The public conformance
/// suite can only observe this through the redacted `TargetAdapterError`
/// (see `cleanup_failure_after_primary_failure_is_still_a_failure` in
/// `tests/conformance.rs`); this module calls the crate-private `reconcile`
/// free function directly so the exact surviving variant can be asserted.
/// Nothing here is exposed outside `#[cfg(test)]`: `GlpiFailure` and
/// `reconcile` remain private to the crate.
#[cfg(test)]
mod cleanup_survival_tests {
    use std::time::Duration;

    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::{MessageDigest, hash},
        nid::Nid,
        pkey::{Id, PKey, PKeyRef, Private},
        x509::{
            X509, X509Name, X509NameRef,
            extension::{BasicConstraints, KeyUsage, SubjectAlternativeName},
        },
    };
    use permissionsync_core::{
        CancellationSignal, DesiredStateEnvelope, EnvelopeVersion, IdentityContext, OpaquePayload,
        SynchronizationContext, TargetAdapterRequest,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_native_tls::TlsAcceptor;

    use super::reconcile;
    use crate::{
        config::{
            GlpiAdapterConfig, GlpiAppToken, GlpiAuthenticationSource, GlpiUserToken, validate,
        },
        error::GlpiFailure,
    };

    const LOOPBACK_ADDRESS: &str = "127.0.0.1";
    const ROOT_LABEL: &str = "permissionsync-glpi-adapter-unit-root-v1";
    const LEAF_LABEL: &str = "permissionsync-glpi-adapter-unit-leaf-v1";
    const NOT_BEFORE_UNIX_SECONDS: i64 = 1_700_000_000;
    const NOT_AFTER_UNIX_SECONDS: i64 = 4_100_000_000;

    struct NeverCancelled;

    impl CancellationSignal for NeverCancelled {
        fn is_cancelled(&self) -> bool {
            false
        }
    }

    fn key_from_label(label: &str) -> PKey<Private> {
        let digest = hash(MessageDigest::sha256(), label.as_bytes()).expect("sha-256 digest");
        let seed: [u8; 32] = digest.as_ref().try_into().expect("32-byte digest");
        PKey::private_key_from_raw_bytes(&seed, Id::ED25519).expect("valid ed25519 seed")
    }

    fn name(common_name: &str) -> X509Name {
        let mut builder = openssl::x509::X509NameBuilder::new().expect("name builder");
        builder
            .append_entry_by_nid(Nid::COMMONNAME, common_name)
            .expect("append common name");
        builder.build()
    }

    fn builder(
        subject: &X509NameRef,
        issuer: &X509NameRef,
        public_key: &PKeyRef<Private>,
        serial: u32,
    ) -> openssl::x509::X509Builder {
        let mut builder = X509::builder().expect("x509 builder");
        builder.set_version(2).expect("version");
        builder.set_subject_name(subject).expect("subject");
        builder.set_issuer_name(issuer).expect("issuer");
        builder.set_pubkey(public_key).expect("public key");
        let serial_number = BigNum::from_u32(serial).expect("serial bignum");
        builder
            .set_serial_number(&serial_number.to_asn1_integer().expect("serial asn1"))
            .expect("set serial");
        builder
            .set_not_before(&Asn1Time::from_unix(NOT_BEFORE_UNIX_SECONDS).unwrap())
            .expect("not before");
        builder
            .set_not_after(&Asn1Time::from_unix(NOT_AFTER_UNIX_SECONDS).unwrap())
            .expect("not after");
        builder
    }

    /// A minimal loopback TLS test identity: a self-signed CA plus one
    /// SAN-bearing leaf certificate for `127.0.0.1`, deterministically
    /// derived from fixed public labels (never randomly generated, never
    /// committed as raw key bytes). Deliberately kept private and much
    /// smaller than `tests/conformance.rs`'s identity helper: this harness
    /// only needs to prove one concrete-variant failure-survival property.
    fn test_identity() -> (Vec<u8>, TlsAcceptor) {
        let root_key = key_from_label(ROOT_LABEL);
        let root_name = name(ROOT_LABEL);
        let mut root_builder = builder(&root_name, &root_name, &root_key, 1);
        root_builder
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        root_builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        root_builder.sign(&root_key, MessageDigest::null()).unwrap();
        let root_certificate = root_builder.build();

        let leaf_key = key_from_label(LEAF_LABEL);
        let leaf_name = name(LOOPBACK_ADDRESS);
        let mut leaf_builder = builder(&leaf_name, root_certificate.subject_name(), &leaf_key, 2);
        leaf_builder
            .append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        leaf_builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let subject_alternative_name = SubjectAlternativeName::new()
            .ip(LOOPBACK_ADDRESS)
            .build(&leaf_builder.x509v3_context(None, None))
            .unwrap();
        leaf_builder
            .append_extension(subject_alternative_name)
            .unwrap();
        leaf_builder.sign(&root_key, MessageDigest::null()).unwrap();
        let leaf_certificate = leaf_builder.build();

        let leaf_certificate_pem = leaf_certificate.to_pem().unwrap();
        let leaf_key_pem = leaf_key.private_key_to_pem_pkcs8().unwrap();
        let identity =
            native_tls::Identity::from_pkcs8(&leaf_certificate_pem, &leaf_key_pem).unwrap();
        let acceptor = native_tls::TlsAcceptor::builder(identity)
            .min_protocol_version(Some(native_tls::Protocol::Tlsv12))
            .build()
            .unwrap();

        (
            root_certificate.to_pem().unwrap(),
            TlsAcceptor::from(acceptor),
        )
    }

    fn json_response(status_line: &'static str, body: &str) -> (&'static str, Vec<u8>) {
        (status_line, body.as_bytes().to_vec())
    }

    /// Runs a strictly ordered scripted fake GLPI server: one TLS connection
    /// per scripted response, in order. Deliberately does not validate the
    /// outgoing wire contract (that is `tests/conformance.rs`'s job); this
    /// harness exists only to drive `reconcile` through the exact request
    /// sequence needed for the concrete-variant assertions below.
    async fn run_script(
        listener: TcpListener,
        acceptor: TlsAcceptor,
        script: Vec<(&'static str, Vec<u8>)>,
    ) {
        for (status_line, body) in script {
            let (socket, _) = listener.accept().await.expect("accept connection");
            let mut stream = acceptor.accept(socket).await.expect("tls handshake");
            read_request_and_discard(&mut stream).await;
            let response = format!(
                "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let mut bytes = response.into_bytes();
            bytes.extend_from_slice(&body);
            stream.write_all(&bytes).await.expect("write response");
            let _ = stream.shutdown().await;
        }
    }

    async fn read_request_and_discard<S>(stream: &mut S)
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let mut buffer = Vec::new();
        let header_end = loop {
            let mut chunk = [0_u8; 1024];
            let read = stream.read(&mut chunk).await.expect("read request bytes");
            assert!(read > 0, "connection closed before request completed");
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break position;
            }
        };

        let header_text = String::from_utf8(buffer[..header_end].to_vec()).expect("utf8 headers");
        let mut content_length = 0_usize;
        for line in header_text.split("\r\n").skip(1) {
            if let Some((name, value)) = line.split_once(':')
                && name.trim().eq_ignore_ascii_case("content-length")
            {
                content_length = value.trim().parse().expect("content length digits");
            }
        }

        let mut body_len = buffer.len() - (header_end + 4);
        while body_len < content_length {
            let mut chunk = [0_u8; 1024];
            let read = stream.read(&mut chunk).await.expect("read request body");
            assert!(read > 0, "connection closed before request body completed");
            body_len += read;
        }
    }

    fn adapter_config(port: u16, trust_anchor_pem: Vec<u8>) -> GlpiAdapterConfig {
        GlpiAdapterConfig {
            endpoint: format!("https://{LOOPBACK_ADDRESS}:{port}/apirest.php"),
            app_token: GlpiAppToken::new("app-token".to_owned()),
            user_token: GlpiUserToken::new("user-token".to_owned()),
            operation_timeout: Duration::from_secs(5),
            additional_trust_anchors_pem: vec![trust_anchor_pem],
            authentication_source: GlpiAuthenticationSource::default(),
        }
    }

    fn empty_desired_envelope() -> DesiredStateEnvelope {
        DesiredStateEnvelope::new(
            EnvelopeVersion::new(1),
            OpaquePayload::try_from(r#"{"permissions": []}"#.to_owned()).unwrap(),
        )
    }

    async fn bind_loopback_listener() -> TcpListener {
        TcpListener::bind((LOOPBACK_ADDRESS, 0))
            .await
            .expect("bind ephemeral loopback listener")
    }

    fn full_session_body(show_all: u64) -> String {
        format!(r#"{{"session": {{"glpishowallentities": {show_all}}}}}"#)
    }

    fn search_options_body(entries: &[(&str, &str)]) -> String {
        let mut fields = Vec::new();
        for (id, uid) in entries {
            fields.push(format!(r#""{id}": {{"uid": "{uid}"}}"#));
        }
        format!("{{{}}}", fields.join(","))
    }

    fn user_search_two_exact_matches_body() -> String {
        r#"{"totalcount":2,"count":2,"content-range":"0-1/2","data":[{"1":30,"2":"jdoe"},{"1":31,"2":"jdoe"}]}"#
            .to_owned()
    }

    /// The concrete primary `GlpiFailure::AmbiguousReference` (from an
    /// ambiguous exact `User.name` match) must survive a concrete
    /// `GlpiFailure::CleanupFailed` `killSession` failure: ADR 0009's
    /// "does not replace the primary failure" is a specific-variant
    /// requirement, not merely "still an error".
    #[tokio::test]
    async fn ambiguous_reference_primary_failure_survives_cleanup_failure() {
        let (trust_anchor_pem, acceptor) = test_identity();
        let listener = bind_loopback_listener().await;
        let port = listener.local_addr().unwrap().port();
        let config = validate(adapter_config(port, trust_anchor_pem)).expect("valid config");

        let script = vec![
            json_response("200 OK", r#"{"session_token": "sess-1"}"#), // initSession
            json_response("200 OK", "true"),                           // changeActiveEntities
            json_response("200 OK", &full_session_body(1)),            // getFullSession
            json_response(
                "200 OK",
                &search_options_body(&[("1", "User.id"), ("2", "User.name")]),
            ), // listSearchOptions/User
            json_response(
                "200 OK",
                &search_options_body(&[("1", "Profile_User.id"), ("2", "User.name")]),
            ), // listSearchOptions/Profile_User
            json_response("200 OK", &user_search_two_exact_matches_body()), // search User: ambiguous
            // killSession itself also fails (a non-"true" body): the primary
            // AmbiguousReference failure must still be what is returned.
            json_response("200 OK", "false"),
        ];

        let server = tokio::spawn(run_script(listener, acceptor, script));
        let identity = IdentityContext::new("jdoe".to_owned(), vec![]);
        let cancellation = NeverCancelled;
        let context = SynchronizationContext::new(
            std::time::Instant::now() + Duration::from_secs(60),
            &cancellation,
        );
        let envelope = empty_desired_envelope();
        let request = TargetAdapterRequest::new(&identity, &envelope, context);

        let outcome = reconcile(&config, request).await;
        server.await.expect("scripted server completed its script");

        assert!(
            matches!(outcome, Err(GlpiFailure::AmbiguousReference)),
            "the primary AmbiguousReference failure must survive a concurrent CleanupFailed"
        );
    }

    /// A second representative primary-error variant survives a cleanup
    /// failure: an unresolved (missing) entity reference (`MissingReference`)
    /// fails before any user lookup, and that concrete variant must still
    /// survive a failing `killSession`.
    #[tokio::test]
    async fn missing_reference_primary_failure_survives_cleanup_failure() {
        let (trust_anchor_pem, acceptor) = test_identity();
        let listener = bind_loopback_listener().await;
        let port = listener.local_addr().unwrap().port();
        let config = validate(adapter_config(port, trust_anchor_pem)).expect("valid config");

        let script = vec![
            json_response("200 OK", r#"{"session_token": "sess-1"}"#), // initSession
            json_response("200 OK", "true"),                           // changeActiveEntities
            json_response("200 OK", &full_session_body(1)),            // getFullSession
            json_response(
                "200 OK",
                &search_options_body(&[("1", "Entity.id"), ("2", "Entity.completename")]),
            ), // listSearchOptions/Entity
            json_response(
                "200 OK",
                &search_options_body(&[("1", "Profile.id"), ("2", "Profile.name")]),
            ), // listSearchOptions/Profile
            json_response(
                "200 OK",
                &search_options_body(&[("1", "User.id"), ("2", "User.name")]),
            ), // listSearchOptions/User
            json_response(
                "200 OK",
                &search_options_body(&[("1", "Profile_User.id"), ("2", "User.name")]),
            ), // listSearchOptions/Profile_User
            // Zero exact Entity matches: MissingReference, before any user
            // lookup.
            json_response(
                "200 OK",
                r#"{"totalcount":0,"count":0,"content-range":"0--1/0"}"#,
            ),
            // killSession also fails.
            json_response("200 OK", "false"),
        ];

        let server = tokio::spawn(run_script(listener, acceptor, script));
        let identity = IdentityContext::new("jdoe".to_owned(), vec![]);
        let cancellation = NeverCancelled;
        let context = SynchronizationContext::new(
            std::time::Instant::now() + Duration::from_secs(60),
            &cancellation,
        );
        let envelope = DesiredStateEnvelope::new(
            EnvelopeVersion::new(1),
            OpaquePayload::try_from(
                r#"{"permissions": [{"entity": "Root Entity > IT", "profile": "Technician", "recursive": true}]}"#
                    .to_owned(),
            )
            .unwrap(),
        );
        let request = TargetAdapterRequest::new(&identity, &envelope, context);

        let outcome = reconcile(&config, request).await;
        server.await.expect("scripted server completed its script");

        assert!(
            matches!(outcome, Err(GlpiFailure::MissingReference)),
            "the primary MissingReference failure must survive a concurrent CleanupFailed"
        );
    }
}
