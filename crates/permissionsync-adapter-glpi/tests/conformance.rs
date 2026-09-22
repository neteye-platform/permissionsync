//! Hermetic, deterministic conformance tests for the GLPI Target Adapter.
//!
//! These tests use only a local loopback TLS server driven by an explicit,
//! ordered response script and deterministic in-memory Ed25519 certificates
//! derived at runtime from fixed public labels via SHA-256 (never generated
//! randomly, never committed as raw key bytes). They never use the public
//! Internet, Docker, a real GLPI instance, fixed ports, or arbitrary sleeps.
//! Every GLPI production request opens its own TCP+TLS connection (matching
//! the adapter's single-attempt-per-operation transport), so this server
//! accepts one connection per scripted request/response pair, in order.

use std::time::{Duration, Instant};

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
use permissionsync_adapter_glpi::{
    GlpiAdapter, GlpiAdapterConfig, GlpiAppToken, GlpiAuthenticationSource, GlpiUserToken,
};
use permissionsync_core::{
    CancellationSignal, DesiredStateEnvelope, EnvelopeVersion, IdentityContext, OpaquePayload,
    ReconciliationOutcome, SynchronizationContext, TargetAdapter, TargetAdapterRequest,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_native_tls::TlsAcceptor;

const LOOPBACK_ADDRESS: &str = "127.0.0.1";
const ROOT_KEY_LABEL: &str = "permissionsync-glpi-test-root-v1";
const LEAF_KEY_LABEL: &str = "permissionsync-glpi-test-leaf-v1";
const OTHER_ROOT_KEY_LABEL: &str = "permissionsync-glpi-test-other-root-v1";
const OTHER_LEAF_KEY_LABEL: &str = "permissionsync-glpi-test-other-leaf-v1";
const ROOT_CERTIFICATE_SERIAL: u32 = 1;
const LEAF_CERTIFICATE_SERIAL: u32 = 2;
const CERTIFICATE_NOT_BEFORE_UNIX_SECONDS: i64 = 1_700_000_000;
const CERTIFICATE_NOT_AFTER_UNIX_SECONDS: i64 = 4_100_000_000;

// --- Scripted fake GLPI server -----------------------------------------------

/// One scripted GLPI V1 response for the next accepted connection, in order.
struct ScriptedResponse {
    status_line: &'static str,
    body: Vec<u8>,
}

fn json_response(status_line: &'static str, body: &str) -> ScriptedResponse {
    ScriptedResponse {
        status_line,
        body: body.as_bytes().to_vec(),
    }
}

fn ok(body: &str) -> ScriptedResponse {
    json_response("200 OK", body)
}

fn created(body: &str) -> ScriptedResponse {
    json_response("201 Created", body)
}

/// Runs a scripted fake GLPI server: for each entry in `script`, in order,
/// accepts exactly one TLS connection, reads one HTTP request, ignores its
/// content (the adapter's own logic is exercised through its real outcome
/// and through connection *count*, not per-request assertions in most
/// tests), writes the scripted response, and closes. Returns the recorded
/// request lines and header maps for callers that need them.
async fn run_scripted_server(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    script: Vec<ScriptedResponse>,
) -> Vec<(String, Vec<(String, String)>, Vec<u8>)> {
    let mut recorded = Vec::new();
    for entry in script {
        let (socket, _) = listener.accept().await.expect("accept connection");
        let mut stream = acceptor.accept(socket).await.expect("tls handshake");
        let request = read_request(&mut stream).await;
        let response = format!(
            "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            entry.status_line,
            entry.body.len()
        );
        let mut bytes = response.into_bytes();
        bytes.extend_from_slice(&entry.body);
        stream.write_all(&bytes).await.expect("write response");
        let _ = stream.shutdown().await;
        recorded.push(request);
    }
    recorded
}

async fn read_request<S>(stream: &mut S) -> (String, Vec<(String, String)>, Vec<u8>)
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let header_end = loop {
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk).await.expect("read request bytes");
        assert!(
            read > 0,
            "connection closed before request headers completed"
        );
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = find_subslice(&buffer, b"\r\n\r\n") {
            break position;
        }
    };

    let header_text = String::from_utf8(buffer[..header_end].to_vec()).expect("utf8 headers");
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().expect("request line").to_owned();
    let mut headers = Vec::new();
    let mut content_length = 0_usize;
    for line in lines {
        let (name, value) = line.split_once(':').expect("header separator");
        let name = name.trim().to_owned();
        let value = value.trim().to_owned();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().expect("content length digits");
        }
        headers.push((name, value));
    }

    let mut body = buffer[header_end + 4..].to_vec();
    while body.len() < content_length {
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk).await.expect("read request body");
        assert!(read > 0, "connection closed before request body completed");
        body.extend_from_slice(&chunk[..read]);
    }

    (request_line, headers, body)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// --- Deterministic test TLS identity -----------------------------------------

struct TestIdentity {
    trust_anchor_pem: Vec<u8>,
    acceptor: TlsAcceptor,
}

fn ed25519_key_from_label(label: &str) -> PKey<Private> {
    let digest = hash(MessageDigest::sha256(), label.as_bytes()).expect("sha-256 digest");
    let seed: [u8; 32] = digest.as_ref().try_into().expect("32-byte digest");
    PKey::private_key_from_raw_bytes(&seed, Id::ED25519).expect("valid ed25519 seed")
}

fn build_name(common_name: &str) -> X509Name {
    let mut builder = openssl::x509::X509NameBuilder::new().expect("name builder");
    builder
        .append_entry_by_nid(Nid::COMMONNAME, common_name)
        .expect("append common name");
    builder.build()
}

fn new_certificate_builder(
    subject_name: &X509NameRef,
    issuer_name: &X509NameRef,
    public_key: &PKeyRef<Private>,
    serial_number: u32,
) -> openssl::x509::X509Builder {
    let mut builder = X509::builder().expect("x509 builder");
    builder.set_version(2).expect("version");
    builder
        .set_subject_name(subject_name)
        .expect("subject name");
    builder.set_issuer_name(issuer_name).expect("issuer name");
    builder.set_pubkey(public_key).expect("public key");
    let serial = BigNum::from_u32(serial_number).expect("serial bignum");
    builder
        .set_serial_number(&serial.to_asn1_integer().expect("serial asn1"))
        .expect("set serial");
    builder
        .set_not_before(&Asn1Time::from_unix(CERTIFICATE_NOT_BEFORE_UNIX_SECONDS).unwrap())
        .expect("not before");
    builder
        .set_not_after(&Asn1Time::from_unix(CERTIFICATE_NOT_AFTER_UNIX_SECONDS).unwrap())
        .expect("not after");
    builder
}

fn build_root_certificate(label: &str) -> (X509, PKey<Private>) {
    let key = ed25519_key_from_label(label);
    let name = build_name(label);
    let mut builder = new_certificate_builder(&name, &name, &key, ROOT_CERTIFICATE_SERIAL);
    let basic_constraints = BasicConstraints::new().critical().ca().build().unwrap();
    builder.append_extension(basic_constraints).unwrap();
    let key_usage = KeyUsage::new()
        .critical()
        .key_cert_sign()
        .crl_sign()
        .build()
        .unwrap();
    builder.append_extension(key_usage).unwrap();
    builder.sign(&key, MessageDigest::null()).unwrap();
    (builder.build(), key)
}

fn build_leaf_certificate(
    ip_address: &str,
    root_name: &X509NameRef,
    root_key: &PKeyRef<Private>,
    label: &str,
) -> (X509, PKey<Private>) {
    let key = ed25519_key_from_label(label);
    let name = build_name(ip_address);
    let mut builder = new_certificate_builder(&name, root_name, &key, LEAF_CERTIFICATE_SERIAL);
    let basic_constraints = BasicConstraints::new().critical().build().unwrap();
    builder.append_extension(basic_constraints).unwrap();
    let key_usage = KeyUsage::new()
        .critical()
        .digital_signature()
        .build()
        .unwrap();
    builder.append_extension(key_usage).unwrap();
    let subject_alternative_name = SubjectAlternativeName::new()
        .ip(ip_address)
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(subject_alternative_name).unwrap();
    builder.sign(root_key, MessageDigest::null()).unwrap();
    (builder.build(), key)
}

fn build_test_identity(ip_address: &str, root_label: &str, leaf_label: &str) -> TestIdentity {
    let (root_certificate, root_key) = build_root_certificate(root_label);
    let (leaf_certificate, leaf_key) = build_leaf_certificate(
        ip_address,
        root_certificate.subject_name(),
        &root_key,
        leaf_label,
    );

    let leaf_certificate_pem = leaf_certificate.to_pem().unwrap();
    let leaf_key_pem = leaf_key.private_key_to_pem_pkcs8().unwrap();
    let identity = native_tls::Identity::from_pkcs8(&leaf_certificate_pem, &leaf_key_pem).unwrap();
    let acceptor = native_tls::TlsAcceptor::builder(identity)
        .min_protocol_version(Some(native_tls::Protocol::Tlsv12))
        .build()
        .unwrap();

    TestIdentity {
        trust_anchor_pem: root_certificate.to_pem().unwrap(),
        acceptor: TlsAcceptor::from(acceptor),
    }
}

// --- Test support -------------------------------------------------------------

struct NeverCancelled;

impl CancellationSignal for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

fn far_future_deadline() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

fn empty_desired_envelope() -> DesiredStateEnvelope {
    DesiredStateEnvelope::new(
        EnvelopeVersion::new(1),
        OpaquePayload::try_from(r#"{"permissions": []}"#.to_owned()).unwrap(),
    )
}

fn one_permission_envelope() -> DesiredStateEnvelope {
    DesiredStateEnvelope::new(
        EnvelopeVersion::new(1),
        OpaquePayload::try_from(
            r#"{"permissions": [{"entity": "Root Entity > IT", "profile": "Technician", "recursive": true}]}"#
                .to_owned(),
        )
        .unwrap(),
    )
}

async fn bind_loopback_listener() -> TcpListener {
    TcpListener::bind((LOOPBACK_ADDRESS, 0))
        .await
        .expect("bind ephemeral loopback listener")
}

fn adapter_for(port: u16, trust_anchor_pem: Vec<u8>) -> GlpiAdapter {
    GlpiAdapter::new(GlpiAdapterConfig {
        endpoint: format!("https://{LOOPBACK_ADDRESS}:{port}/apirest.php"),
        app_token: GlpiAppToken::new("app-token".to_owned()),
        user_token: GlpiUserToken::new("user-token".to_owned()),
        operation_timeout: Duration::from_secs(5),
        additional_trust_anchors_pem: vec![trust_anchor_pem],
        authentication_source: GlpiAuthenticationSource::default(),
    })
    .expect("valid GLPI adapter configuration")
}

async fn reconcile(
    adapter: &GlpiAdapter,
    envelope: &DesiredStateEnvelope,
) -> Result<ReconciliationOutcome, permissionsync_core::TargetAdapterError> {
    let identity = IdentityContext::new("jdoe".to_owned(), vec![]);
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(far_future_deadline(), &cancellation);
    let request = TargetAdapterRequest::new(&identity, envelope, context);
    adapter.reconcile(request).await
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

fn search_body(total: u64, rows: &[(u64, &str, &str)]) -> String {
    let mut data = Vec::new();
    for (id, name, name_field) in rows {
        data.push(format!(r#"{{"1": {id}, "{name_field}": "{name}"}}"#));
    }
    format!(
        r#"{{"totalcount": {total}, "count": {}, "range": "0-{}", "data": [{}]}}"#,
        rows.len(),
        rows.len().saturating_sub(1),
        data.join(",")
    )
}

// --- Conformance tests --------------------------------------------------------

/// End-to-end happy path: existing user, no current assignments, one
/// desired assignment resolves and is added; outcome is `Changed`; and
/// `killSession` cleanup is attempted last.
#[tokio::test]
async fn full_reconciliation_creates_the_missing_assignment_and_returns_changed() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#), // initSession
        ok("true"),                           // changeActiveEntities
        ok(&full_session_body(1)),            // getFullSession
        ok(&search_options_body(&[
            ("1", "Entity.id"),
            ("2", "Entity.completename"),
        ])), // listSearchOptions/Entity
        ok(&search_options_body(&[
            ("1", "Profile.id"),
            ("2", "Profile.name"),
        ])), // listSearchOptions/Profile
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])), // listSearchOptions/User
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "Profile_User.users_id"),
            ("3", "Profile_User.profiles_id"),
            ("4", "Profile_User.entities_id"),
            ("5", "Profile_User.is_recursive"),
        ])), // listSearchOptions/Profile_User
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])), // search Entity
        ok(&search_body(1, &[(20, "Technician", "2")])), // search Profile
        ok(&search_body(1, &[(30, "jdoe", "2")])), // search User
        ok(r#"{"totalcount": 0, "count": 0, "range": "0-0", "data": []}"#), // search Profile_User (current)
        created(r#"{"id": 99}"#),                                           // POST Profile_User
        ok("true"),                                                         // killSession
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope())
        .await
        .unwrap();
    server.await.expect("scripted server completed");

    assert_eq!(outcome, ReconciliationOutcome::Changed);
}

/// The complete-visibility precondition (`glpishowallentities == 1`) must
/// hold before any User/Profile_User work starts. When it does not, the
/// adapter fails closed and makes zero further GLPI requests beyond the
/// session-establishment and cleanup steps.
#[tokio::test]
async fn incomplete_visibility_fails_closed_before_any_user_lookup() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#), // initSession
        ok("true"),                           // changeActiveEntities
        ok(&full_session_body(0)),            // getFullSession: NOT all entities visible
        ok("true"),                           // killSession (cleanup still attempted)
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(outcome.is_err());
}

/// More than one exact `User.name` match is an adapter failure.
#[tokio::test]
async fn ambiguous_user_lookup_is_a_failure() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "Entity.id"),
            ("2", "Entity.completename"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile.id"),
            ("2", "Profile.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "Profile_User.users_id"),
            ("3", "Profile_User.profiles_id"),
            ("4", "Profile_User.entities_id"),
            ("5", "Profile_User.is_recursive"),
        ])),
        ok(&search_body(2, &[(30, "jdoe", "2"), (31, "jdoe", "2")])), // two exact User matches
        ok("true"),                                                   // killSession
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(outcome.is_err());
}

/// An envelope version other than `1` is rejected before any GLPI request.
#[tokio::test]
async fn unsupported_envelope_version_makes_zero_glpi_requests() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let envelope = DesiredStateEnvelope::new(
        EnvelopeVersion::new(2),
        OpaquePayload::try_from(r#"{"permissions": []}"#.to_owned()).unwrap(),
    );

    let outcome = reconcile(&adapter, &envelope).await;

    assert!(outcome.is_err());
    match listener.try_accept_nonblocking() {
        Err(kind) => assert_eq!(kind, std::io::ErrorKind::WouldBlock),
        Ok(()) => panic!("adapter unexpectedly connected to GLPI for an unsupported version"),
    }
}

/// Invalid v1 payload (unknown top-level field) is rejected before any GLPI
/// request.
#[tokio::test]
async fn invalid_payload_makes_zero_glpi_requests() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let envelope = DesiredStateEnvelope::new(
        EnvelopeVersion::new(1),
        OpaquePayload::try_from(r#"{"permissions": [], "unexpected": true}"#.to_owned()).unwrap(),
    );

    let outcome = reconcile(&adapter, &envelope).await;

    assert!(outcome.is_err());
    match listener.try_accept_nonblocking() {
        Err(kind) => assert_eq!(kind, std::io::ErrorKind::WouldBlock),
        Ok(()) => panic!("adapter unexpectedly connected to GLPI for an invalid payload"),
    }
}

/// TLS certificates outside the configured trust anchor must be rejected.
#[tokio::test]
async fn rejects_a_server_certificate_signed_by_an_untrusted_root() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let server_identity =
        build_test_identity(LOOPBACK_ADDRESS, OTHER_ROOT_KEY_LABEL, OTHER_LEAF_KEY_LABEL);
    let trusted_identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    // The adapter trusts `trusted_identity`'s root, but the server presents a
    // certificate signed by a completely independent root.
    let adapter = adapter_for(port, trusted_identity.trust_anchor_pem);

    let accept_task = tokio::spawn(async move {
        if let Ok((socket, _)) = listener.accept().await {
            let _ = server_identity.acceptor.accept(socket).await;
        }
    });

    let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
    accept_task.await.expect("accept task completed");

    assert!(outcome.is_err());
}

/// A `killSession` failure after otherwise-successful reconciliation must be
/// returned as the adapter's failure.
#[tokio::test]
async fn cleanup_failure_after_success_becomes_the_returned_failure() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "Entity.id"),
            ("2", "Entity.completename"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile.id"),
            ("2", "Profile.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "Profile_User.users_id"),
            ("3", "Profile_User.profiles_id"),
            ("4", "Profile_User.entities_id"),
            ("5", "Profile_User.is_recursive"),
        ])),
        ok(&search_body(1, &[(30, "jdoe", "2")])), // search User: existing
        ok(r#"{"totalcount": 0, "count": 0, "range": "0-0", "data": []}"#), // current assignments empty
        json_response("500 Internal Server Error", "{}"),                   // killSession fails
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(
        outcome.is_err(),
        "a killSession failure after success must be returned as failure"
    );
}

/// Reconciling the identical already-canonical desired state a second time
/// returns `Unchanged` with no additional mutation.
#[tokio::test]
async fn idempotent_second_reconciliation_of_an_already_canonical_state_is_unchanged() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "Entity.id"),
            ("2", "Entity.completename"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile.id"),
            ("2", "Profile.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "Profile_User.users_id"),
            ("3", "Profile_User.profiles_id"),
            ("4", "Profile_User.entities_id"),
            ("5", "Profile_User.is_recursive"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        ok(&search_body(1, &[(20, "Technician", "2")])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        // Current state already has exactly the canonical row.
        ok(
            r#"{"totalcount": 1, "count": 1, "range": "0-0", "data": [{"1": 99, "2": 30, "3": 20, "4": 10, "5": true}]}"#,
        ),
        ok("true"), // killSession
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope())
        .await
        .unwrap();
    server
        .await
        .expect("scripted server completed exactly its script");

    assert_eq!(outcome, ReconciliationOutcome::Unchanged);
}

/// A pre-cancelled synchronization context makes zero GLPI requests.
#[tokio::test]
async fn pre_cancelled_context_makes_zero_requests() {
    struct AlwaysCancelled;
    impl CancellationSignal for AlwaysCancelled {
        fn is_cancelled(&self) -> bool {
            true
        }
    }

    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let cancellation = AlwaysCancelled;
    let context = SynchronizationContext::new(far_future_deadline(), &cancellation);
    let user_identity = IdentityContext::new("jdoe".to_owned(), vec![]);
    let envelope = empty_desired_envelope();
    let request = TargetAdapterRequest::new(&user_identity, &envelope, context);

    let outcome = adapter.reconcile(request).await;

    assert!(outcome.is_err());
    match listener.try_accept_nonblocking() {
        Err(kind) => assert_eq!(kind, std::io::ErrorKind::WouldBlock),
        Ok(()) => panic!("adapter unexpectedly connected to GLPI while already cancelled"),
    }
}

trait TryAcceptNonblocking {
    fn try_accept_nonblocking(&self) -> Result<(), std::io::ErrorKind>;
}

impl TryAcceptNonblocking for TcpListener {
    fn try_accept_nonblocking(&self) -> Result<(), std::io::ErrorKind> {
        use std::task::{Context, Poll, Waker};
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        match self.poll_accept(&mut context) {
            Poll::Ready(Ok(_)) => Ok(()),
            Poll::Ready(Err(error)) => Err(error.kind()),
            Poll::Pending => Err(std::io::ErrorKind::WouldBlock),
        }
    }
}
