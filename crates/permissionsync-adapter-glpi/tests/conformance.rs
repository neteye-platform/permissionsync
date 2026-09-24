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

use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

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
    task::JoinHandle,
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
const FAKE_SERVER_TIMEOUT: Duration = Duration::from_secs(10);
const HELD_RESPONSE_DEADLINE: Duration = Duration::from_secs(5);

// --- Scripted fake GLPI server -----------------------------------------------

/// One scripted GLPI V1 response for the next accepted connection, in order.
struct ScriptedResponse {
    status_line: &'static str,
    body: Vec<u8>,
}

async fn await_fake_server_step<T>(waiting_for: &str, future: impl Future<Output = T>) -> T {
    tokio::time::timeout(FAKE_SERVER_TIMEOUT, future)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "fake GLPI server timed out waiting for {waiting_for} after {FAKE_SERVER_TIMEOUT:?}"
            )
        })
}

async fn join_fake_server<T>(server: JoinHandle<T>, task_name: &str) -> T {
    await_fake_server_step(&format!("{task_name} task to finish"), server)
        .await
        .unwrap_or_else(|error| panic!("{task_name} task failed: {error}"))
}

async fn abort_fake_server<T>(server: JoinHandle<T>, task_name: &str) {
    server.abort();
    let result =
        await_fake_server_step(&format!("aborted {task_name} task to finish"), server).await;
    if let Err(error) = result {
        assert!(
            error.is_cancelled(),
            "{task_name} task failed before it could be aborted: {error}"
        );
    }
}

async fn accept_one_tls_connection(listener: TcpListener, acceptor: TlsAcceptor) {
    let (socket, _) = await_fake_server_step("expected TLS connection", listener.accept())
        .await
        .expect("accept connection");
    let _ = await_fake_server_step("TLS handshake", acceptor.accept(socket)).await;
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

fn partial(body: &str) -> ScriptedResponse {
    json_response("206 Partial Content", body)
}

fn deleted(id: u64) -> ScriptedResponse {
    ok(&format!(r#"[{{"{id}":true,"message":"deleted"}}]"#))
}

/// Runs a scripted fake GLPI server: for each entry in `script`, in order,
/// accepts exactly one TLS connection, strictly validates one HTTP request,
/// writes the scripted response, and closes. Returns the recorded request
/// lines and header maps for scenario-specific value assertions.
async fn run_scripted_server(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    script: Vec<ScriptedResponse>,
) -> Vec<(String, Vec<(String, String)>, Vec<u8>)> {
    let mut recorded = Vec::new();
    for (request_index, entry) in script.into_iter().enumerate() {
        let (socket, _) = await_fake_server_step(
            &format!("expected request {} connection", request_index + 1),
            listener.accept(),
        )
        .await
        .expect("accept connection");
        let mut stream = await_fake_server_step("TLS handshake", acceptor.accept(socket))
            .await
            .expect("tls handshake");
        let request = read_request(&mut stream).await;
        assert_outgoing_wire_contract(&request);
        let response = format!(
            "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            entry.status_line,
            entry.body.len()
        );
        let mut bytes = response.into_bytes();
        bytes.extend_from_slice(&entry.body);
        await_fake_server_step("response write", stream.write_all(&bytes))
            .await
            .expect("write response");
        let _ = await_fake_server_step("response shutdown", stream.shutdown()).await;
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
        let read = await_fake_server_step("request headers", stream.read(&mut chunk))
            .await
            .expect("read request bytes");
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
        let read = await_fake_server_step("request body", stream.read(&mut chunk))
            .await
            .expect("read request body");
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

fn envelope_json(json: &str) -> DesiredStateEnvelope {
    DesiredStateEnvelope::new(
        EnvelopeVersion::new(1),
        OpaquePayload::try_from(json.to_owned()).unwrap(),
    )
}

async fn bind_loopback_listener() -> TcpListener {
    TcpListener::bind((LOOPBACK_ADDRESS, 0))
        .await
        .expect("bind ephemeral loopback listener")
}

fn adapter_for(port: u16, trust_anchor_pem: Vec<u8>) -> GlpiAdapter {
    adapter_for_with_timeout(port, trust_anchor_pem, Duration::from_secs(5))
}

fn adapter_for_with_timeout(
    port: u16,
    trust_anchor_pem: Vec<u8>,
    operation_timeout: Duration,
) -> GlpiAdapter {
    GlpiAdapter::new(GlpiAdapterConfig {
        endpoint: format!("https://{LOOPBACK_ADDRESS}:{port}/apirest.php"),
        app_token: GlpiAppToken::new("app-token".to_owned()),
        user_token: GlpiUserToken::new("user-token".to_owned()),
        operation_timeout,
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

fn search_page_body(total: u64, start: u64, rows: &[(u64, &str, &str)]) -> String {
    if total == 0 {
        assert!(rows.is_empty(), "zero-result search cannot contain rows");
        return r#"{"totalcount":0,"count":0,"content-range":"0--1/0"}"#.to_owned();
    }

    let mut data = Vec::new();
    for (id, name, name_field) in rows {
        data.push(format!(
            r#"{{"1": {id}, "{name_field}": {}}}"#,
            serde_json::to_string(name).expect("fixture name serializes to JSON")
        ));
    }
    let end = start + rows.len() as u64 - 1;
    format!(
        r#"{{"totalcount":{total},"count":{},"content-range":"{start}-{end}/{total}","data":[{}]}}"#,
        rows.len(),
        data.join(",")
    )
}

fn search_body(total: u64, rows: &[(u64, &str, &str)]) -> String {
    search_page_body(total, 0, rows)
}

/// A scripted `Profile_User` candidate-discovery search response: one row
/// per `(row_id, username)` pair, keyed by the "Profile_User.id" (`"1"`) and
/// joined "User.name" (`"2"`) search-option ids.
fn profile_user_search_body(total: u64, rows: &[(u64, &str)]) -> String {
    let named_rows: Vec<(u64, &str, &str)> = rows
        .iter()
        .map(|(id, username)| (*id, *username, "2"))
        .collect();
    search_body(total, &named_rows)
}

fn profile_user_search_page_body(total: u64, start: u64, rows: &[(u64, &str)]) -> String {
    let named_rows: Vec<(u64, &str, &str)> = rows
        .iter()
        .map(|(id, username)| (*id, *username, "2"))
        .collect();
    search_page_body(total, start, &named_rows)
}

/// A scripted `GET /apirest.php/Profile_User/:id` item-read response
/// carrying the item's raw fields, as the generic V1 item endpoint returns
/// them (never through any search-option id).
fn profile_user_item_body(
    id: u64,
    users_id: u64,
    profiles_id: u64,
    entities_id: u64,
    is_recursive: u64,
) -> String {
    format!(
        r#"{{"id": {id}, "users_id": {users_id}, "profiles_id": {profiles_id}, "entities_id": {entities_id}, "is_recursive": {is_recursive}}}"#
    )
}

// --- Request-inspection assertion support ------------------------------------
//
// The scripted fake server above already records the exact request line,
// headers, and body for every accepted connection, in order. The helpers
// below turn those raw recordings into structural assertions (method, path,
// percent-decoded query parameters, header presence/absence/value, and
// exact/structural JSON body) so tests fail if the adapter sends an
// unexpected request, not merely when a connection count differs.

type RecordedRequest = (String, Vec<(String, String)>, Vec<u8>);

/// Splits one recorded HTTP/1.1 request line into its method, path, and
/// percent-decoded query parameters. Percent-encoded characters (spaces,
/// `>`, etc.) are decoded exactly once by `url::Url`'s standard query-pair
/// decoding, proving the raw wire request really was percent-encoded in the
/// first place (a request line containing a literal, unencoded space or `>`
/// would not parse as one HTTP request line at all).
fn parsed_request_line(line: &str) -> (String, String, Vec<(String, String)>) {
    let mut parts = line.split(' ');
    let method = parts.next().expect("request line has a method").to_owned();
    let target = parts.next().expect("request line has a target").to_owned();
    assert_eq!(
        parts.next(),
        Some("HTTP/1.1"),
        "request line must be HTTP/1.1: {line}"
    );
    let placeholder = url::Url::parse("https://placeholder.example.test").unwrap();
    let full_url = placeholder.join(&target).expect("valid request target");
    let path = full_url.path().to_owned();
    let query = full_url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    (method, path, query)
}

/// Asserts one recorded request's exact HTTP method and operation path.
fn assert_request(recorded: &RecordedRequest, method: &str, path: &str) {
    let (actual_method, actual_path, _) = parsed_request_line(&recorded.0);
    assert_eq!(
        actual_method, method,
        "method for request line {}",
        recorded.0
    );
    assert_eq!(actual_path, path, "path for request line {}", recorded.0);
}

/// Returns the percent-decoded value of one query parameter on a recorded
/// request, if present.
fn query_value(recorded: &RecordedRequest, key: &str) -> Option<String> {
    let (_, _, query) = parsed_request_line(&recorded.0);
    query
        .into_iter()
        .find(|(actual_key, _)| actual_key == key)
        .map(|(_, value)| value)
}

/// Returns the exact header value (case-insensitive name lookup) recorded
/// on a request, if present.
fn header_value<'a>(recorded: &'a RecordedRequest, name: &str) -> Option<&'a str> {
    recorded
        .1
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn assert_header(recorded: &RecordedRequest, name: &str, expected_value: &str) {
    assert_eq!(
        header_value(recorded, name),
        Some(expected_value),
        "header {name} on request line {}",
        recorded.0
    );
}

fn assert_no_header(recorded: &RecordedRequest, name: &str) {
    assert_eq!(
        header_value(recorded, name),
        None,
        "unexpected header {name} on request line {}",
        recorded.0
    );
}

/// GET requests used by this adapter MUST be explicitly proven to have
/// empty request bodies (see the module doc comment): every parameter is
/// carried in the URL/query, never in a request body.
fn assert_empty_body(recorded: &RecordedRequest) {
    assert!(
        recorded.2.is_empty(),
        "expected an empty body for {}, got {:?}",
        recorded.0,
        recorded.2
    );
    assert_no_header(recorded, "content-type");
}

/// Asserts a mutation request's body is exactly the given structurally
/// decoded JSON value, and that `Content-Type: application/json` was sent
/// (JSON mutation requests MUST be proven to use `application/json`).
fn assert_json_body(recorded: &RecordedRequest, expected: serde_json::Value) {
    assert_header(recorded, "content-type", "application/json");
    let actual: serde_json::Value =
        serde_json::from_slice(&recorded.2).expect("request body is valid JSON");
    assert_eq!(actual, expected, "body for request line {}", recorded.0);
}

/// Enforce the selected V1 wire grammar for every fixture request before its
/// response is released. Scenario-specific assertions below then verify exact
/// selector and mutation values for the behavior under test.
fn assert_outgoing_wire_contract(recorded: &RecordedRequest) {
    let (method, path, query) = parsed_request_line(&recorded.0);
    assert!(header_value(recorded, "host").is_some_and(|value| !value.is_empty()));

    if path.ends_with("/initSession") {
        assert!(
            header_value(recorded, "authorization")
                .is_some_and(|value| value.starts_with("user_token "))
        );
        assert!(header_value(recorded, "app-token").is_some_and(|value| !value.is_empty()));
        assert_no_header(recorded, "session-token");
    } else {
        assert!(header_value(recorded, "session-token").is_some_and(|value| !value.is_empty()));
        assert!(header_value(recorded, "app-token").is_some_and(|value| !value.is_empty()));
        assert_no_header(recorded, "authorization");
    }

    match (method.as_str(), path.as_str()) {
        ("GET", "/apirest.php/initSession")
        | ("GET", "/apirest.php/getFullSession")
        | ("GET", "/apirest.php/killSession") => {
            assert!(query.is_empty(), "lifecycle GET has no query");
            assert_empty_body(recorded);
        }
        ("GET", path) if path.starts_with("/apirest.php/listSearchOptions/") => {
            assert!(query.is_empty(), "search-option lookup has no query");
            assert_empty_body(recorded);
        }
        ("GET", path) if path.starts_with("/apirest.php/search/") => {
            assert_empty_body(recorded);
            assert_eq!(
                query.len(),
                8,
                "search has no unrecognized query parameters"
            );
            for key in [
                "range",
                "criteria[0][field]",
                "criteria[0][searchtype]",
                "criteria[0][value]",
                "sort",
                "order",
                "forcedisplay[0]",
                "forcedisplay[1]",
            ] {
                assert!(
                    query.iter().any(|(actual, _)| actual == key),
                    "missing {key}"
                );
            }
            assert_eq!(
                query_value(recorded, "criteria[0][searchtype]"),
                Some("contains".to_owned())
            );
            assert_eq!(query_value(recorded, "order"), Some("ASC".to_owned()));
            for key in [
                "criteria[0][field]",
                "sort",
                "forcedisplay[0]",
                "forcedisplay[1]",
            ] {
                assert!(query_value(recorded, key).unwrap().parse::<u64>().is_ok());
            }
            assert!(
                query_value(recorded, "criteria[0][value]").is_some_and(|value| !value.is_empty())
            );
            let range = query_value(recorded, "range").unwrap();
            let (start, end) = range.split_once('-').expect("inclusive range");
            assert!(start.parse::<u64>().is_ok() && end.parse::<u64>().is_ok());
        }
        ("GET", path) if path.starts_with("/apirest.php/Profile_User/") => {
            assert!(query.is_empty(), "item read has no query");
            assert_empty_body(recorded);
            assert!(path.rsplit('/').next().unwrap().parse::<u64>().is_ok());
        }
        ("POST", "/apirest.php/changeActiveEntities") => {
            assert!(query.is_empty());
            // `entities_id` is deliberately absent: GLPI 11.0.9's
            // `API::changeActiveEntities()` only preserves its internal
            // `"all"` sentinel when the field is entirely unset. Sending the
            // literal string `"all"` would instead hit `intval("all")` (PHP
            // `0`), selecting entity ID `0` rather than every visible entity.
            assert_json_body(recorded, serde_json::json!({"is_recursive":true}));
        }
        ("POST", "/apirest.php/User") => {
            assert!(query.is_empty());
            assert_header(recorded, "content-type", "application/json");
            let body: serde_json::Value = serde_json::from_slice(&recorded.2).unwrap();
            let input = body
                .get("input")
                .and_then(serde_json::Value::as_object)
                .unwrap();
            assert_eq!(body.as_object().unwrap().len(), 1);
            assert!(
                input
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|name| !name.is_empty())
            );
            assert!(
                input
                    .keys()
                    .all(|key| matches!(key.as_str(), "name" | "authtype" | "auths_id"))
            );
        }
        ("POST", "/apirest.php/Profile_User") => {
            assert!(query.is_empty());
            assert_header(recorded, "content-type", "application/json");
            let body: serde_json::Value = serde_json::from_slice(&recorded.2).unwrap();
            let input = body
                .get("input")
                .and_then(serde_json::Value::as_object)
                .unwrap();
            assert_eq!(body.as_object().unwrap().len(), 1);
            assert_eq!(input.len(), 4);
            // `users_id`/`profiles_id` are always positive database ids;
            // `entities_id` alone may legitimately be `0` for GLPI's root
            // entity.
            for key in ["users_id", "profiles_id"] {
                assert!(
                    input
                        .get(key)
                        .and_then(serde_json::Value::as_u64)
                        .is_some_and(|id| id > 0)
                );
            }
            assert!(
                input
                    .get("entities_id")
                    .and_then(serde_json::Value::as_u64)
                    .is_some()
            );
            assert!(
                input
                    .get("is_recursive")
                    .and_then(serde_json::Value::as_bool)
                    .is_some()
            );
        }
        ("DELETE", path) if path.starts_with("/apirest.php/Profile_User/") => {
            assert!(query.is_empty());
            assert_empty_body(recorded);
            assert!(path.rsplit('/').next().unwrap().parse::<u64>().is_ok());
        }
        _ => panic!("unexpected GLPI wire operation: {}", recorded.0),
    }
}

/// A [`CancellationSignal`] that reports cancelled only once at least
/// `threshold` scripted requests have already been fully answered by the
/// fake server. Used to prove cancellation is observed at a specific point
/// mid-reconciliation without any sleep or wall-clock race: the counter is
/// incremented by the fake server strictly before it writes each scripted
/// response, and the adapter always awaits a response before its next
/// cancellation check, so the ordering is deterministic.
struct CancelAfterRequests {
    completed: Arc<AtomicUsize>,
    threshold: usize,
}

impl CancellationSignal for CancelAfterRequests {
    fn is_cancelled(&self) -> bool {
        self.completed.load(Ordering::SeqCst) >= self.threshold
    }
}

/// Like [`run_scripted_server`], but increments `completed` immediately
/// after reading (and before responding to) each request, and stops after
/// the script is exhausted rather than requiring every entry to be
/// consumed. Callers that expect early cancellation must `abort()` the
/// spawned task once the adapter's outcome is available, since a shorter
/// script is intentionally passed and the task would otherwise wait
/// forever for a connection that will never come.
async fn run_counted_scripted_server(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    script: Vec<ScriptedResponse>,
    completed: Arc<AtomicUsize>,
) -> Vec<RecordedRequest> {
    let mut recorded = Vec::new();
    for (request_index, entry) in script.into_iter().enumerate() {
        let (socket, _) = await_fake_server_step(
            &format!("expected request {} connection", request_index + 1),
            listener.accept(),
        )
        .await
        .expect("accept connection");
        let mut stream = await_fake_server_step("TLS handshake", acceptor.accept(socket))
            .await
            .expect("tls handshake");
        let request = read_request(&mut stream).await;
        assert_outgoing_wire_contract(&request);
        completed.fetch_add(1, Ordering::SeqCst);
        let response = format!(
            "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            entry.status_line,
            entry.body.len()
        );
        let mut bytes = response.into_bytes();
        bytes.extend_from_slice(&entry.body);
        await_fake_server_step("response write", stream.write_all(&bytes))
            .await
            .expect("write response");
        let _ = await_fake_server_step("response shutdown", stream.shutdown()).await;
        recorded.push(request);
    }
    recorded
}

/// Accepts exactly one fully formed request then withholds its response until
/// the adapter closes the timed-out connection.
async fn hold_one_response(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    started: tokio::sync::oneshot::Sender<RecordedRequest>,
) {
    let (socket, _) =
        await_fake_server_step("expected held-response connection", listener.accept())
            .await
            .expect("accept connection");
    let mut stream = await_fake_server_step("TLS handshake", acceptor.accept(socket))
        .await
        .expect("tls handshake");
    let request = read_request(&mut stream).await;
    assert_outgoing_wire_contract(&request);
    started
        .send(request)
        .expect("deadline test receiver remains live");
    let mut buffer = [0_u8; 1];
    let read = await_fake_server_step(
        "client to close held-response connection",
        stream.read(&mut buffer),
    )
    .await
    .expect("read client closure");
    assert_eq!(read, 0, "client must not send data while response is held");
}

async fn reconcile_with_cancellation(
    adapter: &GlpiAdapter,
    envelope: &DesiredStateEnvelope,
    cancellation: &CancelAfterRequests,
) -> Result<ReconciliationOutcome, permissionsync_core::TargetAdapterError> {
    let identity = IdentityContext::new("jdoe".to_owned(), vec![]);
    let context = SynchronizationContext::new(far_future_deadline(), cancellation);
    let request = TargetAdapterRequest::new(&identity, envelope, context);
    adapter.reconcile(request).await
}

/// A generous over-long script for cancellation tests: cancellation must
/// stop the adapter well before the script is exhausted, so any entries
/// beyond the expected cut point exist only to prove (by never being
/// consumed) that no further request was sent.
fn oversized_script() -> Vec<ScriptedResponse> {
    let mut script = vec![
        ok(r#"{"session_token": "sess-1"}"#), // 1: initSession
        ok("true"),                           // 2: changeActiveEntities
        ok(&full_session_body(1)),            // 3: getFullSession
        ok(&search_options_body(&[
            ("1", "Entity.id"),
            ("2", "Entity.completename"),
        ])), // 4: listSearchOptions/Entity
        ok(&search_options_body(&[
            ("1", "Profile.id"),
            ("2", "Profile.name"),
        ])), // 5: listSearchOptions/Profile
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])), // 6: listSearchOptions/User
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])), // 7: listSearchOptions/Profile_User
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])), // 8: search Entity
        ok(&search_body(1, &[(20, "Technician", "2")])), // 9: search Profile
        ok(&search_body(1, &[(30, "jdoe", "2")])), // 10: search User
        ok(&profile_user_search_body(1, &[(99, "jdoe")])), // 11: search Profile_User candidates
        ok(&profile_user_item_body(99, 30, 40, 50, 0)), // 12: item read (not canonical -> plan has work: 1 removal + 1 addition)
        deleted(99),                                    // 13: DELETE Profile_User/99 (removal)
        created(r#"{"id":100,"message":"created"}"#),   // 14: POST Profile_User (addition)
        ok("true"),                                     // 15: killSession
    ];
    // Extra trailing entries that must never be consumed in tests that
    // cancel earlier than this point.
    script.push(ok("true"));
    script.push(ok("true"));
    script
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
            ("2", "User.name"),
        ])), // listSearchOptions/Profile_User
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])), // search Entity
        ok(&search_body(1, &[(20, "Technician", "2")])), // search Profile
        ok(&search_body(1, &[(30, "jdoe", "2")])), // search User
        ok(&profile_user_search_body(0, &[])), // search Profile_User (candidate discovery: none)
        created(r#"{"id":99,"message":"created"}"#), // POST Profile_User
        ok("true"),                           // killSession
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope())
        .await
        .unwrap();
    server.await.expect("scripted server completed");

    assert_eq!(outcome, ReconciliationOutcome::Changed);
}

/// GLPI's root entity is physically id `0` (see GLPI's own
/// `install/empty_data.php` seed data). A desired `entity` selector that
/// exactly names the bare root entity must resolve successfully rather than
/// being rejected merely because its resolved id is `0` -- unlike
/// `Profile.id`/`User.id`/`Profile_User.id`, which are never legitimately
/// zero.
#[tokio::test]
async fn desired_entity_selector_resolving_to_root_entity_id_zero_succeeds() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let envelope = envelope_json(
        r#"{"permissions": [{"entity": "Root entity", "profile": "Technician", "recursive": true}]}"#,
    );

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
            ("2", "User.name"),
        ])), // listSearchOptions/Profile_User
        ok(&search_body(1, &[(0, "Root entity", "2")])), // search Entity: id 0
        ok(&search_body(1, &[(20, "Technician", "2")])), // search Profile
        ok(&search_body(1, &[(30, "jdoe", "2")])), // search User
        ok(&profile_user_search_body(0, &[])), // search Profile_User (candidate discovery: none)
        created(r#"{"id":99,"message":"created"}"#), // POST Profile_User
        ok("true"),                           // killSession
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &envelope)
        .await
        .expect("bare 'Root entity' must resolve to the root entity's real id 0");
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
        // No `permissions` entries are desired, so Entity/Profile
        // resolution is never performed and their listSearchOptions
        // requests never happen.
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
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

    let accept_task = tokio::spawn(accept_one_tls_connection(
        listener,
        server_identity.acceptor,
    ));

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
        // No `permissions` entries are desired, so Entity/Profile
        // resolution is never performed and their listSearchOptions
        // requests never happen.
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(30, "jdoe", "2")])), // search User: existing
        ok(&profile_user_search_body(0, &[])), // search Profile_User (candidate discovery: none)
        json_response("500 Internal Server Error", "{}"), // killSession fails
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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        ok(&search_body(1, &[(20, "Technician", "2")])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        // Candidate discovery: one Profile_User row belongs to "jdoe".
        ok(&profile_user_search_body(1, &[(99, "jdoe")])),
        // Item read of that candidate row's raw fields; already the
        // canonical row.
        ok(&profile_user_item_body(99, 30, 20, 10, 1)),
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

// =============================================================================
// PAYLOAD / ZERO-I/O VALIDATION
// =============================================================================

/// Every structurally invalid v1 payload is rejected before any GLPI
/// request, regardless of which structural rule it violates.
#[tokio::test]
async fn every_structurally_invalid_payload_makes_zero_glpi_requests() {
    let invalid_payloads = [
        "null",
        "42",
        "[]",
        "\"permissions\"",
        "{}",
        r#"{"permissions": [], "unexpected": true}"#,
        r#"{"permissions": {}}"#,
        r#"{"permissions": "x"}"#,
        r#"{"permissions": [{"entity": "e", "profile": "p"}]}"#,
        r#"{"permissions": [{"entity": "e", "recursive": true}]}"#,
        r#"{"permissions": [{"profile": "p", "recursive": true}]}"#,
        r#"{"permissions": [{"entity": 1, "profile": "p", "recursive": true}]}"#,
        r#"{"permissions": [{"entity": "e", "profile": "p", "recursive": "true"}]}"#,
        r#"{"permissions": [{"entity": "e", "profile": "p", "recursive": true, "extra": 1}]}"#,
        r#"{"permissions": [{"entity": "", "profile": "p", "recursive": true}]}"#,
        r#"{"permissions": [{"entity": "e", "profile": "", "recursive": true}]}"#,
        r#"{"permissions": [], "permissions": []}"#,
        r#"{"permissions": [{"entity": "e", "entity": "e", "profile": "p", "recursive": true}]}"#,
        r#"{"permissions": [{"entity": "e", "profile": "p", "profile": "p", "recursive": true}]}"#,
        r#"{"permissions": [{"entity": "e", "profile": "p", "recursive": true, "recursive": false}]}"#,
        // An invalid repeated permission entry (wrong type on the second
        // occurrence) must not be hidden by normalization deduplicating the
        // first, otherwise-valid, occurrence.
        r#"{"permissions": [
            {"entity": "e", "profile": "p", "recursive": true},
            {"entity": "e", "profile": "p", "recursive": "true"}
        ]}"#,
    ];

    for payload in invalid_payloads {
        let listener = bind_loopback_listener().await;
        let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
        let port = listener.local_addr().unwrap().port();
        let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
        let envelope = envelope_json(payload);

        let outcome = reconcile(&adapter, &envelope).await;

        assert!(outcome.is_err(), "expected payload validation rejection");
        match listener.try_accept_nonblocking() {
            Err(kind) => assert_eq!(kind, std::io::ErrorKind::WouldBlock),
            Ok(()) => panic!("adapter unexpectedly connected to GLPI for invalid payload"),
        }
    }
}

// =============================================================================
// DESIRED NORMALIZATION
// =============================================================================

/// Duplicate desired permission entries for the same `(entity, profile)`
/// pair, with mixed `recursive` values, canonicalize to one `true` entry;
/// when the current state is already exactly that canonical row, the
/// outcome is `Unchanged` (proving normalization happens before planning,
/// not merely at the payload-parsing layer in isolation).
#[tokio::test]
async fn duplicate_desired_permissions_with_already_canonical_current_state_is_unchanged() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let envelope = envelope_json(
        r#"{"permissions": [
            {"entity": "Root Entity > IT", "profile": "Technician", "recursive": true},
            {"entity": "Root Entity > IT", "profile": "Technician", "recursive": false}
        ]}"#,
    );

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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        ok(&search_body(1, &[(20, "Technician", "2")])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        ok(&profile_user_search_body(1, &[(99, "jdoe")])),
        ok(&profile_user_item_body(99, 30, 20, 10, 1)),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &envelope).await.unwrap();
    join_fake_server(server, "scripted server completed its script").await;

    assert_eq!(outcome, ReconciliationOutcome::Unchanged);
}

/// Selector strings remain untrimmed and uncasefolded within the anchored
/// GLPI `contains` pattern.
#[tokio::test]
async fn selector_strings_reach_glpi_search_untrimmed_and_uncasefolded() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let envelope = envelope_json(
        r#"{"permissions": [{"entity": "  Root Entity > IT ", "profile": "TECH", "recursive": true}]}"#,
    );

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
            ("2", "User.name"),
        ])),
        // Zero exact matches for the untrimmed selector: the adapter fails
        // closed, but the request that carried the untrimmed selector is
        // still captured below.
        ok(&search_body(0, &[])),
        ok("true"), // killSession
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &envelope).await;
    let recorded = server.await.expect("scripted server completed its script");

    assert!(outcome.is_err());
    assert_request(&recorded[7], "GET", "/apirest.php/search/Entity");
    assert_empty_body(&recorded[7]);
    assert_eq!(
        query_value(&recorded[7], "criteria[0][value]"),
        Some("^%  Root Entity > IT %$".to_owned()),
        "the entity selector must remain untrimmed within the GLPI pattern"
    );
}

/// GLPI 11.0.9 receives an anchored `contains` pattern for every exact
/// selector form. The fake deliberately returns a fuzzy row alongside the
/// exact row to prove adapter-side case-sensitive equality remains final.
#[tokio::test]
async fn exact_search_patterns_preserve_selector_metacharacters_and_ignore_fuzzy_rows() {
    for (selector, expected_query_value) in [
        ("Technician", "^Technician$"),
        ("literal%", "^literal%$"),
        ("literal_", "^literal_$"),
        ("^literal", "^^literal$"),
        ("literal$", "^literal$$"),
        (r"literal\backslash", r"^literal\backslash$"),
        (" boundary ", "^% boundary %$"),
    ] {
        let listener = bind_loopback_listener().await;
        let port = listener.local_addr().unwrap().port();
        let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
        let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
        let envelope = envelope_json(
            &serde_json::json!({
                "permissions": [{
                    "entity": selector,
                    "profile": "Technician",
                    "recursive": true,
                }],
            })
            .to_string(),
        );
        let fuzzy_candidate = format!("{selector} fuzzy candidate");
        let entity_search = search_body(
            2,
            &[(10, fuzzy_candidate.as_str(), "2"), (11, selector, "2")],
        );

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
                ("2", "User.name"),
            ])),
            ok(&entity_search),
            // The missing profile ends this scenario after successful entity
            // resolution. Reaching it proves the fuzzy entity row did not
            // count as a second exact match.
            ok(&search_body(0, &[])),
            ok("true"),
        ];

        let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
        let outcome = reconcile(&adapter, &envelope).await;
        let recorded = server.await.expect("scripted server completed its script");

        assert!(
            outcome.is_err(),
            "the deliberately missing profile must stop reconciliation"
        );
        assert_request(&recorded[8], "GET", "/apirest.php/search/Profile");
        assert_eq!(
            query_value(&recorded[7], "criteria[0][value]"),
            Some(expected_query_value.to_owned()),
            "decoded GLPI search pattern must preserve the exact selector"
        );
    }
}

// =============================================================================
// USER LOOKUP / CREATION
// =============================================================================

/// Zero exact `User.name` matches across the complete result set creates a
/// new user whose `input.name` is exactly `IdentityContext.username`, using
/// only the configured authentication-source fields, no password, and no
/// Provider-payload-derived fields; the request is `POST User` with
/// `application/json`.
#[tokio::test]
async fn missing_user_is_created_with_only_the_configured_provisioning_fields() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = GlpiAdapter::new(GlpiAdapterConfig {
        endpoint: format!("https://{LOOPBACK_ADDRESS}:{port}/apirest.php"),
        app_token: GlpiAppToken::new("app-token".to_owned()),
        user_token: GlpiUserToken::new("user-token".to_owned()),
        operation_timeout: Duration::from_secs(5),
        additional_trust_anchors_pem: vec![identity.trust_anchor_pem.clone()],
        authentication_source: GlpiAuthenticationSource {
            authtype: Some(1),
            auths_id: Some(2),
        },
    })
    .expect("valid GLPI adapter configuration");

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_body(0, &[])), // search User: zero exact matches
        created(r#"{"id":55,"message":"created"}"#), // POST User
        ok(&profile_user_search_body(0, &[])), // read_current_assignments: none
        ok("true"),               // killSession
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope())
        .await
        .unwrap();
    let recorded = server.await.expect("scripted server completed its script");

    assert_eq!(outcome, ReconciliationOutcome::Changed);
    assert_request(&recorded[6], "POST", "/apirest.php/User");
    assert_json_body(
        &recorded[6],
        serde_json::json!({
            "input": { "name": "jdoe", "authtype": 1, "auths_id": 2 }
        }),
    );
}

/// More than one exact `User.name` match is an adapter failure, and no
/// mutation of any kind is ever attempted afterward.
#[tokio::test]
async fn ambiguous_user_lookup_makes_zero_mutation_requests() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_body(2, &[(30, "jdoe", "2"), (31, "jdoe", "2")])),
        ok("true"), // killSession
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
    let recorded = server
        .await
        .expect("scripted server completed exactly its script");

    assert!(outcome.is_err());
    for entry in &recorded {
        let (method, path, _) = parsed_request_line(&entry.0);
        // `changeActiveEntities` is a legitimate `POST` unrelated to
        // mutation; only `User`/`Profile_User` mutation methods are
        // disallowed here.
        if path == "/apirest.php/changeActiveEntities" {
            continue;
        }
        assert_ne!(
            method, "POST",
            "no mutation may be attempted after ambiguity"
        );
        assert_ne!(
            method, "DELETE",
            "no mutation may be attempted after ambiguity"
        );
    }
}

/// A search row whose `User.name` differs only by case from the requested
/// username is not an exact match: it is filtered out adapter-side, so the
/// (case-sensitive) result set is empty and a new user is created.
#[tokio::test]
async fn case_sensitive_lookalike_does_not_count_as_an_exact_user_match() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        // GLPI search "equals" can return a fuzzy/lookalike row; only a
        // case-sensitive exact match counts.
        ok(&search_body(1, &[(30, "JDOE", "2")])),
        created(r#"{"id":61,"message":"created"}"#), // POST User: created because "JDOE" != "jdoe"
        ok(&profile_user_search_body(0, &[])),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope())
        .await
        .unwrap();
    join_fake_server(server, "scripted server completed its script").await;

    assert_eq!(outcome, ReconciliationOutcome::Changed);
}

/// User search results spanning more than one page are all read before the
/// adapter decides whether an exact match exists.
#[tokio::test]
async fn user_lookup_reads_every_page_before_deciding() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    // Two pages: page one is full of unrelated rows (declared total forces
    // a second page); page two contains the exact row.
    let mut page_one_rows = Vec::new();
    for index in 0..50 {
        page_one_rows.push((1000 + index, "someone-else", "2"));
    }
    let page_one = search_page_body(51, 0, &page_one_rows);
    let page_two = search_page_body(51, 50, &[(30, "jdoe", "2")]);

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        partial(&page_one),
        partial(&page_two),
        ok(&profile_user_search_body(0, &[])),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope())
        .await
        .unwrap();
    let recorded = server.await.expect("scripted server completed its script");

    assert_eq!(outcome, ReconciliationOutcome::Unchanged);
    assert_eq!(query_value(&recorded[5], "range"), Some("0-49".to_owned()));
    assert_eq!(query_value(&recorded[6], "range"), Some("50-99".to_owned()));
}

/// User creation failure makes zero further `Profile_User` mutation
/// requests: the adapter never retries and never falls back to reusing a
/// fuzzy match.
#[tokio::test]
async fn user_creation_failure_makes_zero_profile_user_mutation_requests() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_body(0, &[])),
        json_response("500 Internal Server Error", "{}"), // POST User fails
        ok("true"),                                       // killSession still attempted
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(outcome.is_err());
}

/// Missing user plus an empty desired state still creates the user and
/// returns `Changed`, even though the reconciliation plan itself is empty.
#[tokio::test]
async fn missing_user_creation_with_empty_desired_state_is_still_changed() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_body(0, &[])),
        created(r#"{"id":70,"message":"created"}"#),
        ok(&profile_user_search_body(0, &[])),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope())
        .await
        .unwrap();
    server.await.expect("scripted server completed its script");

    assert_eq!(outcome, ReconciliationOutcome::Changed);
}

// =============================================================================
// ENTITY RESOLUTION / PROFILE RESOLUTION
// =============================================================================

/// Entity and Profile selectors containing spaces and URL/query
/// metacharacters (`>`, `&`, `=`) are percent-encoded on the wire and encoded
/// in an anchored GLPI `contains` pattern; ambiguous exact matches fail before
/// any user lookup or mutation.
#[tokio::test]
async fn entity_and_profile_selectors_with_metacharacters_are_percent_encoded() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let entity_selector = "R&D > Team=1";
    let envelope = envelope_json(&format!(
        r#"{{"permissions": [{{"entity": "{entity_selector}", "profile": "Technician", "recursive": true}}]}}"#
    ));

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
            ("2", "User.name"),
        ])),
        // Two exact matches: ambiguous entity resolution.
        ok(&search_body(
            2,
            &[(10, entity_selector, "2"), (11, entity_selector, "2")],
        )),
        ok("true"), // killSession
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &envelope).await;
    let recorded = server
        .await
        .expect("scripted server completed exactly its script");

    assert!(outcome.is_err(), "ambiguous entity resolution must fail");
    // The raw wire request line must not contain the selector's literal
    // metacharacters unencoded (proving percent-encoding actually
    // happened), while the decoded query value equals the exact selector.
    assert!(!recorded[7].0.contains("R&D > Team=1"));
    assert_eq!(
        query_value(&recorded[7], "criteria[0][value]"),
        Some(format!("^{entity_selector}$"))
    );
}

/// A nested-looking Entity.completename is one opaque exact selector: its
/// `>` characters are percent-encoded on the wire but never parsed into
/// separate entity-resolution requests.
#[tokio::test]
async fn nested_looking_entity_completename_resolves_as_one_opaque_exact_match() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let entity_selector = "Root entity > IT > Operations";
    let envelope = envelope_json(&format!(
        r#"{{"permissions": [{{"entity": "{entity_selector}", "profile": "Technician", "recursive": true}}]}}"#
    ));

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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(11, entity_selector, "2")])),
        ok(&search_body(1, &[(20, "Technician", "2")])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        ok(&profile_user_search_body(0, &[])),
        created(r#"{"id":99,"message":"created"}"#),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &envelope).await.unwrap();
    let recorded = server.await.expect("scripted server completed its script");

    assert_eq!(outcome, ReconciliationOutcome::Changed);
    let entity_searches: Vec<&RecordedRequest> = recorded
        .iter()
        .filter(|recorded| {
            let (_, path, _) = parsed_request_line(&recorded.0);
            path == "/apirest.php/search/Entity"
        })
        .collect();
    assert_eq!(
        entity_searches.len(),
        1,
        "the opaque selector must make exactly one Entity search request"
    );
    let entity_search = entity_searches[0];
    assert_request(entity_search, "GET", "/apirest.php/search/Entity");
    let raw_target = entity_search
        .0
        .split(' ')
        .nth(1)
        .expect("request line has a target");
    assert!(
        !entity_search.0.contains(entity_selector),
        "the complete selector must be percent-encoded on the wire"
    );
    assert!(
        !raw_target.contains('>'),
        "the raw Entity search target must not contain literal > characters"
    );
    assert_eq!(
        raw_target.to_ascii_lowercase().matches("%3e").count(),
        2,
        "the raw Entity search target must percent-encode both > characters"
    );
    assert_eq!(
        query_value(entity_search, "criteria[0][value]"),
        Some(format!("^{entity_selector}$")),
        "the complete selector must remain inside the single Entity search pattern"
    );
}

/// A missing entity fails before any user lookup or creation request.
#[tokio::test]
async fn missing_entity_fails_before_any_user_lookup() {
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
            ("2", "User.name"),
        ])),
        ok(&search_body(0, &[])), // zero exact Entity matches
        ok("true"),               // killSession
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope()).await;
    let recorded = server
        .await
        .expect("scripted server completed exactly its script");

    assert!(outcome.is_err());
    assert_eq!(
        recorded.len(),
        9,
        "no request after the failed Entity search except cleanup"
    );
}

/// A fuzzy (non-exact) Profile search result is ignored: it does not count
/// toward ambiguity and does not count as a match, so zero exact matches is
/// treated as a missing profile.
#[tokio::test]
async fn fuzzy_profile_search_results_are_ignored() {
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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        // "Technician II" is a fuzzy, non-exact result for "Technician".
        ok(&search_body(1, &[(21, "Technician II", "2")])),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(
        outcome.is_err(),
        "a fuzzy-only profile result must not resolve"
    );
}

// =============================================================================
// CURRENT PROFILE_USER READING
// =============================================================================

/// All `Profile_User` candidate-discovery pages are read, and every
/// candidate's raw fields are read via the item endpoint, before planning.
#[tokio::test]
async fn current_assignment_discovery_reads_every_page_before_planning() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let mut page_one_rows = Vec::new();
    for index in 0..50 {
        page_one_rows.push((2000 + index, "jdoe"));
    }
    let page_one = profile_user_search_page_body(51, 0, &page_one_rows);
    let page_two = profile_user_search_page_body(51, 50, &[(99, "jdoe")]);

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        partial(&page_one),
        partial(&page_two),
    ];
    // 50 item reads for page one's candidates, plus 1 for page two's.
    let mut full_script = script;
    for index in 0..50 {
        full_script.push(ok(&profile_user_item_body(2000 + index, 30, 999, 999, 0)));
    }
    full_script.push(ok(&profile_user_item_body(99, 30, 999, 999, 0)));
    // Every one of the 51 rows is an undesired pair (empty desired state):
    // all 51 physical rows are removed via one exact GLPI 11.0.9 deletion
    // response. The planner emits physical ids in ascending order.
    full_script.push(deleted(99));
    for index in 0..50 {
        full_script.push(deleted(2000 + index));
    }
    full_script.push(ok("true")); // killSession

    let server = tokio::spawn(run_scripted_server(
        listener,
        identity.acceptor,
        full_script,
    ));
    let outcome = reconcile(&adapter, &empty_desired_envelope())
        .await
        .unwrap();
    server.await.expect("scripted server completed its script");

    // Every one of the 51 rows is an undesired pair (empty desired state):
    // all 51 physical rows are removed, so the outcome is `Changed`.
    assert_eq!(outcome, ReconciliationOutcome::Changed);
}

/// A current `Profile_User` row whose item-read `users_id` differs from the
/// resolved synchronized user id fails closed rather than being silently
/// dropped or reconciled.
#[tokio::test]
async fn current_row_with_mismatched_users_id_fails_closed() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        ok(&profile_user_search_body(1, &[(99, "jdoe")])),
        // The item read's own `users_id` (31) does not equal the resolved
        // user id (30): must fail closed, not silently drop the row.
        ok(&profile_user_item_body(99, 31, 20, 10, 1)),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(outcome.is_err());
}

/// Only the raw wire integers `0`/`1` are accepted for `is_recursive`; every
/// other representation (`2`, a string, a bool, null) fails closed rather
/// than silently becoming `false`.
#[tokio::test]
async fn malformed_is_recursive_representations_fail_closed() {
    for malformed_body in [
        r#"{"id": 99, "users_id": 30, "profiles_id": 20, "entities_id": 10, "is_recursive": 2}"#,
        r#"{"id": 99, "users_id": 30, "profiles_id": 20, "entities_id": 10, "is_recursive": "0"}"#,
        r#"{"id": 99, "users_id": 30, "profiles_id": 20, "entities_id": 10, "is_recursive": true}"#,
        r#"{"id": 99, "users_id": 30, "profiles_id": 20, "entities_id": 10, "is_recursive": null}"#,
        r#"{"id": 99, "users_id": 30, "profiles_id": 20, "entities_id": 10}"#,
    ] {
        let listener = bind_loopback_listener().await;
        let port = listener.local_addr().unwrap().port();
        let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
        let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

        let script = vec![
            ok(r#"{"session_token": "sess-1"}"#),
            ok("true"),
            ok(&full_session_body(1)),
            ok(&search_options_body(&[
                ("1", "User.id"),
                ("2", "User.name"),
            ])),
            ok(&search_options_body(&[
                ("1", "Profile_User.id"),
                ("2", "User.name"),
            ])),
            ok(&search_body(1, &[(30, "jdoe", "2")])),
            ok(&profile_user_search_body(1, &[(99, "jdoe")])),
            ok(malformed_body),
            ok("true"),
        ];

        let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
        let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
        server
            .await
            .expect("scripted server completed exactly its script");

        assert!(
            outcome.is_err(),
            "malformed is_recursive body must fail closed: {malformed_body}"
        );
    }
}

/// Unlike `Profile`/`User`/`Profile_User`, `Entity.id` may legitimately be
/// `0` (GLPI's own root entity). This is intentionally NOT a "zero id fails
/// closed" test: see
/// `desired_entity_selector_resolving_to_root_entity_id_zero_succeeds` for
/// the corresponding bare-"Root entity" success case. `Entity.id` is a
/// unique primary key, so a real GLPI instance can never return id `0` for
/// any `Entity.completename` other than its actual root entity; there is no
/// wire-distinguishable "impossible" zero-id Entity row to reject.
#[tokio::test]
async fn zero_entity_search_id_resolves_successfully_as_the_root_entity() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let script = vec![
        ok(r#"{"session_token":"sess-1"}"#),
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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(0, "Root Entity > IT", "2")])),
        ok(&search_body(1, &[(20, "Technician", "2")])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        ok(&profile_user_search_body(0, &[])),
        created(r#"{"id":99,"message":"created"}"#),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope())
        .await
        .expect("an exact Entity.completename match with id 0 must resolve, not fail");
    server.await.expect("scripted server completed its script");

    assert_eq!(outcome, ReconciliationOutcome::Changed);
}

/// Zero is not a usable resolved Profile id: User lookup and mutation never
/// start after the invalid exact Profile row.
#[tokio::test]
async fn zero_profile_search_id_is_rejected_before_user_lookup_or_mutation() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let script = vec![
        ok(r#"{"session_token":"sess-1"}"#),
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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        ok(&search_body(1, &[(0, "Technician", "2")])),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope()).await;
    let recorded = server.await.expect("scripted server completed its script");

    assert!(outcome.is_err(), "zero Profile id must fail closed");
    assert_eq!(
        recorded.len(),
        10,
        "only cleanup follows the Profile search"
    );
    assert_request(&recorded[8], "GET", "/apirest.php/search/Profile");
    assert_request(&recorded[9], "GET", "/apirest.php/killSession");
}

/// Zero is not a usable resolved User id: no candidate discovery or assignment
/// mutation starts after the invalid exact User row.
#[tokio::test]
async fn zero_user_search_id_is_rejected_before_assignment_discovery_or_mutation() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let script = vec![
        ok(r#"{"session_token":"sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(0, "jdoe", "2")])),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
    let recorded = server.await.expect("scripted server completed its script");

    assert!(outcome.is_err(), "zero User id must fail closed");
    assert_eq!(recorded.len(), 7, "only cleanup follows the User search");
    assert_request(&recorded[5], "GET", "/apirest.php/search/User");
    assert_request(&recorded[6], "GET", "/apirest.php/killSession");
}

/// A zero Profile_User search candidate is not an item id: the adapter neither
/// reads `/Profile_User/0` nor begins deletion before cleanup.
#[tokio::test]
async fn zero_profile_user_candidate_id_is_rejected_before_item_read_or_mutation() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let script = vec![
        ok(r#"{"session_token":"sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        ok(&profile_user_search_body(1, &[(0, "jdoe")])),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
    let recorded = server.await.expect("scripted server completed its script");

    assert!(outcome.is_err(), "zero candidate id must fail closed");
    assert_eq!(
        recorded.len(),
        8,
        "no Profile_User item read or deletion starts"
    );
    assert_request(&recorded[6], "GET", "/apirest.php/search/Profile_User");
    assert_request(&recorded[7], "GET", "/apirest.php/killSession");
}

/// Item `id`, `users_id`, and `profiles_id` are positive GLPI database ids.
/// A zero in any one raw field fails closed before the candidate can be
/// reconciled or deleted.
#[tokio::test]
async fn zero_required_profile_user_raw_ids_are_rejected_before_mutation() {
    for (field, item_body) in [
        ("id", profile_user_item_body(0, 30, 20, 10, 0)),
        ("users_id", profile_user_item_body(99, 0, 20, 10, 0)),
        ("profiles_id", profile_user_item_body(99, 30, 0, 10, 0)),
    ] {
        let listener = bind_loopback_listener().await;
        let port = listener.local_addr().unwrap().port();
        let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
        let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
        let script = vec![
            ok(r#"{"session_token":"sess-1"}"#),
            ok("true"),
            ok(&full_session_body(1)),
            ok(&search_options_body(&[
                ("1", "User.id"),
                ("2", "User.name"),
            ])),
            ok(&search_options_body(&[
                ("1", "Profile_User.id"),
                ("2", "User.name"),
            ])),
            ok(&search_body(1, &[(30, "jdoe", "2")])),
            ok(&profile_user_search_body(1, &[(99, "jdoe")])),
            ok(&item_body),
            ok("true"),
        ];

        let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
        let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
        let recorded = server.await.expect("scripted server completed its script");

        assert!(outcome.is_err(), "zero raw {field} must fail closed");
        assert_eq!(recorded.len(), 9, "zero raw {field} cannot start deletion");
        assert_request(&recorded[7], "GET", "/apirest.php/Profile_User/99");
        assert_request(&recorded[8], "GET", "/apirest.php/killSession");
    }
}

/// GLPI's root entity is raw `entities_id: 0`, so unlike the other raw ids it
/// remains valid and its current row is authoritatively removed for an empty
/// desired state.
#[tokio::test]
async fn zero_profile_user_raw_entity_id_is_accepted_as_the_glpi_root_entity() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let script = vec![
        ok(r#"{"session_token":"sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        ok(&profile_user_search_body(1, &[(99, "jdoe")])),
        ok(&profile_user_item_body(99, 30, 20, 0, 0)),
        deleted(99),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope())
        .await
        .expect("root-entity assignment is a valid current row");
    let recorded = server.await.expect("scripted server completed its script");

    assert_eq!(outcome, ReconciliationOutcome::Changed);
    assert_request(&recorded[8], "DELETE", "/apirest.php/Profile_User/99");
    assert_request(&recorded[9], "GET", "/apirest.php/killSession");
}

/// Malformed pagination metadata (an empty page while rows remain
/// outstanding against the declared `totalcount`) fails rather than
/// silently accepting a gap.
#[tokio::test]
async fn malformed_pagination_with_a_short_empty_page_fails_closed() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        // Declares a total of 5 rows but returns zero: a gap, not progress.
        ok(r#"{"totalcount":5,"count":0,"content-range":"0--1/5","data":[]}"#),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(outcome.is_err());
}

/// Inconsistent `totalcount` between successive pages of the same search
/// fails rather than silently trusting the later value.
#[tokio::test]
async fn inconsistent_totalcount_across_pages_fails_closed() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let mut page_one_rows = Vec::new();
    for index in 0..50 {
        page_one_rows.push((3000 + index, "jdoe"));
    }
    let page_one = profile_user_search_page_body(51, 0, &page_one_rows);
    // Second page reports a different totalcount than the first.
    let page_two = profile_user_search_page_body(52, 50, &[(99, "jdoe")]);

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        partial(&page_one),
        partial(&page_two),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(outcome.is_err());
}

// =============================================================================
// AUTHORITATIVE PLAN: DESIRED FALSE / DESIRED TRUE / UNDESIRED PAIR
// =============================================================================
//
// The pure planning combinatorics (one/duplicate/opposite/mixed current
// rows against a desired `false` or `true`, and undesired pairs) are
// exhaustively covered as fast unit tests directly against `plan::compute`
// in `src/plan.rs`, which is the right layer for pure combinatorial
// coverage with no I/O. The integration tests below prove the *same*
// authoritative-plan behavior end to end through real scripted GLPI
// requests, so the wiring between search, resolution, and planning is also
// exercised, not just the pure function.

/// Desired `true` with current rows `[true, false]` for the same pair keeps
/// the canonical `true` row and removes only the opposite-recursive row,
/// issuing exactly one `DELETE` and no `POST`.
#[tokio::test]
async fn desired_true_with_true_and_false_current_rows_removes_only_the_false_row() {
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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        ok(&search_body(1, &[(20, "Technician", "2")])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        ok(&profile_user_search_body(2, &[(99, "jdoe"), (100, "jdoe")])),
        ok(&profile_user_item_body(99, 30, 20, 10, 1)), // canonical: true
        ok(&profile_user_item_body(100, 30, 20, 10, 0)), // opposite: false
        deleted(100),                                   // DELETE Profile_User/100
        ok("true"),                                     // killSession
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope())
        .await
        .unwrap();
    let recorded = server.await.expect("scripted server completed its script");

    assert_eq!(outcome, ReconciliationOutcome::Changed);
    assert_request(&recorded[13], "DELETE", "/apirest.php/Profile_User/100");
    for entry in &recorded {
        let (method, path, _) = parsed_request_line(&entry.0);
        if path == "/apirest.php/changeActiveEntities" {
            continue;
        }
        assert_ne!(
            method, "POST",
            "no addition is needed when the true row already exists"
        );
    }
}

/// Desired `false` with current rows `[false, false, true]` retains one
/// canonical non-recursive row and removes the duplicate and wrong-recursive
/// rows, leaving exactly one physical canonical row without an addition.
#[tokio::test]
async fn desired_false_with_duplicate_false_and_true_current_rows_retains_one_false_and_removes_the_rest()
 {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let envelope = envelope_json(
        r#"{"permissions": [{"entity": "Root Entity > IT", "profile": "Technician", "recursive": false}]}"#,
    );

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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        ok(&search_body(1, &[(20, "Technician", "2")])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        ok(&profile_user_search_body(
            3,
            &[(99, "jdoe"), (100, "jdoe"), (101, "jdoe")],
        )),
        ok(&profile_user_item_body(99, 30, 20, 10, 0)), // retained canonical false
        ok(&profile_user_item_body(100, 30, 20, 10, 0)), // duplicate canonical false
        ok(&profile_user_item_body(101, 30, 20, 10, 1)), // wrong-recursive true
        deleted(100),
        deleted(101),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &envelope).await.unwrap();
    let recorded = server.await.expect("scripted server completed its script");

    assert_eq!(outcome, ReconciliationOutcome::Changed);
    assert_request(&recorded[14], "DELETE", "/apirest.php/Profile_User/100");
    assert_request(&recorded[15], "DELETE", "/apirest.php/Profile_User/101");
    for entry in &recorded {
        let (method, path, _) = parsed_request_line(&entry.0);
        if path == "/apirest.php/changeActiveEntities" {
            continue;
        }
        assert_ne!(
            method, "POST",
            "the retained canonical false row must prevent an unnecessary addition"
        );
    }
}

/// An undesired pair with mixed recursive current rows is fully removed
/// regardless of either row's `is_recursive` value.
#[tokio::test]
async fn undesired_pair_with_mixed_recursive_rows_is_fully_removed() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        ok(&profile_user_search_body(2, &[(99, "jdoe"), (100, "jdoe")])),
        ok(&profile_user_item_body(99, 30, 20, 10, 1)),
        ok(&profile_user_item_body(100, 30, 20, 10, 0)),
        deleted(99),  // DELETE Profile_User/99
        deleted(100), // DELETE Profile_User/100
        ok("true"),   // killSession
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope())
        .await
        .unwrap();
    let recorded = server.await.expect("scripted server completed its script");

    assert_eq!(outcome, ReconciliationOutcome::Changed);
    assert_request(&recorded[9], "DELETE", "/apirest.php/Profile_User/99");
    assert_request(&recorded[10], "DELETE", "/apirest.php/Profile_User/100");
}

/// Removing an existing undesired assignment for an existing user requires
/// only its `DELETE`; it must not spuriously create a User, Entity, Profile,
/// or replacement Profile_User row.
#[tokio::test]
async fn removing_an_undesired_assignment_does_not_issue_any_creation_post() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        ok(&profile_user_search_body(1, &[(99, "jdoe")])),
        ok(&profile_user_item_body(99, 30, 20, 10, 1)),
        deleted(99),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope())
        .await
        .unwrap();
    let recorded = server.await.expect("scripted server completed its script");

    assert_eq!(outcome, ReconciliationOutcome::Changed);
    assert_request(&recorded[8], "DELETE", "/apirest.php/Profile_User/99");
    for entry in &recorded {
        let (method, path, _) = parsed_request_line(&entry.0);
        if path == "/apirest.php/changeActiveEntities" {
            continue;
        }
        assert_ne!(
            method, "POST",
            "removing an undesired assignment must not create any GLPI resource"
        );
    }
}

// =============================================================================
// PLAN / EXECUTION INVARIANTS
// =============================================================================

/// A plan with removals for two independent undesired pairs and additions
/// for two independent missing pairs performs every removal (in ascending
/// physical id order) before any addition (in ascending `(entities_id,
/// profiles_id)` order): one mutation per request, never batched, never an
/// in-place update.
#[tokio::test]
async fn all_removals_precede_all_additions_one_mutation_per_request() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let envelope = envelope_json(
        r#"{"permissions": [
            {"entity": "Entity One", "profile": "Profile One", "recursive": true},
            {"entity": "Entity Two", "profile": "Profile Two", "recursive": false}
        ]}"#,
    );

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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Entity One", "2")])),
        ok(&search_body(1, &[(20, "Profile One", "2")])),
        ok(&search_body(1, &[(30, "Entity Two", "2")])),
        ok(&search_body(1, &[(40, "Profile Two", "2")])),
        ok(&search_body(1, &[(50, "jdoe", "2")])),
        ok(&profile_user_search_body(2, &[(1, "jdoe"), (2, "jdoe")])),
        // Two current rows, both undesired pairs (neither matches
        // (10,20) nor (30,40)): both are removed, and both desired pairs
        // are pure additions.
        ok(&profile_user_item_body(1, 50, 999, 998, 0)),
        ok(&profile_user_item_body(2, 50, 997, 996, 1)),
        deleted(1),                                   // DELETE Profile_User/1
        deleted(2),                                   // DELETE Profile_User/2
        created(r#"{"id":200,"message":"created"}"#), // POST addition (10,20)
        created(r#"{"id":201,"message":"created"}"#), // POST addition (30,40)
        ok("true"),                                   // killSession
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &envelope).await.unwrap();
    let recorded = server.await.expect("scripted server completed its script");

    assert_eq!(outcome, ReconciliationOutcome::Changed);
    assert_request(&recorded[15], "DELETE", "/apirest.php/Profile_User/1");
    assert_request(&recorded[16], "DELETE", "/apirest.php/Profile_User/2");
    assert_request(&recorded[17], "POST", "/apirest.php/Profile_User");
    assert_json_body(
        &recorded[17],
        serde_json::json!({
            "input": {
                "users_id": 50,
                "profiles_id": 20,
                "entities_id": 10,
                "is_recursive": true,
            }
        }),
    );
    assert_request(&recorded[18], "POST", "/apirest.php/Profile_User");
    assert_json_body(
        &recorded[18],
        serde_json::json!({
            "input": {
                "users_id": 50,
                "profiles_id": 40,
                "entities_id": 30,
                "is_recursive": false,
            }
        }),
    );
    // Never an in-place update: no PATCH/PUT method appears anywhere.
    for entry in &recorded {
        let (method, _, _) = parsed_request_line(&entry.0);
        assert_ne!(method, "PATCH");
        assert_ne!(method, "PUT");
    }
}

/// A `DELETE` failure stops immediately: no further removal and no
/// addition is ever attempted, even though the plan required both.
#[tokio::test]
async fn delete_failure_blocks_every_subsequent_removal_and_addition() {
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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        ok(&search_body(1, &[(20, "Technician", "2")])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        ok(&profile_user_search_body(2, &[(1, "jdoe"), (2, "jdoe")])),
        ok(&profile_user_item_body(1, 30, 998, 997, 0)),
        ok(&profile_user_item_body(2, 30, 996, 995, 0)),
        json_response("500 Internal Server Error", "{}"), // first DELETE fails
        ok("true"),                                       // killSession still attempted
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(outcome.is_err());
}

/// A `DELETE` response with `200 OK` status but an unsuccessful structured
/// GLPI 11.0.9 deletion result is rejected: an HTTP status alone is never
/// sufficient to consider a mutation successful.
#[tokio::test]
async fn delete_with_200_status_but_invalid_structured_result_is_rejected() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        ok(&profile_user_search_body(1, &[(99, "jdoe")])),
        ok(&profile_user_item_body(99, 30, 20, 10, 0)),
        ok("false"), // DELETE Profile_User/99: not a structured success result
        ok("true"),  // killSession still attempted
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(
        outcome.is_err(),
        "a 200 OK DELETE response body that is not a structured success result must be rejected"
    );
}

/// Repeating a reconciliation after cleaning up duplicate rows converges to
/// `Unchanged` on the next run: partial state from a prior run is never
/// rolled back, and a later run converges from wherever the state is.
#[tokio::test]
async fn a_later_reconciliation_converges_and_becomes_unchanged() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    // First run: a duplicate canonical row exists; cleanup returns Changed.
    let script_one = vec![
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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        ok(&search_body(1, &[(20, "Technician", "2")])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        ok(&profile_user_search_body(2, &[(99, "jdoe"), (100, "jdoe")])),
        ok(&profile_user_item_body(99, 30, 20, 10, 1)),
        ok(&profile_user_item_body(100, 30, 20, 10, 1)), // exact duplicate
        deleted(100),                                    // DELETE the duplicate
        ok("true"),                                      // killSession
    ];
    let server_one = tokio::spawn(run_scripted_server(listener, identity.acceptor, script_one));
    let outcome_one = reconcile(&adapter, &one_permission_envelope())
        .await
        .unwrap();
    server_one.await.expect("first scripted server completed");
    assert_eq!(outcome_one, ReconciliationOutcome::Changed);

    // Second run: only the canonical row remains; converges to Unchanged.
    let listener_two = bind_loopback_listener().await;
    let port_two = listener_two.local_addr().unwrap().port();
    let identity_two = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter_two = adapter_for(port_two, identity_two.trust_anchor_pem.clone());
    let script_two = vec![
        ok(r#"{"session_token": "sess-2"}"#),
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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        ok(&search_body(1, &[(20, "Technician", "2")])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        ok(&profile_user_search_body(1, &[(99, "jdoe")])),
        ok(&profile_user_item_body(99, 30, 20, 10, 1)),
        ok("true"),
    ];
    let server_two = tokio::spawn(run_scripted_server(
        listener_two,
        identity_two.acceptor,
        script_two,
    ));
    let outcome_two = reconcile(&adapter_two, &one_permission_envelope())
        .await
        .unwrap();
    server_two.await.expect("second scripted server completed");
    assert_eq!(outcome_two, ReconciliationOutcome::Unchanged);
}

// =============================================================================
// MUTATION RESPONSE VALIDATION
// =============================================================================
//
// Every test in this section is a hypothetical response shape used only to
// exercise the adapter's own decision logic (accept/reject); none of these
// bodies or status codes are asserted as "this is what real GLPI actually
// sends" — see `tests/real_glpi.rs` for wire-shape verification against a
// real GLPI 11.0.9 instance.

/// A malformed success-looking `User`/`Profile_User` creation response
/// (an extra field alongside `id`) is rejected rather than accepted merely
/// because an `id` field happens to be present.
#[tokio::test]
async fn malformed_success_looking_creation_response_is_rejected() {
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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        ok(&search_body(1, &[(20, "Technician", "2")])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        ok(&profile_user_search_body(0, &[])),
        // Hypothetical response shape, not asserted as GLPI's actual wire
        // behavior: an extra unexpected field alongside "id".
        created(r#"{"id":99,"message":"ok","unexpected":true}"#),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(outcome.is_err());
}

/// A creation response with `"id": 0` is rejected: zero is never a valid
/// created id.
#[tokio::test]
async fn zero_id_in_creation_response_is_rejected() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_body(0, &[])),
        // Hypothetical response shape, not asserted as GLPI's actual wire
        // behavior; see `tests/real_glpi.rs`.
        created(r#"{"id":0,"message":"created"}"#),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(outcome.is_err());
}

/// A bare `false` result body for a creation request is rejected: it is not
/// a valid `{"id": ...}` shape regardless of the HTTP status used.
#[tokio::test]
async fn bare_false_creation_result_is_rejected() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_body(0, &[])),
        // Hypothetical response shape, not asserted as GLPI's actual wire
        // behavior; see `tests/real_glpi.rs`.
        created("false"),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(outcome.is_err());
}

/// A semantically successful-looking body is still rejected when the HTTP
/// status is not the expected one for that operation: 2xx status alone is
/// never sufficient.
#[tokio::test]
async fn correct_body_with_wrong_status_code_is_rejected() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_body(0, &[])),
        // Hypothetical response shape, not asserted as GLPI's actual wire
        // behavior: a valid-looking `{"id": N}` body but with status `200
        // OK` where the adapter requires `201 Created` for a creation.
        ok(r#"{"id":42,"message":"created"}"#),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(outcome.is_err());
}

/// A `Profile_User` deletion response with an unexpected (non-`200`)
/// status is rejected, including a plausible `204 No Content`.
#[tokio::test]
async fn delete_response_with_unexpected_status_is_rejected() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        ok(&profile_user_search_body(1, &[(99, "jdoe")])),
        ok(&profile_user_item_body(99, 30, 20, 10, 1)),
        // Hypothetical response shape, not asserted as GLPI's actual wire
        // behavior; see `tests/real_glpi.rs`.
        json_response("204 No Content", ""),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(outcome.is_err());
}

/// A `killSession` response with `200 OK` but a body other than the bare
/// JSON literal `true` is rejected: a `2xx` status alone is not sufficient
/// for cleanup verification either.
#[tokio::test]
async fn kill_session_with_non_true_body_is_rejected() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_body(0, &[])),
        // Hypothetical response shape, not asserted as GLPI's actual wire
        // behavior; see `tests/real_glpi.rs`: a `200 OK` killSession with an
        // unexpected body.
        ok(r#"{"message": "ok"}"#),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(outcome.is_err());
}

// =============================================================================
// SESSION AUTHENTICATION / CLEANUP
// =============================================================================

/// `initSession` authenticates with `Authorization: user_token <token>` and
/// `App-Token` headers (never a `Session-Token` header, since none exists
/// yet), with an empty GET body; every subsequent call instead uses
/// `Session-Token` + `App-Token` and never repeats the user-token
/// `Authorization` header.
#[tokio::test]
async fn init_session_and_subsequent_calls_use_the_correct_distinct_headers() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        ok(&profile_user_search_body(0, &[])),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope())
        .await
        .unwrap();
    let recorded = server.await.expect("scripted server completed its script");

    assert_eq!(outcome, ReconciliationOutcome::Unchanged);

    // initSession (request 0): GET, Authorization + App-Token, no
    // Session-Token, empty body.
    assert_request(&recorded[0], "GET", "/apirest.php/initSession");
    assert_empty_body(&recorded[0]);
    assert_header(&recorded[0], "authorization", "user_token user-token");
    assert_header(&recorded[0], "app-token", "app-token");
    assert_no_header(&recorded[0], "session-token");

    // Every subsequent request: Session-Token + App-Token, never
    // Authorization.
    for entry in &recorded[1..] {
        assert_header(entry, "session-token", "sess-1");
        assert_header(entry, "app-token", "app-token");
        assert_no_header(entry, "authorization");
    }

    // killSession (the last request): GET, empty body.
    let last = recorded.last().unwrap();
    assert_request(last, "GET", "/apirest.php/killSession");
    assert_empty_body(last);
}

/// Two independent reconciliations each start and use their own distinct
/// session token; the second reconciliation never reuses the first's
/// token.
#[tokio::test]
async fn separate_reconciliations_use_separate_session_tokens() {
    for session_token in ["sess-alpha", "sess-beta"] {
        let listener = bind_loopback_listener().await;
        let port = listener.local_addr().unwrap().port();
        let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
        let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

        let script = vec![
            ok(&format!(r#"{{"session_token": "{session_token}"}}"#)),
            ok("true"),
            ok(&full_session_body(1)),
            ok(&search_options_body(&[
                ("1", "User.id"),
                ("2", "User.name"),
            ])),
            ok(&search_options_body(&[
                ("1", "Profile_User.id"),
                ("2", "User.name"),
            ])),
            ok(&search_body(1, &[(30, "jdoe", "2")])),
            ok(&profile_user_search_body(0, &[])),
            ok("true"),
        ];

        let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
        let outcome = reconcile(&adapter, &empty_desired_envelope())
            .await
            .unwrap();
        let recorded = server.await.expect("scripted server completed its script");

        assert_eq!(outcome, ReconciliationOutcome::Unchanged);
        for entry in &recorded[1..] {
            assert_header(entry, "session-token", session_token);
        }
    }
}

/// A `killSession` failure that occurs after the primary reconciliation
/// already failed (ambiguous user) still results in an overall adapter
/// failure (cleanup failure never turns a failed reconciliation into a
/// reported success).
#[tokio::test]
async fn cleanup_failure_after_primary_failure_is_still_a_failure() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_body(2, &[(30, "jdoe", "2"), (31, "jdoe", "2")])), // ambiguous
        json_response("500 Internal Server Error", "{}"),             // killSession also fails
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(
        outcome.is_err(),
        "a primary failure followed by a cleanup failure must still be reported as failure"
    );
}

// =============================================================================
// TRANSPORT / SECURITY
// =============================================================================

/// A server certificate valid for a different address than the one dialed
/// (hostname/SAN mismatch) is rejected even though it chains to the same
/// trusted root.
#[tokio::test]
async fn rejects_a_hostname_mismatched_server_certificate() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    // The presented certificate's SAN covers a different loopback address
    // than the one the adapter actually dials.
    let mismatched_identity = build_test_identity("127.0.0.2", ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, mismatched_identity.trust_anchor_pem.clone());

    let accept_task = tokio::spawn(accept_one_tls_connection(
        listener,
        mismatched_identity.acceptor,
    ));

    let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
    accept_task.await.expect("accept task completed");

    assert!(outcome.is_err());
}

/// A response body beyond the private response-size bound is rejected
/// rather than buffered without limit.
#[tokio::test]
async fn oversized_response_body_is_rejected() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let oversized_body = vec![b'a'; 2 * 1_048_576 + 1];
    let script = vec![ScriptedResponse {
        status_line: "200 OK",
        body: oversized_body,
    }];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(outcome.is_err());
}

/// A malformed (non-JSON) `initSession` response body is rejected.
#[tokio::test]
async fn malformed_json_response_body_is_rejected() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let script = vec![ok("not json at all")];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(outcome.is_err());
}

/// An unexpected HTTP status for `initSession` (neither documented success
/// nor a status the adapter otherwise handles) is rejected, including a
/// `3xx` redirect status: the adapter never follows redirects.
#[tokio::test]
async fn unexpected_and_redirect_statuses_for_init_session_are_rejected() {
    for status_line in [
        "301 Moved Permanently",
        "302 Found",
        "303 See Other",
        "307 Temporary Redirect",
        "308 Permanent Redirect",
        "418 I'm a Teapot",
        "500 Internal Server Error",
    ] {
        let listener = bind_loopback_listener().await;
        let port = listener.local_addr().unwrap().port();
        let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
        let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

        let script = vec![json_response(status_line, r#"{"session_token": "sess-1"}"#)];

        let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
        let outcome = reconcile(&adapter, &empty_desired_envelope()).await;
        server
            .await
            .expect("scripted server completed exactly its script");

        assert!(outcome.is_err(), "status {status_line} must be rejected");
    }
}

/// The `Host` header always carries the explicit non-default loopback port
/// the adapter actually dialed, proving unambiguous query/path composition
/// against that exact authority.
#[tokio::test]
async fn host_header_includes_the_explicit_non_default_port() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let script = vec![ok(r#"{"session_token": "sess-1"}"#), ok("true")];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let _ = reconcile(&adapter, &empty_desired_envelope()).await;
    let recorded = server
        .await
        .expect("scripted server completed exactly its script");

    assert_header(&recorded[0], "host", &format!("{LOOPBACK_ADDRESS}:{port}"));
}

/// No sentinel App-Token, User-Token, session token, username, entity, or
/// profile value ever appears in the adapter's public `Debug`/`Display`
/// error output.
#[tokio::test]
async fn no_sentinel_secret_or_selector_value_appears_in_public_errors() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let sentinel_app_token = "sentinel-app-token-zzz";
    let sentinel_user_token = "sentinel-user-token-zzz";
    let adapter = GlpiAdapter::new(GlpiAdapterConfig {
        endpoint: format!("https://{LOOPBACK_ADDRESS}:{port}/apirest.php"),
        app_token: GlpiAppToken::new(sentinel_app_token.to_owned()),
        user_token: GlpiUserToken::new(sentinel_user_token.to_owned()),
        operation_timeout: Duration::from_secs(5),
        additional_trust_anchors_pem: vec![identity.trust_anchor_pem.clone()],
        authentication_source: GlpiAuthenticationSource::default(),
    })
    .expect("valid GLPI adapter configuration");
    let sentinel_entity = "sentinel-entity-zzz";
    let sentinel_profile = "sentinel-profile-zzz";
    let envelope = envelope_json(&format!(
        r#"{{"permissions": [{{"entity": "{sentinel_entity}", "profile": "{sentinel_profile}", "recursive": true}}]}}"#
    ));

    let script = vec![json_response("500 Internal Server Error", "{}")];
    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &envelope).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    let error = outcome.expect_err("initSession failure must be reported");
    let debug_text = format!("{error:?}");
    let display_text = error.to_string();
    for sentinel in [
        sentinel_app_token,
        sentinel_user_token,
        sentinel_entity,
        sentinel_profile,
        "sess-1",
        "jdoe",
    ] {
        assert!(!debug_text.contains(sentinel), "Debug leaked {sentinel}");
        assert!(
            !display_text.contains(sentinel),
            "Display leaked {sentinel}"
        );
    }
}

// =============================================================================
// CANCELLATION / DEADLINES
// =============================================================================

/// Cancellation observed immediately after `initSession` completes stops
/// the adapter before `changeActiveEntities` is ever sent.
#[tokio::test]
async fn cancellation_after_init_session_stops_before_visibility_change() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let completed = Arc::new(AtomicUsize::new(0));
    let cancellation = CancelAfterRequests {
        completed: Arc::clone(&completed),
        threshold: 1,
    };

    let server = tokio::spawn(run_counted_scripted_server(
        listener,
        identity.acceptor,
        oversized_script(),
        Arc::clone(&completed),
    ));
    let outcome =
        reconcile_with_cancellation(&adapter, &one_permission_envelope(), &cancellation).await;
    abort_fake_server(server, "counted scripted server").await;

    assert!(outcome.is_err());
    assert_eq!(completed.load(Ordering::SeqCst), 1);
}

/// Cancellation observed after `changeActiveEntities` completes stops the
/// adapter before `getFullSession` is ever sent.
#[tokio::test]
async fn cancellation_during_visibility_establishment_stops_before_verification() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let completed = Arc::new(AtomicUsize::new(0));
    let cancellation = CancelAfterRequests {
        completed: Arc::clone(&completed),
        threshold: 2,
    };

    let server = tokio::spawn(run_counted_scripted_server(
        listener,
        identity.acceptor,
        oversized_script(),
        Arc::clone(&completed),
    ));
    let outcome =
        reconcile_with_cancellation(&adapter, &one_permission_envelope(), &cancellation).await;
    abort_fake_server(server, "counted scripted server").await;

    assert!(outcome.is_err());
    assert_eq!(completed.load(Ordering::SeqCst), 2);
}

/// Cancellation observed between semantic-resolution search-option lookups
/// (after `Entity`, before `Profile`) stops immediately.
#[tokio::test]
async fn cancellation_between_semantic_resolution_stages_stops_immediately() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let completed = Arc::new(AtomicUsize::new(0));
    let cancellation = CancelAfterRequests {
        completed: Arc::clone(&completed),
        threshold: 4,
    };

    let server = tokio::spawn(run_counted_scripted_server(
        listener,
        identity.acceptor,
        oversized_script(),
        Arc::clone(&completed),
    ));
    let outcome =
        reconcile_with_cancellation(&adapter, &one_permission_envelope(), &cancellation).await;
    abort_fake_server(server, "counted scripted server").await;

    assert!(outcome.is_err());
    assert_eq!(completed.load(Ordering::SeqCst), 4);
}

/// Cancellation observed right after entity and profile resolution
/// complete stops the adapter before the user lookup is ever sent.
#[tokio::test]
async fn cancellation_before_user_lookup_stops_immediately() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let completed = Arc::new(AtomicUsize::new(0));
    let cancellation = CancelAfterRequests {
        completed: Arc::clone(&completed),
        threshold: 9,
    };

    let server = tokio::spawn(run_counted_scripted_server(
        listener,
        identity.acceptor,
        oversized_script(),
        Arc::clone(&completed),
    ));
    let outcome =
        reconcile_with_cancellation(&adapter, &one_permission_envelope(), &cancellation).await;
    abort_fake_server(server, "counted scripted server").await;

    assert!(outcome.is_err());
    assert_eq!(completed.load(Ordering::SeqCst), 9);
}

/// Cancellation observed right after the user lookup completes (an
/// existing user) stops the adapter before user creation would ever be
/// considered and before the current-state read is ever sent.
#[tokio::test]
async fn cancellation_before_current_state_read_stops_immediately() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let completed = Arc::new(AtomicUsize::new(0));
    let cancellation = CancelAfterRequests {
        completed: Arc::clone(&completed),
        threshold: 10,
    };

    let server = tokio::spawn(run_counted_scripted_server(
        listener,
        identity.acceptor,
        oversized_script(),
        Arc::clone(&completed),
    ));
    let outcome =
        reconcile_with_cancellation(&adapter, &one_permission_envelope(), &cancellation).await;
    abort_fake_server(server, "counted scripted server").await;

    assert!(outcome.is_err());
    assert_eq!(completed.load(Ordering::SeqCst), 10);
}

/// Cancellation observed right after the current-state read completes
/// stops the adapter before the first removal is ever sent.
#[tokio::test]
async fn cancellation_before_first_delete_stops_immediately() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let completed = Arc::new(AtomicUsize::new(0));
    let cancellation = CancelAfterRequests {
        completed: Arc::clone(&completed),
        threshold: 12,
    };

    let server = tokio::spawn(run_counted_scripted_server(
        listener,
        identity.acceptor,
        oversized_script(),
        Arc::clone(&completed),
    ));
    let outcome =
        reconcile_with_cancellation(&adapter, &one_permission_envelope(), &cancellation).await;
    abort_fake_server(server, "counted scripted server").await;

    assert!(outcome.is_err());
    assert_eq!(completed.load(Ordering::SeqCst), 12);
}

/// Cancellation observed right after the (only) removal completes stops
/// the adapter before the addition phase is ever entered.
#[tokio::test]
async fn cancellation_between_delete_and_add_phases_stops_immediately() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let completed = Arc::new(AtomicUsize::new(0));
    let cancellation = CancelAfterRequests {
        completed: Arc::clone(&completed),
        threshold: 13,
    };

    let server = tokio::spawn(run_counted_scripted_server(
        listener,
        identity.acceptor,
        oversized_script(),
        Arc::clone(&completed),
    ));
    let outcome =
        reconcile_with_cancellation(&adapter, &one_permission_envelope(), &cancellation).await;
    abort_fake_server(server, "counted scripted server").await;

    assert!(outcome.is_err());
    assert_eq!(completed.load(Ordering::SeqCst), 13);
}

/// Cancellation observed right after every mutation completes suppresses
/// `killSession` cleanup entirely, per ADR 0009, without turning an
/// otherwise-successful reconciliation into a reported failure.
#[tokio::test]
async fn cancellation_before_cleanup_suppresses_kill_session_without_failing() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let completed = Arc::new(AtomicUsize::new(0));
    let cancellation = CancelAfterRequests {
        completed: Arc::clone(&completed),
        threshold: 14,
    };

    let server = tokio::spawn(run_counted_scripted_server(
        listener,
        identity.acceptor,
        oversized_script(),
        Arc::clone(&completed),
    ));
    let outcome =
        reconcile_with_cancellation(&adapter, &one_permission_envelope(), &cancellation).await;
    abort_fake_server(server, "counted scripted server").await;

    assert_eq!(
        outcome.unwrap(),
        ReconciliationOutcome::Changed,
        "cancellation must suppress cleanup without failing an already-successful reconciliation"
    );
    assert_eq!(completed.load(Ordering::SeqCst), 14);
}

/// Cancellation observed between pages of one paginated `Profile_User`
/// search stops before the next page is ever requested, rather than only
/// being checked once before the overall search starts.
#[tokio::test]
async fn cancellation_between_search_pages_stops_before_next_page() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let completed = Arc::new(AtomicUsize::new(0));
    // Completed after: initSession(1), changeActiveEntities(2),
    // getFullSession(3), User search-options(4), Profile_User
    // search-options(5), resolve_user_id search(6), and the first
    // `Profile_User` search page(7). Cancellation must be observed here,
    // before the second page is ever requested.
    let cancellation = CancelAfterRequests {
        completed: Arc::clone(&completed),
        threshold: 7,
    };

    // None of page one's rows match "jdoe": this page exists only to
    // establish (via `totalcount`) that a second page is required, without
    // triggering any per-candidate item read as a side effect.
    let mut page_one_rows = Vec::new();
    for index in 0..50 {
        page_one_rows.push((3000 + index, "other-user"));
    }
    let page_one = profile_user_search_page_body(51, 0, &page_one_rows);
    // A second page that must never be requested: if cancellation were only
    // checked before the overall search started (not between pages), the
    // adapter would fetch this page too.
    let page_two = profile_user_search_page_body(51, 50, &[(99, "jdoe")]);

    let script = vec![
        ok(r#"{"session_token": "sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        partial(&page_one),
        ok(&page_two),
        ok("true"),
    ];

    let server = tokio::spawn(run_counted_scripted_server(
        listener,
        identity.acceptor,
        script,
        Arc::clone(&completed),
    ));
    let outcome =
        reconcile_with_cancellation(&adapter, &empty_desired_envelope(), &cancellation).await;
    abort_fake_server(server, "counted scripted server").await;

    assert!(outcome.is_err());
    assert_eq!(completed.load(Ordering::SeqCst), 7);
}

/// Cancellation observed after the first authoritative raw item read stops
/// before the second `Profile_User/:id` request starts. This is distinct from
/// cancelling between candidate-search pages: the item reads are individual
/// outbound operations with their own context gate.
#[tokio::test]
async fn cancellation_between_profile_user_item_reads_stops_before_second_read() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let completed = Arc::new(AtomicUsize::new(0));
    let cancellation = CancelAfterRequests {
        completed: Arc::clone(&completed),
        // init, active entities, full session, User/Profile_User options,
        // User search, Profile_User candidate search, first raw item read.
        threshold: 8,
    };
    let script = vec![
        ok(r#"{"session_token":"sess-1"}"#),
        ok("true"),
        ok(&full_session_body(1)),
        ok(&search_options_body(&[
            ("1", "User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_options_body(&[
            ("1", "Profile_User.id"),
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        ok(&profile_user_search_body(2, &[(99, "jdoe"), (100, "jdoe")])),
        ok(&profile_user_item_body(99, 30, 20, 10, 0)),
        ok(&profile_user_item_body(100, 30, 20, 10, 0)),
    ];
    let server = tokio::spawn(run_counted_scripted_server(
        listener,
        identity.acceptor,
        script,
        Arc::clone(&completed),
    ));

    let outcome =
        reconcile_with_cancellation(&adapter, &empty_desired_envelope(), &cancellation).await;
    abort_fake_server(server, "counted scripted server").await;

    assert!(outcome.is_err());
    assert_eq!(completed.load(Ordering::SeqCst), 8);
}

/// A held response consumes the fresh per-operation budget. The server first
/// confirms the request, then waits for the adapter to close its timed-out
/// connection.
#[tokio::test]
async fn held_response_respects_operation_deadline_and_closes_connection() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for_with_timeout(
        port,
        identity.trust_anchor_pem.clone(),
        HELD_RESPONSE_DEADLINE,
    );
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(hold_one_response(listener, identity.acceptor, started_tx));

    let envelope = empty_desired_envelope();
    let reconciliation = reconcile(&adapter, &envelope);
    tokio::pin!(reconciliation);
    let request = tokio::select! {
        request = await_fake_server_step("held initSession request", started_rx) => request
            .expect("held server reports the request"),
        outcome = &mut reconciliation => panic!("reconciliation ended before held initSession request: {outcome:?}"),
    };
    assert_request(&request, "GET", "/apirest.php/initSession");
    let outcome = await_fake_server_step("operation deadline", &mut reconciliation).await;
    join_fake_server(server, "held-response server").await;
    assert!(outcome.is_err());
}

/// An earlier overall deadline wins over a longer operation timeout while a
/// response is held, and the adapter closes the held connection.
#[tokio::test]
async fn held_response_respects_earlier_overall_deadline_and_closes_connection() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for_with_timeout(
        port,
        identity.trust_anchor_pem.clone(),
        Duration::from_secs(10),
    );
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(hold_one_response(listener, identity.acceptor, started_tx));
    let cancellation = NeverCancelled;
    let identity_context = IdentityContext::new("jdoe".to_owned(), vec![]);
    let envelope = empty_desired_envelope();
    let context =
        SynchronizationContext::new(Instant::now() + HELD_RESPONSE_DEADLINE, &cancellation);
    let request = TargetAdapterRequest::new(&identity_context, &envelope, context);

    let reconciliation = adapter.reconcile(request);
    tokio::pin!(reconciliation);
    let held_request = tokio::select! {
        request = await_fake_server_step("held initSession request", started_rx) => request
            .expect("held server reports the request"),
        outcome = &mut reconciliation => panic!("reconciliation ended before held initSession request: {outcome:?}"),
    };
    assert_request(&held_request, "GET", "/apirest.php/initSession");
    let outcome = await_fake_server_step("overall deadline", &mut reconciliation).await;
    join_fake_server(server, "held-response server").await;
    assert!(outcome.is_err());
}

/// A synchronization deadline that has already elapsed before the adapter
/// starts makes zero GLPI requests.
#[tokio::test]
async fn deadline_already_elapsed_before_start_makes_zero_requests() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let cancellation = NeverCancelled;
    let elapsed_deadline = Instant::now() - Duration::from_secs(1);
    let context = SynchronizationContext::new(elapsed_deadline, &cancellation);
    let identity_ctx = IdentityContext::new("jdoe".to_owned(), vec![]);
    let envelope = empty_desired_envelope();
    let request = TargetAdapterRequest::new(&identity_ctx, &envelope, context);

    let outcome = adapter.reconcile(request).await;

    assert!(outcome.is_err());
    match listener.try_accept_nonblocking() {
        Err(kind) => assert_eq!(kind, std::io::ErrorKind::WouldBlock),
        Ok(()) => panic!("adapter unexpectedly connected to GLPI past an elapsed deadline"),
    }
}

// =============================================================================
// LANE A ADDITIONS: deterministic cleanup race, entity/profile resolution
// matrices, partial-failure convergence, and GLPI-default-assignment cleanup
// =============================================================================

/// A cancellation signal that stays `false` until the fake server has
/// completed `threshold` requests, then returns `false` exactly once more
/// (its very next read) before becoming permanently cancelled thereafter.
/// This deterministically exercises the exact race ADR 0009 closes:
/// cancellation becoming observable strictly *between* reconciliation's
/// `cleanup_allowed` eligibility check and its immediately-following second
/// `effective_deadline` observation right before `kill_session` (see
/// `adapter.rs::reconcile`'s doc comment on that `Err(_)` arm). Unlike
/// `CancelAfterRequests` above (which reports the same answer on every call
/// once its threshold is reached, so it cannot distinguish "checked once" vs
/// "checked twice"), this signal proves the second, later check is what
/// actually suppresses cleanup.
struct CancelOnSecondReadAfterThreshold {
    completed: Arc<AtomicUsize>,
    threshold: usize,
    reads_after_threshold: AtomicUsize,
}

impl CancellationSignal for CancelOnSecondReadAfterThreshold {
    fn is_cancelled(&self) -> bool {
        if self.completed.load(Ordering::SeqCst) < self.threshold {
            return false;
        }
        let read_index = self.reads_after_threshold.fetch_add(1, Ordering::SeqCst);
        read_index >= 1
    }
}

/// Cancellation flipping to `true` strictly between the `cleanup_allowed`
/// eligibility check and the second `effective_deadline` observation right
/// before `kill_session` must suppress `killSession` entirely (never send
/// it), without turning an already-successful reconciliation into a
/// reported failure.
#[tokio::test]
async fn cancellation_flip_between_cleanup_eligibility_check_and_kill_session_suppresses_cleanup() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let completed = Arc::new(AtomicUsize::new(0));
    // 14 requests complete the primary reconciliation (see `oversized_script`
    // comments): the 15th would be `killSession`.
    let cancellation = CancelOnSecondReadAfterThreshold {
        completed: Arc::clone(&completed),
        threshold: 14,
        reads_after_threshold: AtomicUsize::new(0),
    };

    let server = tokio::spawn(run_counted_scripted_server(
        listener,
        identity.acceptor,
        oversized_script(),
        Arc::clone(&completed),
    ));

    let identity_ctx = IdentityContext::new("jdoe".to_owned(), vec![]);
    let context = SynchronizationContext::new(far_future_deadline(), &cancellation);
    let envelope = one_permission_envelope();
    let request = TargetAdapterRequest::new(&identity_ctx, &envelope, context);
    let outcome = adapter.reconcile(request).await;
    abort_fake_server(server, "counted scripted server").await;

    assert_eq!(
        outcome.unwrap(),
        ReconciliationOutcome::Changed,
        "an already-successful primary outcome must not become a reported failure"
    );
    assert_eq!(
        completed.load(Ordering::SeqCst),
        14,
        "killSession must never be sent once cancellation is observed inside the race window \
         between the eligibility check and the pre-kill_session deadline recomputation"
    );
}

// --- Entity resolution coverage matrix ---------------------------------------

/// A selector that differs from the row's `Entity.completename` only in
/// letter case must NOT match: no case-fold is ever applied.
#[tokio::test]
async fn entity_selector_case_mismatch_is_not_a_match() {
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
            ("2", "User.name"),
        ])),
        // Only a case-differing candidate row: zero exact matches.
        ok(&search_body(1, &[(10, "root entity > it", "2")])),
        ok("true"), // killSession
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope()).await;
    let recorded = server
        .await
        .expect("scripted server completed exactly its script");

    assert!(
        outcome.is_err(),
        "a case-differing candidate must not resolve as an exact match"
    );
    assert_eq!(
        recorded.len(),
        9,
        "no request after the failed Entity search except cleanup"
    );
}

/// More than one exact `Entity.completename` match is an adapter failure,
/// and it happens before any User lookup or creation request.
#[tokio::test]
async fn ambiguous_exact_entity_fails_before_any_user_lookup() {
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
            ("2", "User.name"),
        ])),
        // Two rows with an identical exact `completename` match.
        ok(&search_body(
            2,
            &[(10, "Root Entity > IT", "2"), (11, "Root Entity > IT", "2")],
        )),
        ok("true"), // killSession
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope()).await;
    let recorded = server
        .await
        .expect("scripted server completed exactly its script");

    assert!(outcome.is_err(), "an ambiguous exact entity must fail");
    assert_eq!(
        recorded.len(),
        9,
        "ambiguous entity resolution must fail before any User or Profile_User request"
    );
}

/// A fuzzy/lookalike GLPI search candidate that is not an exact
/// `completename` match must not be accepted: only exact equality counts.
#[tokio::test]
async fn entity_fuzzy_lookalike_is_not_accepted_as_a_match() {
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
            ("2", "User.name"),
        ])),
        // "Root Entity > IT > Ops" is a fuzzy, non-exact result for
        // "Root Entity > IT".
        ok(&search_body(1, &[(10, "Root Entity > IT > Ops", "2")])),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(
        outcome.is_err(),
        "a fuzzy-only entity result must not resolve"
    );
}

/// Entity resolution reads every page before deciding a match, and the
/// desired exact-match row may be found on a page beyond the first.
#[tokio::test]
async fn entity_resolution_reads_every_page_before_matching() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let page_one_names: Vec<String> = (0..50)
        .map(|index| format!("Other Entity {index}"))
        .collect();
    let page_one_rows: Vec<(u64, &str, &str)> = page_one_names
        .iter()
        .enumerate()
        .map(|(index, name)| (2000 + index as u64, name.as_str(), "2"))
        .collect();
    let page_one = search_page_body(51, 0, &page_one_rows);
    let page_two = search_page_body(51, 50, &[(10, "Root Entity > IT", "2")]);

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
            ("2", "User.name"),
        ])),
        partial(&page_one),
        partial(&page_two),
        ok(&search_body(1, &[(20, "Technician", "2")])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        ok(&profile_user_search_body(0, &[])),
        created(r#"{"id":99,"message":"created"}"#),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope())
        .await
        .expect("the exact match on the second page must resolve");
    server.await.expect("scripted server completed its script");

    assert_eq!(outcome, ReconciliationOutcome::Changed);
}

/// A malformed entity search row (a non-numeric `Entity.id`) fails closed
/// rather than being silently skipped.
#[tokio::test]
async fn malformed_entity_row_fails_closed() {
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
            ("2", "User.name"),
        ])),
        ok(
            r#"{"totalcount":1,"count":1,"content-range":"0-0/1","data":[{"1":"not-a-number","2":"Root Entity > IT"}]}"#,
        ),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(
        outcome.is_err(),
        "a malformed exact-match entity row must fail closed"
    );
}

/// Inconsistent `totalcount` between successive pages of an Entity search
/// fails closed rather than silently trusting the later value.
#[tokio::test]
async fn malformed_entity_pagination_fails_closed() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let page_one_names: Vec<String> = (0..50)
        .map(|index| format!("Other Entity {index}"))
        .collect();
    let page_one_rows: Vec<(u64, &str, &str)> = page_one_names
        .iter()
        .enumerate()
        .map(|(index, name)| (2000 + index as u64, name.as_str(), "2"))
        .collect();
    let page_one = search_page_body(51, 0, &page_one_rows);
    // Second page declares a different totalcount than the first.
    let page_two = search_page_body(52, 50, &[(10, "Root Entity > IT", "2")]);

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
            ("2", "User.name"),
        ])),
        partial(&page_one),
        partial(&page_two),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(outcome.is_err());
}

// --- Profile resolution coverage matrix ---------------------------------------

/// A missing profile (zero exact `Profile.name` matches) is a direct
/// failure before any User lookup or creation request.
#[tokio::test]
async fn missing_profile_fails_before_any_user_lookup() {
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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])), // entity resolves
        ok(&search_body(0, &[])),                              // zero exact Profile matches
        ok("true"),                                            // killSession
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope()).await;
    let recorded = server
        .await
        .expect("scripted server completed exactly its script");

    assert!(outcome.is_err());
    assert_eq!(
        recorded.len(),
        10,
        "no request after the failed Profile search except cleanup"
    );
}

/// More than one exact `Profile.name` match is an adapter failure, and it
/// happens before any User lookup or creation/Profile_User mutation.
#[tokio::test]
async fn ambiguous_exact_profile_fails_before_any_user_lookup() {
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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        ok(&search_body(
            2,
            &[(20, "Technician", "2"), (21, "Technician", "2")],
        )),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope()).await;
    let recorded = server
        .await
        .expect("scripted server completed exactly its script");

    assert!(outcome.is_err());
    assert_eq!(
        recorded.len(),
        10,
        "ambiguous profile resolution must fail before any User or Profile_User request"
    );
}

/// A selector differing only in letter case from the row's `Profile.name`
/// must NOT match.
#[tokio::test]
async fn profile_selector_case_mismatch_is_not_a_match() {
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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        ok(&search_body(1, &[(20, "technician", "2")])),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(
        outcome.is_err(),
        "a case-differing candidate must not resolve as an exact profile match"
    );
}

/// A profile selector containing search metacharacters is percent-encoded on
/// the wire and remains inside the anchored GLPI `contains` pattern.
#[tokio::test]
async fn profile_selector_metacharacters_are_percent_encoded() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let profile_selector = "Level 1 & Support=Y";
    let envelope = envelope_json(&format!(
        r#"{{"permissions": [{{"entity": "Root Entity > IT", "profile": "{profile_selector}", "recursive": true}}]}}"#
    ));

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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        ok(&search_body(0, &[])), // zero exact matches
        ok("true"),               // killSession
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &envelope).await;
    let recorded = server.await.expect("scripted server completed its script");

    assert!(outcome.is_err(), "zero exact matches must fail");
    assert!(!recorded[8].0.contains(profile_selector));
    assert_eq!(
        query_value(&recorded[8], "criteria[0][value]"),
        Some(format!("^{profile_selector}$"))
    );
}

/// Profile resolution reads every page before deciding a match, and the
/// desired exact-match row may be found on a page beyond the first.
#[tokio::test]
async fn profile_resolution_reads_every_page_before_matching() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let page_one_names: Vec<String> = (0..50)
        .map(|index| format!("Other Profile {index}"))
        .collect();
    let page_one_rows: Vec<(u64, &str, &str)> = page_one_names
        .iter()
        .enumerate()
        .map(|(index, name)| (3000 + index as u64, name.as_str(), "2"))
        .collect();
    let page_one = search_page_body(51, 0, &page_one_rows);
    let page_two = search_page_body(51, 50, &[(20, "Technician", "2")]);

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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        partial(&page_one),
        partial(&page_two),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        ok(&profile_user_search_body(0, &[])),
        created(r#"{"id":99,"message":"created"}"#),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope())
        .await
        .expect("the exact match on the second page must resolve");
    server.await.expect("scripted server completed its script");

    assert_eq!(outcome, ReconciliationOutcome::Changed);
}

/// A malformed profile search row (a non-numeric `Profile.id`) fails closed
/// rather than being silently skipped.
#[tokio::test]
async fn malformed_profile_row_fails_closed() {
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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        ok(
            r#"{"totalcount":1,"count":1,"content-range":"0-0/1","data":[{"1":"nope","2":"Technician"}]}"#,
        ),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(
        outcome.is_err(),
        "a malformed exact-match profile row must fail closed"
    );
}

/// Inconsistent `totalcount` between successive pages of a Profile search
/// fails closed rather than silently trusting the later value.
#[tokio::test]
async fn malformed_profile_pagination_fails_closed() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    let page_one_names: Vec<String> = (0..50)
        .map(|index| format!("Other Profile {index}"))
        .collect();
    let page_one_rows: Vec<(u64, &str, &str)> = page_one_names
        .iter()
        .enumerate()
        .map(|(index, name)| (3000 + index as u64, name.as_str(), "2"))
        .collect();
    let page_one = search_page_body(51, 0, &page_one_rows);
    let page_two = search_page_body(52, 50, &[(20, "Technician", "2")]);

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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        partial(&page_one),
        partial(&page_two),
        ok("true"),
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope()).await;
    server
        .await
        .expect("scripted server completed exactly its script");

    assert!(outcome.is_err());
}

// --- Partial failure after user creation, and after removals -----------------

/// A missing user is created, then the subsequent current-assignment
/// (`Profile_User`) read fails: exactly one `POST /User` request occurred,
/// the overall result is an error, and no `Profile_User` mutation is ever
/// attempted. The server task completing exactly its script proves there is
/// no automatic retry.
#[tokio::test]
async fn partial_failure_after_user_creation_during_current_assignment_read_makes_no_assignment_mutation()
 {
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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        ok(&search_body(1, &[(20, "Technician", "2")])),
        ok(&search_body(0, &[])),                    // search User: absent
        created(r#"{"id":55,"message":"created"}"#), // POST User succeeds exactly once
        json_response("500 Internal Server Error", "{}"), // current-assignment read fails
        ok("true"),                                  // killSession still attempted
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope()).await;
    let recorded = server
        .await
        .expect("scripted server completed exactly its script, proving no automatic retry");

    assert!(outcome.is_err());
    let user_creation_requests = recorded
        .iter()
        .filter(|recorded| {
            let (method, path, _) = parsed_request_line(&recorded.0);
            method == "POST" && path == "/apirest.php/User"
        })
        .count();
    assert_eq!(user_creation_requests, 1, "exactly one POST /User request");
    assert!(
        !recorded.iter().any(|recorded| {
            let (method, path, _) = parsed_request_line(&recorded.0);
            path.starts_with("/apirest.php/Profile_User")
                && (method == "POST" || method == "DELETE")
        }),
        "no Profile_User mutation may be attempted after the current-assignment read fails"
    );
}

/// After the partial-failure scenario above leaves a user created with no
/// assignments yet, a later legitimate reconciliation converges: the first
/// call (current assignments still empty) is `Changed`, and an identical
/// second call against the now-canonical state is `Unchanged`.
#[tokio::test]
async fn reconciliation_after_partial_user_creation_failure_converges_then_becomes_unchanged() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());

    // First run: the user already exists (created by the earlier partial
    // run) but has no current assignments yet; the desired assignment must
    // be added.
    let script_one = vec![
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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        ok(&search_body(1, &[(20, "Technician", "2")])),
        ok(&search_body(1, &[(55, "jdoe", "2")])),
        ok(&profile_user_search_body(0, &[])),
        created(r#"{"id":200,"message":"created"}"#),
        ok("true"),
    ];
    let server_one = tokio::spawn(run_scripted_server(listener, identity.acceptor, script_one));
    let outcome_one = reconcile(&adapter, &one_permission_envelope())
        .await
        .unwrap();
    server_one.await.expect("first scripted server completed");
    assert_eq!(outcome_one, ReconciliationOutcome::Changed);

    // Second run: the added assignment is now the canonical current state.
    let listener_two = bind_loopback_listener().await;
    let port_two = listener_two.local_addr().unwrap().port();
    let identity_two = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter_two = adapter_for(port_two, identity_two.trust_anchor_pem.clone());
    let script_two = vec![
        ok(r#"{"session_token": "sess-2"}"#),
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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        ok(&search_body(1, &[(20, "Technician", "2")])),
        ok(&search_body(1, &[(55, "jdoe", "2")])),
        ok(&profile_user_search_body(1, &[(200, "jdoe")])),
        ok(&profile_user_item_body(200, 55, 20, 10, 1)),
        ok("true"),
    ];
    let server_two = tokio::spawn(run_scripted_server(
        listener_two,
        identity_two.acceptor,
        script_two,
    ));
    let outcome_two = reconcile(&adapter_two, &one_permission_envelope())
        .await
        .unwrap();
    server_two.await.expect("second scripted server completed");
    assert_eq!(outcome_two, ReconciliationOutcome::Unchanged);
}

/// Two desired pairs, both missing: stale-row deletion succeeds, the first
/// addition succeeds, and the second addition fails. Earlier successful
/// deletions/additions are never undone (the scripted server's fixed,
/// exhausted-exactly-once script itself proves no compensating request and
/// no retry occur).
#[tokio::test]
async fn add_phase_partial_failure_after_removal_and_first_addition_makes_no_compensating_request()
{
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let envelope = envelope_json(
        r#"{"permissions": [
            {"entity": "Root Entity > IT", "profile": "Technician", "recursive": true},
            {"entity": "Root Entity > IT > Operations", "profile": "Read-Only", "recursive": false}
        ]}"#,
    );

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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        ok(&search_body(1, &[(20, "Technician", "2")])),
        ok(&search_body(
            1,
            &[(11, "Root Entity > IT > Operations", "2")],
        )),
        ok(&search_body(1, &[(21, "Read-Only", "2")])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        ok(&profile_user_search_body(1, &[(99, "jdoe")])),
        // A stale row for an undesired pair.
        ok(&profile_user_item_body(99, 30, 99, 99, 0)),
        deleted(99),                                      // removal succeeds
        created(r#"{"id":100,"message":"created"}"#),     // first addition (10,20) succeeds
        json_response("500 Internal Server Error", "{}"), // second addition (11,21) fails
        ok("true"),                                       // killSession still attempted
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &envelope).await;
    server
        .await
        .expect("scripted server completed exactly its script, proving no retry or rollback");

    assert!(outcome.is_err());
}

/// After the add-phase partial failure above, a later reconciliation reads
/// real partial state (the stale row gone, the first addition present, the
/// second addition still missing) and converges; a second identical
/// reconciliation after that is `Unchanged`.
#[tokio::test]
async fn reconciliation_after_add_phase_partial_failure_converges_then_becomes_unchanged() {
    let listener = bind_loopback_listener().await;
    let port = listener.local_addr().unwrap().port();
    let identity = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter = adapter_for(port, identity.trust_anchor_pem.clone());
    let envelope = envelope_json(
        r#"{"permissions": [
            {"entity": "Root Entity > IT", "profile": "Technician", "recursive": true},
            {"entity": "Root Entity > IT > Operations", "profile": "Read-Only", "recursive": false}
        ]}"#,
    );

    // First run: only the surviving (10,20) addition is present; (11,21)
    // must still be added.
    let script_one = vec![
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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        ok(&search_body(1, &[(20, "Technician", "2")])),
        ok(&search_body(
            1,
            &[(11, "Root Entity > IT > Operations", "2")],
        )),
        ok(&search_body(1, &[(21, "Read-Only", "2")])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        ok(&profile_user_search_body(1, &[(100, "jdoe")])),
        ok(&profile_user_item_body(100, 30, 20, 10, 1)),
        created(r#"{"id":101,"message":"created"}"#), // add missing (11,21)
        ok("true"),
    ];
    let server_one = tokio::spawn(run_scripted_server(listener, identity.acceptor, script_one));
    let outcome_one = reconcile(&adapter, &envelope).await.unwrap();
    server_one.await.expect("first scripted server completed");
    assert_eq!(outcome_one, ReconciliationOutcome::Changed);

    // Second run: both pairs are now canonical; converges to Unchanged.
    let listener_two = bind_loopback_listener().await;
    let port_two = listener_two.local_addr().unwrap().port();
    let identity_two = build_test_identity(LOOPBACK_ADDRESS, ROOT_KEY_LABEL, LEAF_KEY_LABEL);
    let adapter_two = adapter_for(port_two, identity_two.trust_anchor_pem.clone());
    let script_two = vec![
        ok(r#"{"session_token": "sess-2"}"#),
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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        ok(&search_body(1, &[(20, "Technician", "2")])),
        ok(&search_body(
            1,
            &[(11, "Root Entity > IT > Operations", "2")],
        )),
        ok(&search_body(1, &[(21, "Read-Only", "2")])),
        ok(&search_body(1, &[(30, "jdoe", "2")])),
        ok(&profile_user_search_body(
            2,
            &[(100, "jdoe"), (101, "jdoe")],
        )),
        ok(&profile_user_item_body(100, 30, 20, 10, 1)),
        ok(&profile_user_item_body(101, 30, 21, 11, 0)),
        ok("true"),
    ];
    let server_two = tokio::spawn(run_scripted_server(
        listener_two,
        identity_two.acceptor,
        script_two,
    ));
    let outcome_two = reconcile(&adapter_two, &envelope).await.unwrap();
    server_two.await.expect("second scripted server completed");
    assert_eq!(outcome_two, ReconciliationOutcome::Unchanged);
}

/// A GLPI-created/default `Profile_User` row that appears immediately after
/// missing-user creation (representing GLPI's own rule- or default-driven
/// assignment) is deleted as part of normal authoritative reconciliation,
/// proving user creation never lets the adapter assume an empty assignment
/// set.
#[tokio::test]
async fn glpi_default_assignment_after_user_creation_is_cleaned_up() {
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
            ("2", "User.name"),
        ])),
        ok(&search_body(1, &[(10, "Root Entity > IT", "2")])),
        ok(&search_body(1, &[(20, "Technician", "2")])),
        ok(&search_body(0, &[])),                    // search User: absent
        created(r#"{"id":55,"message":"created"}"#), // POST User
        ok(&profile_user_search_body(1, &[(200, "jdoe")])), // GLPI created a default row
        ok(&profile_user_item_body(200, 55, 99, 99, 0)), // an undesired pair
        deleted(200),                                // the undesired default row is removed
        created(r#"{"id":201,"message":"created"}"#), // the desired assignment is added
        ok("true"),                                  // killSession
    ];

    let server = tokio::spawn(run_scripted_server(listener, identity.acceptor, script));
    let outcome = reconcile(&adapter, &one_permission_envelope())
        .await
        .unwrap();
    server.await.expect("scripted server completed its script");

    assert_eq!(outcome, ReconciliationOutcome::Changed);
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
