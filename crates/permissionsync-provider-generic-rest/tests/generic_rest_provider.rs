//! Hermetic behavioral tests for the Generic REST Permission Provider.
//!
//! These tests exercise only the crate's public API together with a local
//! loopback TLS server and fully deterministic in-memory Ed25519 certificates.
//! Test keys are derived at runtime from fixed public labels via SHA-256
//! (never generated randomly, and never stored as raw private-key bytes in
//! source), and certificate validity uses a fixed absolute timestamp window
//! (never the wall clock). They never use the public Internet, committed key
//! material, arbitrary sleeps, or unseeded randomness, in line with [ADR
//! 0008](../../../docs/adr/0008-generic-rest-permission-provider-wire-and-transport-contract.md)
//! and the repository testing policy.

use std::{
    error::Error,
    future::Future,
    io::ErrorKind,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
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
use permissionsync_core::{
    CancellationSignal, IdentityContext, LogicalTarget, PermissionProvider,
    PermissionProviderRequest, SynchronizationContext, TechnicalCallerBearerToken,
};
use permissionsync_provider_generic_rest::{
    GenericRestPermissionProvider, GenericRestPermissionProviderConfig,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::Instant as TokioInstant,
};
use tokio_native_tls::TlsAcceptor;

const LOOPBACK_ADDRESS: &str = "127.0.0.1";

/// Fixed, non-secret public labels used to deterministically derive
/// ephemeral Ed25519 test keys at runtime via SHA-256 (see
/// [`ed25519_key_from_label`]). A label is not key material: it is hashed
/// with a mature, existing hash implementation to produce the 32-byte
/// Ed25519 raw private-key seed for that identity. The same label always
/// yields the same key, and distinct labels yield independent keys, which is
/// what the untrusted-root test below relies on. No private-key bytes are
/// ever written to source, and no RNG is used anywhere in this file.
const PRIMARY_ROOT_KEY_LABEL: &str = "permissionsync-test-primary-root-v1";
const PRIMARY_LEAF_KEY_LABEL: &str = "permissionsync-test-primary-leaf-v1";
const ALTERNATE_ROOT_KEY_LABEL: &str = "permissionsync-test-alternate-root-v1";
const ALTERNATE_LEAF_KEY_LABEL: &str = "permissionsync-test-alternate-leaf-v1";

const ROOT_CERTIFICATE_SERIAL: u32 = 1;
const LEAF_CERTIFICATE_SERIAL: u32 = 2;

/// Fixed absolute certificate validity window shared by every test fixture.
/// Both bounds are fixed Unix timestamps, never derived from the wall clock:
/// a broad multi-decade window chosen only to comfortably cover any test
/// run, not a claim that the fixture is perpetually valid.
const CERTIFICATE_NOT_BEFORE_UNIX_SECONDS: i64 = 1_700_000_000; // 2023-11-14T22:13:20Z
const CERTIFICATE_NOT_AFTER_UNIX_SECONDS: i64 = 4_100_000_000; // 2099-11-16T09:46:40Z

// --- Configuration validation -----------------------------------------------

#[test]
fn rejects_non_https_endpoint() {
    let error = GenericRestPermissionProvider::new(test_config("http://127.0.0.1/permissions"));

    assert!(error.is_err());
}

#[test]
fn rejects_endpoint_without_authority_or_host() {
    for endpoint in ["https:///permissions", "https://", "not-a-uri"] {
        assert!(
            GenericRestPermissionProvider::new(test_config(endpoint)).is_err(),
            "{endpoint}"
        );
    }
}

#[test]
fn rejects_endpoint_with_userinfo_query_fragment_or_template() {
    for endpoint in [
        "https://user:pass@127.0.0.1/permissions",
        "https://127.0.0.1/permissions?x=1",
        "https://127.0.0.1/permissions#frag",
        "https://127.0.0.1/{id}",
    ] {
        assert!(
            GenericRestPermissionProvider::new(test_config(endpoint)).is_err(),
            "{endpoint}"
        );
    }
}

#[test]
fn rejects_zero_operation_timeout() {
    let mut config = test_config("https://127.0.0.1/permissions");
    config.operation_timeout = Duration::ZERO;

    assert!(GenericRestPermissionProvider::new(config).is_err());
}

#[test]
fn rejects_malformed_trust_anchor_bytes() {
    let mut config = test_config("https://127.0.0.1/permissions");
    config.additional_trust_anchors_der = vec![vec![0, 1, 2, 3]];

    assert!(GenericRestPermissionProvider::new(config).is_err());
}

// --- Runtime, cancellation, and deadline short-circuits ---------------------

#[test]
fn fails_safely_without_an_active_tokio_runtime() {
    let provider = GenericRestPermissionProvider::new(test_config("https://127.0.0.1/permissions"))
        .expect("valid configuration");
    let identity = IdentityContext::new("jdoe".to_owned(), vec![]);
    let target = LogicalTarget::try_from("example".to_owned()).expect("valid target");
    let token = TechnicalCallerBearerToken::new("token".to_owned());
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(far_future_deadline(), &cancellation);
    let request = PermissionProviderRequest::new(&identity, &target, &token, context);

    let outcome = poll_once(provider.resolve(request));

    assert!(outcome.is_err());
}

#[tokio::test]
async fn fails_immediately_when_cancellation_is_already_requested() {
    let listener = bind_loopback_listener().await;
    let port = local_port(&listener);
    let provider = GenericRestPermissionProvider::new(test_config(&format!(
        "https://{LOOPBACK_ADDRESS}:{port}/permissions"
    )))
    .expect("valid configuration");
    let identity = IdentityContext::new("jdoe".to_owned(), vec![]);
    let target = LogicalTarget::try_from("example".to_owned()).expect("valid target");
    let token = TechnicalCallerBearerToken::new("token".to_owned());
    let cancellation = AlwaysCancelled;
    let context = SynchronizationContext::new(far_future_deadline(), &cancellation);
    let request = PermissionProviderRequest::new(&identity, &target, &token, context);

    let outcome = provider.resolve(request).await;

    assert!(outcome.is_err());
    assert_listener_received_no_connection(&listener);
}

#[tokio::test]
async fn fails_immediately_when_the_context_deadline_has_already_passed() {
    let listener = bind_loopback_listener().await;
    let port = local_port(&listener);
    let provider = GenericRestPermissionProvider::new(test_config(&format!(
        "https://{LOOPBACK_ADDRESS}:{port}/permissions"
    )))
    .expect("valid configuration");
    let identity = IdentityContext::new("jdoe".to_owned(), vec![]);
    let target = LogicalTarget::try_from("example".to_owned()).expect("valid target");
    let token = TechnicalCallerBearerToken::new("token".to_owned());
    let cancellation = NeverCancelled;
    let expired_deadline = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("test process uptime exceeds one second");
    let context = SynchronizationContext::new(expired_deadline, &cancellation);
    let request = PermissionProviderRequest::new(&identity, &target, &token, context);

    let outcome = provider.resolve(request).await;

    assert!(outcome.is_err());
    assert_listener_received_no_connection(&listener);
}

#[tokio::test]
async fn fails_before_any_i_o_for_an_invalid_bearer_token() {
    let listener = bind_loopback_listener().await;
    let port = local_port(&listener);
    let provider = GenericRestPermissionProvider::new(test_config(&format!(
        "https://{LOOPBACK_ADDRESS}:{port}/permissions"
    )))
    .expect("valid configuration");
    let identity = IdentityContext::new("jdoe".to_owned(), vec![]);
    let target = LogicalTarget::try_from("example".to_owned()).expect("valid target");
    let token = TechnicalCallerBearerToken::new("invalid\r\nbearer".to_owned());
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(far_future_deadline(), &cancellation);
    let request = PermissionProviderRequest::new(&identity, &target, &token, context);

    let outcome = provider.resolve(request).await;

    assert!(outcome.is_err());
    assert_listener_received_no_connection(&listener);
}

#[tokio::test(start_paused = true)]
async fn fails_when_the_provider_operation_timeout_elapses() {
    let listener = bind_loopback_listener().await;
    let port = local_port(&listener);
    let identity = build_primary_test_identity(LOOPBACK_ADDRESS);
    let acceptor = TlsAcceptor::from(identity.acceptor);

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept connection");
        let mut stream = acceptor.accept(socket).await.expect("tls handshake");
        let _ = read_request(&mut stream).await;
        // Sleep far longer than the configured operation timeout before
        // responding, simulating an unresponsive Provider.
        tokio::time::sleep(Duration::from_secs(60)).await;
        let _ = stream
            .write_all(&ok_response(br#"{"version":1,"payload":null}"#))
            .await;
    });

    let mut config = test_config(&format!("https://{LOOPBACK_ADDRESS}:{port}/permissions"));
    config.operation_timeout = Duration::from_millis(50);
    config.additional_trust_anchors_der = vec![identity.trust_anchor_der];
    let provider = GenericRestPermissionProvider::new(config).expect("valid configuration");

    let identity_context = IdentityContext::new("jdoe".to_owned(), vec![]);
    let target = LogicalTarget::try_from("example".to_owned()).expect("valid target");
    let token = TechnicalCallerBearerToken::new("token".to_owned());
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(far_future_deadline(), &cancellation);
    let request = PermissionProviderRequest::new(&identity_context, &target, &token, context);

    let outcome = provider.resolve(request).await;

    assert!(outcome.is_err());
    server.abort();
}

#[tokio::test(start_paused = true)]
async fn the_shorter_core_deadline_wins_over_a_longer_provider_timeout() {
    let listener = bind_loopback_listener().await;
    let port = local_port(&listener);
    let identity = build_primary_test_identity(LOOPBACK_ADDRESS);
    let acceptor = TlsAcceptor::from(identity.acceptor);

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept connection");
        let mut stream = acceptor.accept(socket).await.expect("tls handshake");
        let _ = read_request(&mut stream).await;
        // Never respond: the Provider must be bounded by the much shorter
        // Core deadline below, not by its own longer operation timeout.
        std::future::pending::<()>().await
    });

    let mut config = test_config(&format!("https://{LOOPBACK_ADDRESS}:{port}/permissions"));
    // Deliberately much longer than the Core deadline used below, so that
    // observing a fast failure proves the Core deadline, not this timeout,
    // bounded the operation.
    config.operation_timeout = Duration::from_secs(60);
    config.additional_trust_anchors_der = vec![identity.trust_anchor_der];
    let provider = GenericRestPermissionProvider::new(config).expect("valid configuration");

    let identity_context = IdentityContext::new("jdoe".to_owned(), vec![]);
    let target = LogicalTarget::try_from("example".to_owned()).expect("valid target");
    let token = TechnicalCallerBearerToken::new("token".to_owned());
    let cancellation = NeverCancelled;
    let core_deadline = Instant::now() + Duration::from_millis(50);
    let context = SynchronizationContext::new(core_deadline, &cancellation);
    let request = PermissionProviderRequest::new(&identity_context, &target, &token, context);

    let started = TokioInstant::now();
    let outcome = provider.resolve(request).await;
    let elapsed = started.elapsed();

    assert!(outcome.is_err());
    // Comfortably between the 50ms Core deadline and the 60s Provider
    // timeout: only a bug that ignored the Core deadline could take this
    // long under the paused, auto-advancing virtual clock.
    assert!(
        elapsed < Duration::from_secs(5),
        "resolve() waited {elapsed:?}, longer than the configured Core deadline allows"
    );

    server.abort();
}

#[tokio::test]
async fn cancellation_after_the_request_is_sent_is_observed_before_reading_the_response() {
    let listener = bind_loopback_listener().await;
    let port = local_port(&listener);
    let identity = build_primary_test_identity(LOOPBACK_ADDRESS);
    let trust_anchor = identity.trust_anchor_der.clone();
    let acceptor = TlsAcceptor::from(identity.acceptor);

    let (request_received_tx, request_received_rx) = tokio::sync::oneshot::channel::<()>();
    let (proceed_tx, proceed_rx) = tokio::sync::oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept connection");
        let mut stream = acceptor.accept(socket).await.expect("tls handshake");
        let _ = read_request(&mut stream).await;

        request_received_tx
            .send(())
            .expect("test still waiting for the request-received signal");
        proceed_rx.await.expect("test still coordinating");

        let response = ok_response(br#"{"version":1,"payload":null}"#);
        let _ = stream.write_all(&response).await;
        let _ = stream.shutdown().await;
    });

    let mut config = test_config(&format!("https://{LOOPBACK_ADDRESS}:{port}/permissions"));
    config.additional_trust_anchors_der = vec![trust_anchor];
    let provider = GenericRestPermissionProvider::new(config).expect("valid configuration");

    let identity_context = IdentityContext::new("jdoe".to_owned(), vec![]);
    let target = LogicalTarget::try_from("example".to_owned()).expect("valid target");
    let token = TechnicalCallerBearerToken::new("token".to_owned());
    let cancellation = FlippableCancellation::new();
    let context = SynchronizationContext::new(far_future_deadline(), &cancellation);
    let request = PermissionProviderRequest::new(&identity_context, &target, &token, context);

    // The Core `CancellationSignal` contract has no wake mechanism, so
    // cancellation is only ever observed at a controlled boundary. This
    // coordinator flips the flag only after confirming the request was
    // already sent, then lets the server respond so the client reaches its
    // next check_context boundary (immediately after receiving the response,
    // before the status is even inspected) with cancellation already set.
    let coordinator = async {
        request_received_rx
            .await
            .expect("server confirmed the request was received");
        cancellation.cancel();
        proceed_tx
            .send(())
            .expect("server still waiting to proceed");
    };

    let (outcome, ()) = tokio::join!(provider.resolve(request), coordinator);

    assert!(outcome.is_err());
    server.await.expect("server task completed");
}

// --- Public error redaction ---------------------------------------------------

#[tokio::test]
async fn public_provider_error_redacts_sensitive_values() {
    let provider =
        GenericRestPermissionProvider::new(test_config("https://127.0.0.1/sentinel-endpoint-path"))
            .expect("valid configuration");
    let identity = IdentityContext::new(
        "sentinel-fake-username".to_owned(),
        vec!["sentinel-fake-group".to_owned()],
    );
    let target = LogicalTarget::try_from("example".to_owned()).expect("valid target");
    // A bearer value containing a raw CR/LF cannot become a valid header
    // value, so this fails before any network I/O while still exercising the
    // exact public error path returned from `resolve()`.
    let token = TechnicalCallerBearerToken::new("sentinel-fake-bearer\r\ntoken".to_owned());
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(far_future_deadline(), &cancellation);
    let request = PermissionProviderRequest::new(&identity, &target, &token, context);

    let error = match provider.resolve(request).await {
        Ok(_) => panic!("expected an invalid bearer header value to fail"),
        Err(error) => error,
    };

    let debug_output = format!("{error:?}");
    let display_output = error.to_string();
    let source_output = error.source().map(ToString::to_string);

    for sensitive in [
        "sentinel-fake-username",
        "sentinel-fake-group",
        "sentinel-fake-bearer",
        "sentinel-endpoint-path",
    ] {
        assert!(!debug_output.contains(sensitive), "{debug_output}");
        assert!(!display_output.contains(sensitive), "{display_output}");
        if let Some(source_text) = &source_output {
            assert!(!source_text.contains(sensitive), "{source_text}");
        }
    }
}

// --- TLS trust and hostname validation ---------------------------------------

#[tokio::test]
async fn accepts_a_server_certificate_signed_by_a_configured_trust_anchor() {
    let listener = bind_loopback_listener().await;
    let port = local_port(&listener);
    let identity = build_primary_test_identity(LOOPBACK_ADDRESS);
    let acceptor = TlsAcceptor::from(identity.acceptor);

    let response = ok_response(br#"{"version":7,"payload":{"role":"operator"}}"#);
    let server = tokio::spawn(serve_one_request(listener, acceptor, response));

    let mut config = test_config(&format!("https://{LOOPBACK_ADDRESS}:{port}"));
    config.additional_trust_anchors_der = vec![identity.trust_anchor_der];
    let provider = GenericRestPermissionProvider::new(config).expect("valid configuration");

    let identity_context = IdentityContext::new(
        "jdoe".to_owned(),
        vec!["/staff".to_owned(), "/staff".to_owned()],
    );
    let target = LogicalTarget::try_from("example".to_owned()).expect("valid target");
    let token = TechnicalCallerBearerToken::new("secret-token".to_owned());
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(far_future_deadline(), &cancellation);
    let request = PermissionProviderRequest::new(&identity_context, &target, &token, context);

    let envelope = provider
        .resolve(request)
        .await
        .expect("successful resolution");

    assert_eq!(envelope.version().get(), 7);
    assert_eq!(envelope.payload().as_json(), r#"{"role":"operator"}"#);

    let received = server.await.expect("server task completed");
    assert_eq!(received.request_line, "POST / HTTP/1.1");
    assert_eq!(
        received.header("authorization"),
        Some("Bearer secret-token")
    );
    assert_eq!(received.header("content-type"), Some("application/json"));
    assert_eq!(received.header("accept"), Some("application/json"));
    assert_eq!(received.header("accept-encoding"), Some(""));
    assert_eq!(
        received.body,
        br#"{"username":"jdoe","groups":["/staff","/staff"]}"#
    );
}

#[tokio::test]
async fn rejects_a_server_certificate_signed_by_an_untrusted_root() {
    let listener = bind_loopback_listener().await;
    let port = local_port(&listener);
    let untrusted_identity = build_test_identity(
        LOOPBACK_ADDRESS,
        PRIMARY_ROOT_KEY_LABEL,
        PRIMARY_LEAF_KEY_LABEL,
    );
    // A distinct, unrelated deterministic root: the server's certificate
    // chain must not validate against it.
    let unrelated_trust_anchor = build_test_identity(
        LOOPBACK_ADDRESS,
        ALTERNATE_ROOT_KEY_LABEL,
        ALTERNATE_LEAF_KEY_LABEL,
    )
    .trust_anchor_der;
    let acceptor = TlsAcceptor::from(untrusted_identity.acceptor);

    let server = tokio::spawn(accept_ignoring_handshake_errors(listener, acceptor));

    let mut config = test_config(&format!("https://{LOOPBACK_ADDRESS}:{port}/permissions"));
    config.additional_trust_anchors_der = vec![unrelated_trust_anchor];
    let provider = GenericRestPermissionProvider::new(config).expect("valid configuration");

    let outcome = resolve_with_defaults(&provider).await;

    assert!(outcome.is_err());
    server.await.expect("server task completed");
}

#[tokio::test]
async fn rejects_a_server_certificate_with_a_mismatched_host() {
    let listener = bind_loopback_listener().await;
    let port = local_port(&listener);
    let identity = build_primary_test_identity("192.0.2.1");
    let trust_anchor = identity.trust_anchor_der.clone();
    let acceptor = TlsAcceptor::from(identity.acceptor);

    let server = tokio::spawn(accept_ignoring_handshake_errors(listener, acceptor));

    let mut config = test_config(&format!("https://{LOOPBACK_ADDRESS}:{port}/permissions"));
    config.additional_trust_anchors_der = vec![trust_anchor];
    let provider = GenericRestPermissionProvider::new(config).expect("valid configuration");

    let outcome = resolve_with_defaults(&provider).await;

    assert!(outcome.is_err());
    server.await.expect("server task completed");
}

// --- Single-attempt delivery -------------------------------------------------

#[tokio::test]
async fn one_resolve_call_makes_at_most_one_outbound_connection_attempt() {
    let listener = bind_loopback_listener().await;
    let port = local_port(&listener);
    let identity = build_primary_test_identity(LOOPBACK_ADDRESS);
    let trust_anchor = identity.trust_anchor_der.clone();
    let acceptor = TlsAcceptor::from(identity.acceptor);
    let response = ok_response(br#"{"version":1,"payload":null}"#);

    let accepted_connections = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted_connections);
    // Keeps accepting so that a defective client making a second connection
    // attempt would be observed here rather than merely hanging; the
    // assertion below is what actually proves at most one attempt occurred.
    let server = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut stream) = acceptor.accept(socket).await {
                let _ = read_request(&mut stream).await;
                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
            }
        }
    });

    let mut config = test_config(&format!("https://{LOOPBACK_ADDRESS}:{port}/permissions"));
    config.additional_trust_anchors_der = vec![trust_anchor];
    let provider = GenericRestPermissionProvider::new(config).expect("valid configuration");

    let outcome = resolve_with_defaults(&provider).await;

    assert!(outcome.is_ok());
    assert_eq!(accepted_connections.load(Ordering::SeqCst), 1);

    server.abort();
}

#[tokio::test]
async fn a_failed_exchange_produces_no_retry_or_second_connection_attempt() {
    let listener = bind_loopback_listener().await;
    let port = local_port(&listener);
    let identity = build_primary_test_identity(LOOPBACK_ADDRESS);
    let trust_anchor = identity.trust_anchor_der.clone();
    let acceptor = TlsAcceptor::from(identity.acceptor);

    let accepted_connections = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted_connections);
    // Keeps accepting indefinitely so that a defective client's second
    // connection attempt would be observed here; the assertion below is what
    // actually proves at most one attempt occurred, deterministically, with
    // no timing guesses.
    let server = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut stream) = acceptor.accept(socket).await {
                let _ = read_request(&mut stream).await;
                // Terminate the exchange without ever sending a response,
                // simulating a Provider that accepts the request but fails
                // before producing any output.
                let _ = stream.shutdown().await;
            }
        }
    });

    let mut config = test_config(&format!("https://{LOOPBACK_ADDRESS}:{port}/permissions"));
    config.additional_trust_anchors_der = vec![trust_anchor];
    let provider = GenericRestPermissionProvider::new(config).expect("valid configuration");

    let outcome = resolve_with_defaults(&provider).await;

    assert!(outcome.is_err());
    assert_eq!(accepted_connections.load(Ordering::SeqCst), 1);

    server.abort();
}

// --- Connection lifecycle -----------------------------------------------------

#[tokio::test]
async fn resolves_successfully_without_waiting_for_the_server_to_close_the_connection() {
    let listener = bind_loopback_listener().await;
    let port = local_port(&listener);
    let identity = build_primary_test_identity(LOOPBACK_ADDRESS);
    let trust_anchor = identity.trust_anchor_der.clone();
    let acceptor = TlsAcceptor::from(identity.acceptor);

    let (client_done_tx, client_done_rx) = tokio::sync::oneshot::channel::<()>();
    let (eof_observed_tx, eof_observed_rx) = tokio::sync::oneshot::channel::<bool>();

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept connection");
        let mut stream = acceptor.accept(socket).await.expect("tls handshake");
        let _ = read_request(&mut stream).await;

        // No `Connection: close`, and a correct, finite `Content-Length`:
        // the socket stays open after a complete response.
        let response = build_keep_alive_response(br#"{"version":1,"payload":null}"#);
        stream.write_all(&response).await.expect("write response");

        // Wait until the client's resolve() call has already returned
        // before checking for a closed connection: this proves resolve()
        // did not need the close to complete, and that the client actually
        // dropped its own connection afterward rather than leaving a
        // detached driver alive.
        client_done_rx.await.expect("client completion signal");

        let mut probe = [0_u8; 1];
        let read = stream.read(&mut probe).await.unwrap_or(0);
        let _ = eof_observed_tx.send(read == 0);
    });

    let mut config = test_config(&format!("https://{LOOPBACK_ADDRESS}:{port}/permissions"));
    config.additional_trust_anchors_der = vec![trust_anchor];
    let provider = GenericRestPermissionProvider::new(config).expect("valid configuration");

    let envelope = resolve_with_defaults(&provider)
        .await
        .expect("successful resolution without waiting for a connection close");
    assert_eq!(envelope.version().get(), 1);

    client_done_tx
        .send(())
        .expect("server still waiting for the completion signal");

    // This watchdog bounds only the test's post-resolution EOF observation;
    // it is deliberately generous and is not an operation-latency assertion.
    let observed_eof = tokio::time::timeout(Duration::from_secs(5), eof_observed_rx)
        .await
        .expect("server did not report its eof observation before the test watchdog elapsed")
        .expect("server reported its eof observation");
    assert!(
        observed_eof,
        "server did not observe the client closing its connection after resolve() returned"
    );

    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server did not complete before the test watchdog elapsed")
        .expect("server task completed");
}

// --- Response validation ------------------------------------------------------

#[tokio::test]
async fn rejects_every_non_200_status_including_redirects() {
    for (status, reason) in [(404, "Not Found"), (302, "Found"), (201, "Created")] {
        let listener = bind_loopback_listener().await;
        let port = local_port(&listener);
        let identity = build_primary_test_identity(LOOPBACK_ADDRESS);
        let trust_anchor = identity.trust_anchor_der.clone();
        let acceptor = TlsAcceptor::from(identity.acceptor);

        let response = build_response(status, reason, "application/json", &[], b"{}");
        let server = tokio::spawn(serve_one_request(listener, acceptor, response));

        let mut config = test_config(&format!("https://{LOOPBACK_ADDRESS}:{port}/permissions"));
        config.additional_trust_anchors_der = vec![trust_anchor];
        let provider = GenericRestPermissionProvider::new(config).expect("valid configuration");

        let outcome = resolve_with_defaults(&provider).await;

        assert!(outcome.is_err(), "status {status}");
        server.await.expect("server task completed");
    }
}

#[tokio::test]
async fn rejects_provider_204_no_content_as_a_failure() {
    let listener = bind_loopback_listener().await;
    let port = local_port(&listener);
    let identity = build_primary_test_identity(LOOPBACK_ADDRESS);
    let trust_anchor = identity.trust_anchor_der.clone();
    let acceptor = TlsAcceptor::from(identity.acceptor);

    // A remote Provider `204` must never become a successful resolution:
    // PermissionSync's own `204` targetless no-op outcome is a Core/inbound
    // concept, unrelated to and never derived from a Provider status.
    let response = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_vec();
    let server = tokio::spawn(serve_one_request(listener, acceptor, response));

    let mut config = test_config(&format!("https://{LOOPBACK_ADDRESS}:{port}/permissions"));
    config.additional_trust_anchors_der = vec![trust_anchor];
    let provider = GenericRestPermissionProvider::new(config).expect("valid configuration");

    let outcome = resolve_with_defaults(&provider).await;

    assert!(outcome.is_err());
    server.await.expect("server task completed");
}

#[tokio::test]
async fn rejects_a_non_json_content_type() {
    let listener = bind_loopback_listener().await;
    let port = local_port(&listener);
    let identity = build_primary_test_identity(LOOPBACK_ADDRESS);
    let trust_anchor = identity.trust_anchor_der.clone();
    let acceptor = TlsAcceptor::from(identity.acceptor);

    let response = build_response(200, "OK", "text/plain", &[], b"not json");
    let server = tokio::spawn(serve_one_request(listener, acceptor, response));

    let mut config = test_config(&format!("https://{LOOPBACK_ADDRESS}:{port}/permissions"));
    config.additional_trust_anchors_der = vec![trust_anchor];
    let provider = GenericRestPermissionProvider::new(config).expect("valid configuration");

    let outcome = resolve_with_defaults(&provider).await;

    assert!(outcome.is_err());
    server.await.expect("server task completed");
}

#[tokio::test]
async fn rejects_a_successful_json_response_with_invalid_utf8_body_bytes() {
    let listener = bind_loopback_listener().await;
    let port = local_port(&listener);
    let identity = build_primary_test_identity(LOOPBACK_ADDRESS);
    let trust_anchor = identity.trust_anchor_der.clone();
    let acceptor = TlsAcceptor::from(identity.acceptor);

    let response = ok_response(b"\xff");
    let server = tokio::spawn(serve_one_request(listener, acceptor, response));

    let mut config = test_config(&format!("https://{LOOPBACK_ADDRESS}:{port}/permissions"));
    config.additional_trust_anchors_der = vec![trust_anchor];
    let provider = GenericRestPermissionProvider::new(config).expect("valid configuration");

    let outcome = resolve_with_defaults(&provider).await;

    assert!(outcome.is_err());
    server.await.expect("server task completed");
}

#[tokio::test]
async fn rejects_a_coded_successful_response() {
    let listener = bind_loopback_listener().await;
    let port = local_port(&listener);
    let identity = build_primary_test_identity(LOOPBACK_ADDRESS);
    let trust_anchor = identity.trust_anchor_der.clone();
    let acceptor = TlsAcceptor::from(identity.acceptor);

    let response = build_response(
        200,
        "OK",
        "application/json",
        &[("Content-Encoding", "gzip")],
        b"\x1f\x8b\x00\x00",
    );
    let server = tokio::spawn(serve_one_request(listener, acceptor, response));

    let mut config = test_config(&format!("https://{LOOPBACK_ADDRESS}:{port}/permissions"));
    config.additional_trust_anchors_der = vec![trust_anchor];
    let provider = GenericRestPermissionProvider::new(config).expect("valid configuration");

    let outcome = resolve_with_defaults(&provider).await;

    assert!(outcome.is_err());
    server.await.expect("server task completed");
}

#[tokio::test]
async fn rejects_a_malformed_envelope() {
    for body in [
        &b"{\"payload\":null}"[..],
        &b"{\"version\":1}"[..],
        &b"{\"version\":1,\"payload\":null,\"unexpected\":true}"[..],
    ] {
        let listener = bind_loopback_listener().await;
        let port = local_port(&listener);
        let identity = build_primary_test_identity(LOOPBACK_ADDRESS);
        let trust_anchor = identity.trust_anchor_der.clone();
        let acceptor = TlsAcceptor::from(identity.acceptor);

        let response = ok_response(body);
        let server = tokio::spawn(serve_one_request(listener, acceptor, response));

        let mut config = test_config(&format!("https://{LOOPBACK_ADDRESS}:{port}/permissions"));
        config.additional_trust_anchors_der = vec![trust_anchor];
        let provider = GenericRestPermissionProvider::new(config).expect("valid configuration");

        let outcome = resolve_with_defaults(&provider).await;

        assert!(outcome.is_err());
        server.await.expect("server task completed");
    }
}

#[tokio::test]
async fn rejects_a_declared_content_length_above_the_response_body_limit() {
    let listener = bind_loopback_listener().await;
    let port = local_port(&listener);
    let identity = build_primary_test_identity(LOOPBACK_ADDRESS);
    let trust_anchor = identity.trust_anchor_der.clone();
    let acceptor = TlsAcceptor::from(identity.acceptor);

    // No body is ever sent: the client must fail from the declared
    // Content-Length alone, before attempting to buffer any bytes.
    let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 5000000\r\nConnection: close\r\n\r\n".to_vec();
    let server = tokio::spawn(serve_one_request(listener, acceptor, response));

    let mut config = test_config(&format!("https://{LOOPBACK_ADDRESS}:{port}/permissions"));
    config.additional_trust_anchors_der = vec![trust_anchor];
    let provider = GenericRestPermissionProvider::new(config).expect("valid configuration");

    let outcome = resolve_with_defaults(&provider).await;

    assert!(outcome.is_err());
    server.await.expect("server task completed");
}

#[tokio::test]
async fn rejects_a_streamed_body_that_exceeds_the_response_body_limit() {
    let listener = bind_loopback_listener().await;
    let port = local_port(&listener);
    let identity = build_primary_test_identity(LOOPBACK_ADDRESS);
    let trust_anchor = identity.trust_anchor_der.clone();
    let acceptor = TlsAcceptor::from(identity.acceptor);

    let response = oversized_chunked_response();
    let server = tokio::spawn(serve_one_request(listener, acceptor, response));

    let mut config = test_config(&format!("https://{LOOPBACK_ADDRESS}:{port}/permissions"));
    config.additional_trust_anchors_der = vec![trust_anchor];
    let provider = GenericRestPermissionProvider::new(config).expect("valid configuration");

    let outcome = resolve_with_defaults(&provider).await;

    assert!(outcome.is_err());
    server.await.expect("server task completed");
}

#[tokio::test]
async fn a_non_200_response_body_and_www_authenticate_are_not_read_or_exposed() {
    let listener = bind_loopback_listener().await;
    let port = local_port(&listener);
    let identity = build_primary_test_identity(LOOPBACK_ADDRESS);
    let trust_anchor = identity.trust_anchor_der.clone();
    let acceptor = TlsAcceptor::from(identity.acceptor);
    let (headers_sent_tx, mut headers_sent_rx) = tokio::sync::oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept connection");
        let mut stream = acceptor.accept(socket).await.expect("tls handshake");
        let _ = read_request(&mut stream).await;

        // Advertise a body that is never actually sent, and keep the
        // connection open: if the Provider tried to read or drain it, it
        // would have to wait for bytes that never arrive.
        let response = b"HTTP/1.1 500 Internal Server Error\r\n\
Content-Type: text/plain\r\n\
Content-Length: 999999\r\n\
WWW-Authenticate: sentinel-www-authenticate-value\r\n\
X-Provider-Diagnostic: sentinel-provider-diagnostic-value\r\n\r\n";
        stream
            .write_all(response)
            .await
            .expect("write response headers");
        headers_sent_tx
            .send(())
            .expect("test still waiting for the headers-sent signal");

        // Never send the body and never close: resolve() must return based on
        // the non-200 headers rather than waiting for body bytes or EOF.
        std::future::pending::<()>().await
    });

    let mut config = test_config(&format!("https://{LOOPBACK_ADDRESS}:{port}/permissions"));
    config.operation_timeout = Duration::from_secs(60);
    config.additional_trust_anchors_der = vec![trust_anchor];
    let provider = GenericRestPermissionProvider::new(config).expect("valid configuration");

    let resolve = resolve_with_defaults(&provider);
    tokio::pin!(resolve);

    // The watchdog starts only after the server has confirmed that headers are
    // written. A body read or EOF wait then fails this bounded test, while a
    // correct status-only failure may race the signal harmlessly.
    let outcome = tokio::select! {
        headers_sent = &mut headers_sent_rx => {
            headers_sent.expect("server did not signal that response headers were sent");
            tokio::time::timeout(Duration::from_secs(5), &mut resolve)
                .await
                .expect("resolve() waited for a non-200 response body or EOF")
        }
        outcome = &mut resolve => {
            headers_sent_rx
                .await
                .expect("server did not signal that response headers were sent");
            outcome
        }
    };
    let error = match outcome {
        Ok(_) => panic!("expected a non-200 status to fail"),
        Err(error) => error,
    };

    let debug_output = format!("{error:?}");
    let display_output = error.to_string();
    let source_output = error.source().map(ToString::to_string);
    for sensitive in [
        "sentinel-www-authenticate-value",
        "sentinel-provider-diagnostic-value",
    ] {
        assert!(!debug_output.contains(sensitive), "{debug_output}");
        assert!(!display_output.contains(sensitive), "{display_output}");
        if let Some(source_text) = &source_output {
            assert!(!source_text.contains(sensitive), "{source_text}");
        }
    }

    server.abort();
}

// --- Request construction ------------------------------------------------------

#[tokio::test]
async fn uses_the_configured_path_and_host_header_with_an_explicit_port() {
    let listener = bind_loopback_listener().await;
    let port = local_port(&listener);
    let identity = build_primary_test_identity(LOOPBACK_ADDRESS);
    let trust_anchor = identity.trust_anchor_der.clone();
    let acceptor = TlsAcceptor::from(identity.acceptor);

    let response = ok_response(br#"{"version":1,"payload":null}"#);
    let server = tokio::spawn(serve_one_request(listener, acceptor, response));

    let path = "/some/nontrivial/path/with%20space";
    let mut config = test_config(&format!("https://{LOOPBACK_ADDRESS}:{port}{path}"));
    config.additional_trust_anchors_der = vec![trust_anchor];
    let provider = GenericRestPermissionProvider::new(config).expect("valid configuration");

    let outcome = resolve_with_defaults(&provider).await;
    assert!(outcome.is_ok());

    let received = server.await.expect("server task completed");
    assert_eq!(received.request_line, format!("POST {path} HTTP/1.1"));
    assert_eq!(
        received.header("host"),
        Some(format!("{LOOPBACK_ADDRESS}:{port}").as_str())
    );
}

// --- Test support -------------------------------------------------------------

fn test_config(endpoint: &str) -> GenericRestPermissionProviderConfig {
    GenericRestPermissionProviderConfig {
        endpoint: endpoint.to_owned(),
        operation_timeout: Duration::from_secs(5),
        additional_trust_anchors_der: Vec::new(),
    }
}

fn far_future_deadline() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

async fn resolve_with_defaults(
    provider: &GenericRestPermissionProvider,
) -> Result<permissionsync_core::DesiredStateEnvelope, permissionsync_core::PermissionProviderError>
{
    let identity = IdentityContext::new("jdoe".to_owned(), vec![]);
    let target = LogicalTarget::try_from("example".to_owned()).expect("valid target");
    let token = TechnicalCallerBearerToken::new("token".to_owned());
    let cancellation = NeverCancelled;
    let context = SynchronizationContext::new(far_future_deadline(), &cancellation);
    let request = PermissionProviderRequest::new(&identity, &target, &token, context);

    provider.resolve(request).await
}

struct NeverCancelled;

impl CancellationSignal for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

struct AlwaysCancelled;

impl CancellationSignal for AlwaysCancelled {
    fn is_cancelled(&self) -> bool {
        true
    }
}

/// A cancellation signal a test can flip from `false` to `true` at a chosen
/// point during an in-flight Provider operation, modeling the real Core
/// `CancellationSignal` contract: there is no wake mechanism, so a flipped
/// signal is only ever observed the next time cooperating code checks it.
struct FlippableCancellation(AtomicBool);

impl FlippableCancellation {
    fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl CancellationSignal for FlippableCancellation {
    fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

fn poll_once<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = Box::pin(future);

    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test future unexpectedly returned Poll::Pending"),
    }
}

async fn bind_loopback_listener() -> TcpListener {
    TcpListener::bind((LOOPBACK_ADDRESS, 0))
        .await
        .expect("bind ephemeral loopback listener")
}

fn local_port(listener: &TcpListener) -> u16 {
    listener
        .local_addr()
        .expect("listener local address")
        .port()
}

fn assert_listener_received_no_connection(listener: &TcpListener) {
    match listener.try_accept() {
        Err(error) => assert_eq!(error.kind(), ErrorKind::WouldBlock),
        Ok(_) => panic!("provider unexpectedly initiated an outbound connection"),
    }
}

/// Supplies a synchronous `try_accept` operation for Tokio 1.52's listener,
/// whose public API exposes only `poll_accept`. A pending poll is precisely the
/// nonblocking `WouldBlock` condition the short-circuit tests must assert.
trait TryAccept {
    fn try_accept(&self) -> std::io::Result<(tokio::net::TcpStream, std::net::SocketAddr)>;
}

impl TryAccept for TcpListener {
    fn try_accept(&self) -> std::io::Result<(tokio::net::TcpStream, std::net::SocketAddr)> {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);

        match self.poll_accept(&mut context) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(ErrorKind::WouldBlock.into()),
        }
    }
}

struct ReceivedRequest {
    request_line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl ReceivedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

async fn read_request<S>(stream: &mut S) -> ReceivedRequest
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let header_end = loop {
        let mut chunk = [0_u8; 512];
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
        let mut chunk = [0_u8; 512];
        let read = stream.read(&mut chunk).await.expect("read request body");
        assert!(read > 0, "connection closed before request body completed");
        body.extend_from_slice(&chunk[..read]);
    }

    ReceivedRequest {
        request_line,
        headers,
        body,
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

async fn serve_one_request(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    response: Vec<u8>,
) -> ReceivedRequest {
    let (socket, _) = listener.accept().await.expect("accept connection");
    let mut stream = acceptor.accept(socket).await.expect("tls handshake");
    let request = read_request(&mut stream).await;
    stream.write_all(&response).await.expect("write response");
    let _ = stream.shutdown().await;
    request
}

async fn accept_ignoring_handshake_errors(listener: TcpListener, acceptor: TlsAcceptor) {
    if let Ok((socket, _)) = listener.accept().await {
        let _ = acceptor.accept(socket).await;
    }
}

fn ok_response(body: &[u8]) -> Vec<u8> {
    build_response(200, "OK", "application/json", &[], body)
}

/// Builds a valid `200 application/json` response with a correct, finite
/// `Content-Length` and deliberately no `Connection: close`, so the socket
/// stays open after the complete response.
fn build_keep_alive_response(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn build_response(
    status: u16,
    reason: &str,
    content_type: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in extra_headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("Connection: close\r\n\r\n");

    let mut bytes = response.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn oversized_chunked_response() -> Vec<u8> {
    let mut response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();

    let chunk = vec![b'a'; 8192];
    // Comfortably above any plausible private response-body ceiling.
    let target_total = 3_000_000_usize;
    let mut sent = 0_usize;
    while sent < target_total {
        write_chunk(&mut response, &chunk);
        sent += chunk.len();
    }
    response.extend_from_slice(b"0\r\n\r\n");

    response
}

fn write_chunk(buffer: &mut Vec<u8>, data: &[u8]) {
    buffer.extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
    buffer.extend_from_slice(data);
    buffer.extend_from_slice(b"\r\n");
}

struct TestIdentity {
    trust_anchor_der: Vec<u8>,
    acceptor: native_tls::TlsAcceptor,
}

/// Builds a deterministic in-memory root-and-leaf TLS identity from the
/// given fixed public key-derivation labels. Calling this twice with the
/// same labels and `ip_address` produces byte-identical certificates;
/// calling it with different labels produces an entirely independent trust
/// chain, which the untrusted-root test relies on.
fn build_test_identity(ip_address: &str, root_label: &str, leaf_label: &str) -> TestIdentity {
    let (root_certificate, root_key) = build_root_certificate(root_label);
    let (leaf_certificate, leaf_key) = build_leaf_certificate(
        ip_address,
        root_certificate.subject_name(),
        &root_key,
        leaf_label,
    );

    let leaf_certificate_pem = leaf_certificate.to_pem().expect("leaf certificate pem");
    let leaf_key_pem = leaf_key
        .private_key_to_pem_pkcs8()
        .expect("leaf private key pkcs8 pem");

    let identity = native_tls::Identity::from_pkcs8(&leaf_certificate_pem, &leaf_key_pem)
        .expect("valid pkcs8 identity");
    let acceptor = native_tls::TlsAcceptor::builder(identity)
        .min_protocol_version(Some(native_tls::Protocol::Tlsv12))
        .build()
        .expect("build tls acceptor");

    TestIdentity {
        trust_anchor_der: root_certificate.to_der().expect("root certificate der"),
        acceptor,
    }
}

/// Builds a deterministic test identity from the shared primary fixed labels.
fn build_primary_test_identity(ip_address: &str) -> TestIdentity {
    build_test_identity(ip_address, PRIMARY_ROOT_KEY_LABEL, PRIMARY_LEAF_KEY_LABEL)
}

/// Deterministically derives an Ed25519 private key from a fixed public
/// label via SHA-256, using OpenSSL's existing, mature hash implementation
/// rather than any bespoke cryptography or committed key bytes.
///
/// No randomness is used: SHA-256 is a deterministic function of its input,
/// so the same label always yields the same 32-byte Ed25519 raw private-key
/// seed, and thus the same key. The label itself carries no cryptographic
/// value; it is not key material.
fn ed25519_key_from_label(label: &str) -> PKey<Private> {
    let digest = hash(MessageDigest::sha256(), label.as_bytes()).expect("sha-256 digest");
    let seed: [u8; 32] = digest
        .as_ref()
        .try_into()
        .expect("sha-256 digest is exactly 32 bytes");

    PKey::private_key_from_raw_bytes(&seed, Id::ED25519).expect("valid ed25519 seed bytes")
}

fn build_name(common_name: &str) -> X509Name {
    let mut builder = openssl::x509::X509NameBuilder::new().expect("x509 name builder");
    builder
        .append_entry_by_nid(Nid::COMMONNAME, common_name)
        .expect("append common name");
    builder.build()
}

/// Builds a certificate with a fixed serial number and a fixed absolute
/// validity window. Nothing here reads the wall clock or any random source.
fn new_certificate_builder(
    subject_name: &X509NameRef,
    issuer_name: &X509NameRef,
    public_key: &PKeyRef<Private>,
    serial_number: u32,
) -> openssl::x509::X509Builder {
    let mut builder = X509::builder().expect("x509 builder");
    builder.set_version(2).expect("x509 version");
    builder
        .set_subject_name(subject_name)
        .expect("set subject name");
    builder
        .set_issuer_name(issuer_name)
        .expect("set issuer name");
    builder.set_pubkey(public_key).expect("set public key");

    let serial = BigNum::from_u32(serial_number).expect("fixed serial bignum");
    builder
        .set_serial_number(&serial.to_asn1_integer().expect("serial asn1 integer"))
        .expect("set serial number");

    builder
        .set_not_before(
            &Asn1Time::from_unix(CERTIFICATE_NOT_BEFORE_UNIX_SECONDS).expect("fixed not before"),
        )
        .expect("set not before");
    builder
        .set_not_after(
            &Asn1Time::from_unix(CERTIFICATE_NOT_AFTER_UNIX_SECONDS).expect("fixed not after"),
        )
        .expect("set not after");

    builder
}

fn build_root_certificate(label: &str) -> (X509, PKey<Private>) {
    let key = ed25519_key_from_label(label);
    let name = build_name("permissionsync-test-root");
    let mut builder = new_certificate_builder(&name, &name, &key, ROOT_CERTIFICATE_SERIAL);

    let basic_constraints = BasicConstraints::new()
        .critical()
        .ca()
        .build()
        .expect("root basic constraints");
    builder
        .append_extension(basic_constraints)
        .expect("append root basic constraints");
    let key_usage = KeyUsage::new()
        .critical()
        .key_cert_sign()
        .crl_sign()
        .build()
        .expect("root key usage");
    builder
        .append_extension(key_usage)
        .expect("append root key usage");

    builder
        .sign(&key, MessageDigest::null())
        .expect("sign root certificate");

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

    let basic_constraints = BasicConstraints::new()
        .critical()
        .build()
        .expect("leaf basic constraints");
    builder
        .append_extension(basic_constraints)
        .expect("append leaf basic constraints");
    let key_usage = KeyUsage::new()
        .critical()
        .digital_signature()
        .build()
        .expect("leaf key usage");
    builder
        .append_extension(key_usage)
        .expect("append leaf key usage");
    let subject_alternative_name = SubjectAlternativeName::new()
        .ip(ip_address)
        .build(&builder.x509v3_context(None, None))
        .expect("leaf subject alternative name");
    builder
        .append_extension(subject_alternative_name)
        .expect("append leaf subject alternative name");

    builder
        .sign(root_key, MessageDigest::null())
        .expect("sign leaf certificate");

    (builder.build(), key)
}
