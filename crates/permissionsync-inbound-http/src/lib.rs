//! Framework-neutral inbound HTTP handling for PermissionSync.
//!
//! This crate accepts already-buffered HTTP request material but deliberately
//! does not choose an HTTP server, listener, routing implementation, runtime
//! configuration, or response-body format. It authenticates before examining
//! the body and exposes only coarse, safe semantic outcomes.

use std::time::Instant;

use permissionsync_auth::{
    AuthenticatedTechnicalCaller, AuthenticationError, AuthenticationRequest,
    TechnicalCallerAuthenticator,
};
use permissionsync_core::{IdentityContext, SynchronizationContext, TechnicalCallerBearerToken};
use permissionsync_orchestration::{
    SelectedTargetSynchronizationError, SelectedTargetSynchronizationRequest,
    SelectedTargetSynchronizer,
};
use serde::Deserialize;

/// One borrowed inbound HTTP header field.
///
/// Header names and values are retained as bytes so callers do not need to
/// decode or normalize them before this boundary validates `Authorization`.
/// This type intentionally has no formatting implementation because a header
/// value can contain a bearer credential.
pub struct HeaderField<'a> {
    name: &'a [u8],
    value: &'a [u8],
}

impl<'a> HeaderField<'a> {
    /// Creates one borrowed header field without decoding or normalizing it.
    #[must_use]
    pub const fn new(name: &'a [u8], value: &'a [u8]) -> Self {
        Self { name, value }
    }
}

/// A multiplicity-preserving borrowed list of inbound HTTP header fields.
///
/// In particular, this representation retains duplicate `Authorization`
/// fields so the handler can reject ambiguous credentials rather than silently
/// selecting one. It intentionally has no formatting implementation.
pub struct HeaderList<'a> {
    fields: &'a [HeaderField<'a>],
}

impl<'a> HeaderList<'a> {
    /// Creates a borrowed list of all request header fields in their received
    /// multiplicity.
    #[must_use]
    pub const fn new(fields: &'a [HeaderField<'a>]) -> Self {
        Self { fields }
    }
}

/// A safe, bounded stage/category signal, not caller-facing response detail.
///
/// This closed type carries no request, identity, bearer, target, adapter, or
/// error data. Only [`Self::status_code`] gives the caller-facing contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum HttpOutcome {
    /// A selected target reconciliation changed target state.
    Changed,
    /// A valid request selected no target and started no target work.
    TargetlessNoop,
    /// A selected target reconciliation completed without changing target state.
    Unchanged,
    /// Strict fixed-body validation failed.
    InvalidRequest,
    /// The selected logical target was not routed.
    UnknownTarget,
    /// The technical caller credential or required claims were rejected.
    AuthenticationRejected,
    /// The authenticated caller's target grant was forbidden.
    AuthorizationForbidden,
    /// Trusted verifier infrastructure could not establish credential validity.
    VerifierUnavailable,
    /// The request context was cancelled or its deadline expired.
    CancelledOrExpired,
    /// The selected target's compiled adapter was unavailable.
    TargetUnavailable,
    /// Selected-target synchronization capacity was unavailable.
    CapacityUnavailable,
    /// The selected-target Permission Provider failed.
    ProviderFailed,
    /// The selected-target Target Adapter failed.
    AdapterFailed,
}

impl HttpOutcome {
    /// Returns the numeric HTTP status for this semantic outcome.
    #[must_use]
    pub const fn status_code(self) -> u16 {
        match self {
            Self::Changed => 200,
            Self::TargetlessNoop | Self::Unchanged => 204,
            Self::InvalidRequest | Self::UnknownTarget => 400,
            Self::AuthenticationRejected => 401,
            Self::AuthorizationForbidden => 403,
            Self::VerifierUnavailable
            | Self::CancelledOrExpired
            | Self::TargetUnavailable
            | Self::CapacityUnavailable
            | Self::ProviderFailed
            | Self::AdapterFailed => 500,
        }
    }
}

/// Handles one complete inbound synchronization request.
///
/// The supplied authenticator and selected-target synchronizer are composed by
/// the application. This boundary neither configures nor replaces either one.
pub struct InboundHttpHandler<'a> {
    authenticator: &'a TechnicalCallerAuthenticator,
    selected_synchronizer: &'a SelectedTargetSynchronizer<'a>,
}

impl<'a> InboundHttpHandler<'a> {
    /// Creates a handler over the current authentication and selected-target
    /// synchronization composition.
    #[must_use]
    pub const fn new(
        authenticator: &'a TechnicalCallerAuthenticator,
        selected_synchronizer: &'a SelectedTargetSynchronizer<'a>,
    ) -> Self {
        Self {
            authenticator,
            selected_synchronizer,
        }
    }

    /// Authenticates, validates, and synchronizes one complete request.
    ///
    /// The original deadline and cancellation reference are reused for every
    /// stage. No bearer credential is included in the returned outcome.
    pub async fn handle<'request>(
        &self,
        headers: HeaderList<'request>,
        body: &'request [u8],
        context: SynchronizationContext<'request>,
    ) -> HttpOutcome {
        if context_unavailable(&context) {
            return HttpOutcome::CancelledOrExpired;
        }

        let credential = extract_bearer(headers);

        if context_unavailable(&context) {
            return HttpOutcome::CancelledOrExpired;
        }

        // `AuthenticationRequest` owns its context, so reconstruct only that
        // carrier from the exact deadline and cancellation reference supplied
        // to this request.
        let authentication_context =
            SynchronizationContext::new(context.deadline(), context.cancellation());
        let authentication = self
            .authenticator
            .authenticate(AuthenticationRequest::new(
                credential,
                authentication_context,
            ))
            .await;

        self.continue_after_authentication(authentication, body, context)
            .await
    }

    async fn continue_after_authentication<'request>(
        &self,
        authentication: Result<AuthenticatedTechnicalCaller, AuthenticationError>,
        body: &'request [u8],
        context: SynchronizationContext<'request>,
    ) -> HttpOutcome {
        let authenticated = match authentication {
            Ok(authenticated) => authenticated,
            Err(error) => return authentication_failure_outcome(error),
        };

        if context_unavailable(&context) {
            return HttpOutcome::CancelledOrExpired;
        }

        self.handle_authenticated(
            authenticated.bearer_token(),
            authenticated.target_selection().selected(),
            body,
            context,
        )
        .await
    }

    async fn handle_authenticated<'request>(
        &self,
        bearer: &TechnicalCallerBearerToken,
        selected_target: Option<&permissionsync_core::LogicalTarget>,
        body: &'request [u8],
        context: SynchronizationContext<'request>,
    ) -> HttpOutcome {
        // Preserve cancellation/deadline precedence over the body result: a
        // request that expires during parsing is a synchronization failure.
        let parsed = serde_json::from_slice::<LoginBody>(body);
        if context_unavailable(&context) {
            return HttpOutcome::CancelledOrExpired;
        }
        let body = match parsed {
            Ok(body) if body.event_type == "LOGIN" => body,
            Ok(_) | Err(_) => return HttpOutcome::InvalidRequest,
        };
        let identity = IdentityContext::new(body.username, body.groups);

        let Some(target) = selected_target else {
            if context_unavailable(&context) {
                return HttpOutcome::CancelledOrExpired;
            }
            return HttpOutcome::TargetlessNoop;
        };

        let request = SelectedTargetSynchronizationRequest::new(&identity, target, bearer, context);
        match self.selected_synchronizer.synchronize(request).await {
            Ok(permissionsync_core::ReconciliationOutcome::Changed) => HttpOutcome::Changed,
            Ok(permissionsync_core::ReconciliationOutcome::Unchanged) => HttpOutcome::Unchanged,
            Err(SelectedTargetSynchronizationError::UnknownTarget) => HttpOutcome::UnknownTarget,
            Err(SelectedTargetSynchronizationError::Cancelled) => HttpOutcome::CancelledOrExpired,
            Err(SelectedTargetSynchronizationError::TargetUnavailable) => {
                HttpOutcome::TargetUnavailable
            }
            Err(SelectedTargetSynchronizationError::CapacityUnavailable) => {
                HttpOutcome::CapacityUnavailable
            }
            Err(SelectedTargetSynchronizationError::ProviderFailed) => HttpOutcome::ProviderFailed,
            Err(SelectedTargetSynchronizationError::AdapterFailed) => HttpOutcome::AdapterFailed,
        }
    }
}

/// Private fixed-shape representation of the inbound JSON body.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginBody {
    event_type: String,
    username: String,
    groups: Vec<String>,
}

fn context_unavailable(context: &SynchronizationContext<'_>) -> bool {
    context.cancellation().is_cancelled() || Instant::now() >= context.deadline()
}

fn authentication_failure_outcome(error: AuthenticationError) -> HttpOutcome {
    match error {
        AuthenticationError::Rejected => HttpOutcome::AuthenticationRejected,
        AuthenticationError::Forbidden => HttpOutcome::AuthorizationForbidden,
        AuthenticationError::VerifierUnavailable => HttpOutcome::VerifierUnavailable,
        AuthenticationError::Cancelled => HttpOutcome::CancelledOrExpired,
    }
}

fn extract_bearer(headers: HeaderList<'_>) -> Option<&str> {
    let mut authorization = None;

    for field in headers.fields {
        if field.name.eq_ignore_ascii_case(b"authorization")
            && authorization.replace(field.value).is_some()
        {
            return None;
        }
    }

    let value = authorization?;
    let scheme = b"bearer";
    if value.len() <= scheme.len() || !value[..scheme.len()].eq_ignore_ascii_case(scheme) {
        return None;
    }

    let mut credential_start = scheme.len();
    while value.get(credential_start) == Some(&b' ') {
        credential_start += 1;
    }
    if credential_start == scheme.len() || credential_start == value.len() {
        return None;
    }

    let credential = &value[credential_start..];
    if !is_b64token(credential) {
        return None;
    }

    // The accepted grammar is ASCII, therefore this conversion neither changes
    // nor normalizes the credential bytes.
    std::str::from_utf8(credential).ok()
}

fn is_b64token(credential: &[u8]) -> bool {
    let padding_start = credential
        .iter()
        .position(|byte| *byte == b'=')
        .unwrap_or(credential.len());
    !credential[..padding_start].is_empty()
        && credential[..padding_start]
            .iter()
            .copied()
            .all(is_b64token_non_padding_character)
        && credential[padding_start..].iter().all(|byte| *byte == b'=')
}

fn is_b64token_non_padding_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        task::{Context, Poll, Waker},
        time::{Duration, Instant},
    };

    use josekit::{
        jwk::Jwk,
        jws::{self, JwsContext, JwsHeader},
    };
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        nid::Nid,
        pkey::{PKey, Private},
        x509::{
            X509, X509NameRef,
            extension::{BasicConstraints, KeyUsage, SubjectAlternativeName},
        },
    };

    use permissionsync_auth::{
        JwtAlgorithm, TechnicalCallerAuthenticatorConfig, TrustedVerificationSource,
        VerificationCachePolicy,
    };
    use permissionsync_core::{
        BoxFuture, CancellationSignal, DesiredStateEnvelope, EnvelopeVersion, LogicalTarget,
        OpaquePayload, PermissionProvider, PermissionProviderError, PermissionProviderRequest,
        ReconciliationOutcome, SynchronizationContext, TargetAdapter, TargetAdapterError,
        TargetAdapterRequest, TechnicalCallerBearerToken,
    };
    use permissionsync_orchestration::{
        SelectedTargetSynchronizer, SynchronizationCapacity, SynchronizationCapacityError,
        SynchronizationPermit,
    };
    use permissionsync_routing::{
        AdapterIdentifier, AdapterRegistration, TargetRoute, TargetRouter,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::Notify,
        time::timeout,
    };
    use tokio_native_tls::TlsAcceptor;

    use super::{
        HeaderField, HeaderList, HttpOutcome, InboundHttpHandler, LoginBody, extract_bearer,
    };

    struct NeverCancelled;
    impl CancellationSignal for NeverCancelled {
        fn is_cancelled(&self) -> bool {
            false
        }
    }
    struct Cancelled;
    impl CancellationSignal for Cancelled {
        fn is_cancelled(&self) -> bool {
            true
        }
    }
    struct ToggleCancelled(AtomicBool);
    impl CancellationSignal for ToggleCancelled {
        fn is_cancelled(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }

    const FIXTURE_TIMEOUT: Duration = Duration::from_secs(10);
    const MAX_REQUEST_HEADER_BYTES: usize = 8 * 1024;
    const NOT_BEFORE: i64 = 1_700_000_000;
    const NOT_AFTER: i64 = 4_100_000_000;

    struct ServerTask(Option<tokio::task::JoinHandle<()>>);

    impl ServerTask {
        fn new(handle: tokio::task::JoinHandle<()>) -> Self {
            Self(Some(handle))
        }

        async fn finish(mut self) {
            let mut handle = self.0.take().unwrap();
            match timeout(FIXTURE_TIMEOUT, &mut handle).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => panic!("JWKS fixture task failed: {error}"),
                Err(_) => {
                    handle.abort();
                    let _ = timeout(FIXTURE_TIMEOUT, &mut handle).await;
                    panic!("JWKS fixture task timed out");
                }
            }
        }
    }

    impl Drop for ServerTask {
        fn drop(&mut self) {
            if let Some(handle) = self.0.take() {
                handle.abort();
            }
        }
    }

    async fn read_request_header(stream: &mut tokio_native_tls::TlsStream<TcpStream>) -> Vec<u8> {
        timeout(FIXTURE_TIMEOUT, async {
            let mut header = Vec::with_capacity(1024);
            let mut chunk = [0; 1024];
            loop {
                assert!(
                    header.len() < MAX_REQUEST_HEADER_BYTES,
                    "request header too large"
                );
                let remaining = MAX_REQUEST_HEADER_BYTES - header.len();
                let chunk_length = remaining.min(chunk.len());
                let read = stream.read(&mut chunk[..chunk_length]).await.unwrap();
                assert_ne!(read, 0, "connection closed before request header completed");
                header.extend_from_slice(&chunk[..read]);
                if header.windows(4).any(|window| window == b"\r\n\r\n") {
                    return header;
                }
            }
        })
        .await
        .expect("request header must arrive before fixture timeout")
    }

    fn poll_ready<F: Future>(future: F) -> F::Output {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = Box::pin(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("test future unexpectedly returned Poll::Pending"),
        }
    }

    #[derive(Default)]
    struct Calls {
        capacity: AtomicUsize,
        provider: AtomicUsize,
        adapter: AtomicUsize,
        observation: Mutex<Option<ProviderObservation>>,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct ProviderObservation {
        username: String,
        groups: Vec<String>,
        target: String,
        bearer: String,
        deadline: Instant,
        cancelled: bool,
    }

    #[derive(Clone, Copy)]
    enum ResultKind {
        Changed,
        Unchanged,
        ProviderFailure,
        AdapterFailure,
    }

    struct FakeProvider {
        calls: Arc<Calls>,
        kind: ResultKind,
    }
    impl PermissionProvider for FakeProvider {
        fn resolve<'a>(
            &'a self,
            request: PermissionProviderRequest<'a>,
        ) -> BoxFuture<'a, Result<DesiredStateEnvelope, PermissionProviderError>> {
            Box::pin(async move {
                self.calls.provider.fetch_add(1, Ordering::SeqCst);
                *self.calls.observation.lock().unwrap() = Some(ProviderObservation {
                    username: request.identity().username().to_owned(),
                    groups: request.identity().groups().to_vec(),
                    target: request.target().as_str().to_owned(),
                    bearer: request.technical_caller_bearer_token().as_str().to_owned(),
                    deadline: request.context().deadline(),
                    cancelled: request.context().cancellation().is_cancelled(),
                });
                if matches!(self.kind, ResultKind::ProviderFailure) {
                    return Err(PermissionProviderError::new(std::io::Error::other("test")));
                }
                Ok(DesiredStateEnvelope::new(
                    EnvelopeVersion::new(1),
                    OpaquePayload::try_from("null".to_owned()).unwrap(),
                ))
            })
        }
    }
    struct FakeAdapter {
        calls: Arc<Calls>,
        kind: ResultKind,
    }
    struct PublicProvider<'a> {
        calls: Arc<Calls>,
        expected_bearer: &'a str,
        bearer_matched: AtomicBool,
    }
    impl PermissionProvider for PublicProvider<'_> {
        fn resolve<'a>(
            &'a self,
            request: PermissionProviderRequest<'a>,
        ) -> BoxFuture<'a, Result<DesiredStateEnvelope, PermissionProviderError>> {
            Box::pin(async move {
                self.calls.provider.fetch_add(1, Ordering::SeqCst);
                self.bearer_matched.store(
                    request.technical_caller_bearer_token().as_str() == self.expected_bearer,
                    Ordering::SeqCst,
                );
                *self.calls.observation.lock().unwrap() = Some(ProviderObservation {
                    username: request.identity().username().to_owned(),
                    groups: request.identity().groups().to_vec(),
                    target: request.target().as_str().to_owned(),
                    bearer: String::new(),
                    deadline: request.context().deadline(),
                    cancelled: request.context().cancellation().is_cancelled(),
                });
                Ok(DesiredStateEnvelope::new(
                    EnvelopeVersion::new(1),
                    OpaquePayload::try_from("null".to_owned()).unwrap(),
                ))
            })
        }
    }
    impl TargetAdapter for FakeAdapter {
        fn reconcile<'a>(
            &'a self,
            _request: TargetAdapterRequest<'a>,
        ) -> BoxFuture<'a, Result<ReconciliationOutcome, TargetAdapterError>> {
            Box::pin(async move {
                self.calls.adapter.fetch_add(1, Ordering::SeqCst);
                match self.kind {
                    ResultKind::AdapterFailure => {
                        Err(TargetAdapterError::new(std::io::Error::other("test")))
                    }
                    ResultKind::Unchanged => Ok(ReconciliationOutcome::Unchanged),
                    _ => Ok(ReconciliationOutcome::Changed),
                }
            })
        }
    }
    struct Permit;
    impl SynchronizationPermit for Permit {}
    struct FakeCapacity {
        calls: Arc<Calls>,
        fails: bool,
    }
    impl SynchronizationCapacity for FakeCapacity {
        fn acquire<'a>(
            &'a self,
            _context: &'a SynchronizationContext<'a>,
        ) -> BoxFuture<
            'a,
            Result<Box<dyn SynchronizationPermit + Send + 'a>, SynchronizationCapacityError>,
        > {
            Box::pin(async move {
                self.calls.capacity.fetch_add(1, Ordering::SeqCst);
                if self.fails {
                    Err(SynchronizationCapacityError)
                } else {
                    Ok(Box::new(Permit) as Box<dyn SynchronizationPermit + Send + 'a>)
                }
            })
        }
    }

    fn target(value: &str) -> LogicalTarget {
        LogicalTarget::try_from(value.to_owned()).unwrap()
    }
    fn context<'a>(cancellation: &'a dyn CancellationSignal) -> SynchronizationContext<'a> {
        SynchronizationContext::new(Instant::now() + Duration::from_secs(3600), cancellation)
    }
    fn body() -> &'static [u8] {
        br#"{"event_type":"LOGIN","username":"u","groups":["a","a"]}"#
    }
    fn count(calls: &Calls) -> (usize, usize, usize) {
        (
            calls.capacity.load(Ordering::SeqCst),
            calls.provider.load(Ordering::SeqCst),
            calls.adapter.load(Ordering::SeqCst),
        )
    }

    fn assert_outcome(actual: HttpOutcome, expected: HttpOutcome, status: u16) {
        assert_eq!(actual, expected);
        assert_eq!(actual.status_code(), status);
    }

    fn selected_router(calls: Arc<Calls>, kind: ResultKind, available: bool) -> TargetRouter {
        let identifier = AdapterIdentifier::new("adapter".to_owned());
        TargetRouter::new(
            vec![TargetRoute::new(target("target-a"), identifier.clone())],
            if available {
                vec![AdapterRegistration::new(
                    identifier,
                    Box::new(FakeAdapter { calls, kind }),
                )]
            } else {
                Vec::new()
            },
        )
        .unwrap()
    }

    fn auth() -> permissionsync_auth::TechnicalCallerAuthenticator {
        permissionsync_auth::TechnicalCallerAuthenticator::new(
            TechnicalCallerAuthenticatorConfig::new(
                "https://issuer.test".to_owned(),
                "audience".to_owned(),
                TrustedVerificationSource::DirectJwks {
                    uri: "https://issuer.test/jwks".to_owned(),
                },
                vec![JwtAlgorithm::RS256],
                Duration::from_secs(1),
                VerificationCachePolicy::new(Duration::from_secs(1), Duration::ZERO),
                Duration::ZERO,
                Vec::new(),
            )
            .unwrap(),
        )
    }

    fn certificate(
        subject: &X509NameRef,
        issuer: &X509NameRef,
        key: &PKey<Private>,
        serial: u32,
    ) -> openssl::x509::X509Builder {
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate.set_subject_name(subject).unwrap();
        certificate.set_issuer_name(issuer).unwrap();
        certificate.set_pubkey(key).unwrap();
        certificate
            .set_serial_number(&BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        certificate
            .set_not_before(&Asn1Time::from_unix(NOT_BEFORE).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::from_unix(NOT_AFTER).unwrap())
            .unwrap();
        certificate
    }

    fn tls_identity() -> (native_tls::TlsAcceptor, Vec<u8>) {
        let root_key = PKey::generate_ed25519().unwrap();
        let mut root_name = openssl::x509::X509NameBuilder::new().unwrap();
        root_name
            .append_entry_by_nid(Nid::COMMONNAME, "inbound-test-root")
            .unwrap();
        let root_name = root_name.build();
        let mut root = certificate(&root_name, &root_name, &root_key, 1);
        root.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        root.append_extension(KeyUsage::new().critical().key_cert_sign().build().unwrap())
            .unwrap();
        root.sign(&root_key, openssl::hash::MessageDigest::null())
            .unwrap();
        let root = root.build();
        let leaf_key = PKey::generate_ed25519().unwrap();
        let mut leaf_name = openssl::x509::X509NameBuilder::new().unwrap();
        leaf_name
            .append_entry_by_nid(Nid::COMMONNAME, "127.0.0.1")
            .unwrap();
        let leaf_name = leaf_name.build();
        let mut leaf = certificate(&leaf_name, root.subject_name(), &leaf_key, 2);
        leaf.append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        leaf.append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .unwrap(),
        )
        .unwrap();
        leaf.append_extension(
            SubjectAlternativeName::new()
                .ip("127.0.0.1")
                .build(&leaf.x509v3_context(None, None))
                .unwrap(),
        )
        .unwrap();
        leaf.sign(&root_key, openssl::hash::MessageDigest::null())
            .unwrap();
        let leaf = leaf.build();
        let identity = native_tls::Identity::from_pkcs8(
            &leaf.to_pem().unwrap(),
            &leaf_key.private_key_to_pem_pkcs8().unwrap(),
        )
        .unwrap();
        (
            native_tls::TlsAcceptor::builder(identity).build().unwrap(),
            root.to_pem().unwrap(),
        )
    }

    async fn jwks_fixture(
        wait_for_release: bool,
    ) -> (
        permissionsync_auth::TechnicalCallerAuthenticator,
        String,
        Arc<AtomicUsize>,
        Arc<Notify>,
        Arc<Notify>,
        ServerTask,
    ) {
        let mut signing_key = Jwk::generate_rsa_key(2048).unwrap();
        signing_key.set_key_id("test-key");
        let mut public_key = signing_key.to_public_key().unwrap();
        public_key.set_key_id("test-key");
        let jwks = serde_json::to_vec(&serde_json::json!({"keys":[public_key]})).unwrap();
        let payload = serde_json::to_vec(&serde_json::json!({"iss":"https://issuer.test","aud":"audience","exp":4_000_000_000_f64,"iat":1_700_000_000_f64,"client_id":"test-client","scope":"permissionsync:target-a"})).unwrap();
        let token = JwsContext::new()
            .serialize_compact(
                &payload,
                &JwsHeader::new(),
                &jws::RS256.signer_from_jwk(&signing_key).unwrap(),
            )
            .unwrap();
        let (acceptor, root) = tls_identity();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());
        let arrived = Arc::new(Notify::new());
        let server_count = count.clone();
        let server_release = release.clone();
        let server_arrived = arrived.clone();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = TlsAcceptor::from(acceptor).accept(stream).await.unwrap();
            let request = read_request_header(&mut stream).await;
            assert!(request.starts_with(b"GET /jwks HTTP/1.1\r\n"));
            server_count.fetch_add(1, Ordering::SeqCst);
            server_arrived.notify_one();
            if wait_for_release {
                server_release.notified().await;
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                jwks.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.write_all(&jwks).await;
            let _ = stream.shutdown().await;
        });
        let authenticator = permissionsync_auth::TechnicalCallerAuthenticator::new(
            TechnicalCallerAuthenticatorConfig::new(
                "https://issuer.test".to_owned(),
                "audience".to_owned(),
                TrustedVerificationSource::DirectJwks {
                    uri: format!("https://{address}/jwks"),
                },
                vec![JwtAlgorithm::RS256],
                Duration::from_secs(5),
                VerificationCachePolicy::new(Duration::from_secs(30), Duration::ZERO),
                Duration::ZERO,
                vec![root],
            )
            .unwrap(),
        );
        (
            authenticator,
            token,
            count,
            arrived,
            release,
            ServerTask::new(task),
        )
    }

    #[test]
    fn header_extraction_preserves_the_exact_accepted_credential() {
        let credential = b"AbC-._~+/==";
        let fields = [HeaderField::new(b"aUtHoRiZaTiOn", b"bEaReR   AbC-._~+/==")];

        assert_eq!(
            extract_bearer(HeaderList::new(&fields)).map(str::as_bytes),
            Some(credential.as_slice())
        );
    }

    #[test]
    fn header_extraction_rejects_missing_duplicate_and_malformed_fields() {
        let cases: &[&[(&[u8], &[u8])]] = &[
            &[],
            &[
                (b"authorization", b"Bearer one"),
                (b"Authorization", b"Bearer two"),
            ],
            &[(b"authorization", b"Basic token")],
            &[(b"authorization", b"Bearer")],
            &[(b"authorization", b"Bearer  ")],
            &[(b"authorization", b"BearerX token")],
            &[(b"authorization", b"Bearer\ttoken")],
            &[(b"authorization", b"Bearer token ")],
            &[(b"authorization", b"Bearer token,other")],
            &[(b"authorization", b"Bearer token;parameter")],
            &[(b"authorization", b"Bearer tok:en")],
            &[(b"authorization", b"Bearer tok=en")],
            &[(b"authorization", b"Bearer =")],
            &[(b"authorization", b"Bearer \xff")],
        ];

        for values in cases {
            let fields: Vec<_> = values
                .iter()
                .map(|(name, value)| HeaderField::new(name, value))
                .collect();
            assert!(extract_bearer(HeaderList::new(&fields)).is_none());
        }
    }

    #[test]
    fn strict_body_accepts_preserved_strings_and_trailing_whitespace() {
        let cases = [
            (
                br#"{"event_type":"LOGIN","username":"","groups":[]}"#.as_slice(),
                "",
                vec![],
            ),
            (
                br#"{"event_type":"LOGIN","username":"  m\u00fcller\t","groups":["","/staff","/staff"]}"#,
                "  müller\t",
                vec!["", "/staff", "/staff"],
            ),
            (
                b"{\"event_type\":\"LOGIN\",\"username\":\"\\u0000\",\"groups\":[\" /\\u00fcnit \"]}\r\n ",
                "\0",
                vec![" /ünit "],
            ),
        ];
        for (body, username, groups) in cases {
            let parsed: LoginBody = serde_json::from_slice(body).unwrap();
            assert_eq!(parsed.event_type, "LOGIN");
            assert_eq!(parsed.username, username);
            assert_eq!(parsed.groups, groups);
        }
    }

    #[test]
    fn strict_body_rejects_all_non_contract_shapes() {
        let cases = [
            b"".as_slice(),
            b"null".as_slice(),
            b"[]".as_slice(),
            br#"{"event_type":"LOGIN","username":"u"}"#.as_slice(),
            br#"{"event_type":"LOGIN","groups":[]}"#.as_slice(),
            br#"{"username":"u","groups":[]}"#.as_slice(),
            br#"{"event_type":null,"username":"u","groups":[]}"#.as_slice(),
            br#"{"event_type":1,"username":"u","groups":[]}"#.as_slice(),
            br#"{"event_type":"LOGIN","username":null,"groups":[]}"#.as_slice(),
            br#"{"event_type":"LOGIN","username":false,"groups":[]}"#.as_slice(),
            br#"{"event_type":"LOGIN","username":"u","groups":null}"#.as_slice(),
            br#"{"event_type":"LOGIN","username":"u","groups":"g"}"#.as_slice(),
            br#"{"event_type":"LOGIN","username":"u","groups":[1]}"#.as_slice(),
            br#"{"event_type":"LOGIN","username":"u","groups":[true]}"#.as_slice(),
            br#"{"event_type":"LOGIN","username":"u","groups":[null]}"#.as_slice(),
            br#"{"event_type":"LOGIN","username":"u","groups":[{}]}"#.as_slice(),
            br#"{"event_type":"LOGIN","username":"u","groups":[],"extra":true}"#.as_slice(),
            br#"{"event_type":"LOGIN","event_type":"LOGIN","username":"u","groups":[]}"#.as_slice(),
            b"\xff".as_slice(),
            br#"{"event_type":"LOGIN","username":"u","groups":[]} false"#.as_slice(),
        ];

        for body in cases {
            assert!(serde_json::from_slice::<LoginBody>(body).is_err());
        }

        let wrong_event: LoginBody =
            serde_json::from_slice(br#"{"event_type":"LOGOUT","username":"u","groups":[]}"#)
                .unwrap();
        assert_ne!(wrong_event.event_type, "LOGIN");
    }

    #[test]
    fn outcomes_have_only_the_contract_statuses() {
        assert_eq!(HttpOutcome::Changed.status_code(), 200);
        assert_eq!(HttpOutcome::TargetlessNoop.status_code(), 204);
        assert_eq!(HttpOutcome::Unchanged.status_code(), 204);
        assert_eq!(HttpOutcome::InvalidRequest.status_code(), 400);
        assert_eq!(HttpOutcome::UnknownTarget.status_code(), 400);
        assert_eq!(HttpOutcome::AuthenticationRejected.status_code(), 401);
        assert_eq!(HttpOutcome::AuthorizationForbidden.status_code(), 403);
        for outcome in [
            HttpOutcome::VerifierUnavailable,
            HttpOutcome::CancelledOrExpired,
            HttpOutcome::TargetUnavailable,
            HttpOutcome::CapacityUnavailable,
            HttpOutcome::ProviderFailed,
            HttpOutcome::AdapterFailed,
        ] {
            assert_eq!(outcome.status_code(), 500);
        }
    }

    #[test]
    fn malformed_authorization_uses_the_production_authentication_path_without_network() {
        let calls = Arc::new(Calls::default());
        let router = selected_router(calls.clone(), ResultKind::Changed, true);
        let provider = FakeProvider {
            calls: calls.clone(),
            kind: ResultKind::Changed,
        };
        let capacity = FakeCapacity {
            calls: calls.clone(),
            fails: false,
        };
        let sync = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
        let authenticator = auth();
        let handler = InboundHttpHandler::new(&authenticator, &sync);
        let fields = [HeaderField::new(b"authorization", b"Basic secret")];
        assert_outcome(
            poll_ready(handler.handle(HeaderList::new(&fields), b"{", context(&NeverCancelled))),
            HttpOutcome::AuthenticationRejected,
            401,
        );
        assert_eq!(count(&calls), (0, 0, 0));
    }

    #[test]
    fn authentication_failures_take_precedence_over_a_malformed_body() {
        let calls = Arc::new(Calls::default());
        let router = selected_router(calls.clone(), ResultKind::Changed, true);
        let provider = FakeProvider {
            calls: calls.clone(),
            kind: ResultKind::Changed,
        };
        let capacity = FakeCapacity {
            calls: calls.clone(),
            fails: false,
        };
        let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
        let authenticator = auth();
        let handler = InboundHttpHandler::new(&authenticator, &synchronizer);
        for (error, expected) in [
            (
                permissionsync_auth::AuthenticationError::Rejected,
                HttpOutcome::AuthenticationRejected,
            ),
            (
                permissionsync_auth::AuthenticationError::Forbidden,
                HttpOutcome::AuthorizationForbidden,
            ),
            (
                permissionsync_auth::AuthenticationError::VerifierUnavailable,
                HttpOutcome::VerifierUnavailable,
            ),
            (
                permissionsync_auth::AuthenticationError::Cancelled,
                HttpOutcome::CancelledOrExpired,
            ),
        ] {
            assert_outcome(
                poll_ready(handler.continue_after_authentication(
                    Err(error),
                    b"{",
                    context(&NeverCancelled),
                )),
                expected,
                expected.status_code(),
            );
            assert_eq!(count(&calls), (0, 0, 0));
        }
    }

    #[test]
    fn targetless_and_malformed_selected_never_start_selected_work() {
        let calls = Arc::new(Calls::default());
        let router = selected_router(calls.clone(), ResultKind::Changed, true);
        let provider = FakeProvider {
            calls: calls.clone(),
            kind: ResultKind::Changed,
        };
        let capacity = FakeCapacity {
            calls: calls.clone(),
            fails: false,
        };
        let sync = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
        let authenticator = auth();
        let handler = InboundHttpHandler::new(&authenticator, &sync);
        let bearer = TechnicalCallerBearerToken::new("sentinel-bearer".to_owned());
        assert_outcome(
            poll_ready(handler.handle_authenticated(
                &bearer,
                None,
                body(),
                context(&NeverCancelled),
            )),
            HttpOutcome::TargetlessNoop,
            204,
        );
        assert_eq!(count(&calls), (0, 0, 0));
        assert_outcome(
            poll_ready(handler.handle_authenticated(&bearer, None, b"{", context(&NeverCancelled))),
            HttpOutcome::InvalidRequest,
            400,
        );
        assert_outcome(
            poll_ready(handler.handle_authenticated(
                &bearer,
                Some(&target("target-a")),
                b"{",
                context(&NeverCancelled),
            )),
            HttpOutcome::InvalidRequest,
            400,
        );
        assert_eq!(count(&calls), (0, 0, 0));
    }

    #[test]
    fn every_invalid_body_is_bad_request_before_selected_work() {
        let invalid = [
            b"{".as_slice(),
            b"",
            b"null",
            b"[]",
            br#"{"event_type":"LOGIN","username":"u"}"#,
            br#"{"event_type":"LOGIN","groups":[]}"#,
            br#"{"username":"u","groups":[]}"#,
            br#"{"event_type":null,"username":"u","groups":[]}"#,
            br#"{"event_type":1,"username":"u","groups":[]}"#,
            br#"{"event_type":"LOGOUT","username":"u","groups":[]}"#,
            br#"{"event_type":"LOGIN","username":null,"groups":[]}"#,
            br#"{"event_type":"LOGIN","username":true,"groups":[]}"#,
            br#"{"event_type":"LOGIN","username":"u","groups":null}"#,
            br#"{"event_type":"LOGIN","username":"u","groups":{}}"#,
            br#"{"event_type":"LOGIN","username":"u","groups":[1]}"#,
            br#"{"event_type":"LOGIN","username":"u","groups":[true]}"#,
            br#"{"event_type":"LOGIN","username":"u","groups":[null]}"#,
            br#"{"event_type":"LOGIN","username":"u","groups":[{}]}"#,
            br#"{"event_type":"LOGIN","username":"u","groups":[],"extra":true}"#,
            br#"{"event_type":"LOGIN","event_type":"LOGIN","username":"u","groups":[]}"#,
            b"\xff",
            br#"{"event_type":"LOGIN","username":"u","groups":[]} false"#,
        ];
        let calls = Arc::new(Calls::default());
        let router = selected_router(calls.clone(), ResultKind::Changed, true);
        let provider = FakeProvider {
            calls: calls.clone(),
            kind: ResultKind::Changed,
        };
        let capacity = FakeCapacity {
            calls: calls.clone(),
            fails: false,
        };
        let sync = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
        let authenticator = auth();
        let handler = InboundHttpHandler::new(&authenticator, &sync);
        let bearer = TechnicalCallerBearerToken::new("token".to_owned());
        let selected = target("target-a");
        for input in invalid {
            assert_outcome(
                poll_ready(handler.handle_authenticated(
                    &bearer,
                    Some(&selected),
                    input,
                    context(&NeverCancelled),
                )),
                HttpOutcome::InvalidRequest,
                400,
            );
        }
        assert_eq!(count(&calls), (0, 0, 0));
    }

    #[test]
    fn selected_success_preserves_inputs_and_runs_once() {
        let calls = Arc::new(Calls::default());
        let router = selected_router(calls.clone(), ResultKind::Changed, true);
        let provider = FakeProvider {
            calls: calls.clone(),
            kind: ResultKind::Changed,
        };
        let capacity = FakeCapacity {
            calls: calls.clone(),
            fails: false,
        };
        let sync = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
        let authenticator = auth();
        let handler = InboundHttpHandler::new(&authenticator, &sync);
        let bearer = TechnicalCallerBearerToken::new("sentinel-bearer".to_owned());
        let selected = target("target-a");
        let cancellation = NeverCancelled;
        let deadline = Instant::now() + Duration::from_secs(3600);
        let request_context = SynchronizationContext::new(deadline, &cancellation);
        let request = "{\"event_type\":\"LOGIN\",\"username\":\"  müller \",\"groups\":[\"\",\"a\",\"a\",\" ü \"]}".as_bytes();
        assert_outcome(
            poll_ready(handler.handle_authenticated(
                &bearer,
                Some(&selected),
                request,
                request_context,
            )),
            HttpOutcome::Changed,
            200,
        );
        assert_eq!(count(&calls), (1, 1, 1));
        assert_eq!(
            calls.observation.lock().unwrap().take(),
            Some(ProviderObservation {
                username: "  müller ".to_owned(),
                groups: vec![
                    "".to_owned(),
                    "a".to_owned(),
                    "a".to_owned(),
                    " ü ".to_owned()
                ],
                target: "target-a".to_owned(),
                bearer: "sentinel-bearer".to_owned(),
                deadline,
                cancelled: false,
            })
        );
        assert!(!format!("{:?}", HttpOutcome::Changed).contains("sentinel-bearer"));
    }

    #[test]
    fn selected_outcomes_and_failures_have_exact_statuses() {
        for (kind, available, capacity_fails, expected) in [
            (ResultKind::Unchanged, true, false, HttpOutcome::Unchanged),
            (
                ResultKind::Changed,
                false,
                false,
                HttpOutcome::TargetUnavailable,
            ),
            (
                ResultKind::Changed,
                true,
                true,
                HttpOutcome::CapacityUnavailable,
            ),
            (
                ResultKind::ProviderFailure,
                true,
                false,
                HttpOutcome::ProviderFailed,
            ),
            (
                ResultKind::AdapterFailure,
                true,
                false,
                HttpOutcome::AdapterFailed,
            ),
        ] {
            let calls = Arc::new(Calls::default());
            let router = selected_router(calls.clone(), kind, available);
            let provider = FakeProvider {
                calls: calls.clone(),
                kind,
            };
            let capacity = FakeCapacity {
                calls: calls.clone(),
                fails: capacity_fails,
            };
            let sync = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
            let authenticator = auth();
            let handler = InboundHttpHandler::new(&authenticator, &sync);
            let bearer = TechnicalCallerBearerToken::new("token".to_owned());
            let selected = target("target-a");
            assert_outcome(
                poll_ready(handler.handle_authenticated(
                    &bearer,
                    Some(&selected),
                    body(),
                    context(&NeverCancelled),
                )),
                expected,
                expected.status_code(),
            );
        }
        let calls = Arc::new(Calls::default());
        let router = TargetRouter::new(Vec::new(), Vec::new()).unwrap();
        let provider = FakeProvider {
            calls: calls.clone(),
            kind: ResultKind::Changed,
        };
        let capacity = FakeCapacity {
            calls: calls.clone(),
            fails: false,
        };
        let sync = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
        let authenticator = auth();
        let handler = InboundHttpHandler::new(&authenticator, &sync);
        let bearer = TechnicalCallerBearerToken::new("token".to_owned());
        let selected = target("target-a");
        assert_outcome(
            poll_ready(handler.handle_authenticated(
                &bearer,
                Some(&selected),
                body(),
                context(&NeverCancelled),
            )),
            HttpOutcome::UnknownTarget,
            400,
        );
        assert_eq!(count(&calls), (0, 0, 0));
    }

    #[test]
    fn pre_cancelled_selected_request_returns_cancelled_without_work() {
        let calls = Arc::new(Calls::default());
        let router = selected_router(calls.clone(), ResultKind::Changed, true);
        let provider = FakeProvider {
            calls: calls.clone(),
            kind: ResultKind::Changed,
        };
        let capacity = FakeCapacity {
            calls: calls.clone(),
            fails: false,
        };
        let sync = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
        let authenticator = auth();
        let handler = InboundHttpHandler::new(&authenticator, &sync);
        let bearer = TechnicalCallerBearerToken::new("token".to_owned());
        let selected = target("target-a");
        assert_outcome(
            poll_ready(handler.handle_authenticated(
                &bearer,
                Some(&selected),
                body(),
                context(&Cancelled),
            )),
            HttpOutcome::CancelledOrExpired,
            500,
        );
        assert_eq!(count(&calls), (0, 0, 0));
    }

    #[test]
    fn expired_targetless_request_returns_cancelled_without_selected_work() {
        let calls = Arc::new(Calls::default());
        let router = selected_router(calls.clone(), ResultKind::Changed, true);
        let provider = FakeProvider {
            calls: calls.clone(),
            kind: ResultKind::Changed,
        };
        let capacity = FakeCapacity {
            calls: calls.clone(),
            fails: false,
        };
        let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
        let authenticator = auth();
        let handler = InboundHttpHandler::new(&authenticator, &synchronizer);
        let bearer = TechnicalCallerBearerToken::new("token".to_owned());
        let deadline = Instant::now();
        assert_outcome(
            poll_ready(handler.handle_authenticated(
                &bearer,
                None,
                body(),
                SynchronizationContext::new(deadline, &NeverCancelled),
            )),
            HttpOutcome::CancelledOrExpired,
            500,
        );
        assert_eq!(count(&calls), (0, 0, 0));
    }

    #[tokio::test]
    async fn public_handle_authenticates_over_trusted_loopback_https_and_preserves_selected_inputs()
    {
        let (authenticator, token, jwks_calls, _arrived, _release, server) =
            jwks_fixture(false).await;
        let calls = Arc::new(Calls::default());
        let router = selected_router(calls.clone(), ResultKind::Changed, true);
        let provider = PublicProvider {
            calls: calls.clone(),
            expected_bearer: &token,
            bearer_matched: AtomicBool::new(false),
        };
        let capacity = FakeCapacity {
            calls: calls.clone(),
            fails: false,
        };
        let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
        let handler = InboundHttpHandler::new(&authenticator, &synchronizer);
        let cancellation = NeverCancelled;
        let deadline = Instant::now() + Duration::from_secs(60);
        let header_value = format!("Bearer {token}");
        let headers = [HeaderField::new(b"Authorization", header_value.as_bytes())];
        let body = "{\"event_type\":\"LOGIN\",\"username\":\"ü\",\"groups\":[\"a\",\"a\",\" b \"]}";
        let outcome = timeout(
            Duration::from_secs(10),
            handler.handle(
                HeaderList::new(&headers),
                body.as_bytes(),
                SynchronizationContext::new(deadline, &cancellation),
            ),
        )
        .await
        .unwrap();
        assert_outcome(outcome, HttpOutcome::Changed, 200);
        assert_eq!(jwks_calls.load(Ordering::SeqCst), 1);
        assert_eq!(count(&calls), (1, 1, 1));
        assert!(provider.bearer_matched.load(Ordering::SeqCst));
        let observation = calls.observation.lock().unwrap().take().unwrap();
        assert_eq!(observation.username, "ü");
        assert_eq!(observation.groups, ["a", "a", " b "]);
        assert_eq!(observation.target, "target-a");
        assert_eq!(observation.deadline, deadline);
        assert!(!observation.cancelled);
        server.finish().await;
    }

    #[tokio::test]
    async fn public_handle_rejects_one_segment_bearer_before_jwks_or_target_work() {
        let calls = Arc::new(Calls::default());
        let router = selected_router(calls.clone(), ResultKind::Changed, true);
        let provider = FakeProvider {
            calls: calls.clone(),
            kind: ResultKind::Changed,
        };
        let capacity = FakeCapacity {
            calls: calls.clone(),
            fails: false,
        };
        let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
        let authenticator = auth();
        let handler = InboundHttpHandler::new(&authenticator, &synchronizer);
        let headers = [HeaderField::new(b"Authorization", b"Bearer segment")];
        assert_outcome(
            handler
                .handle(HeaderList::new(&headers), b"{", context(&NeverCancelled))
                .await,
            HttpOutcome::AuthenticationRejected,
            401,
        );
        assert_eq!(count(&calls), (0, 0, 0));
    }

    #[tokio::test]
    async fn public_pre_cancelled_and_expired_contexts_return_without_target_work() {
        let calls = Arc::new(Calls::default());
        let router = selected_router(calls.clone(), ResultKind::Changed, true);
        let provider = FakeProvider {
            calls: calls.clone(),
            kind: ResultKind::Changed,
        };
        let capacity = FakeCapacity {
            calls: calls.clone(),
            fails: false,
        };
        let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
        let authenticator = auth();
        let handler = InboundHttpHandler::new(&authenticator, &synchronizer);
        let headers = [HeaderField::new(b"Authorization", b"Bearer segment")];
        assert_outcome(
            handler
                .handle(HeaderList::new(&headers), body(), context(&Cancelled))
                .await,
            HttpOutcome::CancelledOrExpired,
            500,
        );
        let past = Instant::now();
        assert_outcome(
            handler
                .handle(
                    HeaderList::new(&headers),
                    body(),
                    SynchronizationContext::new(past, &NeverCancelled),
                )
                .await,
            HttpOutcome::CancelledOrExpired,
            500,
        );
        assert_eq!(count(&calls), (0, 0, 0));
    }

    #[tokio::test]
    async fn public_handle_observes_cancellation_during_one_joined_jwks_response() {
        let (authenticator, token, jwks_calls, arrived, release, server) = jwks_fixture(true).await;
        let calls = Arc::new(Calls::default());
        let router = selected_router(calls.clone(), ResultKind::Changed, true);
        let provider = FakeProvider {
            calls: calls.clone(),
            kind: ResultKind::Changed,
        };
        let capacity = FakeCapacity {
            calls: calls.clone(),
            fails: false,
        };
        let synchronizer = SelectedTargetSynchronizer::new(&router, &provider, &capacity);
        let handler = InboundHttpHandler::new(&authenticator, &synchronizer);
        let cancellation = ToggleCancelled(AtomicBool::new(false));
        let header_value = format!("Bearer {token}");
        let headers = [HeaderField::new(b"Authorization", header_value.as_bytes())];
        let mut request =
            Box::pin(handler.handle(HeaderList::new(&headers), body(), context(&cancellation)));
        tokio::select! {
            outcome = &mut request => panic!("handler completed before the JWKS response: {outcome:?}"),
            arrival = timeout(Duration::from_secs(10), arrived.notified()) => {
                arrival.expect("JWKS request must arrive before cancellation");
            }
        }
        cancellation.0.store(true, Ordering::SeqCst);
        release.notify_one();
        assert_outcome(
            timeout(Duration::from_secs(10), &mut request)
                .await
                .unwrap(),
            HttpOutcome::CancelledOrExpired,
            500,
        );
        assert_eq!(jwks_calls.load(Ordering::SeqCst), 1);
        assert_eq!(count(&calls), (0, 0, 0));
        server.finish().await;
    }
}
