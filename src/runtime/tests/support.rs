//! Private, hermetic fixtures for the executable-runtime tests.
//!
//! Everything here is local and deterministic: loopback listeners on ephemeral
//! ports, certificates generated in-process with fixed validity, deterministic
//! signing material, and controlled cache policy. Nothing contacts the public
//! internet or a production service, and no test mutates process environment
//! state.

use std::{
    collections::VecDeque,
    net::SocketAddr,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    http::{Request, Response, StatusCode},
};
use josekit::{
    jwk::Jwk,
    jws::{self, JwsContext, JwsHeader},
};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, PKeyRef, Private},
    x509::{
        X509, X509Name, X509NameRef,
        extension::{BasicConstraints, KeyUsage, SubjectAlternativeName},
    },
};
use permissionsync::{
    ComposedApplication, ConfiguredTarget, GLPI_ADAPTER_IDENTIFIER, ProviderConfiguration,
    RuntimeConfiguration,
};
use permissionsync_adapter_glpi::{
    GlpiAdapterConfig, GlpiAppToken, GlpiAuthenticationSource, GlpiUserToken,
};
use permissionsync_auth::{
    JwtAlgorithm, TechnicalCallerAuthenticator, TechnicalCallerAuthenticatorConfig,
    TrustedVerificationSource, VerificationCachePolicy,
};
use permissionsync_provider_generic_rest::GenericRestPermissionProviderConfig;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_native_tls::TlsAcceptor;
use tower::ServiceExt;

use crate::runtime::{
    admission::{Admission, AdmissionObservation, AdmittedRequest, InboundAdmission},
    capacity::SemaphoreCapacity,
    lifecycle::Lifecycle,
    transport::{RuntimeState, router},
};

/// Bound on any fixture wait, so a defect fails rather than hanging.
pub(super) const FIXTURE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REQUEST_HEADER_BYTES: usize = 16 * 1024;
const NOT_BEFORE: i64 = 1_700_000_000;
const NOT_AFTER: i64 = 4_100_000_000;

pub(super) const TEST_ISSUER: &str = "https://issuer.test";
pub(super) const TEST_AUDIENCE: &str = "permissionsync";
pub(super) const TEST_CLIENT_ID: &str = "sentinel-client-id";

/// A valid fixed three-field synchronization body.
pub(super) fn valid_body() -> Vec<u8> {
    br#"{"event_type":"LOGIN","username":"sentinel-username","groups":["/sentinel/group/path"]}"#
        .to_vec()
}

// ---------------------------------------------------------------------------
// Local TLS identity
// ---------------------------------------------------------------------------

pub(super) struct TestIdentity {
    pub(super) trust_anchor_pem: Vec<u8>,
    acceptor: native_tls::TlsAcceptor,
}

fn generate_key() -> PKey<Private> {
    PKey::generate_ed25519().unwrap()
}

fn name(common_name: &str) -> X509Name {
    let mut builder = openssl::x509::X509NameBuilder::new().unwrap();
    builder
        .append_entry_by_nid(Nid::COMMONNAME, common_name)
        .unwrap();
    builder.build()
}

fn certificate(
    subject: &X509NameRef,
    issuer: &X509NameRef,
    key: &PKeyRef<Private>,
    serial: u32,
) -> openssl::x509::X509Builder {
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(subject).unwrap();
    builder.set_issuer_name(issuer).unwrap();
    builder.set_pubkey(key).unwrap();
    let serial = BigNum::from_u32(serial).unwrap();
    builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    builder
        .set_not_before(&Asn1Time::from_unix(NOT_BEFORE).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::from_unix(NOT_AFTER).unwrap())
        .unwrap();
    builder
}

/// Builds a private test root and a loopback leaf certificate.
pub(super) fn build_identity(ip: &str) -> TestIdentity {
    let root_key = generate_key();
    let root_name = name("permissionsync-runtime-test-root");
    let mut root = certificate(&root_name, &root_name, &root_key, 1);
    root.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    root.append_extension(KeyUsage::new().critical().key_cert_sign().build().unwrap())
        .unwrap();
    root.sign(&root_key, MessageDigest::null()).unwrap();
    let root = root.build();

    let leaf_key = generate_key();
    let leaf_name = name(ip);
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
            .ip(ip)
            .build(&leaf.x509v3_context(None, None))
            .unwrap(),
    )
    .unwrap();
    leaf.sign(&root_key, MessageDigest::null()).unwrap();
    let leaf = leaf.build();

    let identity = native_tls::Identity::from_pkcs8(
        &leaf.to_pem().unwrap(),
        &leaf_key.private_key_to_pem_pkcs8().unwrap(),
    )
    .unwrap();
    let acceptor = native_tls::TlsAcceptor::builder(identity)
        .min_protocol_version(Some(native_tls::Protocol::Tlsv12))
        .build()
        .unwrap();

    TestIdentity {
        trust_anchor_pem: root.to_pem().unwrap(),
        acceptor,
    }
}

// ---------------------------------------------------------------------------
// Local HTTPS fixture
// ---------------------------------------------------------------------------

/// One scripted HTTPS response.
#[derive(Clone)]
pub(super) struct ScriptedResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl ScriptedResponse {
    pub(super) fn json(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body,
        }
    }

    pub(super) fn empty(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub(super) fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

/// What one fixture request looked like on the wire.
#[derive(Clone, Debug)]
pub(super) struct ObservedRequest {
    pub(super) request_line: String,
    pub(super) headers: Vec<(String, String)>,
    pub(super) body: Vec<u8>,
}

impl ObservedRequest {
    pub(super) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// A local HTTPS endpoint serving scripted responses over a private test CA.
///
/// Requests that arrive after the script is exhausted receive `503`, which
/// keeps a defect deterministic instead of hanging.
pub(super) struct HttpsFixture {
    base_uri: String,
    trust_anchor_pem: Vec<u8>,
    requests: Arc<AtomicUsize>,
    observed: Arc<std::sync::Mutex<Vec<ObservedRequest>>>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl HttpsFixture {
    pub(super) async fn start(responses: Vec<ScriptedResponse>) -> Self {
        let identity = build_identity("127.0.0.1");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_uri = format!("https://{}", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (shutdown, mut shutdown_receiver) = oneshot::channel();
        let acceptor = TlsAcceptor::from(identity.acceptor);
        let script = Arc::new(tokio::sync::Mutex::new(VecDeque::from(responses)));

        let task_requests = Arc::clone(&requests);
        let task_observed = Arc::clone(&observed);
        let task = tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = &mut shutdown_receiver => break,
                    accepted = listener.accept() => accepted,
                };
                let Ok((stream, _)) = accepted else { break };
                let acceptor = acceptor.clone();
                let script = Arc::clone(&script);
                let requests = Arc::clone(&task_requests);
                let observed = Arc::clone(&task_observed);
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let Ok(request) = read_request(&mut stream).await else {
                        return;
                    };
                    requests.fetch_add(1, Ordering::SeqCst);
                    observed.lock().unwrap().push(request);
                    let response = script
                        .lock()
                        .await
                        .pop_front()
                        .unwrap_or_else(|| ScriptedResponse::empty(503));
                    write_response(&mut stream, &response).await;
                });
            }
        });

        Self {
            base_uri,
            trust_anchor_pem: identity.trust_anchor_pem,
            requests,
            observed,
            shutdown: Some(shutdown),
            task: Some(task),
        }
    }

    pub(super) fn base_uri(&self) -> &str {
        &self.base_uri
    }

    pub(super) fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.base_uri, path)
    }

    pub(super) fn trust_anchor_pem(&self) -> &[u8] {
        &self.trust_anchor_pem
    }

    pub(super) fn request_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    pub(super) fn observed(&self) -> Vec<ObservedRequest> {
        self.observed.lock().unwrap().clone()
    }

    pub(super) async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = timeout(FIXTURE_TIMEOUT, task).await;
        }
    }
}

impl Drop for HttpsFixture {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn read_request(
    stream: &mut tokio_native_tls::TlsStream<TcpStream>,
) -> Result<ObservedRequest, ()> {
    let (header, mut buffered) = timeout(FIXTURE_TIMEOUT, async {
        let mut received = Vec::with_capacity(1024);
        let mut chunk = [0_u8; 1024];
        loop {
            if received.len() >= MAX_REQUEST_HEADER_BYTES {
                return Err(());
            }
            let read = stream.read(&mut chunk).await.map_err(|_| ())?;
            if read == 0 {
                return Err(());
            }
            received.extend_from_slice(&chunk[..read]);
            if let Some(position) = received.windows(4).position(|window| window == b"\r\n\r\n") {
                let body = received[position + 4..].to_vec();
                return Ok((received[..position].to_vec(), body));
            }
        }
    })
    .await
    .map_err(|_| ())??;

    let text = String::from_utf8_lossy(&header).into_owned();
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        })
        .collect();

    // Read the declared request body so assertions can inspect it.
    let declared = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    if declared > buffered.len() {
        let remaining = declared - buffered.len();
        let mut rest = vec![0_u8; remaining];
        if timeout(FIXTURE_TIMEOUT, stream.read_exact(&mut rest))
            .await
            .is_ok()
        {
            buffered.extend_from_slice(&rest);
        }
    }
    buffered.truncate(declared);

    Ok(ObservedRequest {
        request_line,
        headers,
        body: buffered,
    })
}

async fn write_response(
    stream: &mut tokio_native_tls::TlsStream<TcpStream>,
    response: &ScriptedResponse,
) {
    let mut head = format!("HTTP/1.1 {} FIXTURE\r\n", response.status);
    for (name, value) in &response.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!("content-length: {}\r\n", response.body.len()));
    head.push_str("connection: close\r\n\r\n");
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(&response.body).await;
    let _ = stream.flush().await;
}

/// A listener that accepts a TCP connection and immediately closes it.
///
/// It gives a deterministic outbound failure without needing an unused port.
pub(super) struct RefusingEndpoint {
    address: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl RefusingEndpoint {
    pub(super) async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, mut shutdown_receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_receiver => break,
                    accepted = listener.accept() => {
                        // Dropping the stream closes the connection before any
                        // TLS handshake can complete.
                        if accepted.is_err() { break }
                    }
                }
            }
        });
        Self {
            address,
            shutdown: Some(shutdown),
            task: Some(task),
        }
    }

    pub(super) fn endpoint(&self, path: &str) -> String {
        format!("https://{}{}", self.address, path)
    }
}

impl Drop for RefusingEndpoint {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// A listener that accepts a TCP connection and then never speaks.
///
/// It gives a deterministic *stalled* peer, as opposed to
/// [`RefusingEndpoint`]'s deterministic *failing* peer: a TLS handshake started
/// against it never completes, so anything waiting on it waits until its own
/// bound fires. Accepted streams are retained so the connection stays open.
pub(super) struct StalledEndpoint {
    address: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl StalledEndpoint {
    pub(super) async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, mut shutdown_receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                tokio::select! {
                    _ = &mut shutdown_receiver => break,
                    accepted = listener.accept() => match accepted {
                        // Retaining the stream keeps the connection open while
                        // nothing is ever read from it or written to it.
                        Ok((stream, _)) => held.push(stream),
                        Err(_) => break,
                    },
                }
            }
        });
        Self {
            address,
            shutdown: Some(shutdown),
            task: Some(task),
        }
    }

    pub(super) fn endpoint(&self, path: &str) -> String {
        format!("https://{}{}", self.address, path)
    }
}

impl Drop for StalledEndpoint {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// A local HTTPS endpoint that reports every arriving request and answers only
/// when the test releases it.
///
/// It gives a deterministic *blocked* peer whose retrieval can still be made to
/// succeed later: the TLS handshake completes and the request is fully read, so
/// receiving the report proves retrieval really started, and no response is
/// written until [`Self::release`] is called. That is what makes a race against
/// shutdown expressible without any timing assumption — the test decides both
/// when shutdown begins and when the retrieval would have succeeded.
///
/// An unreleased fixture answers nothing at all, which models a metadata source
/// that simply never replies.
pub(super) struct GatedHttpsFixture {
    base_uri: String,
    trust_anchor_pem: Vec<u8>,
    requests: Arc<AtomicUsize>,
    release: tokio::sync::watch::Sender<bool>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl GatedHttpsFixture {
    /// Starts the endpoint and returns it with the channel on which each
    /// arriving request is reported.
    ///
    /// Every released request is answered with `response`.
    pub(super) async fn start(
        response: ScriptedResponse,
    ) -> (Self, tokio::sync::mpsc::Receiver<()>) {
        let identity = build_identity("127.0.0.1");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_uri = format!("https://{}", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let (shutdown, mut shutdown_receiver) = oneshot::channel();
        let (arrived, arrivals) = tokio::sync::mpsc::channel(16);
        let (release, released) = tokio::sync::watch::channel(false);
        let acceptor = TlsAcceptor::from(identity.acceptor);

        let task_requests = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            // Connection tasks are owned here, so nothing is detached and a
            // dropped fixture takes its blocked connections with it.
            let mut held = Vec::new();
            loop {
                let accepted = tokio::select! {
                    _ = &mut shutdown_receiver => break,
                    accepted = listener.accept() => accepted,
                };
                let Ok((stream, _)) = accepted else { break };
                let acceptor = acceptor.clone();
                let requests = Arc::clone(&task_requests);
                let arrived = arrived.clone();
                let response = response.clone();
                let mut released = released.clone();
                held.push(tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let Ok(_request) = read_request(&mut stream).await else {
                        return;
                    };
                    requests.fetch_add(1, Ordering::SeqCst);
                    // Reported only after the request was fully read, so a
                    // receiver learns that retrieval really started.
                    let _ = arrived.send(()).await;
                    // Answer nothing until the test releases this endpoint.
                    if released.wait_for(|released| *released).await.is_err() {
                        return;
                    }
                    write_response(&mut stream, &response).await;
                }));
            }
            for connection in held {
                connection.abort();
            }
        });

        (
            Self {
                base_uri,
                trust_anchor_pem: identity.trust_anchor_pem,
                requests,
                release,
                shutdown: Some(shutdown),
                task: Some(task),
            },
            arrivals,
        )
    }

    /// Lets every arrived and every future request be answered.
    pub(super) fn release(&self) {
        let _ = self.release.send(true);
    }

    pub(super) fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.base_uri, path)
    }

    pub(super) fn trust_anchor_pem(&self) -> &[u8] {
        &self.trust_anchor_pem
    }

    pub(super) fn request_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

impl Drop for GatedHttpsFixture {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Emits exactly one finished, sampled span through a provider's own tracer.
///
/// This is what makes a test exercise the configured span processor and exporter
/// rather than the exporter's HTTP client on its own.
pub(super) fn emit_one_span(provider: &opentelemetry_sdk::trace::SdkTracerProvider) {
    use opentelemetry::trace::{Tracer, TracerProvider};

    let tracer = provider.tracer("permissionsync-test");
    tracer.in_span("permissionsync.test", |_| {});
}

// ---------------------------------------------------------------------------
// Signing material
// ---------------------------------------------------------------------------

/// Deterministic in-process signing material producing a JWT and its JWKS.
pub(super) struct SigningMaterial {
    key: Jwk,
    public: Jwk,
}

impl SigningMaterial {
    pub(super) fn new(kid: &str) -> Self {
        let mut key = Jwk::generate_rsa_key(2048).unwrap();
        key.set_key_id(kid);
        let mut public = key.to_public_key().unwrap();
        public.set_key_id(kid);
        Self { key, public }
    }

    pub(super) fn jwks(&self) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"keys": [self.public.clone()]})).unwrap()
    }

    /// Mints a token whose required claims are valid and whose `scope` is
    /// exactly as supplied.
    pub(super) fn token(&self, scope: Option<&str>) -> String {
        let mut payload = serde_json::json!({
            "iss": TEST_ISSUER,
            "aud": TEST_AUDIENCE,
            "exp": 4_000_000_000_f64,
            "iat": 1_700_000_000_f64,
            "client_id": TEST_CLIENT_ID,
        });
        if let Some(scope) = scope {
            payload["scope"] = serde_json::Value::String(scope.to_owned());
        }
        let payload = serde_json::to_vec(&payload).unwrap();
        let header = JwsHeader::new();
        JwsContext::new()
            .serialize_compact(
                &payload,
                &header,
                &jws::RS256.signer_from_jwk(&self.key).unwrap(),
            )
            .unwrap()
    }
}

// ---------------------------------------------------------------------------
// Runtime state assembly
// ---------------------------------------------------------------------------

/// A local, plausible GLPI configuration.
///
/// GLPI construction is entirely local validation, so a configured route is
/// usable without any GLPI service being reachable.
pub(super) fn glpi_configuration(endpoint: &str) -> GlpiAdapterConfig {
    GlpiAdapterConfig {
        endpoint: endpoint.to_owned(),
        app_token: GlpiAppToken::new("sentinel-app-token".to_owned()),
        user_token: GlpiUserToken::new("sentinel-user-token".to_owned()),
        operation_timeout: Duration::from_secs(5),
        additional_trust_anchors_pem: Vec::new(),
        authentication_source: GlpiAuthenticationSource::Default,
    }
}

pub(super) fn provider_configuration(
    endpoint: &str,
    trust_anchor_pem: Vec<Vec<u8>>,
) -> ProviderConfiguration {
    ProviderConfiguration::GenericRest(GenericRestPermissionProviderConfig {
        endpoint: endpoint.to_owned(),
        operation_timeout: Duration::from_secs(5),
        additional_trust_anchors_pem: trust_anchor_pem,
    })
}

pub(super) fn target(logical_target: &str, adapter_identifier: &str) -> ConfiguredTarget {
    ConfiguredTarget {
        logical_target: logical_target.to_owned(),
        adapter_identifier: adapter_identifier.to_owned(),
    }
}

/// Builds the real authenticator over a local JWKS fixture.
pub(super) fn authenticator(
    jwks_uri: String,
    trust_anchor_pem: Vec<u8>,
) -> TechnicalCallerAuthenticator {
    let config = TechnicalCallerAuthenticatorConfig::new(
        TEST_ISSUER.to_owned(),
        TEST_AUDIENCE.to_owned(),
        TrustedVerificationSource::DirectJwks { uri: jwks_uri },
        vec![JwtAlgorithm::RS256],
        Duration::from_secs(5),
        VerificationCachePolicy::new(Duration::from_secs(300), Duration::from_secs(600)),
        Duration::from_secs(5),
        vec![trust_anchor_pem],
    )
    .expect("valid test authenticator configuration");
    TechnicalCallerAuthenticator::new(config)
}

/// The knobs an executable-runtime test needs to vary.
pub(super) struct RuntimeFixtureOptions {
    pub(super) provider: Option<ProviderConfiguration>,
    pub(super) glpi: Option<GlpiAdapterConfig>,
    pub(super) targets: Vec<ConfiguredTarget>,
    pub(super) overall_request_deadline: Duration,
    pub(super) inbound_admission_limit: NonZeroUsize,
    pub(super) synchronization_capacity: NonZeroUsize,
    /// The bounded readiness and warm-up budget. A test raises it when it needs
    /// a readiness evaluation that cannot possibly end by expiring, so that any
    /// answer it does produce must have come from somewhere else.
    pub(super) readiness_budget: Duration,
    pub(super) trace_context_enabled: bool,
}

impl Default for RuntimeFixtureOptions {
    fn default() -> Self {
        Self {
            provider: None,
            glpi: None,
            targets: Vec::new(),
            overall_request_deadline: Duration::from_secs(30),
            inbound_admission_limit: NonZeroUsize::new(8).unwrap(),
            synchronization_capacity: NonZeroUsize::new(4).unwrap(),
            readiness_budget: Duration::from_secs(5),
            trace_context_enabled: false,
        }
    }
}

/// An assembled runtime with its own Prometheus recorder.
///
/// The recorder is local to the constructing thread, so concurrent tests never
/// share global observability state.
pub(super) struct RuntimeFixture {
    pub(super) state: Arc<RuntimeState>,
    pub(super) router: Router,
    pub(super) lifecycle: Arc<Lifecycle>,
    recorder: metrics_exporter_prometheus::PrometheusRecorder,
    handle: metrics_exporter_prometheus::PrometheusHandle,
}

impl RuntimeFixture {
    pub(super) fn new(
        authenticator: TechnicalCallerAuthenticator,
        options: RuntimeFixtureOptions,
    ) -> Self {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        let application = ComposedApplication::compose(RuntimeConfiguration {
            provider: options.provider,
            glpi: options.glpi,
            targets: options.targets,
        })
        .expect("test composition must be globally valid");
        let capacity = SemaphoreCapacity::new(options.synchronization_capacity)
            .expect("test capacity is within the product ceiling");
        let admission = InboundAdmission::new(options.inbound_admission_limit)
            .expect("test admission limits are constructible");
        let lifecycle = Arc::new(Lifecycle::new());

        let state = Arc::new(RuntimeState::new(
            application,
            capacity,
            authenticator,
            admission,
            Arc::clone(&lifecycle),
            handle.clone(),
            options.overall_request_deadline,
            options.readiness_budget,
            options.trace_context_enabled,
        ));
        let router = router(Arc::clone(&state));

        Self {
            state,
            router,
            lifecycle,
            recorder,
            handle,
        }
    }

    /// Installs this fixture's recorder for the current thread.
    pub(super) fn recorder_guard(&self) -> metrics::LocalRecorderGuard<'_> {
        metrics::set_default_local_recorder(&self.recorder)
    }

    /// Renders the Prometheus text exposition.
    pub(super) fn rendered_metrics(&self) -> String {
        self.handle.render()
    }

    /// Holds one admission permit for as long as the returned guard lives.
    pub(super) async fn hold_admission(&self) -> AdmittedRequest {
        let deadline = std::time::Instant::now() + Duration::from_secs(600);
        match self
            .state
            .admission()
            .admit(deadline, &self.lifecycle)
            .await
        {
            Admission::Admitted(admitted) => admitted,
            Admission::NotAdmitted | Admission::RefusedWithoutWaiting => {
                panic!("the configured admission limit must be admissible")
            }
        }
    }

    /// Fills every admission permit and returns the held guards.
    pub(super) async fn saturate_admission(&self) -> Vec<AdmittedRequest> {
        let limit = self.state.admission().limit().get();
        let mut held = Vec::with_capacity(limit);
        for _ in 0..limit {
            held.push(self.hold_admission().await);
        }
        assert_eq!(self.state.admission().available_permits(), 0);
        held
    }

    /// Waits until the bounded admission populations reach an expected shape.
    ///
    /// This is the synchronization mechanism the tests rely on: it observes real
    /// admission state rather than assuming any scheduling order. The timeout is
    /// only a deadlock guard and never establishes ordering.
    pub(super) async fn await_admission(
        &self,
        expected: impl FnMut(&AdmissionObservation) -> bool,
    ) -> AdmissionObservation {
        let mut observation = self.state.admission().observe();
        let reached = timeout(FIXTURE_TIMEOUT, observation.wait_for(expected))
            .await
            .expect("the expected admission state must be reached")
            .expect("the observation channel stays open");
        *reached
    }

    /// Calls the router directly, with no socket involved.
    pub(super) async fn call(&self, request: Request<Body>) -> Response<Body> {
        timeout(FIXTURE_TIMEOUT, self.router.clone().oneshot(request))
            .await
            .expect("router must answer within the fixture timeout")
            .expect("the router service is infallible")
    }

    /// Issues `POST /api/sync-user` and returns the complete response.
    ///
    /// Used where a test must inspect more than the status, such as whether the
    /// response is the private transport-refusal placeholder that never reaches
    /// a caller.
    pub(super) async fn synchronize_response(
        &self,
        bearer: Option<&str>,
        body: Body,
    ) -> Response<Body> {
        let mut request = Request::builder()
            .method("POST")
            .uri(crate::runtime::transport::SYNCHRONIZATION_ROUTE)
            .header("content-type", "application/json");
        if let Some(bearer) = bearer {
            request = request.header("authorization", format!("Bearer {bearer}"));
        }
        self.call(request.body(body).unwrap()).await
    }

    /// Issues `POST /api/sync-user` with the supplied bearer and body.
    pub(super) async fn synchronize(&self, bearer: Option<&str>, body: Body) -> StatusCode {
        let mut request = Request::builder()
            .method("POST")
            .uri(crate::runtime::transport::SYNCHRONIZATION_ROUTE)
            .header("content-type", "application/json");
        if let Some(bearer) = bearer {
            request = request.header("authorization", format!("Bearer {bearer}"));
        }
        self.call(request.body(body).unwrap()).await.status()
    }

    pub(super) async fn get(&self, path: &str) -> Response<Body> {
        self.call(
            Request::builder()
                .method("GET")
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }
}

/// Reads a whole response body for assertions.
pub(super) async fn body_bytes(response: Response<Body>) -> Vec<u8> {
    use http_body_util::BodyExt;

    timeout(FIXTURE_TIMEOUT, response.into_body().collect())
        .await
        .expect("body must arrive within the fixture timeout")
        .expect("test response bodies are complete")
        .to_bytes()
        .to_vec()
}

/// A synchronization body of exactly `bytes` length that is otherwise valid
/// JSON, so body size is the only variable.
pub(super) fn body_of_length(bytes: usize) -> Vec<u8> {
    let prefix = br#"{"event_type":"LOGIN","username":"u","groups":[""#.to_vec();
    let suffix = br#""]}"#.to_vec();
    assert!(bytes > prefix.len() + suffix.len());
    let filler = bytes - prefix.len() - suffix.len();
    let mut body = prefix;
    body.extend(std::iter::repeat_n(b'g', filler));
    body.extend(suffix);
    assert_eq!(body.len(), bytes);
    body
}

/// Starts a JWKS fixture that can answer `responses` successful refreshes.
pub(super) async fn jwks_fixture(signing: &SigningMaterial, responses: usize) -> HttpsFixture {
    HttpsFixture::start(
        std::iter::repeat_n(ScriptedResponse::jwks(signing.jwks()), responses).collect(),
    )
    .await
}

/// Starts a JWKS fixture whose metadata source is unavailable.
pub(super) async fn unavailable_jwks_fixture(responses: usize) -> HttpsFixture {
    HttpsFixture::start(std::iter::repeat_n(ScriptedResponse::empty(500), responses).collect())
        .await
}

impl ScriptedResponse {
    pub(super) fn jwks(body: Vec<u8>) -> Self {
        Self::json(200, body)
    }
}

/// The GLPI adapter identifier, for route fixtures.
pub(super) const GLPI: &str = GLPI_ADAPTER_IDENTIFIER;
