//! Private test-only signing, clock, configuration, cache, and HTTPS fixtures.

use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use josekit::{
    jwk::{
        Jwk,
        alg::{ec::EcCurve, ed::EdCurve},
    },
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
use permissionsync_core::{CancellationSignal, SynchronizationContext};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{oneshot, watch},
};
use tokio_native_tls::TlsAcceptor;

use super::{
    super::{
        authenticator::{Snapshot, TechnicalCallerAuthenticator},
        clock::Clock,
        config::{
            JwtAlgorithm, TechnicalCallerAuthenticatorConfig, TrustedVerificationSource,
            VerificationCachePolicy,
        },
        error::AuthenticationError,
        jwks::parse_jwks,
    },
    transport::{ResponseBody, ScriptedResponse},
};

const NOT_BEFORE: i64 = 1_700_000_000;
const NOT_AFTER: i64 = 4_100_000_000;

/// A deterministic, mutable clock unavailable outside this test subtree.
#[derive(Clone)]
pub(super) struct TestClock(Arc<Mutex<ClockState>>);

struct ClockState {
    tick: Instant,
    unix_seconds: Option<f64>,
}

impl TestClock {
    pub(super) fn new(tick: Instant, unix_seconds: Option<f64>) -> Self {
        Self(Arc::new(Mutex::new(ClockState { tick, unix_seconds })))
    }

    pub(super) fn advance(&self, duration: Duration) {
        let mut state = self.0.lock().unwrap();
        state.tick += duration;
        if let Some(unix_seconds) = &mut state.unix_seconds {
            *unix_seconds += duration.as_secs_f64();
        }
    }
}

impl Clock for TestClock {
    fn tick(&self) -> Instant {
        self.0.lock().unwrap().tick
    }

    fn unix_seconds(&self) -> Option<f64> {
        self.0.lock().unwrap().unix_seconds
    }
}

pub(super) struct NeverCancelled;

impl CancellationSignal for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

pub(super) struct AlreadyCancelled;

impl CancellationSignal for AlreadyCancelled {
    fn is_cancelled(&self) -> bool {
        true
    }
}

/// A test-controlled cancellation signal for operations already in flight.
#[derive(Default)]
pub(super) struct MutableCancellationSignal(AtomicBool);

impl MutableCancellationSignal {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Permanently cancels every context borrowing this signal.
    pub(super) fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
}

impl CancellationSignal for MutableCancellationSignal {
    fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

pub(super) fn context<'a>(
    deadline: Instant,
    cancellation: &'a dyn CancellationSignal,
) -> SynchronizationContext<'a> {
    SynchronizationContext::new(deadline, cancellation)
}

pub(super) fn config(
    source: TrustedVerificationSource,
    trust_anchor_pem: Vec<u8>,
    algorithms: Vec<JwtAlgorithm>,
    policy: VerificationCachePolicy,
) -> TechnicalCallerAuthenticatorConfig {
    TechnicalCallerAuthenticatorConfig::new(
        "https://issuer.test".to_owned(),
        "permissionsync".to_owned(),
        source,
        algorithms,
        Duration::from_secs(1),
        policy,
        Duration::from_secs(5),
        vec![trust_anchor_pem],
    )
    .unwrap()
}

pub(super) fn authenticator(
    config: TechnicalCallerAuthenticatorConfig,
    clock: TestClock,
) -> TechnicalCallerAuthenticator {
    let mut authenticator = TechnicalCallerAuthenticator::new(config);
    Arc::get_mut(&mut authenticator.inner).unwrap().clock = Arc::new(clock);
    authenticator
}

pub(super) async fn install_jwks(
    authenticator: &mut TechnicalCallerAuthenticator,
    jwks: &[u8],
    context: &SynchronizationContext<'_>,
) -> Result<u64, AuthenticationError> {
    let inner = Arc::get_mut(&mut authenticator.inner).unwrap();
    let candidates = parse_jwks(jwks, &inner.config.algorithms, context)?;
    let generation = inner
        .cache
        .read()
        .await
        .as_ref()
        .map_or(0, |snapshot| snapshot.generation)
        .saturating_add(1);
    *inner.cache.write().await = Some(Snapshot {
        candidates,
        acquired: inner.clock.tick(),
        generation,
    });
    Ok(generation)
}

/// Builds a `Snapshot` for the given raw JWKS bytes without installing it,
/// so a caller can install it through `test_only_cache()` directly and
/// control the exact moment the write lock is acquired.
pub(super) fn build_snapshot(
    authenticator: &TechnicalCallerAuthenticator,
    jwks: &[u8],
    generation: u64,
    context: &SynchronizationContext<'_>,
) -> Result<Snapshot, AuthenticationError> {
    let candidates = parse_jwks(jwks, &authenticator.inner.config.algorithms, context)?;
    Ok(Snapshot {
        candidates,
        acquired: authenticator.inner.clock.tick(),
        generation,
    })
}

pub(super) async fn cache_generation(authenticator: &TechnicalCallerAuthenticator) -> Option<u64> {
    authenticator
        .test_only_cache()
        .read()
        .await
        .as_ref()
        .map(|snapshot| snapshot.generation)
}

/// In-memory signing material that can produce a compact JWT and matching JWKS.
pub(super) struct SigningMaterial {
    key: Jwk,
    public: Jwk,
    algorithm: JwtAlgorithm,
}

impl SigningMaterial {
    pub(super) fn new(algorithm: JwtAlgorithm, kid: &str) -> Self {
        let mut key = match algorithm {
            JwtAlgorithm::RS256
            | JwtAlgorithm::RS384
            | JwtAlgorithm::RS512
            | JwtAlgorithm::PS256
            | JwtAlgorithm::PS384
            | JwtAlgorithm::PS512 => Jwk::generate_rsa_key(2048).unwrap(),
            JwtAlgorithm::ES256 => Jwk::generate_ec_key(EcCurve::P256).unwrap(),
            JwtAlgorithm::ES384 => Jwk::generate_ec_key(EcCurve::P384).unwrap(),
            JwtAlgorithm::ES512 => Jwk::generate_ec_key(EcCurve::P521).unwrap(),
            JwtAlgorithm::EdDSA => Jwk::generate_ed_key(EdCurve::Ed25519).unwrap(),
        };
        key.set_key_id(kid);
        let mut public = key.to_public_key().unwrap();
        public.set_key_id(kid);
        Self {
            key,
            public,
            algorithm,
        }
    }

    pub(super) fn jwks(&self) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"keys": [self.public.clone()]})).unwrap()
    }

    pub(super) fn token(&self, payload: &[u8], header: &JwsHeader) -> String {
        let context = JwsContext::new();
        match self.algorithm {
            JwtAlgorithm::RS256 => context.serialize_compact(
                payload,
                header,
                &jws::RS256.signer_from_jwk(&self.key).unwrap(),
            ),
            JwtAlgorithm::RS384 => context.serialize_compact(
                payload,
                header,
                &jws::RS384.signer_from_jwk(&self.key).unwrap(),
            ),
            JwtAlgorithm::RS512 => context.serialize_compact(
                payload,
                header,
                &jws::RS512.signer_from_jwk(&self.key).unwrap(),
            ),
            JwtAlgorithm::PS256 => context.serialize_compact(
                payload,
                header,
                &jws::PS256.signer_from_jwk(&self.key).unwrap(),
            ),
            JwtAlgorithm::PS384 => context.serialize_compact(
                payload,
                header,
                &jws::PS384.signer_from_jwk(&self.key).unwrap(),
            ),
            JwtAlgorithm::PS512 => context.serialize_compact(
                payload,
                header,
                &jws::PS512.signer_from_jwk(&self.key).unwrap(),
            ),
            JwtAlgorithm::ES256 => context.serialize_compact(
                payload,
                header,
                &jws::ES256.signer_from_jwk(&self.key).unwrap(),
            ),
            JwtAlgorithm::ES384 => context.serialize_compact(
                payload,
                header,
                &jws::ES384.signer_from_jwk(&self.key).unwrap(),
            ),
            JwtAlgorithm::ES512 => context.serialize_compact(
                payload,
                header,
                &jws::ES512.signer_from_jwk(&self.key).unwrap(),
            ),
            JwtAlgorithm::EdDSA => context.serialize_compact(
                payload,
                header,
                &jws::EdDSA.signer_from_jwk(&self.key).unwrap(),
            ),
        }
        .unwrap()
    }

    pub(super) fn bearer_payload(scope: Option<&str>) -> Vec<u8> {
        let mut payload = serde_json::json!({
            "iss": "https://issuer.test",
            "aud": "permissionsync",
            "exp": 4_000_000_000_f64,
            "iat": 1_700_000_000_f64,
            "client_id": "test-caller",
        });
        if let Some(scope) = scope {
            payload["scope"] = serde_json::Value::String(scope.to_owned());
        }
        serde_json::to_vec(&payload).unwrap()
    }
}

pub(super) struct HttpsFixture {
    address: SocketAddr,
    base_uri: String,
    trust_anchor_pem: Vec<u8>,
    requests: Arc<AtomicUsize>,
    request_arrivals: watch::Sender<usize>,
    body_progress: watch::Sender<usize>,
    shutdown: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl HttpsFixture {
    pub(super) async fn start(responses: Vec<ScriptedResponse>) -> Self {
        Self::start_with_script(move |_| responses).await
    }

    /// Starts a local fixture and constructs its scripts after its HTTPS base URI is known.
    pub(super) async fn start_with_script(
        script: impl FnOnce(&str) -> Vec<ScriptedResponse>,
    ) -> Self {
        let identity = build_identity("127.0.0.1");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let base_uri = format!("https://{address}");
        let requests = Arc::new(AtomicUsize::new(0));
        let (request_arrivals, _) = watch::channel(0);
        let (body_progress, _) = watch::channel(0);
        let (shutdown, mut shutdown_receiver) = oneshot::channel();
        let acceptor = TlsAcceptor::from(identity.acceptor);
        let responses = Arc::new(tokio::sync::Mutex::new(VecDeque::from(script(&base_uri))));
        let task_requests = Arc::clone(&requests);
        let task_request_arrivals = request_arrivals.clone();
        let task_body_progress = body_progress.clone();
        let task = tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = &mut shutdown_receiver => break,
                    accepted = listener.accept() => accepted,
                };
                let Ok((stream, _)) = accepted else {
                    break;
                };
                let acceptor = acceptor.clone();
                let responses = Arc::clone(&responses);
                let requests = Arc::clone(&task_requests);
                let request_arrivals = task_request_arrivals.clone();
                let body_progress = task_body_progress.clone();
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    if read_request(&mut stream).await.is_err() {
                        return;
                    }
                    let request = requests.fetch_add(1, Ordering::SeqCst) + 1;
                    request_arrivals.send_replace(request);
                    let response = responses.lock().await.pop_front();
                    if let Some(response) = response {
                        write_response(&mut stream, response, &body_progress).await;
                    }
                });
            }
        });
        Self {
            address,
            base_uri,
            trust_anchor_pem: identity.trust_anchor_pem,
            requests,
            request_arrivals,
            body_progress,
            shutdown,
            task,
        }
    }

    pub(super) fn address(&self) -> SocketAddr {
        self.address
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

    /// Waits without polling until at least `expected` HTTPS requests arrived.
    pub(super) async fn wait_for_request(&self, expected: usize) {
        let mut arrivals = self.request_arrivals.subscribe();
        while *arrivals.borrow_and_update() < expected {
            arrivals
                .changed()
                .await
                .expect("fixture request notification sender must remain live");
        }
    }

    /// Returns the durable body progress stage: headers are stage one and each body write adds one.
    pub(super) fn body_stage(&self) -> usize {
        *self.body_progress.borrow()
    }

    /// Waits without polling until headers or the requested body write stage is reached.
    pub(super) async fn wait_for_body_stage(&self, expected: usize) {
        let mut progress = self.body_progress.subscribe();
        while *progress.borrow_and_update() < expected {
            progress
                .changed()
                .await
                .expect("fixture body progress sender must remain live");
        }
    }

    pub(super) async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.task.await;
    }
}

async fn read_request(
    stream: &mut tokio_native_tls::TlsStream<tokio::net::TcpStream>,
) -> Result<(), ()> {
    let mut request = Vec::new();
    let mut byte = [0_u8; 1];
    while request.len() <= 16 * 1024 {
        stream.read_exact(&mut byte).await.map_err(|_| ())?;
        request.push(byte[0]);
        if request.ends_with(b"\r\n\r\n") {
            return Ok(());
        }
    }
    Err(())
}

async fn write_response(
    stream: &mut tokio_native_tls::TlsStream<tokio::net::TcpStream>,
    response: ScriptedResponse,
    body_progress: &watch::Sender<usize>,
) {
    let ScriptedResponse {
        status,
        headers,
        body,
        release,
        chunk_releases,
    } = response;
    if let Some(release) = release {
        let _ = release.await;
    }
    let reason = if status == 200 { "OK" } else { "Test" };
    let mut wire = format!("HTTP/1.1 {} {}\r\nConnection: close\r\n", status, reason).into_bytes();
    for (name, value) in headers {
        wire.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    match &body {
        ResponseBody::Complete(body) => {
            wire.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        }
        ResponseBody::Chunks(_) => wire.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n"),
    }
    if stream.write_all(&wire).await.is_err() {
        return;
    }
    body_progress.send_modify(|stage| *stage = stage.saturating_add(1));
    match body {
        ResponseBody::Complete(body) => {
            if stream.write_all(&body).await.is_ok() {
                body_progress.send_modify(|stage| *stage = stage.saturating_add(1));
            }
        }
        ResponseBody::Chunks(chunks) => {
            let mut releases = chunk_releases.into_iter();
            for chunk in chunks {
                if let Some(release) = releases.next() {
                    let _ = release.await;
                }
                let mut wire = format!("{:x}\r\n", chunk.len()).into_bytes();
                wire.extend_from_slice(&chunk);
                wire.extend_from_slice(b"\r\n");
                if stream.write_all(&wire).await.is_err() {
                    return;
                }
                body_progress.send_modify(|stage| *stage = stage.saturating_add(1));
            }
            if stream.write_all(b"0\r\n\r\n").await.is_ok() {
                body_progress.send_modify(|stage| *stage = stage.saturating_add(1));
            }
        }
    }
    let _ = stream.shutdown().await;
}

struct TestIdentity {
    trust_anchor_pem: Vec<u8>,
    acceptor: native_tls::TlsAcceptor,
}

fn build_identity(ip: &str) -> TestIdentity {
    let root_key = generate_key();
    let root_name = name("permissionsync-auth-test-root");
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

#[cfg(test)]
mod fixture_tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::oneshot,
    };
    use tokio_native_tls::TlsConnector;

    use super::super::transport::ScriptedResponse;
    use super::{HttpsFixture, MutableCancellationSignal};
    use permissionsync_core::CancellationSignal;

    async fn get(address: std::net::SocketAddr, trust_anchor_pem: Vec<u8>) -> Vec<u8> {
        let connector = native_tls::TlsConnector::builder()
            .add_root_certificate(native_tls::Certificate::from_pem(&trust_anchor_pem).unwrap())
            .build()
            .unwrap();
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut stream = TlsConnector::from(connector)
            .connect("127.0.0.1", stream)
            .await
            .unwrap();
        stream
            .write_all(b"GET /metadata HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn script_factory_receives_the_fixture_base_uri() {
        let fixture = HttpsFixture::start_with_script(|base_uri| {
            vec![ScriptedResponse::discovery(
                "https://issuer.test",
                &format!("{base_uri}/jwks"),
            )]
        })
        .await;
        let response =
            String::from_utf8(get(fixture.address(), fixture.trust_anchor_pem().to_vec()).await)
                .unwrap();

        assert!(response.contains(&format!("\"jwks_uri\":\"{}/jwks\"", fixture.base_uri())));
        fixture.shutdown().await;
    }

    #[tokio::test]
    async fn arrival_and_body_progress_are_durable_across_a_held_response() {
        let (release, held) = oneshot::channel();
        let fixture = HttpsFixture::start(vec![
            ScriptedResponse::json(200, br#"{"keys":[]}"#.to_vec()).hold_until(held),
        ])
        .await;
        let client = tokio::spawn(get(fixture.address(), fixture.trust_anchor_pem().to_vec()));

        fixture.wait_for_request(1).await;
        assert_eq!(fixture.request_count(), 1);
        assert_eq!(fixture.body_stage(), 0);
        release.send(()).unwrap();
        fixture.wait_for_body_stage(2).await;

        let response = client.await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert_eq!(fixture.body_stage(), 2);
        fixture.shutdown().await;
    }

    #[tokio::test]
    async fn held_chunks_expose_header_and_chunk_progress_without_polling() {
        let (release, held) = oneshot::channel();
        let fixture = HttpsFixture::start(vec![ScriptedResponse::held_chunks(
            200,
            vec![(br#"{"keys":[]}"#.to_vec(), held)],
        )])
        .await;
        let client = tokio::spawn(get(fixture.address(), fixture.trust_anchor_pem().to_vec()));

        fixture.wait_for_request(1).await;
        fixture.wait_for_body_stage(1).await;
        assert_eq!(fixture.body_stage(), 1);
        release.send(()).unwrap();
        fixture.wait_for_body_stage(3).await;

        let response = client.await.unwrap();
        assert!(
            response
                .windows(11)
                .any(|window| window == b"{\"keys\":[]}")
        );
        fixture.shutdown().await;
    }

    #[test]
    fn mutable_cancellation_signal_is_safe_and_permanent() {
        let cancellation = MutableCancellationSignal::new();

        assert!(!cancellation.is_cancelled());
        cancellation.cancel();
        assert!(cancellation.is_cancelled());
    }
}
