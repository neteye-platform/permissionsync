use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    task::Poll,
    time::{Duration, Instant},
};

use bytes::Bytes;
use hickory_net::{
    proto::{
        op::{DnsRequest, DnsRequestOptions, DnsResponse, Query, ResponseCode},
        rr::{Name, RData, RecordType},
    },
    runtime::TokioRuntimeProvider,
    udp::UdpClientStream,
    xfer::{DnsRequestSender, FirstAnswer},
};
use hickory_resolver::{config::ProtocolConfig, system_conf::read_system_conf};
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, StatusCode, Uri, Version,
    body::Incoming,
    header::{ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, CONTENT_TYPE, HOST, HeaderValue},
    http::uri::Scheme,
};
use hyper_util::rt::TokioIo;
use native_tls::{Certificate, Protocol, TlsConnector as NativeTlsConnector};
use permissionsync_core::{
    DesiredStateEnvelope, PermissionProviderRequest, SynchronizationContext,
};
use tokio::{
    net::TcpStream,
    time::{Instant as TokioInstant, timeout_at},
};
pub(crate) use tokio_native_tls::TlsConnector;

use crate::{
    error::{GenericRestPermissionProviderConfigError, ProviderFailure},
    wire,
};

/// The absolute product-owned Provider response-body safety ceiling required
/// by [ADR
/// 0008](../../../docs/adr/0008-generic-rest-permission-provider-wire-and-transport-contract.md).
///
/// Rationale for exactly 1 MiB:
///
/// - Desired-state documents are adapter-specific permission payloads and
///   are expected to be materially smaller than this ceiling in normal
///   operation.
/// - 1 MiB leaves substantial headroom above that expected size without
///   approaching a platform-maximum or effectively unbounded value.
/// - It bounds per-request buffering: the client never buffers more than
///   this many bytes for one response, regardless of how a misbehaving
///   Provider responds.
/// - It bounds JSON parser work and memory amplification, since the fully
///   buffered body is handed to a single-pass parser only after this
///   ceiling has already been enforced.
/// - It reduces the impact of a defective or malicious Provider response
///   that attempts to exhaust memory or CPU through an oversized payload.
///
/// This is the absolute ceiling: a future deployment-specific limit under
/// [ADR
/// 0006](../../../docs/adr/0006-runtime-configuration-oci-and-observability.md)
/// may only lower the effective limit, never raise it above this value.
/// This constant is intentionally private; this crate exposes no
/// response-body-limit configuration.
const RESPONSE_BODY_LIMIT_BYTES: usize = 1_048_576;

pub(crate) fn parse_endpoint(
    endpoint: &str,
) -> Result<Uri, GenericRestPermissionProviderConfigError> {
    if endpoint.contains(['{', '}', '#']) {
        return Err(GenericRestPermissionProviderConfigError::new());
    }

    let endpoint = endpoint
        .parse::<Uri>()
        .map_err(|_| GenericRestPermissionProviderConfigError::new())?;

    if endpoint.scheme() != Some(&Scheme::HTTPS)
        || endpoint.host().is_none_or(str::is_empty)
        || endpoint.authority().is_none()
        || endpoint.query().is_some()
        || endpoint
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
    {
        return Err(GenericRestPermissionProviderConfigError::new());
    }

    if endpoint.path().is_empty() {
        let mut parts = endpoint.into_parts();
        parts.path_and_query = Some("/".parse().expect("slash is a valid URI path"));
        Uri::from_parts(parts).map_err(|_| GenericRestPermissionProviderConfigError::new())
    } else {
        Ok(endpoint)
    }
}

/// Immutable endpoint-address state selected while Provider configuration is
/// validated. Hostnames retain only the first configured UDP system nameserver;
/// literals retain no DNS state and never query the system resolver.
pub(crate) struct EndpointHost {
    port: u16,
    kind: EndpointHostKind,
}

enum EndpointHostKind {
    Literal(IpAddr),
    Hostname {
        name: Name,
        name_server: UdpNameServer,
    },
}

#[derive(Clone, Copy)]
struct UdpNameServer {
    address: SocketAddr,
    bind_addr: Option<SocketAddr>,
}

pub(crate) fn classify_endpoint_host(
    endpoint: &Uri,
) -> Result<EndpointHost, GenericRestPermissionProviderConfigError> {
    let host = bare_host(endpoint);
    let port = endpoint.port_u16().unwrap_or(443);

    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(EndpointHost {
            port,
            kind: EndpointHostKind::Literal(address),
        });
    }

    let name = endpoint_dns_name(host)?;
    let name_server = configured_udp_name_server()?;

    Ok(EndpointHost {
        port,
        kind: EndpointHostKind::Hostname { name, name_server },
    })
}

fn endpoint_dns_name(host: &str) -> Result<Name, GenericRestPermissionProviderConfigError> {
    let mut name =
        Name::from_str(host).map_err(|_| GenericRestPermissionProviderConfigError::new())?;
    name.set_fqdn(true);
    Ok(name)
}

fn configured_udp_name_server() -> Result<UdpNameServer, GenericRestPermissionProviderConfigError> {
    let (config, _) =
        read_system_conf().map_err(|_| GenericRestPermissionProviderConfigError::new())?;

    config
        .name_servers()
        .iter()
        .flat_map(|name_server| {
            name_server
                .connections
                .iter()
                .filter_map(move |connection| {
                    if !matches!(&connection.protocol, ProtocolConfig::Udp)
                        || connection.port == 0
                        || connection.bind_addr.is_some_and(|bind_addr| {
                            bind_addr.is_ipv4() != name_server.ip.is_ipv4()
                        })
                    {
                        return None;
                    }

                    Some(UdpNameServer {
                        address: SocketAddr::new(name_server.ip, connection.port),
                        bind_addr: connection.bind_addr,
                    })
                })
        })
        .next()
        .ok_or_else(GenericRestPermissionProviderConfigError::new)
}

/// Builds the reusable TLS connector for this Provider instance.
///
/// System trust roots remain enabled. `additional_trust_anchors_der` may be
/// empty and, when present, only adds private trust anchors. This connector
/// carries no connection pool, executor, or resolver: each Provider operation
/// performs its own single-attempt DNS resolution, TCP connect, and TLS and
/// HTTP/1.1 handshake, as required by ADR 0008.
pub(crate) fn build_tls_connector(
    additional_trust_anchors_der: &[Vec<u8>],
) -> Result<TlsConnector, GenericRestPermissionProviderConfigError> {
    let mut tls_builder = NativeTlsConnector::builder();
    tls_builder
        .min_protocol_version(Some(Protocol::Tlsv12))
        .danger_accept_invalid_certs(false)
        .danger_accept_invalid_hostnames(false)
        .use_sni(true);

    for certificate_der in additional_trust_anchors_der {
        let certificate = Certificate::from_der(certificate_der)
            .map_err(|_| GenericRestPermissionProviderConfigError::new())?;
        tls_builder.add_root_certificate(certificate);
    }

    let tls = tls_builder
        .build()
        .map_err(|_| GenericRestPermissionProviderConfigError::new())?;

    Ok(TlsConnector::from(tls))
}

pub(crate) async fn resolve(
    tls_connector: &TlsConnector,
    endpoint: &Uri,
    endpoint_host: &EndpointHost,
    operation_timeout: Duration,
    request: PermissionProviderRequest<'_>,
) -> Result<DesiredStateEnvelope, ProviderFailure> {
    let effective_deadline = effective_deadline(request.context(), operation_timeout)?;
    if tokio::runtime::Handle::try_current().is_err() {
        return Err(ProviderFailure::RuntimeUnavailable);
    }
    let timeout_deadline = TokioInstant::from_std(effective_deadline);

    timeout_at(
        timeout_deadline,
        resolve_within_deadline(
            tls_connector,
            endpoint,
            endpoint_host,
            request,
            effective_deadline,
        ),
    )
    .await
    .map_err(|_| ProviderFailure::DeadlineExceeded)?
}

/// Performs one bounded, single-attempt Provider operation.
///
/// DNS resolution, the TCP connect, the TLS handshake, the HTTP/1.1
/// handshake, the request write, and response reading all happen inside this
/// one future so that timing it out or dropping it also drops the
/// connection-driving future below; there is no detached connection driver
/// task and no automatic retry or reconnection.
async fn resolve_within_deadline(
    tls_connector: &TlsConnector,
    endpoint: &Uri,
    endpoint_host: &EndpointHost,
    request: PermissionProviderRequest<'_>,
    effective_deadline: Instant,
) -> Result<DesiredStateEnvelope, ProviderFailure> {
    let context = request.context();
    check_context(context, effective_deadline)?;

    let request_body = wire::serialize_request_body(request.identity())?;
    let authorization = authorization_header(request.technical_caller_bearer_token().as_str())?;
    let outbound_request = build_request(endpoint, request_body, authorization)?;

    check_context(context, effective_deadline)?;
    let address = resolve_one_address(endpoint_host, effective_deadline).await?;

    check_context(context, effective_deadline)?;
    let tcp_stream = TcpStream::connect(address)
        .await
        .map_err(|_| ProviderFailure::Transport)?;

    check_context(context, effective_deadline)?;
    let domain = bare_host(endpoint);
    let tls_stream = tls_connector
        .connect(domain, tcp_stream)
        .await
        .map_err(|_| ProviderFailure::Transport)?;

    check_context(context, effective_deadline)?;
    let io = TokioIo::new(tls_stream);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|_| ProviderFailure::Transport)?;

    // Drive the connection and the response future together, inside this
    // same bounded future. The connection is polled first on every wake so
    // that any response data it delivers this tick is immediately visible
    // to the response future in the same tick; this avoids a race where a
    // fully-buffered response could otherwise be dropped in favor of a
    // simultaneously completing connection. Once the connection has ended,
    // an outcome future that is still pending can only mean the exchange
    // did not complete, which is a transport failure with no retry. The
    // connection is dropped as soon as this future resolves, closing the
    // socket without pooling or reuse.
    drive_connection_and_response(
        connection,
        send_and_read_response(&mut sender, outbound_request, context, effective_deadline),
    )
    .await
}

async fn send_and_read_response(
    sender: &mut hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    outbound_request: Request<Full<Bytes>>,
    context: &SynchronizationContext<'_>,
    effective_deadline: Instant,
) -> Result<DesiredStateEnvelope, ProviderFailure> {
    check_context(context, effective_deadline)?;
    let response = sender
        .send_request(outbound_request)
        .await
        .map_err(|_| ProviderFailure::Transport)?;

    check_context(context, effective_deadline)?;
    if response.status() != StatusCode::OK {
        return Err(ProviderFailure::UnexpectedStatus);
    }

    let (parts, body) = response.into_parts();
    let declared_length =
        wire::validate_success_headers(&parts.headers, RESPONSE_BODY_LIMIT_BYTES)?;
    let response_body = read_body(
        body,
        declared_length,
        RESPONSE_BODY_LIMIT_BYTES,
        context,
        effective_deadline,
    )
    .await?;

    check_context(context, effective_deadline)?;
    let envelope = wire::parse_success_envelope(&response_body)?;
    check_context(context, effective_deadline)?;

    Ok(envelope)
}

/// Polls a HTTP/1.1 connection driver and a dependent response future
/// together until the response future completes or the connection ends.
///
/// The connection is always polled first on every wake, so any progress it
/// makes (including fully delivering a response) is visible to `response`
/// within that same poll; this is what makes it safe to drive both futures
/// without a background task while still resolving deterministically
/// instead of racing them as two independent top-level futures.
async fn drive_connection_and_response<C, F>(
    connection: C,
    response: F,
) -> Result<DesiredStateEnvelope, ProviderFailure>
where
    C: Future<Output = hyper::Result<()>>,
    F: Future<Output = Result<DesiredStateEnvelope, ProviderFailure>>,
{
    let mut connection = std::pin::pin!(connection);
    let mut response = std::pin::pin!(response);
    let mut connection_done = false;

    std::future::poll_fn(move |task_context| {
        if !connection_done && connection.as_mut().poll(task_context).is_ready() {
            connection_done = true;
        }

        match response.as_mut().poll(task_context) {
            Poll::Ready(outcome) => Poll::Ready(outcome),
            Poll::Pending if connection_done => Poll::Ready(Err(ProviderFailure::Transport)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

/// Resolves the endpoint host to exactly one socket address and returns it.
///
/// A literal address returns directly and never loads or queries DNS. A
/// hostname sends exactly one A query and one AAAA query to the single UDP
/// nameserver captured at construction. The two queries compose one logical
/// resolution: neither is retried, fails over, or uses Happy Eyeballs. Both
/// request futures are owned by this operation and are dropped together with
/// it. If both families are ready with usable data in the same poll, IPv4 is
/// preferred; otherwise the first usable family supplies the one connection
/// address without waiting for an unavailable family.
async fn resolve_one_address(
    endpoint_host: &EndpointHost,
    effective_deadline: Instant,
) -> Result<SocketAddr, ProviderFailure> {
    match &endpoint_host.kind {
        EndpointHostKind::Literal(address) => Ok(SocketAddr::new(*address, endpoint_host.port)),
        EndpointHostKind::Hostname { name, name_server } => {
            let remaining = effective_deadline
                .checked_duration_since(Instant::now())
                .filter(|duration| !duration.is_zero())
                .ok_or(ProviderFailure::DeadlineExceeded)?;
            let mut ipv4 = std::pin::pin!(resolve_record(
                name.clone(),
                RecordType::A,
                *name_server,
                remaining,
            ));
            let mut ipv6 = std::pin::pin!(resolve_record(
                name.clone(),
                RecordType::AAAA,
                *name_server,
                remaining,
            ));
            let mut ipv4_done = false;
            let mut ipv6_done = false;
            let mut ipv4_address = None;
            let mut ipv6_address = None;

            std::future::poll_fn(move |task_context| {
                if !ipv4_done {
                    match ipv4.as_mut().poll(task_context) {
                        Poll::Ready(address) => {
                            ipv4_done = true;
                            ipv4_address = address;
                        }
                        Poll::Pending => {}
                    }
                }

                if !ipv6_done {
                    match ipv6.as_mut().poll(task_context) {
                        Poll::Ready(address) => {
                            ipv6_done = true;
                            ipv6_address = address;
                        }
                        Poll::Pending => {}
                    }
                }

                // Poll both futures before selecting an address so the A and
                // AAAA queries are always started as one logical resolution.
                if let Some(address) = ipv4_address.or(ipv6_address) {
                    return Poll::Ready(Some(address));
                }

                if ipv4_done && ipv6_done {
                    Poll::Ready(None)
                } else {
                    Poll::Pending
                }
            })
            .await
            .map(|address| SocketAddr::new(address, endpoint_host.port))
            .ok_or(ProviderFailure::Transport)
        }
    }
}

async fn resolve_record(
    name: Name,
    record_type: RecordType,
    name_server: UdpNameServer,
    timeout: Duration,
) -> Option<IpAddr> {
    let mut stream = UdpClientStream::builder(name_server.address, TokioRuntimeProvider::new())
        .with_bind_addr(name_server.bind_addr)
        .with_timeout(Some(timeout))
        // Hickory counts the immediately-started request as task one, so one
        // is exactly one datagram and no retransmission.
        .with_max_retries(1)
        .build();
    let request = DnsRequest::from_query(
        Query::query(name.clone(), record_type),
        DnsRequestOptions::default(),
    );
    let response = stream.send_message(request).first_answer().await.ok()?;

    response_address(&response, &name, record_type)
}

fn response_address(
    response: &DnsResponse,
    name: &Name,
    record_type: RecordType,
) -> Option<IpAddr> {
    if response.metadata.response_code != ResponseCode::NoError || response.metadata.truncation {
        return None;
    }

    // A response can include a CNAME chain and its final A/AAAA record in one
    // DNS exchange. Follow only that in-response chain; never send a second
    // query for a canonical name.
    let mut accepted_names = vec![name.clone()];
    loop {
        let known_count = accepted_names.len();
        for record in &response.answers {
            if !accepted_names
                .iter()
                .any(|accepted_name| accepted_name == &record.name)
            {
                continue;
            }

            let RData::CNAME(canonical_name) = &record.data else {
                continue;
            };
            if !accepted_names
                .iter()
                .any(|accepted_name| accepted_name == &canonical_name.0)
            {
                accepted_names.push(canonical_name.0.clone());
            }
        }

        if accepted_names.len() == known_count {
            break;
        }
    }

    response.answers.iter().find_map(|record| {
        if !accepted_names
            .iter()
            .any(|accepted_name| accepted_name == &record.name)
            || record.record_type() != record_type
        {
            return None;
        }

        match (record_type, &record.data) {
            (RecordType::A, RData::A(address)) => Some(IpAddr::V4((*address).into())),
            (RecordType::AAAA, RData::AAAA(address)) => Some(IpAddr::V6((*address).into())),
            _ => None,
        }
    })
}

/// Returns the endpoint host without the `[...]` literal delimiter that
/// IPv6 authorities use, for DNS resolution and TLS domain verification.
/// `endpoint` was already validated at construction to always have a host.
fn bare_host(endpoint: &Uri) -> &str {
    endpoint
        .host()
        .expect("validated endpoint always has a host")
        .trim_start_matches('[')
        .trim_end_matches(']')
}

fn effective_deadline(
    context: &SynchronizationContext<'_>,
    operation_timeout: Duration,
) -> Result<Instant, ProviderFailure> {
    if context.cancellation().is_cancelled() {
        return Err(ProviderFailure::Cancelled);
    }

    let now = Instant::now();
    if context.deadline() <= now {
        return Err(ProviderFailure::DeadlineExceeded);
    }

    let provider_deadline = now
        .checked_add(operation_timeout)
        .unwrap_or(context.deadline());
    Ok(context.deadline().min(provider_deadline))
}

fn check_context(
    context: &SynchronizationContext<'_>,
    effective_deadline: Instant,
) -> Result<(), ProviderFailure> {
    if context.cancellation().is_cancelled() {
        return Err(ProviderFailure::Cancelled);
    }

    if Instant::now() >= effective_deadline {
        return Err(ProviderFailure::DeadlineExceeded);
    }

    Ok(())
}

fn authorization_header(token: &str) -> Result<HeaderValue, ProviderFailure> {
    let mut header = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| ProviderFailure::InvalidAuthorization)?;
    header.set_sensitive(true);
    Ok(header)
}

fn build_request(
    endpoint: &Uri,
    request_body: Vec<u8>,
    authorization: HeaderValue,
) -> Result<Request<Full<Bytes>>, ProviderFailure> {
    let authority = endpoint
        .authority()
        .expect("validated endpoint always has an authority");
    let host_header = HeaderValue::from_str(authority.as_str())
        .map_err(|_| ProviderFailure::RequestConstruction)?;

    Request::builder()
        .method(Method::POST)
        .version(Version::HTTP_11)
        .uri(endpoint.path())
        .header(HOST, host_header)
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .header(ACCEPT, HeaderValue::from_static("application/json"))
        .header(ACCEPT_ENCODING, HeaderValue::from_static(""))
        .header(AUTHORIZATION, authorization)
        .body(Full::new(Bytes::from(request_body)))
        .map_err(|_| ProviderFailure::RequestConstruction)
}

async fn read_body(
    mut body: Incoming,
    declared_length: Option<usize>,
    limit: usize,
    context: &SynchronizationContext<'_>,
    effective_deadline: Instant,
) -> Result<Vec<u8>, ProviderFailure> {
    let mut bytes = Vec::with_capacity(declared_length.unwrap_or_default());

    while let Some(frame) = body.frame().await {
        check_context(context, effective_deadline)?;
        let frame = frame.map_err(|_| ProviderFailure::ResponseBody)?;

        if let Ok(data) = frame.into_data() {
            accumulate_within_limit(bytes.len(), data.len(), limit)?;
            bytes.extend_from_slice(&data);
        }
    }

    check_context(context, effective_deadline)?;
    Ok(bytes)
}

/// Adds `chunk_len` unencoded response-body bytes to `total` and enforces
/// `limit`, returning the new running total while still within bounds.
///
/// Extracted so the exact accept/reject boundary, including the real
/// production ceiling, can be tested directly and cheaply, without
/// buffering an actual oversized HTTP response body in tests.
fn accumulate_within_limit(
    total: usize,
    chunk_len: usize,
    limit: usize,
) -> Result<usize, ProviderFailure> {
    let next_total = total
        .checked_add(chunk_len)
        .ok_or(ProviderFailure::ResponseTooLarge)?;

    if next_total > limit {
        return Err(ProviderFailure::ResponseTooLarge);
    }

    Ok(next_total)
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, str::FromStr, time::Duration};

    use hickory_net::proto::{
        op::Message,
        rr::{
            RData, Record, RecordType,
            rdata::{A, AAAA, CNAME},
        },
    };
    use tokio::{net::UdpSocket, time::timeout};

    use super::{
        EndpointHost, EndpointHostKind, RESPONSE_BODY_LIMIT_BYTES, UdpNameServer,
        accumulate_within_limit, authorization_header, endpoint_dns_name, parse_endpoint,
        resolve_one_address,
    };

    const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

    fn hostname_endpoint(name: &str, name_server: SocketAddr) -> EndpointHost {
        EndpointHost {
            port: 443,
            kind: EndpointHostKind::Hostname {
                name: endpoint_dns_name(name).expect("test hostname must parse"),
                name_server: UdpNameServer {
                    address: name_server,
                    bind_addr: None,
                },
            },
        }
    }

    fn dns_response(request: &[u8]) -> (RecordType, Vec<u8>) {
        let request = Message::from_vec(request).expect("received DNS request must parse");
        let query = request
            .queries
            .first()
            .expect("DNS request must contain one query");
        let record_type = query.query_type;
        let mut response = Message::response(request.metadata.id, request.metadata.op_code);
        response.queries = request.queries.clone();
        let canonical_name = hickory_net::proto::rr::Name::from_str("canonical.provider.test.")
            .expect("canonical test name must parse");
        response.add_answer(Record::from_rdata(
            query.name.clone(),
            0,
            RData::CNAME(CNAME(canonical_name.clone())),
        ));
        let answer = match record_type {
            RecordType::A => Record::from_rdata(canonical_name, 0, RData::A(A::new(192, 0, 2, 44))),
            RecordType::AAAA => Record::from_rdata(
                canonical_name,
                0,
                RData::AAAA(AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 44)),
            ),
            record_type => panic!("unexpected DNS record type: {record_type:?}"),
        };
        response.add_answer(answer);
        (
            record_type,
            response.to_vec().expect("test DNS response must encode"),
        )
    }

    async fn answer_a_then_require_aaaa_and_assert_quiet(socket: UdpSocket) {
        let mut buffer = [0; 512];
        let mut sent_a_response = false;
        let mut aaaa_response = None;

        while !sent_a_response || aaaa_response.is_none() {
            let (length, peer) = timeout(DNS_QUERY_TIMEOUT, socket.recv_from(&mut buffer))
                .await
                .expect("local DNS endpoint did not receive one query per family")
                .expect("local DNS endpoint must receive a query");
            let (record_type, response) = dns_response(&buffer[..length]);

            match record_type {
                RecordType::A => {
                    assert!(
                        !sent_a_response,
                        "DNS resolution sent more than one A query"
                    );
                    socket
                        .send_to(&response, peer)
                        .await
                        .expect("local DNS endpoint must send the A response");
                    sent_a_response = true;
                }
                RecordType::AAAA => {
                    assert!(
                        aaaa_response.is_none(),
                        "DNS resolution sent more than one AAAA query"
                    );
                    aaaa_response = Some((response, peer));
                }
                record_type => panic!("unexpected DNS record type: {record_type:?}"),
            }
        }

        let (response, peer) = aaaa_response.expect("the AAAA query must be received");
        socket
            .send_to(&response, peer)
            .await
            .expect("local DNS endpoint must send the AAAA response");

        assert!(
            timeout(DNS_QUERY_TIMEOUT, socket.recv_from(&mut buffer))
                .await
                .is_err(),
            "DNS resolution sent a retransmission or residual datagram"
        );
    }

    async fn receive_two_queries_then_assert_quiet(socket: UdpSocket) {
        let mut buffer = [0; 512];
        let mut received_a = false;
        let mut received_aaaa = false;
        for _ in 0..2 {
            let (length, _) = timeout(DNS_QUERY_TIMEOUT, socket.recv_from(&mut buffer))
                .await
                .expect("local DNS endpoint did not receive one query per family")
                .expect("local DNS endpoint must receive one query per family");
            match dns_response(&buffer[..length]).0 {
                RecordType::A => received_a = true,
                RecordType::AAAA => received_aaaa = true,
                record_type => panic!("unexpected DNS record type: {record_type:?}"),
            }
        }
        assert!(received_a, "DNS resolution did not send an A query");
        assert!(received_aaaa, "DNS resolution did not send an AAAA query");
        assert!(
            timeout(DNS_QUERY_TIMEOUT, socket.recv_from(&mut buffer))
                .await
                .is_err(),
            "DNS resolution sent a retransmission or residual datagram"
        );
    }

    #[test]
    fn authorization_header_is_sensitive_and_forwards_the_exact_bearer_value() {
        let header =
            authorization_header("sentinel-fake-bearer-token").expect("valid header value");

        assert!(header.is_sensitive());
        assert_eq!(header.as_bytes(), b"Bearer sentinel-fake-bearer-token");
    }

    #[test]
    fn accepts_exactly_the_limit_and_rejects_one_byte_more() {
        let limit = 3;

        assert!(accumulate_within_limit(0, limit, limit).is_ok());
        assert!(accumulate_within_limit(0, limit + 1, limit).is_err());
    }

    #[test]
    fn accepts_the_limit_when_reached_across_multiple_chunks() {
        let limit = 3;

        let total = accumulate_within_limit(0, 1, limit).expect("within limit");
        let total = accumulate_within_limit(total, 2, limit).expect("reaches exact limit");
        assert_eq!(total, limit);

        assert!(accumulate_within_limit(total, 1, limit).is_err());
    }

    #[test]
    fn production_response_body_limit_is_exactly_one_mebibyte() {
        assert_eq!(RESPONSE_BODY_LIMIT_BYTES, 1_048_576);

        assert!(
            accumulate_within_limit(0, RESPONSE_BODY_LIMIT_BYTES, RESPONSE_BODY_LIMIT_BYTES)
                .is_ok()
        );
        assert!(
            accumulate_within_limit(0, RESPONSE_BODY_LIMIT_BYTES + 1, RESPONSE_BODY_LIMIT_BYTES)
                .is_err()
        );
    }

    #[test]
    fn hostname_queries_are_always_fully_qualified() {
        assert!(
            endpoint_dns_name("provider.test")
                .expect("hostname must parse")
                .is_fqdn()
        );
    }

    #[tokio::test]
    async fn hostname_resolution_starts_both_queries_and_deterministically_prefers_ipv4() {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("local DNS endpoint must bind");
        let endpoint = hostname_endpoint("provider.test", socket.local_addr().expect("address"));
        let deadline = std::time::Instant::now() + DNS_QUERY_TIMEOUT;

        let (address, ()) = tokio::join!(
            resolve_one_address(&endpoint, deadline),
            answer_a_then_require_aaaa_and_assert_quiet(socket)
        );

        assert_eq!(
            address.expect("A response must resolve"),
            "192.0.2.44:443".parse().expect("socket address")
        );
    }

    #[tokio::test]
    async fn literal_endpoint_returns_without_dns_state_or_query() {
        let endpoint = parse_endpoint("https://[2001:db8::44]:8443/permissions")
            .and_then(|endpoint| super::classify_endpoint_host(&endpoint))
            .expect("IP literal endpoint must not need system DNS configuration");

        assert_eq!(
            resolve_one_address(&endpoint, std::time::Instant::now())
                .await
                .expect("literal endpoint must resolve directly"),
            "[2001:db8::44]:8443".parse().expect("socket address")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn dns_timeout_has_no_retransmit_or_residual_worker_datagram() {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("local DNS endpoint must bind");
        let endpoint = hostname_endpoint("provider.test", socket.local_addr().expect("address"));
        let deadline = std::time::Instant::now() + DNS_QUERY_TIMEOUT;

        let (result, ()) = tokio::join!(
            resolve_one_address(&endpoint, deadline),
            receive_two_queries_then_assert_quiet(socket),
        );

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn dropping_dns_resolution_cancels_both_operation_owned_queries() {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("local DNS endpoint must bind");
        let endpoint = hostname_endpoint("provider.test", socket.local_addr().expect("address"));
        let deadline = std::time::Instant::now() + DNS_QUERY_TIMEOUT;
        let mut buffer = [0; 512];
        let mut received_a = false;
        let mut received_aaaa = false;

        {
            let resolution = resolve_one_address(&endpoint, deadline);
            tokio::pin!(resolution);
            for _ in 0..2 {
                tokio::select! {
                    outcome = &mut resolution => panic!("DNS unexpectedly completed: {outcome:?}"),
                    received = socket.recv_from(&mut buffer) => {
                        let (length, _) = received.expect("local DNS endpoint must receive one query per family");
                        match dns_response(&buffer[..length]).0 {
                            RecordType::A => received_a = true,
                            RecordType::AAAA => received_aaaa = true,
                            record_type => panic!("unexpected DNS record type: {record_type:?}"),
                        }
                    }
                }
            }
        }

        assert!(received_a, "DNS resolution did not send an A query");
        assert!(received_aaaa, "DNS resolution did not send an AAAA query");

        assert!(
            timeout(DNS_QUERY_TIMEOUT, socket.recv_from(&mut buffer))
                .await
                .is_err(),
            "dropped DNS resolution sent a residual datagram"
        );
    }
}
