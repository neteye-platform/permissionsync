//! Bounded, single-attempt HTTP transport for GLPI V1 REST operations.
//!
//! Modeled on `permissionsync-provider-generic-rest`'s transport: DNS
//! resolution, TCP connect, TLS handshake, HTTP/1.1 handshake, request
//! write, and response reading all happen inside one future per operation,
//! so timing it out or dropping it also drops the connection-driving future.
//! There is no connection pool, no automatic retry, and no redirect
//! following: this module never inspects or follows a `Location` header, and
//! the low-level `hyper::client::conn::http1` handshake used here never
//! follows redirects on its own.

use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    task::Poll,
    time::{Duration, Instant},
};

use bytes::Bytes;
use hickory_net::{
    NetError,
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
    Method, Request, StatusCode, Uri,
    body::Incoming,
    header::{HOST, HeaderName, HeaderValue},
};
use hyper_util::rt::TokioIo;
use tokio::{net::TcpStream, time::timeout_at};
use url::Url;

use crate::error::GlpiFailure;

/// The private response-body safety ceiling for GLPI V1 responses.
///
/// GLPI search/list responses are paginated in small pages (see
/// `search::PAGE_SIZE`) and session/item responses are small JSON objects, so
/// 2 MiB comfortably covers real responses while still bounding a
/// misbehaving or malicious server. This is intentionally private; the
/// crate exposes no response-body-limit configuration.
const RESPONSE_BODY_LIMIT_BYTES: usize = 2 * 1_048_576;

pub(crate) struct RawResponse {
    pub(crate) status: StatusCode,
    pub(crate) body: Vec<u8>,
}

/// Performs one bounded, single-attempt HTTP request against `url`.
///
/// `body` is `None` for every GET request (empty request body, per ADR
/// 0009), or `Some(json_bytes)` for a JSON mutation request, which also adds
/// `Content-Type: application/json`.
pub(crate) async fn request(
    tls_connector: &tokio_native_tls::TlsConnector,
    method: Method,
    url: &Url,
    headers: &[(HeaderName, HeaderValue)],
    body: Option<Vec<u8>>,
    effective_deadline: Instant,
) -> Result<RawResponse, GlpiFailure> {
    if tokio::runtime::Handle::try_current().is_err() {
        return Err(GlpiFailure::RuntimeUnavailable);
    }

    timeout_at(
        tokio::time::Instant::from_std(effective_deadline),
        run(
            tls_connector,
            method,
            url,
            headers,
            body,
            effective_deadline,
        ),
    )
    .await
    .map_err(|_| GlpiFailure::DeadlineExceeded)?
}

async fn run(
    tls_connector: &tokio_native_tls::TlsConnector,
    method: Method,
    url: &Url,
    headers: &[(HeaderName, HeaderValue)],
    body: Option<Vec<u8>>,
    effective_deadline: Instant,
) -> Result<RawResponse, GlpiFailure> {
    check_deadline(effective_deadline)?;

    let host = url.host_str().ok_or(GlpiFailure::Transport)?;
    let port = url.port_or_known_default().ok_or(GlpiFailure::Transport)?;
    let uri: Uri = url.as_str().parse().map_err(|_| GlpiFailure::Transport)?;
    let path_and_query = uri.path_and_query().ok_or(GlpiFailure::Transport)?.clone();

    // The Host header must include an explicit non-default port so the
    // request authority is unambiguous; `https` default is 443.
    let host_header_value = if port == 443 {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    };

    let has_body = body.is_some();
    let body_bytes = body.unwrap_or_default();
    let mut builder = Request::builder()
        .method(method)
        .uri(path_and_query.as_str())
        .header(HOST, host_header_value);
    for (name, value) in headers {
        builder = builder.header(name, value.clone());
    }
    if has_body {
        builder = builder.header(hyper::header::CONTENT_TYPE, "application/json");
    }
    let outbound_request = builder
        .body(Full::new(Bytes::from(body_bytes)))
        .map_err(|_| GlpiFailure::Transport)?;

    check_deadline(effective_deadline)?;
    let address = resolve_one_address(host, port, effective_deadline).await?;
    check_deadline(effective_deadline)?;
    let tcp_stream = TcpStream::connect(address)
        .await
        .map_err(|_| GlpiFailure::Transport)?;

    check_deadline(effective_deadline)?;
    let tls_stream = tls_connector
        .connect(host, tcp_stream)
        .await
        .map_err(|_| GlpiFailure::Transport)?;

    check_deadline(effective_deadline)?;
    let io = TokioIo::new(tls_stream);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|_| GlpiFailure::Transport)?;

    drive_connection_and_response(
        connection,
        send_and_read(&mut sender, outbound_request, effective_deadline),
    )
    .await
}

async fn send_and_read(
    sender: &mut hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    outbound_request: Request<Full<Bytes>>,
    effective_deadline: Instant,
) -> Result<RawResponse, GlpiFailure> {
    check_deadline(effective_deadline)?;
    let response = sender
        .send_request(outbound_request)
        .await
        .map_err(|_| GlpiFailure::Transport)?;

    check_deadline(effective_deadline)?;
    let status = response.status();
    let (_, incoming) = response.into_parts();
    let body = read_body(incoming, effective_deadline).await?;

    Ok(RawResponse { status, body })
}

async fn drive_connection_and_response<C, F>(
    connection: C,
    response: F,
) -> Result<RawResponse, GlpiFailure>
where
    C: Future<Output = hyper::Result<()>>,
    F: Future<Output = Result<RawResponse, GlpiFailure>>,
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
            Poll::Pending if connection_done => Poll::Ready(Err(GlpiFailure::Transport)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

async fn read_body(
    mut body: Incoming,
    effective_deadline: Instant,
) -> Result<Vec<u8>, GlpiFailure> {
    let mut bytes = Vec::new();

    while let Some(frame) = body.frame().await {
        check_deadline(effective_deadline)?;
        let frame = frame.map_err(|_| GlpiFailure::ResponseBody)?;

        if let Ok(data) = frame.into_data() {
            accumulate_within_limit(bytes.len(), data.len(), RESPONSE_BODY_LIMIT_BYTES)?;
            bytes.extend_from_slice(&data);
        }
    }

    Ok(bytes)
}

/// Adds one received frame length to a running total without allocating from
/// an untrusted declared content length. Kept separate so the exact boundary
/// can be tested without buffering oversized response bodies.
fn accumulate_within_limit(
    total: usize,
    chunk_len: usize,
    limit: usize,
) -> Result<usize, GlpiFailure> {
    let next_total = total
        .checked_add(chunk_len)
        .ok_or(GlpiFailure::ResponseTooLarge)?;
    if next_total > limit {
        return Err(GlpiFailure::ResponseTooLarge);
    }
    Ok(next_total)
}

/// Resolves `host` to exactly one [`SocketAddr`], mirroring
/// `permissionsync-provider-generic-rest`'s single-attempt resolution
/// (`crates/permissionsync-provider-generic-rest/src/client.rs`,
/// `resolve_one_address`). This module never lets a bare hostname reach
/// `TcpStream::connect`, since a hostname/port tuple resolves via the OS
/// resolver and can fan out across every returned address; only one
/// concrete address is ever connected to.
///
/// A literal IP address returns directly and never queries DNS. A hostname
/// sends exactly one A query and one AAAA query to the single configured
/// system UDP nameserver; neither is retried, fails over, or uses Happy
/// Eyeballs. If both families are ready with usable data in the same poll,
/// IPv4 is preferred; otherwise the first usable family supplies the one
/// connection address.
async fn resolve_one_address(
    host: &str,
    port: u16,
    effective_deadline: Instant,
) -> Result<SocketAddr, GlpiFailure> {
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(address, port));
    }

    let mut name = Name::from_str(host).map_err(|_| GlpiFailure::Transport)?;
    name.set_fqdn(true);
    let name_server = configured_udp_name_server()?;

    let remaining = effective_deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(GlpiFailure::DeadlineExceeded)?;

    let mut ipv4 = std::pin::pin!(resolve_record(
        name.clone(),
        RecordType::A,
        name_server,
        remaining,
    ));
    let mut ipv6 = std::pin::pin!(resolve_record(
        name,
        RecordType::AAAA,
        name_server,
        remaining,
    ));
    let mut ipv4_done = false;
    let mut ipv6_done = false;
    let mut ipv4_address = None;
    let mut ipv6_address = None;
    let mut ipv4_timed_out = false;
    let mut ipv6_timed_out = false;

    std::future::poll_fn(move |task_context| {
        if !ipv4_done {
            match ipv4.as_mut().poll(task_context) {
                Poll::Ready(outcome) => {
                    ipv4_done = true;
                    ipv4_address = outcome.address;
                    ipv4_timed_out = outcome.timed_out;
                }
                Poll::Pending => {}
            }
        }

        if !ipv6_done {
            match ipv6.as_mut().poll(task_context) {
                Poll::Ready(outcome) => {
                    ipv6_done = true;
                    ipv6_address = outcome.address;
                    ipv6_timed_out = outcome.timed_out;
                }
                Poll::Pending => {}
            }
        }

        if let Some(address) = selected_socket_address(ipv4_address, ipv6_address, port) {
            return Poll::Ready(Ok(address));
        }

        if ipv4_done && ipv6_done {
            Poll::Ready(Err(classify_dns_no_address(ipv4_timed_out, ipv6_timed_out)))
        } else {
            Poll::Pending
        }
    })
    .await
}

/// Chooses the one concrete address passed to `TcpStream::connect`. Keeping
/// selection separate makes the no-fan-out boundary directly testable without
/// making the system-configured resolver injectable.
fn selected_socket_address(
    ipv4_address: Option<IpAddr>,
    ipv6_address: Option<IpAddr>,
    port: u16,
) -> Option<SocketAddr> {
    ipv4_address
        .or(ipv6_address)
        .map(|address| SocketAddr::new(address, port))
}

#[derive(Clone, Copy)]
struct UdpNameServer {
    address: SocketAddr,
    bind_addr: Option<SocketAddr>,
}

fn configured_udp_name_server() -> Result<UdpNameServer, GlpiFailure> {
    let (config, _) = read_system_conf().map_err(|_| GlpiFailure::Transport)?;

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
        .ok_or(GlpiFailure::Transport)
}

/// Outcome of one operation-owned A or AAAA query: either a usable address,
/// or a flag recording whether the query ended because of Hickory timeout
/// exhaustion. The original Hickory error is never retained or formatted.
struct DnsQueryOutcome {
    address: Option<IpAddr>,
    timed_out: bool,
}

async fn resolve_record(
    name: Name,
    record_type: RecordType,
    name_server: UdpNameServer,
    timeout: Duration,
) -> DnsQueryOutcome {
    let mut stream = UdpClientStream::builder(name_server.address, TokioRuntimeProvider::new())
        .with_bind_addr(name_server.bind_addr)
        .with_timeout(Some(timeout))
        // In pinned hickory-net 0.26.3 this value is passed as `max_tasks` to
        // its retry loop, which starts one task immediately. One therefore
        // permits the initial datagram only and no retransmission.
        .with_max_retries(1)
        .build();
    let request = DnsRequest::from_query(
        Query::query(name.clone(), record_type),
        DnsRequestOptions::default(),
    );

    match stream.send_message(request).first_answer().await {
        Ok(response) => DnsQueryOutcome {
            address: response_address(&response, &name, record_type),
            timed_out: false,
        },
        Err(error) => DnsQueryOutcome {
            address: None,
            timed_out: is_hickory_timeout(&error),
        },
    }
}

/// Classifies a Hickory DNS transport error as a timeout or not, without
/// retaining, formatting, or otherwise inspecting its diagnostic content.
fn is_hickory_timeout(error: &NetError) -> bool {
    matches!(error, NetError::Timeout)
}

/// Classifies a completed A/AAAA resolution in which neither family
/// produced a usable address. Any genuine Hickory timeout determines the
/// aggregate category; otherwise the aggregate is a transport failure.
fn classify_dns_no_address(ipv4_timed_out: bool, ipv6_timed_out: bool) -> GlpiFailure {
    if ipv4_timed_out || ipv6_timed_out {
        GlpiFailure::DeadlineExceeded
    } else {
        GlpiFailure::Transport
    }
}

fn response_address(
    response: &DnsResponse,
    name: &Name,
    record_type: RecordType,
) -> Option<IpAddr> {
    if response.metadata.response_code != ResponseCode::NoError || response.metadata.truncation {
        return None;
    }

    // A response can include a CNAME chain and its final A/AAAA record in
    // one DNS exchange. Follow only that in-response chain; never send a
    // second query for a canonical name.
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

fn check_deadline(effective_deadline: Instant) -> Result<(), GlpiFailure> {
    if Instant::now() >= effective_deadline {
        return Err(GlpiFailure::DeadlineExceeded);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{
        RESPONSE_BODY_LIMIT_BYTES, accumulate_within_limit, resolve_one_address,
        selected_socket_address,
    };

    #[test]
    fn production_response_body_limit_is_exactly_two_mebibytes() {
        assert_eq!(RESPONSE_BODY_LIMIT_BYTES, 2 * 1_048_576);
    }

    #[test]
    fn response_body_limit_accepts_limit_minus_one_and_limit_but_not_limit_plus_one() {
        assert!(
            accumulate_within_limit(0, RESPONSE_BODY_LIMIT_BYTES - 1, RESPONSE_BODY_LIMIT_BYTES)
                .is_ok()
        );
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
    fn response_body_limit_is_enforced_across_frames() {
        let total =
            accumulate_within_limit(0, RESPONSE_BODY_LIMIT_BYTES - 1, RESPONSE_BODY_LIMIT_BYTES)
                .expect("first frame is within the limit");
        assert_eq!(total, RESPONSE_BODY_LIMIT_BYTES - 1);
        assert!(
            accumulate_within_limit(total, 1, RESPONSE_BODY_LIMIT_BYTES).is_ok(),
            "a final byte reaches the exact boundary"
        );
        assert!(
            accumulate_within_limit(total, 2, RESPONSE_BODY_LIMIT_BYTES).is_err(),
            "two more bytes exceed the boundary"
        );
    }

    #[tokio::test]
    async fn literal_ip_host_resolves_without_dns_state_or_query() {
        let address = resolve_one_address("192.0.2.44", 8443, std::time::Instant::now())
            .await
            .expect("literal address must resolve directly");

        assert_eq!(
            address,
            "192.0.2.44:8443".parse::<SocketAddr>().expect("address")
        );
    }

    /// A hermetic resolver integration test cannot provide multiple DNS
    /// answers: production deliberately reads the host's system resolver
    /// configuration and sends its UDP queries to that configured server. This
    /// pure selection seam proves the transport still gives `TcpStream` one
    /// concrete address, rather than a resolver-owned multi-address target.
    #[test]
    fn resolver_selection_chooses_one_ipv4_socket_address_when_both_families_resolve() {
        let selected = selected_socket_address(
            Some("192.0.2.44".parse().expect("IPv4 address")),
            Some("2001:db8::44".parse().expect("IPv6 address")),
            8443,
        )
        .expect("one address is selected");

        assert_eq!(
            selected,
            "192.0.2.44:8443"
                .parse::<SocketAddr>()
                .expect("socket address")
        );
    }
}
