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

use std::{future::Future, task::Poll, time::Instant};

use bytes::Bytes;
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

    let has_body = body.is_some();
    let body_bytes = body.unwrap_or_default();
    let mut builder = Request::builder()
        .method(method)
        .uri(path_and_query.as_str())
        .header(HOST, host);
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
    let tcp_stream = TcpStream::connect((host, port))
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
            let next_total = bytes
                .len()
                .checked_add(data.len())
                .ok_or(GlpiFailure::ResponseTooLarge)?;
            if next_total > RESPONSE_BODY_LIMIT_BYTES {
                return Err(GlpiFailure::ResponseTooLarge);
            }
            bytes.extend_from_slice(&data);
        }
    }

    Ok(bytes)
}

fn check_deadline(effective_deadline: Instant) -> Result<(), GlpiFailure> {
    if Instant::now() >= effective_deadline {
        return Err(GlpiFailure::DeadlineExceeded);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::RESPONSE_BODY_LIMIT_BYTES;

    #[test]
    fn production_response_body_limit_is_exactly_two_mebibytes() {
        assert_eq!(RESPONSE_BODY_LIMIT_BYTES, 2 * 1_048_576);
    }
}
