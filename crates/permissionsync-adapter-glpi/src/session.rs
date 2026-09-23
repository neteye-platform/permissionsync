//! GLPI V1 request-scoped session lifecycle.
//!
//! Authentication is request-scoped: the adapter starts a session with the
//! configured user token and App-Token, uses the returned session token for
//! every subsequent request, and ends the session with `killSession` on
//! every exit path where cleanup is still allowed. See ADR 0009 "GLPI API
//! and authentication" for the resolved visibility precondition this
//! session lifecycle establishes.

use std::time::Instant;

use hyper::{
    Method,
    header::{HeaderName, HeaderValue},
};
use serde::Deserialize;

use crate::{config::ValidatedConfig, error::GlpiFailure, transport};

pub(crate) struct GlpiSession {
    pub(crate) token: String,
}

fn app_token_header(config: &ValidatedConfig) -> Result<(HeaderName, HeaderValue), GlpiFailure> {
    let mut value =
        HeaderValue::from_str(config.app_token.as_str()).map_err(|_| GlpiFailure::Transport)?;
    value.set_sensitive(true);
    Ok((HeaderName::from_static("app-token"), value))
}

fn session_token_header(session: &GlpiSession) -> Result<(HeaderName, HeaderValue), GlpiFailure> {
    let mut value = HeaderValue::from_str(&session.token).map_err(|_| GlpiFailure::Transport)?;
    value.set_sensitive(true);
    Ok((HeaderName::from_static("session-token"), value))
}

/// Starts a GLPI V1 session and returns its session token.
///
/// `GET initSession` with an empty body; `Authorization: user_token <token>`
/// and `App-Token` are headers, never query parameters.
pub(crate) async fn init_session(
    config: &ValidatedConfig,
    effective_deadline: Instant,
) -> Result<GlpiSession, GlpiFailure> {
    let url = config
        .base
        .join("initSession")
        .map_err(|_| GlpiFailure::Transport)?;
    let mut authorization =
        HeaderValue::from_str(&format!("user_token {}", config.user_token.as_str()))
            .map_err(|_| GlpiFailure::Transport)?;
    authorization.set_sensitive(true);
    let headers = [
        (hyper::header::AUTHORIZATION, authorization),
        app_token_header(config)?,
    ];

    let response = transport::request(
        &config.tls_connector,
        Method::GET,
        &url,
        &headers,
        None,
        effective_deadline,
    )
    .await?;

    if response.status != hyper::StatusCode::OK {
        return Err(GlpiFailure::SessionInitFailed);
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct InitSessionResponse {
        session_token: String,
    }

    let parsed: InitSessionResponse =
        serde_json::from_slice(&response.body).map_err(|_| GlpiFailure::SessionInitFailed)?;
    if parsed.session_token.is_empty() {
        return Err(GlpiFailure::SessionInitFailed);
    }

    Ok(GlpiSession {
        token: parsed.session_token,
    })
}

/// Forces the session to the complete set of entities the service account's
/// active profile grants, as the input to the `glpishowallentities`
/// visibility precondition. `POST changeActiveEntities` with a JSON body;
/// GLPI returns the bare JSON literal `true` on success.
pub(crate) async fn force_all_entities(
    config: &ValidatedConfig,
    session: &GlpiSession,
    effective_deadline: Instant,
) -> Result<(), GlpiFailure> {
    let url = config
        .base
        .join("changeActiveEntities")
        .map_err(|_| GlpiFailure::Transport)?;
    let headers = [session_token_header(session)?, app_token_header(config)?];
    let body = br#"{"entities_id":"all","is_recursive":true}"#.to_vec();

    let response = transport::request(
        &config.tls_connector,
        Method::POST,
        &url,
        &headers,
        Some(body),
        effective_deadline,
    )
    .await?;

    if response.status != hyper::StatusCode::OK {
        return Err(GlpiFailure::IncompleteVisibility);
    }

    let trimmed = trim_ascii(&response.body);
    if trimmed != b"true" {
        return Err(GlpiFailure::IncompleteVisibility);
    }

    Ok(())
}

/// Verifies the production-observable visibility precondition: after
/// [`force_all_entities`] succeeds, `session.glpishowallentities` must be
/// present and be exactly the JSON number `1`. `GET getFullSession` with an
/// empty body and no query parameters.
pub(crate) async fn verify_complete_visibility(
    config: &ValidatedConfig,
    session: &GlpiSession,
    effective_deadline: Instant,
) -> Result<(), GlpiFailure> {
    let url = config
        .base
        .join("getFullSession")
        .map_err(|_| GlpiFailure::Transport)?;
    let headers = [session_token_header(session)?, app_token_header(config)?];

    let response = transport::request(
        &config.tls_connector,
        Method::GET,
        &url,
        &headers,
        None,
        effective_deadline,
    )
    .await?;

    if response.status != hyper::StatusCode::OK {
        return Err(GlpiFailure::IncompleteVisibility);
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FullSessionResponse {
        // GLPI's session object is large, open-ended, and evolves across
        // releases; only the one required key is extracted, tolerantly, via
        // `serde_json::Value` for this field only. The outer envelope is
        // still validated strictly: exactly one `session` member.
        session: serde_json::Value,
    }

    let parsed: FullSessionResponse =
        serde_json::from_slice(&response.body).map_err(|_| GlpiFailure::IncompleteVisibility)?;
    let show_all = parsed
        .session
        .as_object()
        .and_then(|session| session.get("glpishowallentities"));

    match show_all {
        Some(serde_json::Value::Number(number)) if number.as_u64() == Some(1) => Ok(()),
        _ => Err(GlpiFailure::IncompleteVisibility),
    }
}

/// Ends the request-scoped session. `GET killSession` with an empty body.
pub(crate) async fn kill_session(
    config: &ValidatedConfig,
    session: &GlpiSession,
    effective_deadline: Instant,
) -> Result<(), GlpiFailure> {
    let url = config
        .base
        .join("killSession")
        .map_err(|_| GlpiFailure::Transport)?;
    let headers = [session_token_header(session)?, app_token_header(config)?];

    let response = transport::request(
        &config.tls_connector,
        Method::GET,
        &url,
        &headers,
        None,
        effective_deadline,
    )
    .await?;

    if response.status != hyper::StatusCode::OK {
        return Err(GlpiFailure::CleanupFailed);
    }

    // Mirror `force_all_entities`: a `200 OK` status alone is not sufficient
    // to consider the mutation successful. GLPI returns the bare JSON
    // literal `true` on a successful `killSession`; anything else is
    // rejected rather than assumed successful.
    let trimmed = trim_ascii(&response.body);
    if trimmed != b"true" {
        return Err(GlpiFailure::CleanupFailed);
    }

    Ok(())
}

pub(crate) fn session_headers(
    session: &GlpiSession,
    config: &ValidatedConfig,
) -> Result<[(HeaderName, HeaderValue); 2], GlpiFailure> {
    Ok([session_token_header(session)?, app_token_header(config)?])
}

pub(crate) fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|byte| !byte.is_ascii_whitespace());
    let end = bytes.iter().rposition(|byte| !byte.is_ascii_whitespace());
    match (start, end) {
        (Some(start), Some(end)) => &bytes[start..=end],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::trim_ascii;

    #[test]
    fn trims_ascii_whitespace() {
        assert_eq!(trim_ascii(b"  true \n"), b"true");
        assert_eq!(trim_ascii(b"true"), b"true");
        assert_eq!(trim_ascii(b"   "), b"");
    }
}
