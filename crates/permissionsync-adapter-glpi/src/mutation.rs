//! GLPI V1 mutation requests: user creation, assignment creation, and
//! assignment deletion. One mutation per HTTP request; never batched.

use std::time::Instant;

use hyper::Method;
use serde_json::Value;

use crate::{
    config::{GlpiAuthenticationSource, ValidatedConfig},
    error::GlpiFailure,
    session::{GlpiSession, session_headers, trim_ascii},
    transport,
};

fn parse_created_id(body: &[u8]) -> Result<u64, GlpiFailure> {
    let parsed: Value = serde_json::from_slice(body).map_err(|_| GlpiFailure::MutationFailed)?;
    let object = parsed.as_object().ok_or(GlpiFailure::MutationFailed)?;
    if object.len() != 1 {
        return Err(GlpiFailure::MutationFailed);
    }
    let id = object
        .get("id")
        .and_then(Value::as_u64)
        .ok_or(GlpiFailure::MutationFailed)?;
    if id == 0 {
        return Err(GlpiFailure::MutationFailed);
    }
    Ok(id)
}

/// Creates the exact synchronized username, using only configured
/// authentication-source fields. Never includes a password or unrelated
/// user attributes; never derives fields from Provider payload.
pub(crate) async fn create_user(
    config: &ValidatedConfig,
    session: &GlpiSession,
    username: &str,
    authentication_source: &GlpiAuthenticationSource,
    effective_deadline: Instant,
) -> Result<u64, GlpiFailure> {
    let url = config
        .base
        .join("User")
        .map_err(|_| GlpiFailure::Transport)?;
    let headers = session_headers(session, config)?;

    let mut input = serde_json::Map::new();
    input.insert("name".to_owned(), Value::String(username.to_owned()));
    if let Some(authtype) = authentication_source.authtype {
        input.insert("authtype".to_owned(), Value::from(authtype));
    }
    if let Some(auths_id) = authentication_source.auths_id {
        input.insert("auths_id".to_owned(), Value::from(auths_id));
    }
    let body = serde_json::to_vec(&serde_json::json!({ "input": Value::Object(input) }))
        .map_err(|_| GlpiFailure::MutationFailed)?;

    let response = transport::request(
        &config.tls_connector,
        Method::POST,
        &url,
        &headers,
        Some(body),
        effective_deadline,
    )
    .await?;

    if response.status != hyper::StatusCode::CREATED {
        return Err(GlpiFailure::UserCreationFailed);
    }

    parse_created_id(&response.body).map_err(|_| GlpiFailure::UserCreationFailed)
}

/// Creates exactly one `Profile_User` assignment row.
pub(crate) async fn create_assignment(
    config: &ValidatedConfig,
    session: &GlpiSession,
    users_id: u64,
    profiles_id: u64,
    entities_id: u64,
    is_recursive: bool,
    effective_deadline: Instant,
) -> Result<u64, GlpiFailure> {
    let url = config
        .base
        .join("Profile_User")
        .map_err(|_| GlpiFailure::Transport)?;
    let headers = session_headers(session, config)?;
    let body = serde_json::to_vec(&serde_json::json!({
        "input": {
            "users_id": users_id,
            "profiles_id": profiles_id,
            "entities_id": entities_id,
            "is_recursive": is_recursive,
        }
    }))
    .map_err(|_| GlpiFailure::MutationFailed)?;

    let response = transport::request(
        &config.tls_connector,
        Method::POST,
        &url,
        &headers,
        Some(body),
        effective_deadline,
    )
    .await?;

    if response.status != hyper::StatusCode::CREATED {
        return Err(GlpiFailure::MutationFailed);
    }

    parse_created_id(&response.body)
}

/// Deletes exactly one `Profile_User` row by its physical id.
pub(crate) async fn delete_assignment(
    config: &ValidatedConfig,
    session: &GlpiSession,
    assignment_id: u64,
    effective_deadline: Instant,
) -> Result<(), GlpiFailure> {
    let url = config
        .base
        .join(&format!("Profile_User/{assignment_id}"))
        .map_err(|_| GlpiFailure::Transport)?;
    let headers = session_headers(session, config)?;

    let response = transport::request(
        &config.tls_connector,
        Method::DELETE,
        &url,
        &headers,
        None,
        effective_deadline,
    )
    .await?;

    if response.status != hyper::StatusCode::OK {
        return Err(GlpiFailure::MutationFailed);
    }

    // Mirror `force_all_entities`/`kill_session`: a `200 OK` status alone is
    // not sufficient to consider the deletion successful. GLPI returns the
    // bare JSON literal `true` on a successful delete; anything else is
    // rejected rather than assumed successful.
    let trimmed = trim_ascii(&response.body);
    if trimmed != b"true" {
        return Err(GlpiFailure::MutationFailed);
    }

    Ok(())
}
