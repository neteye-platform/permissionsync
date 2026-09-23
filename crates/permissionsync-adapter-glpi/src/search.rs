//! GLPI V1 semantic search-option discovery, paginated search, and exact
//! adapter-side matching. See ADR 0009 "User, entity, and profile
//! resolution" and "Authoritative reconciliation".

use std::{collections::HashMap, time::Instant};

use hyper::Method;
use permissionsync_core::SynchronizationContext;
use serde_json::Value;

use crate::{
    adapter::check_context, config::ValidatedConfig, error::GlpiFailure, session::GlpiSession,
    session::session_headers, transport,
};

/// Rows-per-page for every paginated GLPI search. Small and fixed so
/// pagination logic is always exercised even for small fixtures.
const PAGE_SIZE: u64 = 50;

/// Resolved GLPI V1 search-option ids for one itemtype's required semantic
/// fields, keyed by their stable `uid`.
pub(crate) struct SearchOptions {
    ids: HashMap<&'static str, u64>,
}

impl SearchOptions {
    fn require(&self, uid: &'static str) -> Result<u64, GlpiFailure> {
        self.ids
            .get(uid)
            .copied()
            .ok_or(GlpiFailure::SearchMetadataUnavailable)
    }
}

/// Fetches `listSearchOptions/:itemtype` and resolves the search-option id
/// for each requested stable `uid`. Missing or ambiguous (duplicate) `uid`
/// values are an adapter failure.
pub(crate) async fn resolve_search_options(
    config: &ValidatedConfig,
    session: &GlpiSession,
    itemtype: &str,
    required_uids: &[&'static str],
    effective_deadline: Instant,
) -> Result<SearchOptions, GlpiFailure> {
    let url = config
        .base
        .join(&format!("listSearchOptions/{itemtype}"))
        .map_err(|_| GlpiFailure::Transport)?;
    let headers = session_headers(session, config)?;

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
        return Err(GlpiFailure::SearchMetadataUnavailable);
    }

    let parsed: Value = serde_json::from_slice(&response.body)
        .map_err(|_| GlpiFailure::SearchMetadataUnavailable)?;
    let object = parsed
        .as_object()
        .ok_or(GlpiFailure::SearchMetadataUnavailable)?;

    let mut found: HashMap<&'static str, u64> = HashMap::new();
    for (key, value) in object {
        let Some(entry) = value.as_object() else {
            continue;
        };
        let Some(uid) = entry.get("uid").and_then(Value::as_str) else {
            continue;
        };
        let Some(required_uid) = required_uids.iter().find(|candidate| **candidate == uid) else {
            continue;
        };
        let Ok(option_id) = key.parse::<u64>() else {
            continue;
        };
        if found.insert(required_uid, option_id).is_some() {
            // A second search-option id claiming the same required `uid` is
            // ambiguous metadata: fail closed rather than pick one.
            return Err(GlpiFailure::SearchMetadataUnavailable);
        }
    }

    for required_uid in required_uids {
        if !found.contains_key(required_uid) {
            return Err(GlpiFailure::SearchMetadataUnavailable);
        }
    }

    Ok(SearchOptions { ids: found })
}

/// One raw search result row, keyed by search-option id (as GLPI returns it).
type Row = HashMap<u64, Value>;

/// Runs one complete paginated GLPI V1 search, applying one equality
/// criterion, and returns every row across every page. Fails on non-progress
/// (a page that does not advance the observed range) or inconsistent
/// `totalcount` between pages, rather than looping forever.
#[allow(clippy::too_many_arguments)]
async fn search_all_pages(
    config: &ValidatedConfig,
    session: &GlpiSession,
    itemtype: &str,
    criterion_field: u64,
    criterion_value: &str,
    forcedisplay: &[u64],
    sort_field: u64,
    context: &SynchronizationContext<'_>,
    effective_deadline: Instant,
) -> Result<Vec<Row>, GlpiFailure> {
    let mut rows = Vec::new();
    let mut start: u64 = 0;
    let mut expected_total: Option<u64> = None;

    loop {
        // Cancellation/deadline must be re-checked at the top of every page
        // iteration, not only once before the overall paginated search
        // starts: a large result set can span many pages, each involving a
        // real outbound request.
        check_context(context, effective_deadline)?;
        let end = start + PAGE_SIZE - 1;
        let mut url = config
            .base
            .join(&format!("search/{itemtype}"))
            .map_err(|_| GlpiFailure::Transport)?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("range", &format!("{start}-{end}"));
            query.append_pair("criteria[0][field]", &criterion_field.to_string());
            query.append_pair("criteria[0][searchtype]", "equals");
            query.append_pair("criteria[0][value]", criterion_value);
            // Pin an explicit, stable sort so monotonic page progress is
            // actually provable across pages, rather than relying on GLPI's
            // unspecified default order.
            query.append_pair("sort", &sort_field.to_string());
            query.append_pair("order", "ASC");
            for (index, field) in forcedisplay.iter().enumerate() {
                query.append_pair(&format!("forcedisplay[{index}]"), &field.to_string());
            }
        }
        let headers = session_headers(session, config)?;

        let response = transport::request(
            &config.tls_connector,
            Method::GET,
            &url,
            &headers,
            None,
            effective_deadline,
        )
        .await?;

        if response.status != hyper::StatusCode::OK
            && response.status != hyper::StatusCode::PARTIAL_CONTENT
        {
            return Err(GlpiFailure::SearchPagination);
        }

        let parsed: Value =
            serde_json::from_slice(&response.body).map_err(|_| GlpiFailure::SearchPagination)?;
        let object = parsed.as_object().ok_or(GlpiFailure::SearchPagination)?;
        let total_count = object
            .get("totalcount")
            .and_then(Value::as_u64)
            .ok_or(GlpiFailure::SearchPagination)?;
        let data = object
            .get("data")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        match expected_total {
            Some(expected) if expected != total_count => return Err(GlpiFailure::SearchPagination),
            None => expected_total = Some(total_count),
            _ => {}
        }

        if data.is_empty() && (rows.len() as u64) < total_count {
            // A page must make progress toward the declared total; an empty
            // page with rows still outstanding is malformed pagination.
            return Err(GlpiFailure::SearchPagination);
        }

        for entry in data {
            let Some(entry) = entry.as_object() else {
                return Err(GlpiFailure::SearchPagination);
            };
            let mut row = Row::new();
            for (key, value) in entry {
                if let Ok(option_id) = key.parse::<u64>() {
                    row.insert(option_id, value.clone());
                }
            }
            rows.push(row);
        }

        if (rows.len() as u64) >= total_count {
            break;
        }
        start += PAGE_SIZE;
    }

    Ok(rows)
}

fn exact_string_field(row: &Row, field: u64) -> Option<&str> {
    row.get(&field).and_then(Value::as_str)
}

fn numeric_id(row: &Row, field: u64) -> Option<u64> {
    row.get(&field).and_then(|value| match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.parse().ok(),
        _ => None,
    })
}

/// Resolves exactly one GLPI object id whose stable semantic field exactly
/// (case-sensitively) equals `selector`, using GLPI search as a narrowing
/// filter only. Zero or more than one exact match is an adapter failure.
#[allow(clippy::too_many_arguments)]
async fn resolve_exact_id(
    config: &ValidatedConfig,
    session: &GlpiSession,
    itemtype: &str,
    id_field: u64,
    name_field: u64,
    selector: &str,
    context: &SynchronizationContext<'_>,
    effective_deadline: Instant,
) -> Result<u64, GlpiFailure> {
    let rows = search_all_pages(
        config,
        session,
        itemtype,
        name_field,
        selector,
        &[id_field, name_field],
        id_field,
        context,
        effective_deadline,
    )
    .await?;

    let mut matches: Vec<u64> = Vec::new();
    for row in &rows {
        if exact_string_field(row, name_field) == Some(selector) {
            let id = numeric_id(row, id_field).ok_or(GlpiFailure::MalformedReference)?;
            if !matches.contains(&id) {
                matches.push(id);
            }
        }
    }

    match matches.as_slice() {
        [] => Err(GlpiFailure::MissingReference),
        [only] => Ok(*only),
        _ => Err(GlpiFailure::AmbiguousReference),
    }
}

pub(crate) async fn resolve_entity_id(
    config: &ValidatedConfig,
    session: &GlpiSession,
    options: &SearchOptions,
    selector: &str,
    context: &SynchronizationContext<'_>,
    effective_deadline: Instant,
) -> Result<u64, GlpiFailure> {
    resolve_exact_id(
        config,
        session,
        "Entity",
        options.require("Entity.id")?,
        options.require("Entity.completename")?,
        selector,
        context,
        effective_deadline,
    )
    .await
}

pub(crate) async fn resolve_profile_id(
    config: &ValidatedConfig,
    session: &GlpiSession,
    options: &SearchOptions,
    selector: &str,
    context: &SynchronizationContext<'_>,
    effective_deadline: Instant,
) -> Result<u64, GlpiFailure> {
    resolve_exact_id(
        config,
        session,
        "Profile",
        options.require("Profile.id")?,
        options.require("Profile.name")?,
        selector,
        context,
        effective_deadline,
    )
    .await
}

/// Resolves the exact GLPI user id for `username`, or `None` when zero
/// exact matches were found across the complete paginated result set. The
/// caller must only interpret `None` as absence once the complete-visibility
/// precondition has already been established.
pub(crate) async fn resolve_user_id(
    config: &ValidatedConfig,
    session: &GlpiSession,
    options: &SearchOptions,
    username: &str,
    context: &SynchronizationContext<'_>,
    effective_deadline: Instant,
) -> Result<Option<u64>, GlpiFailure> {
    match resolve_exact_id(
        config,
        session,
        "User",
        options.require("User.id")?,
        options.require("User.name")?,
        username,
        context,
        effective_deadline,
    )
    .await
    {
        Ok(id) => Ok(Some(id)),
        Err(GlpiFailure::MissingReference) => Ok(None),
        Err(error) => Err(error),
    }
}

/// The per-user `Profile_User` candidate-row sanity bound. Real GLPI
/// deployments own at most a small number of assignment rows per user; a
/// user with more candidate rows than this is treated as malformed search
/// metadata rather than issued an unbounded number of per-row item reads.
const MAX_ASSIGNMENTS_PER_USER: usize = 10_000;

/// Reads the complete current `Profile_User` assignment set for `user_id`.
///
/// `Profile_User`'s own search options expose only semantic joined display
/// fields (the joined `User.name`), never the raw `users_id`/`profiles_id`/
/// `entities_id`/`is_recursive` foreign-key fields, so GLPI search is used
/// only to discover candidate row ids for `username`. Every raw field is
/// then read authoritatively from the generic V1 item endpoint
/// `GET /apirest.php/Profile_User/:id`, which does return the raw fields
/// directly from the item.
pub(crate) async fn read_current_assignments(
    config: &ValidatedConfig,
    session: &GlpiSession,
    options: &SearchOptions,
    username: &str,
    user_id: u64,
    context: &SynchronizationContext<'_>,
    effective_deadline: Instant,
) -> Result<Vec<crate::plan::CurrentRow>, GlpiFailure> {
    let id_field = options.require("Profile_User.id")?;
    let user_name_field = options.require("User.name")?;

    let rows = search_all_pages(
        config,
        session,
        "Profile_User",
        user_name_field,
        username,
        &[id_field, user_name_field],
        id_field,
        context,
        effective_deadline,
    )
    .await?;

    let mut candidate_ids: Vec<u64> = Vec::new();
    for row in &rows {
        if exact_string_field(row, user_name_field) == Some(username) {
            let id = numeric_id(row, id_field).ok_or(GlpiFailure::MalformedReference)?;
            if !candidate_ids.contains(&id) {
                candidate_ids.push(id);
            }
        }
    }

    if candidate_ids.len() > MAX_ASSIGNMENTS_PER_USER {
        return Err(GlpiFailure::AssignmentCountExceeded);
    }

    let mut current = Vec::with_capacity(candidate_ids.len());
    for candidate_id in candidate_ids {
        let item =
            read_profile_user_item(config, session, candidate_id, effective_deadline).await?;
        if item.users_id != user_id {
            // The search-discovered candidate's own joined display name
            // matched `username` exactly, but its raw item-read `users_id`
            // must still equal the resolved synchronized user id. Fail
            // closed rather than silently drop or reconcile a mismatch.
            return Err(GlpiFailure::SearchPagination);
        }
        current.push(crate::plan::CurrentRow {
            id: candidate_id,
            entities_id: item.entities_id,
            profiles_id: item.profiles_id,
            is_recursive: item.is_recursive,
        });
    }

    Ok(current)
}

/// The raw fields of one `Profile_User` item, read directly from the
/// generic V1 item endpoint rather than from any search result row.
struct ProfileUserItem {
    users_id: u64,
    profiles_id: u64,
    entities_id: u64,
    is_recursive: bool,
}

/// Reads one `Profile_User` item's raw fields via
/// `GET /apirest.php/Profile_User/:id`, the generic V1 item endpoint. Every
/// field is validated at the same strictness as the item-read replaces:
/// `users_id`/`profiles_id`/`entities_id` must be plain numeric ids, and
/// `is_recursive` must be the raw wire integer `0` or `1`; anything else,
/// including a mismatched `id`, is rejected rather than coerced.
async fn read_profile_user_item(
    config: &ValidatedConfig,
    session: &GlpiSession,
    id: u64,
    effective_deadline: Instant,
) -> Result<ProfileUserItem, GlpiFailure> {
    let url = config
        .base
        .join(&format!("Profile_User/{id}"))
        .map_err(|_| GlpiFailure::Transport)?;
    let headers = session_headers(session, config)?;

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
        return Err(GlpiFailure::SearchPagination);
    }

    let parsed: Value =
        serde_json::from_slice(&response.body).map_err(|_| GlpiFailure::SearchPagination)?;
    let object = parsed.as_object().ok_or(GlpiFailure::SearchPagination)?;

    let item_id = object
        .get("id")
        .and_then(Value::as_u64)
        .ok_or(GlpiFailure::SearchPagination)?;
    if item_id != id {
        return Err(GlpiFailure::SearchPagination);
    }

    let users_id = object
        .get("users_id")
        .and_then(Value::as_u64)
        .ok_or(GlpiFailure::SearchPagination)?;
    let profiles_id = object
        .get("profiles_id")
        .and_then(Value::as_u64)
        .ok_or(GlpiFailure::SearchPagination)?;
    let entities_id = object
        .get("entities_id")
        .and_then(Value::as_u64)
        .ok_or(GlpiFailure::SearchPagination)?;
    let is_recursive = match object.get("is_recursive") {
        // GLPI's `is_recursive` column is a raw integer (0 or 1) on the
        // wire; anything else (bool, string, other numbers, absent) is
        // rejected rather than coerced.
        Some(Value::Number(number)) if number.as_u64() == Some(0) => false,
        Some(Value::Number(number)) if number.as_u64() == Some(1) => true,
        _ => return Err(GlpiFailure::SearchPagination),
    };

    Ok(ProfileUserItem {
        users_id,
        profiles_id,
        entities_id,
        is_recursive,
    })
}

pub(crate) const REQUIRED_ENTITY_UIDS: &[&str] = &["Entity.id", "Entity.completename"];
pub(crate) const REQUIRED_PROFILE_UIDS: &[&str] = &["Profile.id", "Profile.name"];
pub(crate) const REQUIRED_USER_UIDS: &[&str] = &["User.id", "User.name"];
pub(crate) const REQUIRED_PROFILE_USER_UIDS: &[&str] = &["Profile_User.id", "User.name"];
