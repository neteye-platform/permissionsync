//! GLPI V1 semantic search-option discovery, paginated search, and exact
//! adapter-side matching. See ADR 0009 "User, entity, and profile
//! resolution" and "Authoritative reconciliation".

use std::{collections::HashMap, time::Instant};

use hyper::Method;
use serde_json::Value;

use crate::{
    config::ValidatedConfig, error::GlpiFailure, session::GlpiSession, session::session_headers,
    transport,
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
async fn search_all_pages(
    config: &ValidatedConfig,
    session: &GlpiSession,
    itemtype: &str,
    criterion_field: u64,
    criterion_value: &str,
    forcedisplay: &[u64],
    effective_deadline: Instant,
) -> Result<Vec<Row>, GlpiFailure> {
    let mut rows = Vec::new();
    let mut start: u64 = 0;
    let mut expected_total: Option<u64> = None;

    loop {
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
async fn resolve_exact_id(
    config: &ValidatedConfig,
    session: &GlpiSession,
    itemtype: &str,
    id_field: u64,
    name_field: u64,
    selector: &str,
    effective_deadline: Instant,
) -> Result<u64, GlpiFailure> {
    let rows = search_all_pages(
        config,
        session,
        itemtype,
        name_field,
        selector,
        &[id_field, name_field],
        effective_deadline,
    )
    .await?;

    let mut matches: Vec<u64> = Vec::new();
    for row in &rows {
        if exact_string_field(row, name_field) == Some(selector) {
            let id = numeric_id(row, id_field).ok_or(GlpiFailure::MissingReference)?;
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
    effective_deadline: Instant,
) -> Result<u64, GlpiFailure> {
    resolve_exact_id(
        config,
        session,
        "Entity",
        options.require("Entity.id")?,
        options.require("Entity.completename")?,
        selector,
        effective_deadline,
    )
    .await
}

pub(crate) async fn resolve_profile_id(
    config: &ValidatedConfig,
    session: &GlpiSession,
    options: &SearchOptions,
    selector: &str,
    effective_deadline: Instant,
) -> Result<u64, GlpiFailure> {
    resolve_exact_id(
        config,
        session,
        "Profile",
        options.require("Profile.id")?,
        options.require("Profile.name")?,
        selector,
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
    effective_deadline: Instant,
) -> Result<Option<u64>, GlpiFailure> {
    match resolve_exact_id(
        config,
        session,
        "User",
        options.require("User.id")?,
        options.require("User.name")?,
        username,
        effective_deadline,
    )
    .await
    {
        Ok(id) => Ok(Some(id)),
        Err(GlpiFailure::MissingReference) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Reads the complete current `Profile_User` assignment set for `user_id`.
pub(crate) async fn read_current_assignments(
    config: &ValidatedConfig,
    session: &GlpiSession,
    options: &SearchOptions,
    user_id: u64,
    effective_deadline: Instant,
) -> Result<Vec<crate::plan::CurrentRow>, GlpiFailure> {
    let id_field = options.require("Profile_User.id")?;
    let users_id_field = options.require("Profile_User.users_id")?;
    let profiles_id_field = options.require("Profile_User.profiles_id")?;
    let entities_id_field = options.require("Profile_User.entities_id")?;
    let is_recursive_field = options.require("Profile_User.is_recursive")?;

    let rows = search_all_pages(
        config,
        session,
        "Profile_User",
        users_id_field,
        &user_id.to_string(),
        &[
            id_field,
            users_id_field,
            profiles_id_field,
            entities_id_field,
            is_recursive_field,
        ],
        effective_deadline,
    )
    .await?;

    let mut current = Vec::with_capacity(rows.len());
    for row in &rows {
        let id = numeric_id(row, id_field).ok_or(GlpiFailure::SearchPagination)?;
        let entities_id =
            numeric_id(row, entities_id_field).ok_or(GlpiFailure::SearchPagination)?;
        let profiles_id =
            numeric_id(row, profiles_id_field).ok_or(GlpiFailure::SearchPagination)?;
        let is_recursive = match row.get(&is_recursive_field) {
            Some(Value::Bool(value)) => *value,
            Some(Value::Number(number)) => number.as_u64() == Some(1),
            Some(Value::String(text)) => text == "1",
            _ => return Err(GlpiFailure::SearchPagination),
        };
        current.push(crate::plan::CurrentRow {
            id,
            entities_id,
            profiles_id,
            is_recursive,
        });
    }

    Ok(current)
}

pub(crate) const REQUIRED_ENTITY_UIDS: &[&str] = &["Entity.id", "Entity.completename"];
pub(crate) const REQUIRED_PROFILE_UIDS: &[&str] = &["Profile.id", "Profile.name"];
pub(crate) const REQUIRED_USER_UIDS: &[&str] = &["User.id", "User.name"];
pub(crate) const REQUIRED_PROFILE_USER_UIDS: &[&str] = &[
    "Profile_User.id",
    "Profile_User.users_id",
    "Profile_User.profiles_id",
    "Profile_User.entities_id",
    "Profile_User.is_recursive",
];
