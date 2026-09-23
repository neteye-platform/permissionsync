//! GLPI V1 semantic search-option discovery, paginated search, and exact
//! adapter-side matching. See ADR 0009 "User, entity, and profile
//! resolution" and "Authoritative reconciliation".

use std::{collections::HashMap, time::Instant};

use hyper::Method;
use permissionsync_core::SynchronizationContext;
use serde::Deserialize;
use serde_json::Value;

use crate::{
    adapter::effective_deadline, config::ValidatedConfig, error::GlpiFailure, session::GlpiSession,
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
) -> Result<Vec<Row>, GlpiFailure> {
    let mut rows = Vec::new();
    let mut start: u64 = 0;
    let mut expected_total: Option<u64> = None;

    loop {
        let end = start
            .checked_add(PAGE_SIZE - 1)
            .ok_or(GlpiFailure::SearchPagination)?;
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
        // Each search page is a separate outbound operation. Compute its
        // deadline immediately before issuing the request, never once for
        // the helper-wide pagination loop.
        let effective_deadline = effective_deadline(context, config.operation_timeout)?;

        let response = transport::request(
            &config.tls_connector,
            Method::GET,
            &url,
            &headers,
            None,
            effective_deadline,
        )
        .await?;

        let page = parse_search_page(&response.body, start, end)?;
        let expected_status = if page.count == page.total_count {
            hyper::StatusCode::OK
        } else {
            hyper::StatusCode::PARTIAL_CONTENT
        };
        if response.status != expected_status {
            return Err(GlpiFailure::SearchPagination);
        }

        match expected_total {
            Some(expected) if expected != page.total_count => {
                return Err(GlpiFailure::SearchPagination);
            }
            None => expected_total = Some(page.total_count),
            _ => {}
        }

        for entry in page.data {
            let Some(entry) = entry.as_object() else {
                return Err(GlpiFailure::SearchPagination);
            };
            let mut row = Row::new();
            for (key, value) in entry {
                let option_id = key
                    .parse::<u64>()
                    .map_err(|_| GlpiFailure::SearchPagination)?;
                row.insert(option_id, value.clone());
            }
            rows.push(row);
        }

        if page.total_count == 0 {
            break;
        }
        if rows.len() as u64 != page.returned_end.saturating_add(1) {
            return Err(GlpiFailure::SearchPagination);
        }
        if rows.len() as u64 == page.total_count {
            break;
        }
        start = page
            .returned_end
            .checked_add(1)
            .ok_or(GlpiFailure::SearchPagination)?;
    }

    Ok(rows)
}

struct SearchPage {
    total_count: u64,
    count: u64,
    returned_end: u64,
    data: Vec<Value>,
}

#[derive(Default)]
enum SearchData {
    #[default]
    Missing,
    Present(Vec<Value>),
}

impl<'de> Deserialize<'de> for SearchData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Vec::<Value>::deserialize(deserializer).map(Self::Present)
    }
}

#[derive(Deserialize)]
struct WireSearchPage {
    totalcount: u64,
    count: u64,
    #[serde(rename = "content-range")]
    content_range: String,
    #[serde(default)]
    data: SearchData,
}

/// Parses the exact GLPI 11.0.9 V1 search response metadata. GLPI emits
/// `0--1/0` with no `data` member for a zero-result search; non-empty result
/// sets always include an array-valued `data` member and a normal inclusive
/// `start-end/total` content range.
fn parse_search_page(
    body: &[u8],
    requested_start: u64,
    requested_end: u64,
) -> Result<SearchPage, GlpiFailure> {
    let WireSearchPage {
        totalcount: total_count,
        count,
        content_range,
        data,
    } = serde_json::from_slice(body).map_err(|_| GlpiFailure::SearchPagination)?;

    if total_count == 0 {
        // API::searchItems clamps the requested end to totalcount - 1, which
        // is -1 for zero results. It does not initialize `data` when no rows
        // are emitted (API.php:1752-1880 at GLPI 11.0.9).
        if requested_start != 0
            || count != 0
            || content_range != "0--1/0"
            || !matches!(data, SearchData::Missing)
        {
            return Err(GlpiFailure::SearchPagination);
        }
        return Ok(SearchPage {
            total_count,
            count,
            returned_end: 0,
            data: Vec::new(),
        });
    }

    let SearchData::Present(data) = data else {
        return Err(GlpiFailure::SearchPagination);
    };
    if count == 0 || count != data.len() as u64 || count > total_count {
        return Err(GlpiFailure::SearchPagination);
    }

    let (range, range_total) = content_range
        .rsplit_once('/')
        .ok_or(GlpiFailure::SearchPagination)?;
    let range_total = range_total
        .parse::<u64>()
        .map_err(|_| GlpiFailure::SearchPagination)?;
    let (returned_start, returned_end) =
        range.split_once('-').ok_or(GlpiFailure::SearchPagination)?;
    let returned_start = returned_start
        .parse::<u64>()
        .map_err(|_| GlpiFailure::SearchPagination)?;
    let returned_end = returned_end
        .parse::<u64>()
        .map_err(|_| GlpiFailure::SearchPagination)?;

    if range_total != total_count
        || returned_start != requested_start
        || returned_end < returned_start
        || returned_end > requested_end
        || returned_end >= total_count
        || returned_end
            .checked_sub(returned_start)
            .and_then(|width| width.checked_add(1))
            != Some(count)
        // A short page is valid only for the final, clamped range. Any other
        // short page would skip rows when the next request starts at end + 1.
        || (returned_end != requested_end && returned_end != total_count - 1)
    {
        return Err(GlpiFailure::SearchPagination);
    }

    Ok(SearchPage {
        total_count,
        count,
        returned_end,
        data: data.clone(),
    })
}

fn exact_string_field(row: &Row, field: u64) -> Option<&str> {
    row.get(&field).and_then(Value::as_str)
}

/// Extracts a numeric id field. `allow_zero` must be `true` only for
/// `Entity.id`: GLPI's own top-level "Root entity" is physically id `0`
/// (see `install/empty_data.php`), so a blanket "zero is never a usable id"
/// rule would make the root entity permanently unresolvable as a desired
/// selector. Every other itemtype's search-result/candidate id
/// (`Profile.id`, `User.id`, `Profile_User.id`) is a positive database id;
/// zero there remains a malformed-reference failure.
fn numeric_id(row: &Row, field: u64, allow_zero: bool) -> Option<u64> {
    row.get(&field)
        .and_then(|value| match value {
            Value::Number(number) => number.as_u64(),
            Value::String(text) => text.parse().ok(),
            _ => None,
        })
        .filter(|id| allow_zero || *id != 0)
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
    allow_zero_id: bool,
    context: &SynchronizationContext<'_>,
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
    )
    .await?;

    let mut matches: Vec<u64> = Vec::new();
    for row in &rows {
        if exact_string_field(row, name_field) == Some(selector) {
            let id =
                numeric_id(row, id_field, allow_zero_id).ok_or(GlpiFailure::MalformedReference)?;
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
) -> Result<u64, GlpiFailure> {
    resolve_exact_id(
        config,
        session,
        "Entity",
        options.require("Entity.id")?,
        options.require("Entity.completename")?,
        selector,
        // GLPI's root entity is physically id 0; it must remain resolvable
        // as a desired `entity` selector (e.g. bare "Root entity").
        true,
        context,
    )
    .await
}

pub(crate) async fn resolve_profile_id(
    config: &ValidatedConfig,
    session: &GlpiSession,
    options: &SearchOptions,
    selector: &str,
    context: &SynchronizationContext<'_>,
) -> Result<u64, GlpiFailure> {
    resolve_exact_id(
        config,
        session,
        "Profile",
        options.require("Profile.id")?,
        options.require("Profile.name")?,
        selector,
        false,
        context,
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
) -> Result<Option<u64>, GlpiFailure> {
    match resolve_exact_id(
        config,
        session,
        "User",
        options.require("User.id")?,
        options.require("User.name")?,
        username,
        false,
        context,
    )
    .await
    {
        Ok(id) => Ok(Some(id)),
        Err(GlpiFailure::MissingReference) => Ok(None),
        Err(error) => Err(error),
    }
}

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
    )
    .await?;

    let mut candidate_ids: Vec<u64> = Vec::new();
    for row in &rows {
        if exact_string_field(row, user_name_field) == Some(username) {
            let id = numeric_id(row, id_field, false).ok_or(GlpiFailure::MalformedReference)?;
            if !candidate_ids.contains(&id) {
                candidate_ids.push(id);
            }
        }
    }

    let mut current = Vec::with_capacity(candidate_ids.len());
    for candidate_id in candidate_ids {
        let item = read_profile_user_item(config, session, candidate_id, context).await?;
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
/// `id`, `users_id`, and `profiles_id` must be positive plain numeric ids;
/// `entities_id` is a plain numeric id and may be zero for GLPI's root entity;
/// and `is_recursive` must be the raw wire integer `0` or `1`. Anything else,
/// including a mismatched `id`, is rejected rather than coerced.
async fn read_profile_user_item(
    config: &ValidatedConfig,
    session: &GlpiSession,
    id: u64,
    context: &SynchronizationContext<'_>,
) -> Result<ProfileUserItem, GlpiFailure> {
    let url = config
        .base
        .join(&format!("Profile_User/{id}"))
        .map_err(|_| GlpiFailure::Transport)?;
    let headers = session_headers(session, config)?;
    // Each item read is a separate outbound operation. This check is also the
    // cancellation/overall-deadline gate before every raw Profile_User read.
    let effective_deadline = effective_deadline(context, config.operation_timeout)?;

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
        .filter(|id| *id != 0)
        .ok_or(GlpiFailure::SearchPagination)?;
    if item_id != id {
        return Err(GlpiFailure::SearchPagination);
    }

    let users_id = object
        .get("users_id")
        .and_then(Value::as_u64)
        .filter(|id| *id != 0)
        .ok_or(GlpiFailure::SearchPagination)?;
    let profiles_id = object
        .get("profiles_id")
        .and_then(Value::as_u64)
        .filter(|id| *id != 0)
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

#[cfg(test)]
mod tests {
    use super::parse_search_page;

    #[test]
    fn search_page_accepts_glpi_zero_result_shape() {
        let page = parse_search_page(
            br#"{"totalcount":0,"count":0,"content-range":"0--1/0"}"#,
            0,
            49,
        )
        .expect("GLPI's zero-result shape must be accepted");

        assert_eq!(page.total_count, 0);
        assert!(page.data.is_empty());
    }

    #[test]
    fn search_page_requires_complete_consistent_metadata() {
        let page = parse_search_page(
            br#"{"totalcount":51,"count":50,"content-range":"0-49/51","data":[{},{}]}"#,
            0,
            49,
        );
        assert!(page.is_err(), "count must equal data length");

        for body in [
            br#"{"totalcount":1,"count":1,"data":[{}]}"#.as_slice(),
            br#"{"totalcount":1,"count":1,"content-range":"0-0/1"}"#.as_slice(),
            br#"{"totalcount":1,"count":1,"content-range":"1-1/1","data":[{}]}"#.as_slice(),
            br#"{"totalcount":2,"count":1,"content-range":"0-0/1","data":[{}]}"#.as_slice(),
            br#"{"totalcount":2,"count":1,"content-range":"0-0/2","data":[]}"#.as_slice(),
            br#"{"totalcount":0,"count":0,"content-range":"0-0/0","data":[]}"#.as_slice(),
        ] {
            assert!(
                parse_search_page(body, 0, 49).is_err(),
                "must reject {body:?}"
            );
        }
    }

    #[test]
    fn search_page_accepts_a_final_short_inclusive_range_only() {
        let page = parse_search_page(
            br#"{"totalcount":51,"count":1,"content-range":"50-50/51","data":[{}]}"#,
            50,
            99,
        )
        .expect("final clamped page must be accepted");
        assert_eq!(page.returned_end, 50);

        assert!(
            parse_search_page(
                br#"{"totalcount":100,"count":1,"content-range":"50-50/100","data":[{}]}"#,
                50,
                99,
            )
            .is_err(),
            "non-final short pages must be rejected"
        );
    }
}
