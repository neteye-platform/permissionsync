//! GLPI V1 mutation requests: user creation, assignment creation, and
//! assignment deletion. One mutation per HTTP request; never batched.

use std::{fmt, time::Instant};

use hyper::Method;
use serde::Deserialize;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

use crate::{
    config::{GlpiAuthenticationSource, ValidatedConfig},
    error::GlpiFailure,
    session::{GlpiSession, session_headers},
    transport,
};

fn parse_created_id(body: &[u8]) -> Result<u64, GlpiFailure> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CreatedResponse {
        id: u64,
        message: String,
        // API::createItems conditionally adds this documented field when an
        // upload result was requested; no other response extension is
        // accepted.
        #[serde(default)]
        upload_result: Option<Value>,
    }

    let parsed: CreatedResponse =
        serde_json::from_slice(body).map_err(|_| GlpiFailure::MutationFailed)?;
    if parsed.id == 0 {
        return Err(GlpiFailure::MutationFailed);
    }
    let _ = parsed.message;
    let _ = parsed.upload_result;
    Ok(parsed.id)
}

fn parse_deleted_assignment(body: &[u8], assignment_id: u64) -> Result<(), GlpiFailure> {
    let expected_id = assignment_id.to_string();
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    DeletionResponse {
        expected_id: &expected_id,
    }
    .deserialize(&mut deserializer)
    .and_then(|()| deserializer.end())
    .map_err(|_| GlpiFailure::MutationFailed)
}

struct DeletionResponse<'a> {
    expected_id: &'a str,
}

impl<'de> DeserializeSeed<'de> for DeletionResponse<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(DeletionResponseVisitor {
            expected_id: self.expected_id,
        })
    }
}

struct DeletionResponseVisitor<'a> {
    expected_id: &'a str,
}

impl<'de> Visitor<'de> for DeletionResponseVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a one-element GLPI deletion response array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        sequence
            .next_element_seed(DeletionEntry {
                expected_id: self.expected_id,
            })?
            .ok_or_else(|| serde::de::Error::custom("missing deletion entry"))?;
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom("multiple deletion entries"));
        }
        Ok(())
    }
}

struct DeletionEntry<'a> {
    expected_id: &'a str,
}

impl<'de> DeserializeSeed<'de> for DeletionEntry<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(DeletionEntryVisitor {
            expected_id: self.expected_id,
        })
    }
}

struct DeletionEntryVisitor<'a> {
    expected_id: &'a str,
}

impl<'de> Visitor<'de> for DeletionEntryVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("one successful requested GLPI deletion entry")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut success = None;
        let mut message = None;

        while let Some(key) = map.next_key::<String>()? {
            if key == self.expected_id {
                if success.is_some() {
                    return Err(serde::de::Error::custom("duplicate deletion id"));
                }
                success = Some(map.next_value::<bool>()?);
            } else if key == "message" {
                if message.is_some() {
                    return Err(serde::de::Error::duplicate_field("message"));
                }
                message = Some(map.next_value::<String>()?);
            } else {
                return Err(serde::de::Error::unknown_field(&key, &[]));
            }
        }

        if success != Some(true) || message.is_none() {
            return Err(serde::de::Error::custom("unsuccessful deletion entry"));
        }
        Ok(())
    }
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

    parse_deleted_assignment(&response.body, assignment_id)
}

#[cfg(test)]
mod tests {
    use super::{parse_created_id, parse_deleted_assignment};

    #[test]
    fn creation_response_requires_a_positive_id_and_message() {
        assert_eq!(
            parse_created_id(br#"{"id":42,"message":"created"}"#).expect("valid response"),
            42
        );

        for body in [
            br#"{"id":0,"message":"created"}"#.as_slice(),
            br#"{"id":42}"#.as_slice(),
            br#"{"id":false,"message":"created"}"#.as_slice(),
            br#"{"id":42,"message":false}"#.as_slice(),
            br#"{"id":42,"message":"created","unexpected":true}"#.as_slice(),
            br#"[]"#.as_slice(),
        ] {
            assert!(parse_created_id(body).is_err(), "must reject {body:?}");
        }
    }

    #[test]
    fn creation_response_allows_the_upstream_upload_result_extension() {
        assert_eq!(
            parse_created_id(br#"{"id":42,"message":"created","upload_result":{}}"#)
                .expect("documented extension"),
            42
        );
    }

    #[test]
    fn deletion_response_requires_one_successful_requested_id_and_message() {
        assert!(parse_deleted_assignment(br#"[{"42":true,"message":"deleted"}]"#, 42).is_ok());

        for body in [
            br#"true"#.as_slice(),
            br#"[{"42":false,"message":"deleted"}]"#.as_slice(),
            br#"[{"41":true,"message":"deleted"}]"#.as_slice(),
            br#"[{"42":true}]"#.as_slice(),
            br#"[{"42":true,"message":false}]"#.as_slice(),
            br#"[{"42":true,"message":"deleted"},{"42":true,"message":"deleted"}]"#.as_slice(),
            br#"[{"42":true,"message":"deleted","unexpected":true}]"#.as_slice(),
            br#"[{"42":true,"42":true,"message":"deleted"}]"#.as_slice(),
        ] {
            assert!(
                parse_deleted_assignment(body, 42).is_err(),
                "must reject {body:?}"
            );
        }
    }
}
