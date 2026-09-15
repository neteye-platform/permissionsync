use hyper::{
    HeaderMap,
    header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE},
};
use permissionsync_core::{DesiredStateEnvelope, EnvelopeVersion, IdentityContext, OpaquePayload};
use serde::{Deserialize, Serialize};

use crate::error::ProviderFailure;

/// Serializes the fixed Provider request object without changing identity values.
pub(crate) fn serialize_request_body(
    identity: &IdentityContext,
) -> Result<Vec<u8>, ProviderFailure> {
    serde_json::to_vec(&RequestBody {
        username: identity.username(),
        groups: identity.groups(),
    })
    .map_err(|_| ProviderFailure::RequestSerialization)
}

/// Validates all `Content-Type` field values on a candidate successful response.
pub(crate) fn validate_success_content_type(content_types: &[&str]) -> Result<(), ProviderFailure> {
    let [content_type] = content_types else {
        return Err(ProviderFailure::ResponseMetadata);
    };

    let media_type = content_type
        .parse::<mime::Mime>()
        .map_err(|_| ProviderFailure::ResponseMetadata)?;

    if !media_type
        .type_()
        .as_str()
        .eq_ignore_ascii_case("application")
        || !media_type.subtype().as_str().eq_ignore_ascii_case("json")
    {
        return Err(ProviderFailure::ResponseMetadata);
    }

    // `Mime::get_param` only ever returns the first matching parameter, so a
    // contradictory or merely duplicated `charset` parameter would otherwise
    // go unnoticed. Inspect every parameter explicitly instead.
    let mut charsets = media_type
        .params()
        .filter(|(name, _)| *name == mime::CHARSET)
        .map(|(_, value)| value);

    if let Some(charset) = charsets.next() {
        if charsets.next().is_some() {
            return Err(ProviderFailure::ResponseMetadata);
        }

        let charset = charset.as_str();
        if !charset.eq_ignore_ascii_case("utf-8") && !charset.eq_ignore_ascii_case("utf8") {
            return Err(ProviderFailure::ResponseMetadata);
        }
    }

    Ok(())
}

/// Validates all `Content-Encoding` field values on a candidate successful response.
pub(crate) fn validate_success_content_encoding(
    content_encodings: &[&str],
) -> Result<(), ProviderFailure> {
    for content_encoding in content_encodings {
        let mut found_coding = false;

        for coding in content_encoding.split(',') {
            let coding = coding.trim();
            if coding.is_empty() || !coding.eq_ignore_ascii_case("identity") {
                return Err(ProviderFailure::ResponseMetadata);
            }
            found_coding = true;
        }

        if !found_coding {
            return Err(ProviderFailure::ResponseMetadata);
        }
    }

    Ok(())
}

/// Validates metadata for a candidate successful response before body buffering.
pub(crate) fn validate_success_headers(
    headers: &HeaderMap,
    limit: usize,
) -> Result<Option<usize>, ProviderFailure> {
    let content_types = header_values(headers, CONTENT_TYPE)?;
    validate_success_content_type(&content_types)?;

    let content_encodings = header_values(headers, CONTENT_ENCODING)?;
    validate_success_content_encoding(&content_encodings)?;

    let content_lengths = header_values(headers, CONTENT_LENGTH)?;
    let declared_length = match content_lengths.as_slice() {
        [] => None,
        [content_length] => Some(parse_content_length(content_length)?),
        _ => return Err(ProviderFailure::ResponseMetadata),
    };

    if declared_length.is_some_and(|content_length| content_length > limit) {
        return Err(ProviderFailure::ResponseTooLarge);
    }

    Ok(declared_length)
}

/// Parses one complete, structurally valid Provider desired-state envelope.
pub(crate) fn parse_success_envelope(body: &[u8]) -> Result<DesiredStateEnvelope, ProviderFailure> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let envelope = ResponseEnvelope::deserialize(&mut deserializer)
        .map_err(|_| ProviderFailure::ResponseEnvelope)?;
    serde_json::de::Deserializer::end(&mut deserializer)
        .map_err(|_| ProviderFailure::ResponseEnvelope)?;

    let payload = OpaquePayload::try_from(envelope.payload.get().to_owned())
        .map_err(|_| ProviderFailure::ResponseEnvelope)?;

    Ok(DesiredStateEnvelope::new(
        EnvelopeVersion::new(envelope.version),
        payload,
    ))
}

#[derive(Serialize)]
struct RequestBody<'a> {
    username: &'a str,
    groups: &'a [String],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseEnvelope {
    version: u64,
    payload: Box<serde_json::value::RawValue>,
}

fn header_values(
    headers: &HeaderMap,
    name: hyper::header::HeaderName,
) -> Result<Vec<&str>, ProviderFailure> {
    headers
        .get_all(name)
        .iter()
        .map(|value| {
            value
                .to_str()
                .map_err(|_| ProviderFailure::ResponseMetadata)
        })
        .collect()
}

fn parse_content_length(content_length: &str) -> Result<usize, ProviderFailure> {
    if content_length.is_empty() || !content_length.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ProviderFailure::ResponseMetadata);
    }

    content_length
        .parse()
        .map_err(|_| ProviderFailure::ResponseMetadata)
}

#[cfg(test)]
mod tests {
    use permissionsync_core::IdentityContext;

    use super::{
        parse_success_envelope, serialize_request_body, validate_success_content_encoding,
        validate_success_content_type, validate_success_headers,
    };
    use hyper::{
        HeaderMap,
        header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue},
    };

    #[test]
    fn request_serialization_preserves_identity_values_and_member_order() {
        let identity = IdentityContext::new(
            "  m\u{00fc}ller\t".to_owned(),
            vec![
                "/staff".to_owned(),
                "/staff".to_owned(),
                " group ".to_owned(),
            ],
        );

        let body = serialize_request_body(&identity).unwrap();

        assert_eq!(
            body,
            "{\"username\":\"  m\u{00fc}ller\\t\",\"groups\":[\"/staff\",\"/staff\",\" group \"]}"
                .as_bytes()
        );
    }

    #[test]
    fn accepts_json_content_type_with_optional_utf8_compatible_charset() {
        for content_type in [
            "application/json",
            "application/json; charset=utf-8",
            "Application/Json; charset=UTF-8",
            "application/json; charset=utf8",
            r#"application/json; charset="UTF-8""#,
        ] {
            assert!(
                validate_success_content_type(&[content_type]).is_ok(),
                "{content_type}"
            );
        }
    }

    #[test]
    fn rejects_non_json_contradictory_or_malformed_content_type() {
        for content_types in [
            &[][..],
            &["application/json", "application/json"][..],
            &["application/json", "text/plain"][..],
            &["application/problem+json"][..],
            &["text/json"][..],
            &["application/json; charset=iso-8859-1"][..],
            &["application/json; charset=utf-8; charset=iso-8859-1"][..],
            &["application/json; charset=utf-8; charset=utf-8"][..],
            &[""][..],
            &[r#"application/json; charset="unterminated"#][..],
        ] {
            assert!(
                validate_success_content_type(content_types).is_err(),
                "{content_types:?}"
            );
        }
    }

    #[test]
    fn content_encoding_allows_only_identity_tokens() {
        for content_encodings in [&[][..], &["identity"][..], &["identity, IDENTITY"][..]] {
            assert!(validate_success_content_encoding(content_encodings).is_ok());
        }

        for content_encodings in [
            &[""][..],
            &["gzip"][..],
            &["identity, br"][..],
            &["identity", "gzip"][..],
        ] {
            assert!(validate_success_content_encoding(content_encodings).is_err());
        }
    }

    #[test]
    fn success_headers_require_json_identity_encoding_and_valid_bounded_length() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("identity"));
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("3"));

        assert_eq!(validate_success_headers(&headers, 3).unwrap(), Some(3));

        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("4"));
        assert!(validate_success_headers(&headers, 3).is_err());

        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("not-a-length"));
        assert!(validate_success_headers(&headers, 3).is_err());

        headers.append(CONTENT_LENGTH, HeaderValue::from_static("3"));
        assert!(validate_success_headers(&headers, 3).is_err());

        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("br"));
        assert!(validate_success_headers(&headers, 3).is_err());
    }

    #[test]
    fn accepts_every_valid_payload_shape_and_version_boundary() {
        let cases: &[(&str, u64, &str)] = &[
            (r#"{"version":0,"payload":null}"#, 0, "null"),
            (r#"{"version":1,"payload":true}"#, 1, "true"),
            (r#"{"version":1,"payload":42}"#, 1, "42"),
            (r#"{"version":1,"payload":"value"}"#, 1, r#""value""#),
            (r#"{"version":1,"payload":[]}"#, 1, "[]"),
            (r#"{"version":1,"payload":{}}"#, 1, "{}"),
            (
                r#"{"version":18446744073709551615,"payload":null}"#,
                u64::MAX,
                "null",
            ),
        ];

        for (body, expected_version, expected_payload) in cases {
            let envelope = parse_success_envelope(body.as_bytes())
                .unwrap_or_else(|_| panic!("expected a valid envelope: {body}"));
            assert_eq!(envelope.version().get(), *expected_version, "{body}");
            assert_eq!(envelope.payload().as_json(), *expected_payload, "{body}");
        }
    }

    #[test]
    fn rejects_every_invalid_envelope_shape() {
        for body in [
            br#"{"payload":null}"#.as_slice(),
            br#"{"version":1}"#.as_slice(),
            br#"{"version":1,"payload":null,"unexpected":true}"#.as_slice(),
            br#"{"version":1,"version":2,"payload":null}"#.as_slice(),
            br#"{"version":1,"payload":null,"payload":true}"#.as_slice(),
            br#"{"version":"1","payload":null}"#.as_slice(),
            br#"{"version":-1,"payload":null}"#.as_slice(),
            br#"{"version":1.5,"payload":null}"#.as_slice(),
            br#"{"version":18446744073709551616,"payload":null}"#.as_slice(),
            br#"{"version":1,"payload":null"#.as_slice(),
            br#"{"version":1,"payload":null} null"#.as_slice(),
        ] {
            assert!(
                parse_success_envelope(body).is_err(),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }
}
