//! Claim shape validation and scope-based target authorization.

use permissionsync_core::{LogicalTarget, SynchronizationContext};
use serde_json::Value;

use crate::{
    clock::Clock, config::Config, context::check_context, error::AuthenticationError,
    types::TargetSelection,
};

/// Authentication claims parsed before wall-clock consultation.
struct ParsedAuthenticationClaims<'a> {
    client_id: &'a str,
    exp: f64,
    iat: f64,
    nbf: Option<f64>,
}

/// Validates authentication claim shapes without consulting wall time: `iss`,
/// `aud`, `exp`/`iat` numeric shape, optional `nbf` numeric shape, and
/// `client_id` shape.
fn parse_authentication_claim_shapes<'a>(
    claims: &'a serde_json::Map<String, Value>,
    config: &Config,
) -> Result<ParsedAuthenticationClaims<'a>, AuthenticationError> {
    if claims.get("iss").and_then(Value::as_str) != Some(config.issuer.as_str())
        || !audience_matches(claims.get("aud"), &config.audience)
    {
        return Err(AuthenticationError::Rejected);
    }
    let exp = numeric_date(claims.get("exp")).ok_or(AuthenticationError::Rejected)?;
    let iat = numeric_date(claims.get("iat")).ok_or(AuthenticationError::Rejected)?;
    let client_id = claims
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or(AuthenticationError::Rejected)?;
    let nbf = claims
        .get("nbf")
        .map(|value| numeric_date(Some(value)).ok_or(AuthenticationError::Rejected))
        .transpose()?;
    Ok(ParsedAuthenticationClaims {
        client_id,
        exp,
        iat,
        nbf,
    })
}

pub(crate) fn validate_claims(
    payload: &[u8],
    config: &Config,
    clock: &dyn Clock,
    context: &SynchronizationContext<'_>,
) -> Result<(String, TargetSelection), AuthenticationError> {
    check_context(context)?;
    let claims: Value =
        serde_json::from_slice(payload).map_err(|_| AuthenticationError::Rejected)?;
    let claims = claims.as_object().ok_or(AuthenticationError::Rejected)?;
    // Authentication claim shapes are resolved before the wall clock is
    // consulted, so an unavailable clock never masks an invalid credential.
    let parsed = parse_authentication_claim_shapes(claims, config)?;
    check_context(context)?;
    let now = clock
        .unix_seconds()
        .ok_or(AuthenticationError::VerifierUnavailable)?;
    let allowed = now + config.clock_skew.as_secs_f64();
    if parsed.exp <= now || parsed.iat > allowed || parsed.nbf.is_some_and(|nbf| nbf > allowed) {
        return Err(AuthenticationError::Rejected);
    }
    check_context(context)?;
    // Scope validation and target selection are reachable only after
    // authentication, including temporal validity, has succeeded.
    let selection = select_target(parse_scope_shape(claims.get("scope"))?)?;
    check_context(context)?;
    Ok((parsed.client_id.to_owned(), selection))
}

pub(crate) fn audience_matches(value: Option<&Value>, expected: &str) -> bool {
    match value {
        Some(Value::String(value)) => value == expected,
        Some(Value::Array(values)) if !values.is_empty() => {
            values.iter().all(Value::is_string)
                && values.iter().any(|value| value.as_str() == Some(expected))
        }
        _ => false,
    }
}

pub(crate) fn numeric_date(value: Option<&Value>) -> Option<f64> {
    value?
        .as_f64()
        .filter(|value| value.is_finite() && value.abs() <= 9_007_199_254_740_991.0)
}

/// Validates scope shape and RFC 6749 token grammar after authentication has
/// succeeded. Does not decide target selection or authorization.
pub(crate) fn parse_scope_shape(
    value: Option<&Value>,
) -> Result<Option<Vec<&str>>, AuthenticationError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let scope = value.as_str().ok_or(AuthenticationError::Rejected)?;
    if scope.is_empty() {
        return Ok(None);
    }
    if !scope.split(' ').all(valid_scope_token) {
        return Err(AuthenticationError::Rejected);
    }
    Ok(Some(scope.split(' ').collect()))
}

/// Authorization/target selection from already shape-validated scope tokens.
/// Only reachable after authentication, including temporal validity, has
/// succeeded; `Forbidden` is therefore never returned for a token whose
/// authentication could not otherwise be established.
pub(crate) fn select_target(
    scope_tokens: Option<Vec<&str>>,
) -> Result<TargetSelection, AuthenticationError> {
    let Some(tokens) = scope_tokens else {
        return Ok(TargetSelection::NoTarget);
    };
    let scopes: Vec<&str> = tokens
        .into_iter()
        .filter(|token| token.starts_with("permissionsync:"))
        .collect();
    match scopes.as_slice() {
        [] => Ok(TargetSelection::NoTarget),
        [scope] => LogicalTarget::try_from(scope["permissionsync:".len()..].to_owned())
            .map(TargetSelection::Selected)
            .map_err(|_| AuthenticationError::Forbidden),
        _ => Err(AuthenticationError::Forbidden),
    }
}

pub(crate) fn valid_scope_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .as_bytes()
            .iter()
            .all(|byte| matches!(*byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        time::{Duration, Instant},
    };

    use permissionsync_core::{CancellationSignal, SynchronizationContext};
    use serde_json::json;

    use super::{
        audience_matches, numeric_date, parse_scope_shape, select_target, validate_claims,
    };
    use crate::{
        clock::Clock,
        config::{Config, SourceUri, VerificationCachePolicy, parse_metadata_uri},
        error::AuthenticationError,
        types::TargetSelection,
    };

    fn validate_scope(
        value: Option<&serde_json::Value>,
    ) -> Result<TargetSelection, AuthenticationError> {
        select_target(parse_scope_shape(value)?)
    }

    struct NotCancelled;

    impl CancellationSignal for NotCancelled {
        fn is_cancelled(&self) -> bool {
            false
        }
    }

    struct FixedClock;

    impl Clock for FixedClock {
        fn tick(&self) -> Instant {
            Instant::now()
        }

        fn unix_seconds(&self) -> Option<f64> {
            Some(100.0)
        }
    }

    #[test]
    fn scope_shapes_and_target_selection_follow_the_contract() {
        assert!(validate_scope(None).is_ok());
        assert!(validate_scope(Some(&json!(""))).is_ok());
        assert!(validate_scope(Some(&json!("service permissionsync:glpi"))).is_ok());
        assert!(matches!(
            validate_scope(Some(&json!("permissionsync:glpi permissionsync:glpi"))),
            Err(AuthenticationError::Forbidden)
        ));
        assert!(matches!(
            validate_scope(Some(&json!("permissionsync:"))),
            Err(AuthenticationError::Forbidden)
        ));
        assert!(matches!(
            validate_scope(Some(&json!("one  two"))),
            Err(AuthenticationError::Rejected)
        ));
        assert!(matches!(
            validate_scope(Some(&json!(null))),
            Err(AuthenticationError::Rejected)
        ));
    }

    #[test]
    fn audience_and_numeric_date_shapes_are_strict() {
        assert!(audience_matches(
            Some(&json!("permissionsync")),
            "permissionsync"
        ));
        assert!(audience_matches(
            Some(&json!(["other", "permissionsync"])),
            "permissionsync"
        ));
        assert!(!audience_matches(Some(&json!([])), "permissionsync"));
        assert!(!audience_matches(
            Some(&json!(["permissionsync", 1])),
            "permissionsync"
        ));
        assert!(numeric_date(Some(&json!(1.5))).is_some());
        assert!(numeric_date(Some(&json!(9007199254740992_u64))).is_none());
        assert!(numeric_date(Some(&json!("1"))).is_none());
    }

    #[test]
    fn verified_claim_validation_uses_the_private_controlled_clock() {
        let cancellation = NotCancelled;
        let config = Config {
            issuer: "https://issuer.test".to_owned(),
            audience: "permissionsync".to_owned(),
            source: SourceUri::Direct(parse_metadata_uri("https://issuer.test/keys").unwrap()),
            algorithms: BTreeSet::from([crate::config::JwtAlgorithm::RS256]),
            metadata_timeout: Duration::from_secs(1),
            cache_policy: VerificationCachePolicy::new(Duration::from_secs(1), Duration::ZERO),
            clock_skew: Duration::from_secs(5),
        };
        let payload = serde_json::to_vec(&json!({
            "iss": "https://issuer.test",
            "aud": ["permissionsync"],
            "exp": 100.5,
            "iat": 105.0,
            "client_id": "caller",
        }))
        .unwrap();
        let context =
            SynchronizationContext::new(Instant::now() + Duration::from_secs(1), &cancellation);
        assert!(validate_claims(&payload, &config, &FixedClock, &context).is_ok());
    }
}
