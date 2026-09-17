//! Parsing and structural validation of trusted JWKS documents into
//! signature verifiers, plus preflight inspection of an inbound token's
//! header before any signature verification is attempted. Signature
//! verification always precedes claim/authorization decisions.

use std::collections::BTreeSet;

use josekit::{
    JoseHeader,
    jwk::Jwk,
    jws::{self, JwsHeader, JwsVerifier},
    jwt::JwtContext,
};
use permissionsync_core::SynchronizationContext;
use serde::Deserialize;
use serde_json::Value;

use crate::{
    MAX_JWKS_KEYS, MAX_PUBLIC_COMPONENT_BYTES, MAX_RSA_EXPONENT_BYTES, MAX_TEXT_BYTES,
    config::JwtAlgorithm, context::check_context, error::AuthenticationError,
};

#[derive(Clone)]
pub(crate) struct Candidate {
    pub(crate) kid: Option<String>,
    pub(crate) algorithm: JwtAlgorithm,
    pub(crate) with_kid: Box<dyn JwsVerifier>,
    pub(crate) without_kid: Box<dyn JwsVerifier>,
}

#[derive(Deserialize)]
pub(crate) struct DiscoveryDocument {
    pub(crate) issuer: String,
    pub(crate) jwks_uri: String,
}

pub(crate) fn preflight_header(
    token: &str,
    allowed: &BTreeSet<JwtAlgorithm>,
) -> Result<JwtAlgorithm, AuthenticationError> {
    let header = JwtContext::new()
        .decode_header(token)
        .map_err(|_| AuthenticationError::Rejected)?;
    let header = header
        .as_any()
        .downcast_ref::<JwsHeader>()
        .ok_or(AuthenticationError::Rejected)?;
    if header.claim("crit").is_some() || header.claim("b64").is_some() {
        return Err(AuthenticationError::Rejected);
    }
    if let Some(kid) = header.claim("kid") {
        let kid = kid.as_str().ok_or(AuthenticationError::Rejected)?;
        if kid.len() > MAX_TEXT_BYTES {
            return Err(AuthenticationError::Rejected);
        }
    }
    let algorithm = header.algorithm().ok_or(AuthenticationError::Rejected)?;
    allowed
        .iter()
        .copied()
        .find(|configured| configured.name() == algorithm)
        .ok_or(AuthenticationError::Rejected)
}

pub(crate) fn parse_jwks(
    document: &[u8],
    allowed: &BTreeSet<JwtAlgorithm>,
    context: &SynchronizationContext<'_>,
) -> Result<Vec<Candidate>, AuthenticationError> {
    check_context(context)?;
    let value: Value =
        serde_json::from_slice(document).map_err(|_| AuthenticationError::VerifierUnavailable)?;
    check_context(context)?;
    let keys = value
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(AuthenticationError::VerifierUnavailable)?;
    if keys.len() > MAX_JWKS_KEYS {
        return Err(AuthenticationError::VerifierUnavailable);
    }
    let mut candidates = Vec::new();
    for value in keys {
        check_context(context)?;
        // An entry without a public JWK object shape cannot provide a
        // verifier. It is not, by itself, evidence that secret material was
        // supplied by the trusted public source.
        let Some(object) = value.as_object() else {
            continue;
        };
        match classify_jwk(object) {
            // A well-formed but inapplicable key (declared encryption use, or
            // `key_ops` excluding `verify`) does not poison the trusted JWKS:
            // OIDC explicitly allows a JWK Set to contain both signing and
            // encryption keys. Skip it silently.
            Ok(KeyApplicability::Inapplicable) => continue,
            Ok(KeyApplicability::Applicable) => {}
            // Secret-bearing material unexpectedly returned by a public
            // verification source makes the whole trusted document unusable.
            Err(()) => return Err(AuthenticationError::VerifierUnavailable),
        }
        check_context(context)?;
        let kid = object.get("kid").and_then(Value::as_str).map(str::to_owned);
        let jwk_alg = object.get("alg").and_then(Value::as_str);
        // Skip constructing a verifier entirely for a key that cannot
        // possibly be used by any configured allowed algorithm (explicit
        // `alg` mismatch, or an incompatible key type/curve). This is
        // determinable safely from the raw public JWK metadata alone.
        if !allowed.iter().any(|algorithm| {
            jwk_alg.is_none_or(|value| value == algorithm.name()) && compatible(object, *algorithm)
        }) {
            continue;
        }
        // Let Josekit perform the JWK/base64url conversion. A public entry
        // that it cannot convert is malformed and cannot contribute a
        // candidate, but must not poison other public keys in the set.
        let Ok(jwk_bytes) = serde_json::to_vec(value) else {
            continue;
        };
        let Ok(jwk) = Jwk::from_bytes(jwk_bytes) else {
            continue;
        };
        check_context(context)?;
        for algorithm in allowed {
            check_context(context)?;
            if jwk_alg.is_some_and(|value| value != algorithm.name())
                || !compatible(object, *algorithm)
            {
                check_context(context)?;
                continue;
            }
            let Ok(with_kid) = verifier_from_jwk(*algorithm, &jwk) else {
                continue;
            };
            check_context(context)?;
            let mut without_kid_value = value.clone();
            let Some(without_kid_object) = without_kid_value.as_object_mut() else {
                continue;
            };
            without_kid_object.remove("kid");
            check_context(context)?;
            let Ok(without_kid_bytes) = serde_json::to_vec(&without_kid_value) else {
                continue;
            };
            let Ok(without_kid_jwk) = Jwk::from_bytes(without_kid_bytes) else {
                continue;
            };
            check_context(context)?;
            let Ok(without_kid) = verifier_from_jwk(*algorithm, &without_kid_jwk) else {
                continue;
            };
            check_context(context)?;
            candidates.push(Candidate {
                kid: kid.clone(),
                algorithm: *algorithm,
                with_kid,
                without_kid,
            });
        }
        check_context(context)?;
    }
    Ok(candidates)
}

/// Whether a public JWK entry can provide a PermissionSync signature verifier.
enum KeyApplicability {
    /// Purports to be a public signing/verification key.
    Applicable,
    /// Not a signing key we would ever select, or a malformed/unsupported
    /// public entry. This key must be ignored, not treated as an error.
    Inapplicable,
}

/// Classifies one JWKS key entry.
///
/// Returns `Err(())` only for unsafe/secret-bearing material a *public*
/// verification source must never return (private RSA/EC/OKP or AKP `priv`
/// components, or symmetric/`oct` material). This fails the entire trusted
/// document closed.
/// Malformed or unsupported public entries instead return
/// `Ok(Inapplicable)` and are skipped per key.
fn classify_jwk(object: &serde_json::Map<String, Value>) -> Result<KeyApplicability, ()> {
    if object.contains_key("d")
        || object.contains_key("k")
        || object.contains_key("p")
        || object.contains_key("q")
        || object.contains_key("dp")
        || object.contains_key("dq")
        || object.contains_key("qi")
        || object.contains_key("oth")
        || object.contains_key("priv")
    {
        // Private or symmetric secret components returned by a public
        // verification source: unsafe, fail closed. Never add HMAC support.
        return Err(());
    }
    let Some(kty) = object.get("kty").and_then(Value::as_str) else {
        return Ok(KeyApplicability::Inapplicable);
    };
    if kty == "oct" {
        // Symmetric material must never be accepted from a public verification
        // source. Never add HMAC support.
        return Err(());
    }
    if !matches!(kty, "RSA" | "EC" | "OKP") {
        return Ok(KeyApplicability::Inapplicable);
    }
    for field in ["kid", "alg", "use", "kty", "crv"] {
        if object.get(field).is_some_and(|value| {
            !value.is_string()
                || value
                    .as_str()
                    .is_some_and(|text| text.len() > MAX_TEXT_BYTES)
        }) {
            return Ok(KeyApplicability::Inapplicable);
        }
    }
    if object
        .get("use")
        .is_some_and(|value| value.as_str() != Some("sig"))
    {
        return Ok(KeyApplicability::Inapplicable);
    }
    if let Some(operations) = object.get("key_ops") {
        let Some(operations) = operations.as_array() else {
            return Ok(KeyApplicability::Inapplicable);
        };
        if operations.is_empty() || !operations.iter().all(Value::is_string) {
            return Ok(KeyApplicability::Inapplicable);
        }
        if !operations
            .iter()
            .any(|value| value.as_str() == Some("verify"))
        {
            return Ok(KeyApplicability::Inapplicable);
        }
    }
    match kty {
        "RSA" => {
            if bounded_component(object, "n", MAX_PUBLIC_COMPONENT_BYTES).is_err()
                || bounded_component(object, "e", MAX_RSA_EXPONENT_BYTES).is_err()
            {
                return Ok(KeyApplicability::Inapplicable);
            }
        }
        "EC" => {
            if bounded_component(object, "x", MAX_PUBLIC_COMPONENT_BYTES).is_err()
                || bounded_component(object, "y", MAX_PUBLIC_COMPONENT_BYTES).is_err()
            {
                return Ok(KeyApplicability::Inapplicable);
            }
            if object.get("crv").and_then(Value::as_str).is_none() {
                return Ok(KeyApplicability::Inapplicable);
            }
        }
        "OKP" => {
            if bounded_component(object, "x", MAX_PUBLIC_COMPONENT_BYTES).is_err() {
                return Ok(KeyApplicability::Inapplicable);
            }
            if object.get("crv").and_then(Value::as_str).is_none() {
                return Ok(KeyApplicability::Inapplicable);
            }
        }
        _ => unreachable!("kty already restricted to RSA/EC/OKP above"),
    }
    Ok(KeyApplicability::Applicable)
}

fn bounded_component(
    object: &serde_json::Map<String, Value>,
    name: &str,
    maximum: usize,
) -> Result<(), ()> {
    let value = object.get(name).and_then(Value::as_str).ok_or(())?;
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(());
    }
    Ok(())
}

fn compatible(object: &serde_json::Map<String, Value>, algorithm: JwtAlgorithm) -> bool {
    match algorithm {
        JwtAlgorithm::RS256
        | JwtAlgorithm::RS384
        | JwtAlgorithm::RS512
        | JwtAlgorithm::PS256
        | JwtAlgorithm::PS384
        | JwtAlgorithm::PS512 => object.get("kty").and_then(Value::as_str) == Some("RSA"),
        JwtAlgorithm::ES256 => {
            object.get("kty").and_then(Value::as_str) == Some("EC")
                && object.get("crv").and_then(Value::as_str) == Some("P-256")
        }
        JwtAlgorithm::ES384 => {
            object.get("kty").and_then(Value::as_str) == Some("EC")
                && object.get("crv").and_then(Value::as_str) == Some("P-384")
        }
        JwtAlgorithm::ES512 => {
            object.get("kty").and_then(Value::as_str) == Some("EC")
                && object.get("crv").and_then(Value::as_str) == Some("P-521")
        }
        JwtAlgorithm::EdDSA => {
            object.get("kty").and_then(Value::as_str) == Some("OKP")
                && matches!(
                    object.get("crv").and_then(Value::as_str),
                    Some("Ed25519") | Some("Ed448")
                )
        }
    }
}

fn verifier_from_jwk(algorithm: JwtAlgorithm, jwk: &Jwk) -> Result<Box<dyn JwsVerifier>, ()> {
    let verifier: Box<dyn JwsVerifier> = match algorithm {
        JwtAlgorithm::RS256 => Box::new(jws::RS256.verifier_from_jwk(jwk).map_err(|_| ())?),
        JwtAlgorithm::RS384 => Box::new(jws::RS384.verifier_from_jwk(jwk).map_err(|_| ())?),
        JwtAlgorithm::RS512 => Box::new(jws::RS512.verifier_from_jwk(jwk).map_err(|_| ())?),
        JwtAlgorithm::PS256 => Box::new(jws::PS256.verifier_from_jwk(jwk).map_err(|_| ())?),
        JwtAlgorithm::PS384 => Box::new(jws::PS384.verifier_from_jwk(jwk).map_err(|_| ())?),
        JwtAlgorithm::PS512 => Box::new(jws::PS512.verifier_from_jwk(jwk).map_err(|_| ())?),
        JwtAlgorithm::ES256 => Box::new(jws::ES256.verifier_from_jwk(jwk).map_err(|_| ())?),
        JwtAlgorithm::ES384 => Box::new(jws::ES384.verifier_from_jwk(jwk).map_err(|_| ())?),
        JwtAlgorithm::ES512 => Box::new(jws::ES512.verifier_from_jwk(jwk).map_err(|_| ())?),
        JwtAlgorithm::EdDSA => Box::new(jws::EdDSA.verifier_from_jwk(jwk).map_err(|_| ())?),
    };
    Ok(verifier)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use josekit::jwk::Jwk;
    use permissionsync_core::{CancellationSignal, SynchronizationContext};
    use serde_json::json;

    use super::{JwtAlgorithm, parse_jwks};

    struct NotCancelled;

    impl CancellationSignal for NotCancelled {
        fn is_cancelled(&self) -> bool {
            false
        }
    }

    fn context(cancellation: &NotCancelled) -> SynchronizationContext<'_> {
        SynchronizationContext::new(Instant::now() + Duration::from_secs(1), cancellation)
    }

    #[test]
    fn jwks_rejects_secret_material_and_skips_oversized_public_entries() {
        let allowed = [JwtAlgorithm::RS256].into_iter().collect();
        let cancellation = NotCancelled;
        let private = json!({"keys":[{"kty":"RSA","n":"AA","e":"AQAB","d":"AA"}]});
        let symmetric = json!({"keys":[{"kty":"oct","k":"AA"}]});
        let oversized = json!({"keys":[{"kty":"RSA","n":"A".repeat(1367),"e":"AQAB"}]});
        let context = context(&cancellation);
        assert!(parse_jwks(&serde_json::to_vec(&private).unwrap(), &allowed, &context).is_err());
        assert!(parse_jwks(&serde_json::to_vec(&symmetric).unwrap(), &allowed, &context).is_err());
        assert!(
            parse_jwks(&serde_json::to_vec(&oversized).unwrap(), &allowed, &context)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn jwks_rejects_akp_private_material_alongside_a_valid_signing_key() {
        let allowed = [JwtAlgorithm::RS256].into_iter().collect();
        let cancellation = NotCancelled;

        let signing_key = Jwk::generate_rsa_key(2048).unwrap();
        let signing_public = signing_key.to_public_key().unwrap();
        let document = json!({
            "keys": [
                serde_json::to_value(&signing_public).unwrap(),
                {"kty": "AKP", "priv": "AA"}
            ]
        });
        let context = context(&cancellation);

        assert!(parse_jwks(&serde_json::to_vec(&document).unwrap(), &allowed, &context).is_err());
    }

    #[test]
    fn jwks_skips_malformed_and_incompatible_public_entries() {
        let allowed = [JwtAlgorithm::RS256].into_iter().collect();
        let cancellation = NotCancelled;

        let mut signing_key = Jwk::generate_rsa_key(2048).unwrap();
        signing_key.set_key_id("signing");
        let signing_public = signing_key.to_public_key().unwrap();
        let mut signing_value = serde_json::to_value(&signing_public).unwrap();
        signing_value["alg"] = json!("RS256");

        let malformed_public = json!({"kty": "RSA", "n": "!", "e": "AQAB"});
        let incompatible_public = json!({"kty": "EC", "crv": "P-384", "x": "AA", "y": "AA"});
        let mixed_document =
            json!({"keys": [malformed_public, incompatible_public, signing_value]});
        let context = context(&cancellation);
        let candidates = parse_jwks(
            &serde_json::to_vec(&mixed_document).unwrap(),
            &allowed,
            &context,
        )
        .unwrap();
        assert_eq!(candidates.len(), 1);
    }

    #[test]
    fn jwks_skips_unknown_future_public_key_types() {
        let allowed = [JwtAlgorithm::RS256].into_iter().collect();
        let cancellation = NotCancelled;

        let signing_key = Jwk::generate_rsa_key(2048).unwrap();
        let signing_public = signing_key.to_public_key().unwrap();
        let future_public = json!({"kty": "AKP", "pub": "AA"});
        let mixed_document = json!({
            "keys": [serde_json::to_value(&signing_public).unwrap(), future_public.clone()]
        });
        let future_only_document = json!({"keys": [future_public]});
        let context = context(&cancellation);

        assert_eq!(
            parse_jwks(
                &serde_json::to_vec(&mixed_document).unwrap(),
                &allowed,
                &context,
            )
            .unwrap()
            .len(),
            1
        );
        assert!(
            parse_jwks(
                &serde_json::to_vec(&future_only_document).unwrap(),
                &allowed,
                &context,
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn jwks_with_only_inapplicable_public_entries_installs_no_candidates() {
        let allowed = [JwtAlgorithm::RS256].into_iter().collect();
        let cancellation = NotCancelled;

        let signing_key = Jwk::generate_rsa_key(2048).unwrap();
        let signing_public = signing_key.to_public_key().unwrap();
        let signing_value = serde_json::to_value(&signing_public).unwrap();

        // These are valid public JWKs, but none can verify an allowed token.
        let mut enc_only = signing_value.clone();
        enc_only["use"] = json!("enc");
        let mut no_verify = signing_value.clone();
        no_verify["key_ops"] = json!(["encrypt"]);
        let mut wrong_alg = signing_value;
        wrong_alg["alg"] = json!("PS256");
        let document = json!({"keys": [enc_only, no_verify, wrong_alg]});
        let context = context(&cancellation);
        let candidates =
            parse_jwks(&serde_json::to_vec(&document).unwrap(), &allowed, &context).unwrap();
        assert!(candidates.is_empty());
    }
}
