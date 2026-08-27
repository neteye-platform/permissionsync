//! Rust Target Adapter for the ADR 0006 feasibility PoC.
//!
//! A deliberately simple adapter: it structurally consumes the ADR 0005
//! desired-permission document, performs *target-semantic* validation against
//! a small allow-list (standing in for a real target's supported roles,
//! scopes, constraint types and values), and then reconciles only the managed
//! assignment and managed constraint state of the fake target through the
//! host-mediated HTTPS import.
//!
//! All allow-lists are hard-coded PoC stand-ins; a real adapter would obtain
//! them from its runtime context. This keeps the PoC free of hidden
//! test-only behavior while still proving the transport and rejection
//! properties the gates require.

#![allow(warnings)]

mod bindings;

use bindings::permissionsync::adr0006::permissions::{
    Assignment, AssignmentKind, Constraint, Propagation,
};
use bindings::permissionsync::adr0006::runtime::{self, Snapshot};
use bindings::permissionsync::adr0006::http::Header;
use bindings::exports::permissionsync::adr0006::adapter_api::{
    Document, Outcome, TargetEffect,
};
use bindings::exports::permissionsync::adr0006::adapter_api::Guest;
use bindings::export;

// ---- Target-semantic allow-lists (PoC stand-ins) ----

const ALLOWED_ROLES: &[&str] = &["reader", "editor", "viewer", "technician"];
const ALLOWED_GROUPS: &[&str] = &["release-managers", "operate"];
const ALLOWED_ENTITLEMENTS: &[&str] = &["packet-capture-download"];
const ALLOWED_SCOPE_TYPES: &[&str] = &["resource-boundary", "org"];
const ALLOWED_SCOPE_IDS: &[&str] = &["engineering", "operations", "north"];
const ALLOWED_CONSTRAINT_TYPES: &[&str] = &["network", "interface", "allowed"];
const ALLOWED_INTERFACES: &[&str] = &["collector-a", "collector-b"];

fn validate_assignment(a: &Assignment) -> Result<(), String> {
    match a.kind {
        AssignmentKind::Role => {
            if !ALLOWED_ROLES.contains(&a.id.as_str()) {
                return Err(format!("unsupported role '{}'", a.id));
            }
        }
        AssignmentKind::Group => {
            if !ALLOWED_GROUPS.contains(&a.id.as_str()) {
                return Err(format!("unsupported group '{}'", a.id));
            }
        }
        AssignmentKind::Entitlement => {
            if !ALLOWED_ENTITLEMENTS.contains(&a.id.as_str()) {
                return Err(format!("unsupported entitlement '{}'", a.id));
            }
        }
    }
    if let Some(s) = &a.scope {
        if !ALLOWED_SCOPE_TYPES.contains(&s.scope_type.as_str()) {
            return Err(format!("unsupported scope type '{}'", s.scope_type));
        }
        if !ALLOWED_SCOPE_IDS.contains(&s.id.as_str()) {
            return Err(format!("unsupported scope id '{}'", s.id));
        }
        // Rust adapter supports both `self` (`self-only`) and `descendants`.
        match s.propagation {
            Propagation::SelfOnly | Propagation::Descendants => {}
        }
    }
    Ok(())
}

fn validate_constraint(c: &Constraint) -> Result<(), String> {
    if !ALLOWED_CONSTRAINT_TYPES.contains(&c.constraint_type.as_str()) {
        return Err(format!("unsupported constraint type '{}'", c.constraint_type));
    }
    if c.constraint_type == "interface" {
        for v in &c.values {
            if !ALLOWED_INTERFACES.contains(&v.as_str()) {
                return Err(format!("unsupported interface value '{}'", v));
            }
        }
    }
    Ok(())
}

/// A `network`/`interface` constraint expresses network reachability for
/// principals, so it is meaningless without at least one role or group
/// assignment; an `allowed` constraint expresses an entitlement allowance.
/// Reject such a combination before any target mutation (Gate 4).
fn validate_combination(doc: &Document) -> Result<(), String> {
    let has_role_group = doc.assignments.iter().any(|a| {
        matches!(a.kind, AssignmentKind::Role | AssignmentKind::Group)
    });
    let has_entitlement = doc
        .assignments
        .iter()
        .any(|a| matches!(a.kind, AssignmentKind::Entitlement));
    for c in &doc.constraints {
        match c.constraint_type.as_str() {
            "network" | "interface" => {
                if !has_role_group {
                    return Err(format!(
                        "unsupported assignment/constraint combination: '{}' requires a role or group assignment",
                        c.constraint_type
                    ));
                }
            }
            "allowed" => {
                if !has_entitlement {
                    return Err(
                        "unsupported assignment/constraint combination: 'allowed' requires an entitlement assignment"
                            .into(),
                    );
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn get_config(ctx: &Snapshot, key: &str) -> Option<String> {
    ctx.config.iter().find(|i| i.key == key).map(|i| i.value.clone())
}

fn get_secret(ctx: &Snapshot, key: &str) -> Option<String> {
    ctx.secrets.iter().find(|i| i.key == key).map(|i| i.value.clone())
}

fn kind_str(k: AssignmentKind) -> &'static str {
    match k {
        AssignmentKind::Role => "role",
        AssignmentKind::Group => "group",
        AssignmentKind::Entitlement => "entitlement",
    }
}

fn json_assignments(doc: &Document) -> String {
    let mut parts: Vec<String> = Vec::new();
    for a in &doc.assignments {
        parts.push(format!("\"{}:{}\"", kind_str(a.kind), a.id));
    }
    format!("[{}]", parts.join(","))
}

fn json_constraints(doc: &Document) -> String {
    let mut parts: Vec<String> = Vec::new();
    for c in &doc.constraints {
        let vals: Vec<String> = c.values.iter().map(|v| format!("\"{}\"", v)).collect();
        parts.push(format!("\"{}\":[{}]", c.constraint_type, vals.join(",")));
    }
    format!("{{{}}}", parts.join(","))
}

struct Component;

impl Guest for Component {
    fn reconcile(doc: Document) -> Result<Outcome, String> {
        if doc.version != 1 {
            return Err(format!("unsupported model version {}", doc.version));
        }

        // ---- Target-semantic validation, before any target mutation ----
        for a in &doc.assignments {
            validate_assignment(a)?;
        }
        let mut seen = std::collections::HashSet::new();
        for c in &doc.constraints {
            if !seen.insert(&c.constraint_type) {
                return Err(format!("duplicate constraint type '{}'", c.constraint_type));
            }
            validate_constraint(c)?;
        }
        validate_combination(&doc)?;

        // ---- Desired managed target state ----
        let mut assignments: Vec<String> = Vec::new();
        let mut effects: Vec<TargetEffect> = Vec::new();
        for a in &doc.assignments {
            let label = format!("{}:{}", kind_str(a.kind), a.id);
            assignments.push(label.clone());
            effects.push(TargetEffect {
                assignment_id: label,
                action: "grant".to_string(),
            });
        }

        // ---- Selected target's runtime context ----
        let ctx = runtime::get_context();
        let context_keys: Vec<String> = ctx
            .config
            .iter()
            .chain(ctx.secrets.iter())
            .map(|i| i.key.clone())
            .collect();
        let endpoint = get_config(&ctx, "endpoint").ok_or("missing endpoint")?;
        let client = get_config(&ctx, "client").ok_or("missing client")?;
        let token = get_secret(&ctx, "token").ok_or("missing token secret")?;

        // ---- Reconcile managed state only, via host-mediated HTTPS ----
        let body = format!(
            "{{\"assignments\":{},\"constraints\":{}}}",
            json_assignments(&doc),
            json_constraints(&doc)
        );
        let url = format!("{}/state?client={}", endpoint, client);
        let resp = bindings::permissionsync::adr0006::http::call(
            "POST",
            &url,
            &[Header {
                name: "authorization".to_string(),
                value: format!("Bearer {}", token),
            }],
            Some(&body.into_bytes()),
        )
        .map_err(|e| format!("http call failed: {}", e))?;
        if resp.status != 200 {
            return Err(format!("target rejected reconcile with status {}", resp.status));
        }

        let constraint_count = doc.constraints.len();
        Ok(Outcome {
            received: doc,
            effects,
            diagnostics: vec![
                format!("validated {} assignments", assignments.len()),
                format!("validated {} constraints", constraint_count),
            ],
            context_keys,
        })
    }
}

export!(Component with_types_in bindings);
