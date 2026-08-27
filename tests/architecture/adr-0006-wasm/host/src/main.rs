// ADR 0006 feasibility PoC — Wasmtime 48 host.
//
// This host is the "core boundary" stand-in that ADR 0006 describes: it
// controls what a target-adapter component can reach and how. All of the
// mechanisms that the ADR 0006 gates require are implemented here concretely
// so the gates can be demonstrated with executing behavior rather than prose:
//
//   Gate 1  - a compliance-typed, capability-isolated runtime: the engine is
//             fully sandboxed; the only outbound surface is host-mediated
//             HTTPS, and WASI is wired deny-by-default (WasiCtxBuilder::new()
//             with no env, no preopens, no args, no sockets).
//   Gate 2  - admission is enforced by the world/export contract the host
//             instantiates against (a component that does not export
//             adapter-api is rejected up front).
//   Gate 4  - the host transports the doc intact; rejection of unsupported
//             propagation is delegated to the guest (Go rejects `descendants`).
//   Gate 5  - config/secrets are handed to the adapter as context keys only;
//             secrets never appear in host logs.
//   Gate 6  - outbound HTTPS to an allowlisted origin with explicit TLS trust
//             (a configured CA); no unrestricted egress is exposed.
//   Gate 8  - an epoch-based deadline bounds runaway CPU; StoreLimits bounds
//             runaway memory.
//   Gate 9  - the provider is fetched exactly once and reconcile is invoked
//             exactly once, with no automatic retry.
//
// Not production PermissionSync core.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context};
use serde::Deserialize;

use wasmtime::component::HasSelf;
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

wasmtime::component::bindgen!({
    world: "adapter",
    path: "../wit/permissions.wit",
});

use permissionsync::adr0006::http::{self, Header, HttpResponse};
use permissionsync::adr0006::runtime::{self, ContextItem, Snapshot};
use permissionsync::adr0006::permissions::{
    Assignment, AssignmentKind, Constraint, Document, Propagation, Scope,
};
use exports::permissionsync::adr0006::adapter_api::{Outcome, Guest as AdapterApiGuest};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Clone, Deserialize)]
struct Config {
    adapter: String,
    provider_endpoint: String,
    target_endpoint: String,
    client: String,
    token: String,
    ca_cert: String,
    #[serde(default = "default_deadline_ms")]
    deadline_ms: u64,
    #[serde(default = "default_period_ms")]
    epoch_period_ms: u64,
    #[serde(default = "default_memory_limit")]
    memory_limit_bytes: u64,
    // Gate 5: per-route (per-target) additional context config/secret items.
    // These are handed to the adapter as key/value context items alongside the
    // canonical endpoint/client/token. They let the suite prove that an adapter
    // for target A only ever receives A's context keys, never target B's, and
    // that secret values never reach host output.
    #[serde(default)]
    context_config: Vec<ContextItemIn>,
    #[serde(default)]
    context_secrets: Vec<ContextItemIn>,
}

/// Deserialize-friendly context item (the WIT-generated `ContextItem` is what
/// the adapter sees; this is what the registry/config JSON can express).
#[derive(Clone, Deserialize)]
struct ContextItemIn {
    key: String,
    value: String,
}

fn default_deadline_ms() -> u64 { 3000 }
fn default_period_ms() -> u64 { 10 }
fn default_memory_limit() -> u64 { 8 * 1024 * 1024 }

// ---------------------------------------------------------------------------
// Provider document -> WIT document
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct JsonDocument {
    version: u32,
    assignments: Vec<JsonAssignment>,
    constraints: Vec<JsonConstraint>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct JsonAssignment {
    kind: String,
    id: String,
    scope: Option<JsonScope>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct JsonScope {
    scope_type: String,
    id: String,
    #[serde(default)]
    propagation: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct JsonConstraint {
    constraint_type: String,
    values: Vec<String>,
}

fn kind_from(s: &str) -> Result<AssignmentKind, String> {
    match s {
        "role" => Ok(AssignmentKind::Role),
        "group" => Ok(AssignmentKind::Group),
        "entitlement" => Ok(AssignmentKind::Entitlement),
        other => Err(format!("unknown assignment kind '{}'", other)),
    }
}

fn scope_from(j: &JsonScope) -> Result<Scope, String> {
    if j.scope_type.is_empty() || j.id.is_empty() {
        return Err("partial scope: missing scope-type or scope id".into());
    }
    if j.propagation.is_empty() {
        return Err("partial scope: missing propagation".into());
    }
    let propagation = match j.propagation.as_str() {
        "self-only" => Propagation::SelfOnly,
        "descendants" => Propagation::Descendants,
        other => return Err(format!("unknown propagation '{}'", other)),
    };
    Ok(Scope {
        scope_type: j.scope_type.clone(),
        id: j.id.clone(),
        propagation,
    })
}

/// Structural (core-side) validation that runs before component invocation.
///
/// ADR 0006 Gate 4 requires the *core* to reject unsupported model versions or
/// kinds, partial scopes, and malformed or duplicated constraint types before
/// the target adapter component is ever invoked — not after. This runs on the
/// host side (the `core` stand-in) during document ingestion, so rejection
/// happens with zero component invocation and zero target mutation. The
/// component instead handles *target-semantic* rejection (e.g. unknown roles)
/// in its own update path.
fn validate_structural(d: &Document) -> Result<(), String> {
    if d.version != 1 {
        return Err(format!("unsupported model version {}", d.version));
    }
    let mut seen = std::collections::HashSet::new();
    for c in &d.constraints {
        if c.constraint_type.is_empty() {
            return Err("malformed constraint: empty constraint-type".into());
        }
        if !seen.insert(c.constraint_type.as_str()) {
            return Err(format!("duplicate constraint type '{}'", c.constraint_type));
        }
    }
    for a in &d.assignments {
        if let Some(s) = &a.scope {
            if s.scope_type.is_empty() || s.id.is_empty() {
                return Err("partial scope: missing scope-type or scope id".into());
            }
        }
    }
    Ok(())
}

fn document_from_json(j: &JsonDocument) -> Result<Document, String> {
    let mut assignments = Vec::new();
    for a in &j.assignments {
        let scope = match &a.scope {
            Some(s) => Some(scope_from(s)?),
            None => None,
        };
        assignments.push(Assignment {
            kind: kind_from(&a.kind)?,
            id: a.id.clone(),
            scope,
        });
    }
    let constraints: Vec<Constraint> = j
        .constraints
        .iter()
        .map(|c| Constraint {
            constraint_type: c.constraint_type.clone(),
            values: c.values.clone(),
        })
        .collect();
    let doc = Document {
        version: j.version,
        assignments,
        constraints,
    };
    validate_structural(&doc)?;
    Ok(doc)
}

// ---------------------------------------------------------------------------
// Host state + interface implementations
// ---------------------------------------------------------------------------

struct HostState {
    // Deny-by-default WASI (Gate 1 / Gate 6): empty ctx, table, no perms.
    wasi: WasiCtx,
    table: ResourceTable,
    limits: wasmtime::StoreLimits,
    config: Config,
    context_config: Vec<ContextItem>,
    context_secrets: Vec<ContextItem>,
    deadline: Instant,
    agent: ureq::Agent,
    // Gate 9 accounting: how many times the adapter's `reconcile` export was
    // invoked and how many automatic retries the host performed (always zero —
    // the host never auto-retries a failed reconcile).
    reconcile_calls: u64,
    auto_retries: u64,
}

impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView { ctx: &mut self.wasi, table: &mut self.table }
    }
}

impl HostState {
    fn agent_ref(&self) -> &ureq::Agent {
        &self.agent
    }
}

impl http::Host for HostState {
    fn call(
        &mut self,
        method: String,
        url: String,
        headers: Vec<Header>,
        body: Option<Vec<u8>>,
    ) -> Result<HttpResponse, String> {
        let now = Instant::now();
        if now >= self.deadline {
            return Err("deadline exceeded".into());
        }
        // Gate 6: only the configured target origin is reachable.
        let base = &self.config.target_endpoint;
        if !url.starts_with(base) {
            return Err(format!("egress denied: '{}' is outside allowlist '{}'", url, base));
        }
        let mut req = self.agent.request(&method, &url);
        for h in &headers {
            req = req.set(&h.name, &h.value);
        }
        let payload = body.unwrap_or_default();
        let resp = req.send_bytes(&payload).map_err(|e| format!("http error: {}", e))?;
        let status = resp.status();
        let mut resp_body = Vec::new();
        resp.into_reader()
            .read_to_end(&mut resp_body)
            .map_err(|e| format!("read error: {}", e))?;
        Ok(HttpResponse { status, body: resp_body })
    }
}

impl runtime::Host for HostState {
    fn get_context(&mut self) -> Snapshot {
        Snapshot {
            config: self.context_config.clone(),
            secrets: self.context_secrets.clone(),
        }
    }

    fn remaining_deadline(&mut self) -> Option<u64> {
        let now = Instant::now();
        if now >= self.deadline {
            Some(0)
        } else {
            Some(self.deadline.duration_since(now).as_millis() as u64)
        }
    }
}

// `permissions` has no host functions (only shared types); still needs the
// (empty) trait impl so `Adapter::add_to_linker`'s bounds are satisfied.
impl permissionsync::adr0006::permissions::Host for HostState {}

// ---------------------------------------------------------------------------
// Engine / instance plumbing
// ---------------------------------------------------------------------------

fn build_agent(ca_cert: &str, timeout: Duration) -> anyhow::Result<ureq::Agent> {
    let pem = std::fs::read(ca_cert).with_context(|| format!("read CA cert {}", ca_cert))?;
    let mut reader: &[u8] = &pem;
    let roots = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("parse CA cert PEM")?;
    let mut root_store = rustls::RootCertStore::empty();
    for root in roots {
        root_store.add(root).context("add root cert")?;
    }
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    // Gate 8: a stalled outbound target must not hang the host past the
    // deadline; the agent aborts a call that exceeds `timeout`.
    Ok(ureq::AgentBuilder::new()
        .timeout(timeout)
        .tls_config(Arc::new(tls))
        .build())
}

fn fetch_document(agent: &ureq::Agent, provider_endpoint: &str) -> anyhow::Result<Document> {
    let url = format!("{}/document", provider_endpoint);
    let resp = agent.get(&url).call().with_context(|| format!("GET provider {}", url))?;
    let mut json = Vec::new();
    resp.into_reader().read_to_end(&mut json).context("read provider body")?;
    let parsed: JsonDocument = serde_json::from_slice(&json).context("parse provider JSON")?;
    document_from_json(&parsed).map_err(anyhow::Error::msg)
}

fn make_engine(config: &Config) -> anyhow::Result<(wasmtime::Engine, std::thread::JoinHandle<()>)> {
    let mut wcfg = wasmtime::Config::new();
    wcfg.epoch_interruption(true);
    let engine = wasmtime::Engine::new(&wcfg)?;

    let period = Duration::from_millis(config.epoch_period_ms.max(1));
    let e2 = engine.clone();
    let handle = std::thread::spawn(move || loop {
        e2.increment_epoch();
        std::thread::sleep(period);
    });
    Ok((engine, handle))
}

/// Admission: load + instantiate the component against the `adapter` world.
/// Any incompatible component is rejected here, before provider resolution,
/// reconciliation, or any target mutation (Gate 2 / Gate 10).
fn admit(
    engine: &wasmtime::Engine,
    config: &Config,
    state: HostState,
) -> anyhow::Result<(Adapter, wasmtime::Store<HostState>)> {
    let component = wasmtime::component::Component::from_file(engine, &config.adapter)
        .map_err(|e| anyhow!("load component {}: {}", config.adapter, e))?;

    let mut linker = wasmtime::component::Linker::<HostState>::new(engine);
    // Deny-by-default WASI (required to resolve the adapters' std/wasi imports).
    wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;
    // Our own world imports (http + runtime) via the identity getter.
    Adapter::add_to_linker::<_, HasSelf<_>>(
        &mut linker,
        (|s: &mut HostState| s) as fn(&mut HostState) -> &mut HostState,
    )?;

    let mut store = wasmtime::Store::new(engine, state);
    store.limiter(|s| &mut s.limits);
    let budget_periods = (config.deadline_ms / config.epoch_period_ms.max(1)).max(1);
    store.set_epoch_deadline(budget_periods);
    store.epoch_deadline_trap();

    // Gate 2 admission: instantiating against the `adapter` world requires the
    // component to actually export adapter-api. A non-conforming component
    // fails here with a clear error before any guest code runs.
    let adapter = Adapter::instantiate(&mut store, &component, &linker)
        .map_err(|e| anyhow!("admission/instantiation failed: {}", e))?;
    Ok((adapter, store))
}

fn reconcile(
    guest: &AdapterApiGuest,
    store: &mut wasmtime::Store<HostState>,
    doc: &Document,
) -> anyhow::Result<()> {
    store.data_mut().reconcile_calls += 1;
    let (reconcile_calls, auto_retries) = {
        let d = store.data();
        (d.reconcile_calls, d.auto_retries)
    };
    let ret = guest
        .call_reconcile(store, doc)
        .map_err(|e| anyhow!("reconcile call failed: {}", e))?;
    println!("ACCOUNT reconcile_calls={} auto_retries={}", reconcile_calls, auto_retries);
    match ret {
        Ok(outcome) => print_outcome(&outcome),
        Err(e) => bail!("reconcile rejected by adapter: {}", e),
    }
    Ok(())
}

fn doc_json(d: &Document) -> String {
    use serde::Serialize;
    #[derive(Serialize)]
    struct JScope {
        scope_type: String,
        id: String,
        propagation: String,
    }
    #[derive(Serialize)]
    struct JAssignment {
        kind: String,
        id: String,
        scope: Option<JScope>,
    }
    #[derive(Serialize)]
    struct JConstraint {
        constraint_type: String,
        values: Vec<String>,
    }

    let assignments: Vec<JAssignment> = d
        .assignments
        .iter()
        .map(|a| JAssignment {
            kind: match a.kind {
                AssignmentKind::Role => "role".into(),
                AssignmentKind::Group => "group".into(),
                AssignmentKind::Entitlement => "entitlement".into(),
            },
            id: a.id.clone(),
            scope: a.scope.as_ref().map(|s| JScope {
                scope_type: s.scope_type.clone(),
                id: s.id.clone(),
                propagation: match s.propagation {
                    Propagation::SelfOnly => "self-only".into(),
                    Propagation::Descendants => "descendants".into(),
                },
            }),
        })
        .collect();
    let constraints: Vec<JConstraint> = d
        .constraints
        .iter()
        .map(|c| JConstraint {
            constraint_type: c.constraint_type.clone(),
            values: c.values.clone(),
        })
        .collect();
    serde_json::to_string(&serde_json::json!({
        "version": d.version,
        "assignments": assignments,
        "constraints": constraints,
    }))
    .unwrap_or_default()
}

fn print_outcome(o: &Outcome) {
    println!("RECEIVED={}", doc_json(&o.received));
    for e in &o.effects {
        println!("EFFECT {} {}", e.action, e.assignment_id);
    }
    for d in &o.diagnostics {
        println!("DIAG {}", d);
    }
    println!("CONTEXT_KEYS={}", o.context_keys.join(","));
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Routing registry (Gate 10)
// ---------------------------------------------------------------------------

/// One entry in the routing registry. Distinguished states:
///   - route key absent from registry        -> "unconfigured" (200-equivalent no-op)
///   - route present, `managed` == false     -> "unmanaged" (200-equivalent no-op)
///   - route present, `managed` == true      -> must reconcile; a missing or
///     incompatible component is a 500-equivalent error, NOT a no-op.
#[derive(Clone, Deserialize)]
struct RouteEntry {
    managed: bool,
    #[serde(default)]
    adapter: Option<String>,
    #[serde(default)]
    provider_endpoint: Option<String>,
    target_endpoint: String,
    client: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    context_config: Vec<ContextItemIn>,
    #[serde(default)]
    context_secrets: Vec<ContextItemIn>,
}

#[derive(Deserialize)]
struct Registry {
    ca_cert: String,
    provider_endpoint: String,
    #[serde(default = "default_deadline_ms")]
    deadline_ms: u64,
    #[serde(default = "default_period_ms")]
    epoch_period_ms: u64,
    #[serde(default = "default_memory_limit")]
    memory_limit_bytes: u64,
    routes: std::collections::HashMap<String, RouteEntry>,
}

fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow!("install rustls ring CryptoProvider"))?;
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: host run <cfg.json> | host route <registry.json> <route-key>");
        std::process::exit(2);
    }
    let cmd = args[1].as_str();
    match cmd {
        "run" => {
            let cfg_path = args.get(2).ok_or_else(|| anyhow!("run needs <cfg.json>"))?;
            run(cfg_path)
        }
        "route" => {
            let reg_path = args.get(2).ok_or_else(|| anyhow!("route needs <registry.json>"))?;
            let key = args.get(3).ok_or_else(|| anyhow!("route needs <route-key>"))?;
            route(reg_path, key)
        }
        other => bail!("unknown command '{}'", other),
    }
}

/// Execute one reconcile against a resolved configuration.
fn execute(config: &Config) -> anyhow::Result<()> {
    let timeout = Duration::from_millis(config.deadline_ms.max(1));
    let agent = build_agent(&config.ca_cert, timeout)?;

    // Gate 5: keys (not values) of config+secret the adapter may read. Only the
    // selected route's items are present, never another target's; plain config
    // and secret items from the registry are appended below.
    let mut context_config = vec![
        ContextItem { key: "endpoint".into(), value: config.target_endpoint.clone() },
        ContextItem { key: "client".into(), value: config.client.clone() },
    ];
    let mut context_secrets = vec![
        ContextItem { key: "token".into(), value: config.token.clone() },
    ];
    for ci in &config.context_config {
        context_config.push(ContextItem { key: ci.key.clone(), value: ci.value.clone() });
    }
    for si in &config.context_secrets {
        context_secrets.push(ContextItem { key: si.key.clone(), value: si.value.clone() });
    }

    // Deny-by-default WASI context: nothing preconfigured (Gate 1 / Gate 6).
    let wasi = WasiCtxBuilder::new().build();
    let limits = wasmtime::StoreLimitsBuilder::new()
        .memory_size(config.memory_limit_bytes as usize)
        .build();

    let (engine, _epoch_thread) = make_engine(config)?;

    let state = HostState {
        wasi,
        table: ResourceTable::new(),
        limits,
        config: config.clone(),
        context_config,
        context_secrets,
        deadline: Instant::now() + Duration::from_millis(config.deadline_ms),
        agent,
        reconcile_calls: 0,
        auto_retries: 0,
    };

    // Gate 2 / Gate 10: admission (instantiate) happens here — before the
    // provider is ever contacted — so an incompatible component is rejected
    // with zero provider calls and zero reconciliation calls.
    let (adapter, mut store) = admit(&engine, config, state)?;
    let guest = adapter.permissionsync_adr0006_adapter_api();

    // Gate 9: exactly one provider fetch, no retry — after admission.
    let doc = fetch_document(store.data().agent_ref(), &config.provider_endpoint)?;

    reconcile(guest, &mut store, &doc)?;
    Ok(())
}

fn run(cfg_path: &str) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(cfg_path).with_context(|| format!("read config {}", cfg_path))?;
    let config: Config = serde_json::from_str(&raw).context("parse config JSON")?;
    execute(&config)
}

/// Resolve a single route from the routing registry. The three reachable
/// classification levels are kept distinct per ADR 0006 Gate 10 (an
/// unconfigured/unmanaged route is a successful no-op with provider=0 and
/// adapter=0; a *managed* route that is missing or incompatible is an error).
fn route(reg_path: &str, key: &str) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(reg_path).with_context(|| format!("read registry {}", reg_path))?;
    let reg: Registry = serde_json::from_str(&raw).context("parse registry JSON")?;

    let Some(entry) = reg.routes.get(key) else {
        // Gate 10: an unconfigured route performs no work at all.
        println!("ROUTE unconfigured nocalls");
        return Ok(());
    };
    if !entry.managed {
        // Gate 10: an explicitly unmanaged route performs no work at all.
        println!("ROUTE unmanaged nocalls");
        return Ok(());
    }

    // Managed route: must actually reconcile. A missing or incompatible
    // component is an error (500-equivalent), not a no-op.
    let adapter = entry
        .adapter
        .clone()
        .ok_or_else(|| anyhow!("route '{}': managed but no adapter configured (500)", key))?;
    let provider_endpoint = entry
        .provider_endpoint
        .clone()
        .unwrap_or_else(|| reg.provider_endpoint.clone());

    let config = Config {
        adapter,
        provider_endpoint,
        target_endpoint: entry.target_endpoint.clone(),
        client: entry.client.clone(),
        token: entry.token.clone(),
        ca_cert: reg.ca_cert.clone(),
        deadline_ms: reg.deadline_ms,
        epoch_period_ms: reg.epoch_period_ms,
        memory_limit_bytes: reg.memory_limit_bytes,
        context_config: entry.context_config.clone(),
        context_secrets: entry.context_secrets.clone(),
    };
    execute(&config)
}
