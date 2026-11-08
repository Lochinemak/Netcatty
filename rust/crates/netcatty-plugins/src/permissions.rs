//! Permission resources, declarations, grants and the permission engine
//! (ports of `permissionResources.cjs`, `permissionEngine.cjs`,
//! `permissionDecisionHost.cjs` and `byteStreamEndpoint.cjs`).
//!
//! Policy per `(source owner, permission)` is `allow` (default), `ask` or
//! `deny`. In `ask` mode an operation needs a grant: `once`, `session`,
//! `application` (memory) or `always` (database, bound to the declaration
//! hash which includes the security principal, so a different package
//! digest never inherits grants).

use crate::contract;
use crate::database::PluginDatabase;
use crate::error::{codes, PluginError, PluginResult};
use futures::future::BoxFuture;
use parking_lot::Mutex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(30);
const AUDITED_PERMISSION_USES: &[&str] = &[
    "runtime.advanced", "network", "filesystem.read", "filesystem.write", "secrets", "companion.execute",
    "vault.credentials", "terminal.input", "terminal.intercept.input", "terminal.intercept.output",
];

pub fn permission_denied(message: impl Into<String>, details: Option<Value>) -> PluginError {
    let mut data = json!({ "pluginCode": "permission_denied" });
    if let Some(details) = details {
        data["details"] = details;
    }
    PluginError::rpc_with(codes::PERMISSION_DENIED, message, data)
}

fn enum_set(def: &str) -> HashSet<String> {
    contract::schema()["$defs"][def]["enum"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default()
}

pub fn plugin_permissions() -> &'static HashSet<String> {
    static SET: std::sync::OnceLock<HashSet<String>> = std::sync::OnceLock::new();
    SET.get_or_init(|| enum_set("PluginPermission"))
}

pub fn resource_scoped_permissions() -> &'static HashSet<String> {
    static SET: std::sync::OnceLock<HashSet<String>> = std::sync::OnceLock::new();
    SET.get_or_init(|| enum_set("ResourceScopedPermission"))
}

pub fn assert_permission(permission: &str) -> PluginResult<()> {
    if plugin_permissions().contains(permission) {
        Ok(())
    } else {
        Err(PluginError::invalid(format!("Unknown plugin permission: {permission}")))
    }
}

fn invalid(message: &str) -> PluginError {
    PluginError::invalid(message)
}

/// `canonicalizeStreamEndpoint` → `(endpoint, transport, host, port)`.
pub fn canonicalize_stream_endpoint(value: &str) -> PluginResult<(String, String, String, u16)> {
    if value.len() > 512 {
        return Err(invalid("Byte stream endpoint is invalid"));
    }
    let (transport, rest) = if let Some(rest) = value.strip_prefix("tcp://") {
        ("tcp", rest)
    } else if let Some(rest) = value.strip_prefix("tls://") {
        ("tls", rest)
    } else {
        return Err(invalid("Byte streams require an exact TCP or TLS host and port"));
    };
    let colon = rest.rfind(':').ok_or_else(|| invalid("Byte streams require an exact TCP or TLS host and port"))?;
    let (host_raw, port_raw) = (&rest[..colon], &rest[colon + 1..]);
    if port_raw.is_empty() || port_raw.len() > 5 || !port_raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("Byte streams require an exact TCP or TLS host and port"));
    }
    let port: u32 = port_raw.parse().unwrap_or(0);
    if !(1..=65535).contains(&port) || port.to_string() != port_raw {
        return Err(invalid("Byte stream port is invalid"));
    }
    let mut host = host_raw.to_ascii_lowercase();
    let endpoint_host;
    if host.starts_with('[') {
        if !host.ends_with(']') {
            return Err(invalid("Byte streams require an exact TCP or TLS host and port"));
        }
        let inner = &host[1..host.len() - 1];
        let ip: std::net::Ipv6Addr = inner.parse().map_err(|_| invalid("Byte stream IPv6 address is invalid"))?;
        host = ip.to_string();
        endpoint_host = format!("[{host}]");
    } else if host.parse::<std::net::Ipv4Addr>().is_ok() {
        endpoint_host = host.clone();
    } else {
        let label_ok = |l: &str| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        };
        if host.is_empty()
            || host.len() > 253
            || host.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            || !host.split('.').all(label_ok)
        {
            return Err(invalid("Byte stream hostname is invalid"));
        }
        endpoint_host = host.clone();
    }
    Ok((format!("{transport}://{endpoint_host}:{port}"), transport.into(), host, port as u16))
}

/// `canonicalizeNetworkOrigin`.
pub fn canonicalize_network_origin(value: &str) -> PluginResult<String> {
    if value.is_empty() || value.len() > 2048 {
        return Err(invalid("Plugin network origin is invalid"));
    }
    let url = url::Url::parse(value).map_err(|_| invalid("Plugin network origin is invalid"))?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err(invalid("Plugin network access supports only HTTP and HTTPS origins"));
    }
    if !url.username().is_empty() || url.password().is_some() || !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
        return Err(invalid("Plugin network grants must contain an origin without credentials or a path"));
    }
    Ok(url.origin().ascii_serialization())
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// `canonicalizePermissionResource`.
pub fn canonicalize_resource(permission: &str, resource: &str) -> PluginResult<String> {
    assert_permission(permission)?;
    if permission == "network.stream" {
        return Ok(canonicalize_stream_endpoint(resource)?.0);
    }
    if resource == "*" {
        return Ok(resource.into());
    }
    match permission {
        "network" => canonicalize_network_origin(resource),
        "companion.execute" => {
            let ok = (5..=192).contains(&resource.len())
                && regress::Regex::new(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\.[A-Za-z][A-Za-z0-9_-]*(?:\.[A-Za-z][A-Za-z0-9_-]*)*$")
                    .map(|re| re.find(resource).is_some())
                    .unwrap_or(false);
            if ok {
                Ok(resource.into())
            } else {
                Err(invalid("Plugin companion resource is invalid"))
            }
        }
        "filesystem.read" | "filesystem.write" => {
            if resource.is_empty() || resource.len() > 8192 || resource.contains('\0') || !Path::new(resource).is_absolute() {
                return Err(invalid("Plugin filesystem grants require an absolute canonical path"));
            }
            Ok(normalize_path(Path::new(resource)).to_string_lossy().into_owned())
        }
        _ => {
            if resource.is_empty() || resource.encode_utf16().count() > 2048 {
                return Err(invalid("Plugin permission resource is invalid"));
            }
            Ok(resource.into())
        }
    }
}

fn fs_compare_key(value: &str) -> String {
    let normalized = normalize_path(Path::new(value)).to_string_lossy().into_owned();
    if cfg!(windows) {
        normalized.to_lowercase()
    } else {
        normalized
    }
}

/// `permissionResourceCovers`.
pub fn resource_covers(permission: &str, grant: &str, requested: &str, grant_kind: &str, requested_kind: &str) -> bool {
    if permission == "network.stream" {
        return grant != "*" && grant == requested;
    }
    if grant == "*" {
        return true;
    }
    if permission == "filesystem.read" || permission == "filesystem.write" {
        if requested_kind == "directory" && grant_kind != "directory" {
            return false;
        }
        let parent = fs_compare_key(grant);
        let candidate = fs_compare_key(requested);
        if grant_kind != "directory" {
            return parent == candidate;
        }
        return Path::new(&candidate).starts_with(Path::new(&parent));
    }
    grant == requested
}

#[derive(Debug, Clone, PartialEq)]
pub struct Declaration {
    pub permission: String,
    pub required: bool,
    pub resources: Vec<String>,
    pub reason: String,
}

/// `normalizePermissionDeclarations` (BTreeMap keeps manifest insertion
/// irrelevant; lookups are by name).
pub fn normalize_declarations(manifest: &Value) -> PluginResult<BTreeMap<String, Declaration>> {
    let mut out = BTreeMap::new();
    let mut order = Vec::new();
    for (required, key) in [(true, "required"), (false, "optional")] {
        for value in manifest
            .get("permissions")
            .and_then(|p| p.get(key))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            let permission = crate::package::manifest::permission_name(&value).unwrap_or("").to_string();
            assert_permission(&permission)?;
            let mut resources: Vec<String> = Vec::new();
            if let Some(list) = value.get("resources").and_then(Value::as_array) {
                for resource in list {
                    let canonical = canonicalize_resource(&permission, resource.as_str().unwrap_or(""))?;
                    if !resources.contains(&canonical) {
                        resources.push(canonical);
                    }
                }
            }
            resources.sort();
            if (required && resource_scoped_permissions().contains(&permission)) || permission == "network.stream" {
                if resources.is_empty() {
                    return Err(invalid(&format!("Required permission {permission} must declare resources")));
                }
                if resources.iter().any(|r| r == "*") {
                    return Err(invalid(&format!("Required permission {permission} must not use wildcard resources")));
                }
            }
            order.push(permission.clone());
            out.insert(
                permission.clone(),
                Declaration {
                    permission,
                    required,
                    resources,
                    reason: value.get("reason").and_then(Value::as_str).unwrap_or("").to_string(),
                },
            );
        }
    }
    Ok(out)
}

/// Declarations in manifest order (required first), for policy listings.
pub fn ordered_declarations(manifest: &Value) -> PluginResult<Vec<Declaration>> {
    let map = normalize_declarations(manifest)?;
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for key in ["required", "optional"] {
        for value in manifest.get("permissions").and_then(|p| p.get(key)).and_then(Value::as_array).cloned().unwrap_or_default() {
            if let Some(name) = crate::package::manifest::permission_name(&value) {
                if seen.insert(name.to_string()) {
                    if let Some(d) = map.get(name) {
                        out.push(d.clone());
                    }
                }
            }
        }
    }
    Ok(out)
}

/// `defaultSecurityPrincipal`.
pub fn default_security_principal(manifest: &Value, archive_sha256: Option<&str>) -> PluginResult<String> {
    let id = manifest.get("id").and_then(Value::as_str).ok_or_else(|| invalid("Plugin security principal requires manifest identity"))?;
    let publisher = manifest.get("publisher").and_then(Value::as_str).ok_or_else(|| invalid("Plugin security principal requires manifest identity"))?;
    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    hasher.update(b"\0");
    hasher.update(publisher.as_bytes());
    hasher.update(b"\0");
    hasher.update(archive_sha256.unwrap_or("unbound-development-package").as_bytes());
    let digest = hex::encode(hasher.finalize());
    Ok(format!("{}:{digest}", if archive_sha256.is_some() { "unsigned-package" } else { "unsigned-development" }))
}

/// `permissionDeclarationHash` (byte-identical JSON to the Electron host).
pub fn declaration_hash(declaration: &Declaration, security_principal: &str) -> String {
    let mut resources = declaration.resources.clone();
    resources.sort();
    let text = format!(
        "{{\"permission\":{},\"required\":{},\"resources\":{},\"securityPrincipal\":{}}}",
        serde_json::to_string(&declaration.permission).unwrap_or_default(),
        declaration.required,
        serde_json::to_string(&resources).unwrap_or_default(),
        serde_json::to_string(security_principal).unwrap_or_default(),
    );
    hex::encode(Sha256::digest(text.as_bytes()))
}

pub fn declaration_allows(declaration: &Declaration, resource: &str) -> bool {
    if declaration.resources.is_empty() {
        return true;
    }
    let kind = if matches!(declaration.permission.as_str(), "filesystem.read" | "filesystem.write") { "directory" } else { "exact" };
    declaration.resources.iter().any(|r| resource_covers(&declaration.permission, r, resource, kind, "exact"))
}

fn hash_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn normalize_reason(value: Option<&str>, permission: &str) -> String {
    let reason = value.filter(|v| !v.is_empty()).map(str::to_string).unwrap_or_else(|| format!("Allow {permission}"));
    if reason.encode_utf16().count() <= 1024 {
        return reason;
    }
    let suffix = format!(" [sha256:{}]", hash_hex(&reason));
    let keep: String = reason.chars().take(1024 - suffix.len()).collect();
    format!("{keep}{suffix}")
}

fn normalize_operation_id(value: Option<&str>) -> PluginResult<Option<String>> {
    match value {
        None => Ok(None),
        Some(v) if v.is_empty() || v.contains('\0') => Err(permission_denied("Plugin permission operation ID is invalid", None)),
        Some(v) if v.chars().count() <= 128 => Ok(Some(v.to_string())),
        Some(v) => Ok(Some(format!("sha256:{}", hash_hex(v)))),
    }
}

/// An authorization descriptor (`{ permission, resources, reason, ... }`).
#[derive(Debug, Clone, Default)]
pub struct AuthorizationRequest {
    pub permission: String,
    pub resources: Vec<String>,
    pub resource_kinds: Option<Vec<String>>,
    pub reason: Option<String>,
    pub operation_id: Option<String>,
    pub session_id: Option<String>,
    pub allowed_scopes: Option<Vec<String>>,
    pub interactive: Option<bool>,
    pub defer_decision: bool,
    pub display_context: Option<Value>,
    pub related: Vec<(String, Vec<String>)>,
}

impl AuthorizationRequest {
    /// From the wire-like JSON form used by registrations.
    pub fn from_value(value: &Value) -> PluginResult<Self> {
        let strings = |v: Option<&Value>| -> Option<Vec<String>> {
            v.and_then(Value::as_array).map(|a| a.iter().map(|s| s.as_str().unwrap_or("").to_string()).collect())
        };
        let resources = match value.get("resources") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(a)) if a.len() <= 128 => a.iter().map(|s| s.as_str().unwrap_or("").to_string()).collect(),
            _ => return Err(permission_denied("Plugin permission resources are invalid", None)),
        };
        Ok(Self {
            permission: value.get("permission").and_then(Value::as_str).unwrap_or("").to_string(),
            resources,
            resource_kinds: strings(value.get("resourceKinds")),
            reason: value.get("reason").and_then(Value::as_str).map(str::to_string),
            operation_id: value.get("operationId").and_then(Value::as_str).map(str::to_string),
            session_id: value.get("sessionId").and_then(Value::as_str).map(str::to_string),
            allowed_scopes: strings(value.get("allowedScopes")),
            interactive: value.get("interactive").and_then(Value::as_bool),
            defer_decision: value.get("deferDecision").and_then(Value::as_bool) == Some(true),
            display_context: value.get("displayContext").cloned(),
            related: value
                .get("relatedPermissions")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .map(|i| (i["permission"].as_str().unwrap_or("").to_string(), strings(i.get("resources")).unwrap_or_default()))
                        .collect()
                })
                .unwrap_or_default(),
        })
    }
}

/// Who is asking: a runtime identity or a host-side plugin record.
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub plugin_id: String,
    pub plugin_version: Option<String>,
    pub runtime_id: Option<String>,
    pub runtime_kind: Option<String>,
    pub manifest: Arc<Value>,
    pub security_principal: Option<String>,
    pub source_owner: Option<String>,
    pub signal: Option<CancellationToken>,
    /// Shared per-RPC operation receipt key (related-permission approvals).
    pub operation_key: Option<String>,
}

/// Interactive approver (the renderer prompt in the app).
pub trait DecisionProvider: Send + Sync {
    fn request(&self, request: Value, signal: CancellationToken) -> BoxFuture<'static, PluginResult<Value>>;
}

#[derive(Debug, Clone)]
struct MemoryGrant {
    plugin_id: String,
    source_owner: String,
    permission: String,
    declaration_hash: String,
    resource: String,
    resource_kind: String,
    scope: String,
    session_id: Option<String>,
    granted_at: i64,
}

impl MemoryGrant {
    fn to_value(&self) -> Value {
        json!({
            "pluginId": self.plugin_id, "sourceOwner": self.source_owner, "permission": self.permission,
            "declarationHash": self.declaration_hash, "resource": self.resource, "resourceKind": self.resource_kind,
            "scope": self.scope, "sessionId": self.session_id, "grantedAt": self.granted_at,
        })
    }
}

#[derive(Debug, Clone)]
struct OperationReceipt {
    revision: u64,
    plugin_id: String,
    runtime_id: Option<String>,
    security_principal: String,
    source_owner: Option<String>,
    permissions: Vec<(String, Vec<String>)>,
}

/// Result of a successful authorization.
#[derive(Debug, Clone)]
pub struct Authorization {
    pub resources: Vec<String>,
    pub scope: String,
}

type RevokeListener = Arc<dyn Fn(&Value) + Send + Sync>;

pub struct PermissionEngine {
    database: Arc<PluginDatabase>,
    decision: Mutex<Option<Arc<dyn DecisionProvider>>>,
    application_grants: Mutex<HashMap<String, MemoryGrant>>,
    session_grants: Mutex<HashMap<String, MemoryGrant>>,
    policy_revisions: Mutex<HashMap<String, u64>>,
    policy_instance_id: String,
    prompts: Mutex<Vec<(String, String, String, Vec<String>, Option<String>, CancellationToken)>>,
    receipts: Mutex<HashMap<String, OperationReceipt>>,
    listeners: Mutex<Vec<(u64, RevokeListener)>>,
    next_listener: Mutex<u64>,
    closed: Mutex<bool>,
    shutdown: CancellationToken,
    pub on_policy_changed: Mutex<Option<Arc<dyn Fn(&str, &str, &str) + Send + Sync>>>,
}

impl PermissionEngine {
    pub fn new(database: Arc<PluginDatabase>) -> Self {
        Self {
            database,
            decision: Mutex::new(None),
            application_grants: Mutex::new(HashMap::new()),
            session_grants: Mutex::new(HashMap::new()),
            policy_revisions: Mutex::new(HashMap::new()),
            policy_instance_id: uuid::Uuid::new_v4().to_string(),
            prompts: Mutex::new(Vec::new()),
            receipts: Mutex::new(HashMap::new()),
            listeners: Mutex::new(Vec::new()),
            next_listener: Mutex::new(0),
            closed: Mutex::new(false),
            shutdown: CancellationToken::new(),
            on_policy_changed: Mutex::new(None),
        }
    }

    pub fn set_decision_provider(&self, provider: Arc<dyn DecisionProvider>) {
        *self.decision.lock() = Some(provider);
    }

    pub fn on_did_revoke(&self, listener: RevokeListener) -> u64 {
        let mut next = self.next_listener.lock();
        *next += 1;
        self.listeners.lock().push((*next, listener));
        *next
    }

    pub fn remove_listener(&self, id: u64) {
        self.listeners.lock().retain(|(i, _)| *i != id);
    }

    pub fn revision(&self, plugin_id: &str) -> u64 {
        self.policy_revisions.lock().get(plugin_id).copied().unwrap_or(0)
    }

    fn emit_revocation(&self, event: Value) {
        let plugin_id = event["pluginId"].as_str().unwrap_or("").to_string();
        *self.policy_revisions.lock().entry(plugin_id).or_insert(0) += 1;
        let listeners: Vec<RevokeListener> = self.listeners.lock().iter().map(|(_, l)| l.clone()).collect();
        for listener in listeners {
            listener(&event);
        }
    }

    fn abort_prompts(&self, plugin_id: &str, permission: Option<&str>, resource: Option<&str>) {
        for (_, pid, perm, resources, _, token) in self.prompts.lock().iter() {
            if pid != plugin_id {
                continue;
            }
            if permission.is_some_and(|p| p != perm) {
                continue;
            }
            if resource.is_some_and(|r| !resources.iter().any(|x| x == r)) {
                continue;
            }
            token.cancel();
        }
    }

    pub fn owner_of(&self, plugin_id: &str) -> String {
        self.owner(plugin_id)
    }

    fn owner(&self, plugin_id: &str) -> String {
        self.database.private_owner(plugin_id).unwrap_or_else(|_| plugin_id.to_string())
    }

    pub fn get_mode(&self, plugin_id: &str, source_owner: Option<&str>, permission: &str) -> PluginResult<String> {
        assert_permission(permission)?;
        if let Some(owner) = source_owner {
            if self.owner(plugin_id) != owner {
                return Err(permission_denied("Plugin permission source changed", None));
            }
        }
        self.database.get_permission_mode(plugin_id, permission)
    }

    /// `getPolicyRevision` (opaque optimistic-concurrency token for the UI).
    pub fn policy_revision(&self, plugin_id: &str, active_version: Option<&str>) -> String {
        let text = serde_json::to_string(&json!([self.policy_instance_id, self.owner(plugin_id), active_version, self.revision(plugin_id)])).unwrap_or_default();
        hash_hex(&text)
    }

    pub fn describe_policies(&self, plugin_id: &str, manifest: &Value) -> PluginResult<Vec<Value>> {
        ordered_declarations(manifest)?
            .into_iter()
            .map(|d| {
                Ok(json!({
                    "permission": d.permission,
                    "resources": if d.resources.is_empty() { vec!["*".to_string()] } else { d.resources.clone() },
                    "mode": self.get_mode(plugin_id, None, &d.permission)?,
                }))
            })
            .collect()
    }

    pub fn set_mode(&self, plugin_id: &str, manifest: &Value, permission: &str, mode: &str) -> PluginResult<()> {
        assert_permission(permission)?;
        if !matches!(mode, "allow" | "ask" | "deny") {
            return Err(PluginError::invalid("Plugin permission mode is invalid"));
        }
        if !normalize_declarations(manifest)?.contains_key(permission) {
            return Err(permission_denied("Permission is undeclared", None));
        }
        self.database.set_permission_mode(plugin_id, permission, mode)?;
        self.revoke_all(plugin_id)?;
        let callback = self.on_policy_changed.lock().clone();
        if let Some(callback) = callback {
            callback(plugin_id, permission, mode);
        }
        Ok(())
    }

    fn audit(&self, plugin_id: &str, event: &str, details: Value) {
        let _ = self.database.record_security_audit(plugin_id, event, &details);
    }

    fn assert_declared(&self, context: &AuthContext, permission: &str, resources: &[String]) -> PluginResult<(Declaration, String, String)> {
        let declarations = normalize_declarations(&context.manifest)?;
        let declaration = declarations
            .get(permission)
            .cloned()
            .ok_or_else(|| permission_denied(format!("Plugin did not declare permission: {permission}"), Some(json!({ "permission": permission }))))?;
        for resource in resources {
            if !declaration_allows(&declaration, resource) {
                return Err(permission_denied(
                    format!("Plugin did not declare permission resource: {permission}"),
                    Some(json!({ "permission": permission, "resource": resource })),
                ));
            }
        }
        let principal = match &context.security_principal {
            Some(p) => p.clone(),
            None => default_security_principal(&context.manifest, None)?,
        };
        let hash = declaration_hash(&declaration, &principal);
        Ok((declaration, hash, principal))
    }

    fn memory_grant_covers(&self, grant: &MemoryGrant, context: &AuthContext, permission: &str, hash: &str, resource: &str, kind: &str, session: Option<&str>) -> bool {
        grant.plugin_id == context.plugin_id
            && grant.source_owner == self.owner(&context.plugin_id)
            && grant.permission == permission
            && grant.declaration_hash == hash
            && (grant.scope != "session" || grant.session_id.as_deref() == session)
            && resource_covers(permission, &grant.resource, resource, &grant.resource_kind, kind)
    }

    fn has_grant(&self, context: &AuthContext, permission: &str, hash: &str, resource: &str, kind: &str, session: Option<&str>) -> PluginResult<bool> {
        if self.application_grants.lock().values().any(|g| self.memory_grant_covers(g, context, permission, hash, resource, kind, session)) {
            return Ok(true);
        }
        if session.is_some() && self.session_grants.lock().values().any(|g| self.memory_grant_covers(g, context, permission, hash, resource, kind, session)) {
            return Ok(true);
        }
        Ok(self.database.list_permission_grants(&context.plugin_id)?.iter().any(|g| {
            g.permission == permission && g.declaration_hash == hash && resource_covers(permission, &g.resource, resource, &g.resource_kind, kind)
        }))
    }

    fn normalize_descriptors(permission: &str, values: &[String], kinds: Option<&[String]>) -> PluginResult<Vec<(String, String)>> {
        let run = || -> PluginResult<Vec<(String, String)>> {
            if let Some(kinds) = kinds {
                if kinds.len() != values.len() {
                    return Err(invalid("Resource kinds must align with resources"));
                }
            }
            let mut map: BTreeMap<String, String> = BTreeMap::new();
            for (index, value) in values.iter().enumerate() {
                let resource = canonicalize_resource(permission, value)?;
                let kind = kinds.and_then(|k| k.get(index)).cloned().unwrap_or_else(|| "exact".into());
                if (kind != "exact" && kind != "directory")
                    || (kind == "directory" && permission != "filesystem.read" && permission != "filesystem.write")
                    || (resource == "*" && kind != "exact")
                {
                    return Err(invalid("Resource kind is invalid"));
                }
                if let Some(previous) = map.get(&resource) {
                    if previous != &kind {
                        return Err(invalid("Duplicate resources cannot have conflicting kinds"));
                    }
                }
                map.insert(resource, kind);
            }
            Ok(map.into_iter().collect())
        };
        run().map_err(|_| permission_denied("Plugin permission resources are invalid", Some(json!({ "permission": permission }))))
    }

    /// `authorize(context, descriptor)`.
    pub async fn authorize(&self, context: &AuthContext, request: &AuthorizationRequest) -> PluginResult<Authorization> {
        if *self.closed.lock() {
            return Err(permission_denied("Plugin permission engine is unavailable", None));
        }
        if context.signal.as_ref().is_some_and(CancellationToken::is_cancelled) {
            return Err(PluginError::cancelled());
        }
        let permission = request.permission.clone();
        if request.resources.len() > 128 {
            return Err(permission_denied("Plugin permission resources are invalid", None));
        }
        let host_reason = (permission == "terminal.intercept.input").then_some(
            "This plugin can inspect and rewrite Terminal input. Netcatty bypasses host-recognized credential input, but arbitrary no-echo input may not be detectable.",
        );
        let reason = normalize_reason(host_reason.or(request.reason.as_deref()), &permission);
        let operation_id = normalize_operation_id(request.operation_id.as_deref())?;
        if let Some(session) = &request.session_id {
            if session.is_empty() || session.len() > 128 || session.contains('\0') {
                return Err(permission_denied("Plugin permission session ID is invalid", None));
            }
        }
        if let Some(scopes) = &request.allowed_scopes {
            if scopes.is_empty() || scopes.iter().any(|s| !matches!(s.as_str(), "once" | "session" | "application" | "always")) {
                return Err(permission_denied("Plugin permission grant scopes are invalid", None));
            }
        }
        let wildcard = vec!["*".to_string()];
        let (values, kinds) = if request.resources.is_empty() { (&wildcard, None) } else { (&request.resources, request.resource_kinds.as_deref()) };
        let descriptors = Self::normalize_descriptors(&permission, values, kinds)?;
        let resources: Vec<String> = descriptors.iter().map(|(r, _)| r.clone()).collect();
        let resource_kinds: Vec<String> = descriptors.iter().map(|(_, k)| k.clone()).collect();
        let (declaration, hash, principal) = self.assert_declared(context, &permission, &resources)?;
        let revision = self.revision(&context.plugin_id);
        let mode = self.get_mode(&context.plugin_id, context.source_owner.as_deref(), &permission)?;
        if mode == "deny" {
            self.audit(&context.plugin_id, "permission.denied", json!({ "permission": permission, "resources": resources, "mode": mode }));
            return Err(permission_denied(format!("Plugin permission is disabled: {permission}"), None));
        }
        if request.related.len() > 5 {
            return Err(permission_denied("Related permission scope is invalid", None));
        }
        let mut related = Vec::new();
        for (rp, rr) in &request.related {
            let rres: Vec<String> = Self::normalize_descriptors(rp, if rr.is_empty() { &wildcard } else { rr }, None)?.into_iter().map(|(r, _)| r).collect();
            self.assert_declared(context, rp, &rres)?;
            let rmode = self.get_mode(&context.plugin_id, context.source_owner.as_deref(), rp)?;
            if rmode == "deny" {
                self.audit(&context.plugin_id, "permission.denied", json!({ "permission": rp, "mode": rmode }));
                return Err(permission_denied(format!("Plugin permission is disabled: {rp}"), None));
            }
            related.push((rp.clone(), rres, rmode));
        }
        let related_ask = related.iter().any(|(_, _, m)| m == "ask");
        let source_owner = context.source_owner.clone().or_else(|| self.database.private_owner(&context.plugin_id).ok());
        let operation_approved = context.operation_key.as_ref().and_then(|k| self.receipts.lock().get(k).cloned()).is_some_and(|receipt| {
            receipt.revision == revision
                && receipt.plugin_id == context.plugin_id
                && receipt.runtime_id == context.runtime_id
                && receipt.security_principal == principal
                && receipt.source_owner == source_owner
                && receipt.permissions.iter().any(|(p, r)| p == &permission && resources.iter().all(|x| r.contains(x)))
        });
        if (mode == "allow" && !related_ask) || request.defer_decision || operation_approved {
            self.audit(&context.plugin_id, "permission.used", json!({ "permission": permission, "resources": resources, "mode": mode, "runtimeId": context.runtime_id }));
            return Ok(Authorization { resources, scope: "policy".into() });
        }
        if !related_ask {
            let mut all = true;
            for (index, resource) in resources.iter().enumerate() {
                if !self.has_grant(context, &permission, &hash, resource, &resource_kinds[index], request.session_id.as_deref())? {
                    all = false;
                    break;
                }
            }
            if all {
                if AUDITED_PERMISSION_USES.contains(&permission.as_str()) {
                    self.audit(&context.plugin_id, "permission.used", json!({
                        "permission": permission, "resources": resources, "resourceKinds": resource_kinds,
                        "runtimeId": context.runtime_id, "operationId": operation_id,
                    }));
                }
                return Ok(Authorization { resources, scope: "existing".into() });
            }
        }
        let provider = self.decision.lock().clone();
        let Some(provider) = provider.filter(|_| request.interactive != Some(false)) else {
            self.audit(&context.plugin_id, "permission.denied", json!({ "permission": permission, "resources": resources, "reason": "no-interactive-approver" }));
            return Err(permission_denied(format!("Plugin permission is not granted: {permission}"), Some(json!({ "permission": permission, "resources": resources }))));
        };
        let request_id = uuid::Uuid::new_v4().to_string();
        let mut prompt = json!({
            "requestId": request_id, "pluginId": context.plugin_id,
            "runtimeId": context.runtime_id, "runtimeKind": context.runtime_kind,
            "permission": permission, "resources": resources, "resourceKinds": resource_kinds, "reason": reason,
        });
        if let Some(v) = &context.plugin_version {
            prompt["pluginVersion"] = json!(v);
        }
        if let Some(name) = context.manifest.get("name") {
            prompt["pluginName"] = name.clone();
        }
        if let Some(publisher) = context.manifest.get("publisher") {
            prompt["publisher"] = publisher.clone();
        }
        if let Some(display) = &request.display_context {
            prompt["displayContext"] = display.clone();
        }
        if !related.is_empty() {
            prompt["relatedPermissions"] = Value::Array(related.iter().map(|(p, r, _)| json!({ "permission": p, "resources": r })).collect());
        }
        if let Some(op) = &operation_id {
            prompt["operationId"] = json!(op);
        }
        if let Some(session) = &request.session_id {
            prompt["sessionId"] = json!(session);
        }
        if let Some(scopes) = &request.allowed_scopes {
            prompt["allowedScopes"] = json!(scopes);
        }
        let token = self.shutdown.child_token();
        self.prompts.lock().push((request_id.clone(), context.plugin_id.clone(), permission.clone(), resources.clone(), request.session_id.clone(), token.clone()));
        let signal = context.signal.clone().unwrap_or_default();
        let outcome = tokio::select! {
            result = provider.request(prompt, token.clone()) => result.map_err(|_| "decision-provider-failed"),
            _ = token.cancelled() => Err("prompt-aborted"),
            _ = signal.cancelled() => Err("prompt-aborted"),
            _ = tokio::time::sleep(PROMPT_TIMEOUT) => Err("prompt-aborted"),
        };
        self.prompts.lock().retain(|(id, ..)| id != &request_id);
        let raw = match outcome {
            Ok(raw) => raw,
            Err(reason) => {
                token.cancel();
                self.audit(&context.plugin_id, "permission.denied", json!({ "permission": permission, "resources": resources, "reason": reason }));
                return Err(permission_denied(
                    if reason == "prompt-aborted" { "Plugin permission request was cancelled or timed out" } else { "Plugin permission decision provider failed" },
                    None,
                ));
            }
        };
        if *self.closed.lock() {
            return Err(permission_denied("Plugin permission engine is unavailable", None));
        }
        if raw.get("requestId").and_then(Value::as_str) != Some(request_id.as_str()) {
            return Err(permission_denied("Plugin permission decision does not match the pending request", None));
        }
        let decision = raw.get("decision").and_then(Value::as_str).unwrap_or("");
        if decision != "allow" {
            self.audit(&context.plugin_id, "permission.denied", json!({ "permission": permission, "resources": resources, "decision": decision }));
            let outcome = if decision == "deny" { "denied" } else { "cancelled" };
            return Err(permission_denied(format!("Plugin permission was {outcome}: {permission}"), None));
        }
        let scope = raw.get("scope").and_then(Value::as_str).unwrap_or("").to_string();
        if !matches!(scope.as_str(), "once" | "session" | "application" | "always") {
            return Err(permission_denied("Plugin permission decision is invalid", None));
        }
        if request.allowed_scopes.as_ref().is_some_and(|s| !s.contains(&scope)) {
            return Err(permission_denied(format!("Plugin permission scope is not supported for this operation: {scope}"), None));
        }
        if scope == "session" && request.session_id.is_none() {
            return Err(permission_denied("Session-scoped plugin permission requires a host-owned session", None));
        }
        if (self.revision(&context.plugin_id)) != revision || self.get_mode(&context.plugin_id, context.source_owner.as_deref(), &permission)? != mode {
            return Err(permission_denied("Plugin permission policy changed", None));
        }
        let owner = self.owner(&context.plugin_id);
        let now = crate::constants::now_ms();
        for (index, resource) in resources.iter().enumerate() {
            let kind = resource_kinds[index].clone();
            let key = format!("{owner}\0{permission}\0{hash}\0{resource}");
            let grant = MemoryGrant {
                plugin_id: context.plugin_id.clone(),
                source_owner: owner.clone(),
                permission: permission.clone(),
                declaration_hash: hash.clone(),
                resource: resource.clone(),
                resource_kind: kind.clone(),
                scope: scope.clone(),
                session_id: request.session_id.clone(),
                granted_at: now,
            };
            match scope.as_str() {
                "application" => {
                    self.application_grants.lock().insert(key, grant);
                }
                "session" => {
                    self.session_grants.lock().insert(format!("{}\0{key}", request.session_id.clone().unwrap_or_default()), grant);
                }
                "always" => self.database.upsert_permission_grant(&context.plugin_id, &permission, resource, &kind, &hash)?,
                _ => {}
            }
        }
        let _ = declaration;
        self.audit(&context.plugin_id, "permission.granted", json!({
            "permission": permission, "resources": resources, "resourceKinds": resource_kinds, "scope": scope, "operationId": operation_id,
        }));
        if let Some(key) = &context.operation_key {
            if !related.is_empty() {
                let mut permissions = vec![(permission.clone(), resources.clone())];
                permissions.extend(related.iter().map(|(p, r, _)| (p.clone(), r.clone())));
                self.receipts.lock().insert(
                    key.clone(),
                    OperationReceipt {
                        revision,
                        plugin_id: context.plugin_id.clone(),
                        runtime_id: context.runtime_id.clone(),
                        security_principal: principal,
                        source_owner,
                        permissions,
                    },
                );
            }
        }
        Ok(Authorization { resources, scope })
    }

    /// Drop the per-RPC related-permission receipt.
    pub fn forget_operation(&self, key: &str) {
        self.receipts.lock().remove(key);
    }

    pub fn list_grants(&self, plugin_id: &str) -> PluginResult<Value> {
        let always: Vec<Value> = self
            .database
            .list_permission_grants(plugin_id)?
            .into_iter()
            .map(|g| json!({
                "pluginId": g.plugin_id, "permission": g.permission, "resource": g.resource, "resourceKind": g.resource_kind,
                "declarationHash": g.declaration_hash, "grantedAt": g.granted_at, "scope": "always", "sessionId": null,
            }))
            .collect();
        let application: Vec<Value> = self.application_grants.lock().values().filter(|g| g.plugin_id == plugin_id).map(MemoryGrant::to_value).collect();
        let session: Vec<Value> = self.session_grants.lock().values().filter(|g| g.plugin_id == plugin_id).map(MemoryGrant::to_value).collect();
        Ok(json!({ "always": always, "application": application, "session": session }))
    }

    /// `describeGrants`: grants with `matchesCurrentActivation`.
    pub fn describe_grants(&self, plugin_id: &str, current: Option<(&Value, &str)>) -> PluginResult<Value> {
        let mut groups = self.list_grants(plugin_id)?;
        let declarations = match current {
            Some((manifest, _)) => normalize_declarations(manifest)?,
            None => BTreeMap::new(),
        };
        for scope in ["always", "application", "session"] {
            if let Some(items) = groups[scope].as_array_mut() {
                for grant in items {
                    let permission = grant["permission"].as_str().unwrap_or("");
                    let matches = current.is_some_and(|(_, principal)| {
                        declarations.get(permission).is_some_and(|d| {
                            declaration_allows(d, grant["resource"].as_str().unwrap_or(""))
                                && grant["declarationHash"].as_str() == Some(declaration_hash(d, principal).as_str())
                        })
                    });
                    grant["matchesCurrentActivation"] = json!(matches);
                }
            }
        }
        Ok(groups)
    }

    pub fn revoke_session(&self, session_id: &str) {
        for (_, _, _, _, session, token) in self.prompts.lock().iter() {
            if session.as_deref() == Some(session_id) {
                token.cancel();
            }
        }
        let prefix = format!("{session_id}\0");
        self.session_grants.lock().retain(|k, _| !k.starts_with(&prefix));
    }

    pub fn revoke_all(&self, plugin_id: &str) -> PluginResult<()> {
        self.database.delete_all_permission_grants(plugin_id)?;
        self.application_grants.lock().retain(|_, g| g.plugin_id != plugin_id);
        self.session_grants.lock().retain(|_, g| g.plugin_id != plugin_id);
        self.audit(plugin_id, "permission.revoked", json!({ "scope": "all" }));
        self.abort_prompts(plugin_id, None, None);
        self.emit_revocation(json!({ "pluginId": plugin_id, "scope": "all" }));
        Ok(())
    }

    pub fn revoke_always(&self, plugin_id: &str, permission: &str, resource: &str) -> PluginResult<()> {
        let canonical = canonicalize_resource(permission, resource)?;
        self.database.delete_permission_grant(plugin_id, permission, &canonical)?;
        self.audit(plugin_id, "permission.revoked", json!({ "scope": "always", "permission": permission, "resource": canonical }));
        self.abort_prompts(plugin_id, Some(permission), Some(&canonical));
        self.emit_revocation(json!({ "pluginId": plugin_id, "permission": permission, "resource": canonical, "scope": "always" }));
        Ok(())
    }

    pub fn shutdown(&self) {
        let mut closed = self.closed.lock();
        if *closed {
            return;
        }
        *closed = true;
        self.shutdown.cancel();
        self.application_grants.lock().clear();
        self.session_grants.lock().clear();
        self.prompts.lock().clear();
        self.listeners.lock().clear();
    }
}

// ---- renderer prompt host ---------------------------------------------------

/// `escapePermissionText`.
pub fn escape_permission_text(value: &str, max: usize) -> String {
    let mut out = String::new();
    for ch in value.chars().take(max) {
        let code = ch as u32;
        if code <= 0x1f || (0x7f..=0x9f).contains(&code) || code == 0x2028 || code == 0x2029 || (0x202a..=0x202e).contains(&code) || (0x2066..=0x2069).contains(&code) {
            match ch {
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                _ => out.push_str(&format!("\\u{code:04x}")),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Renderer-facing prompt sink: emits `netcatty:plugins:permission-prompt`
/// to the ready owner window and checks focus / lock state.
pub trait PromptSurface: Send + Sync {
    /// Emit to the owner window; `false` when no focused, unlocked owner.
    fn emit(&self, owner: &str, payload: Value) -> bool;
    fn owner_usable(&self, owner: &str) -> bool;
}

struct PendingPrompt {
    owner: String,
    action_token: String,
    tx: tokio::sync::oneshot::Sender<String>,
    allowed_scopes: Option<Vec<String>>,
    session_id: Option<String>,
}

/// `PluginPermissionDecisionHost`.
pub struct PermissionDecisionHost {
    surface: Arc<dyn PromptSurface>,
    owner: Mutex<Option<String>>,
    pending: Arc<Mutex<HashMap<String, PendingPrompt>>>,
}

impl PermissionDecisionHost {
    pub fn new(surface: Arc<dyn PromptSurface>) -> Self {
        Self { surface, owner: Mutex::new(None), pending: Arc::new(Mutex::new(HashMap::new())) }
    }

    pub fn set_ready(&self, owner: &str, ready: bool) -> bool {
        let mut current = self.owner.lock();
        if current.as_deref() == Some(owner) || !ready {
            self.cancel_owner(owner);
        }
        if ready {
            *current = Some(owner.to_string());
        } else if current.as_deref() == Some(owner) {
            *current = None;
        }
        true
    }

    pub fn cancel_owner(&self, owner: &str) {
        let ids: Vec<String> = self.pending.lock().iter().filter(|(_, p)| p.owner == owner).map(|(k, _)| k.clone()).collect();
        for id in ids {
            self.finish(&id, "cancel");
        }
    }

    pub fn cancel_all(&self) {
        let ids: Vec<String> = self.pending.lock().keys().cloned().collect();
        for id in ids {
            self.finish(&id, "cancel");
        }
    }

    fn finish(&self, request_id: &str, decision: &str) {
        let entry = self.pending.lock().remove(request_id);
        if let Some(entry) = entry {
            self.surface.emit(&entry.owner, json!({ "requestId": request_id, "closed": true }));
            let _ = entry.tx.send(decision.to_string());
        }
    }

    /// `respond(sender, { requestId, actionToken, decision })`.
    pub fn respond(&self, owner: &str, response: &Value) -> PluginResult<bool> {
        let object = response.as_object().ok_or_else(|| permission_denied("Permission response is invalid", None))?;
        if object.keys().any(|k| !matches!(k.as_str(), "requestId" | "actionToken" | "decision"))
            || !matches!(response["decision"].as_str(), Some("allow" | "deny" | "cancel"))
            || !response["actionToken"].is_string()
        {
            return Err(permission_denied("Permission response is invalid", None));
        }
        if !self.surface.owner_usable(owner) || self.owner.lock().as_deref() != Some(owner) {
            return Err(permission_denied("Permission UI requires a focused unlocked app window", None));
        }
        let request_id = response["requestId"].as_str().unwrap_or("");
        let matches = self.pending.lock().get(request_id).is_some_and(|p| {
            p.owner == owner && constant_time_eq(p.action_token.as_bytes(), response["actionToken"].as_str().unwrap_or("").as_bytes())
        });
        if !matches {
            return Ok(false);
        }
        self.finish(request_id, response["decision"].as_str().unwrap_or("cancel"));
        Ok(true)
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl DecisionProvider for PermissionDecisionHost {
    fn request(&self, request: Value, signal: CancellationToken) -> BoxFuture<'static, PluginResult<Value>> {
        let owner = self.owner.lock().clone();
        let known = request["permission"].as_str().is_some_and(|p| plugin_permissions().contains(p));
        let Some(owner) = owner.filter(|o| self.surface.owner_usable(o)).filter(|_| known && self.pending.lock().len() < 16) else {
            return Box::pin(async { Err(permission_denied("Permission UI requires a focused unlocked app window", None)) });
        };
        let request_id = request["requestId"].as_str().unwrap_or("").to_string();
        let token_bytes: [u8; 32] = rand::random();
        let action_token = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, token_bytes);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let allowed_scopes: Option<Vec<String>> = request["allowedScopes"].as_array().map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect());
        let session_id = request["sessionId"].as_str().map(str::to_string);
        self.pending.lock().insert(
            request_id.clone(),
            PendingPrompt { owner: owner.clone(), action_token: action_token.clone(), tx, allowed_scopes, session_id },
        );
        let mut payload = request.clone();
        payload["actionToken"] = json!(action_token);
        if let Some(name) = request["pluginName"].as_str() {
            payload["pluginName"] = json!(escape_permission_text(name, 1024));
        }
        payload["resources"] = Value::Array(
            request["resources"].as_array().cloned().unwrap_or_default().iter().map(|r| json!(escape_permission_text(r.as_str().unwrap_or(""), 1024))).collect(),
        );
        if let Some(related) = request["relatedPermissions"].as_array() {
            payload["relatedPermissions"] = Value::Array(related.iter().map(|item| json!({
                "permission": item["permission"],
                "resources": item["resources"].as_array().cloned().unwrap_or_default().iter().map(|r| json!(escape_permission_text(r.as_str().unwrap_or(""), 1024))).collect::<Vec<_>>(),
            })).collect());
        }
        if !self.surface.emit(&owner, payload) {
            self.pending.lock().remove(&request_id);
            return Box::pin(async { Err(permission_denied("Permission prompt was cancelled", None)) });
        }
        let pending = self.pending.clone();
        let surface = self.surface.clone();
        Box::pin(async move {
            let decision = tokio::select! {
                d = rx => d.unwrap_or_else(|_| "cancel".into()),
                _ = signal.cancelled() => {
                    let entry = pending.lock().remove(&request_id);
                    if let Some(entry) = entry {
                        surface.emit(&entry.owner, json!({ "requestId": request_id, "closed": true }));
                    }
                    return Err(permission_denied("Permission prompt was cancelled", None));
                }
            };
            let mut out = json!({ "requestId": request_id, "decision": decision });
            if decision == "allow" {
                // Renderer "Allow" is one operation unless the request only
                // supports session grants for a host-owned session.
                let entry_scopes = request["allowedScopes"].as_array().map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect::<Vec<_>>());
                let session = request["sessionId"].as_str().is_some();
                let scope = match entry_scopes {
                    Some(s) if !s.iter().any(|x| x == "once") && session && s.iter().any(|x| x == "session") => "session",
                    _ => "once",
                };
                out["scope"] = json!(scope);
            }
            Ok(out)
        })
    }
}

impl PendingPrompt {
    #[allow(dead_code)]
    fn scopes(&self) -> (&Option<Vec<String>>, &Option<String>) {
        (&self.allowed_scopes, &self.session_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::InstallRecord;
    use crate::source::Source;

    fn manifest() -> Value {
        json!({
            "id": "com.example.p", "publisher": "x",
            "permissions": {
                "required": ["storage", { "permission": "network", "resources": ["https://api.example.com"] }],
                "optional": [{ "permission": "filesystem.read", "resources": ["/data"] }]
            }
        })
    }

    fn engine() -> (tempfile::TempDir, Arc<PluginDatabase>, PermissionEngine) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(PluginDatabase::open(&dir.path().join("p.sqlite")).unwrap());
        db.install_version(&InstallRecord {
            source: Source::local(), plugin_id: "com.example.p".into(), version: "1.0.0".into(),
            manifest: manifest(), archive_sha256: "c".repeat(64), package_relative_path: "x".into(),
        }, true, false).unwrap();
        let e = PermissionEngine::new(db.clone());
        (dir, db, e)
    }

    fn ctx() -> AuthContext {
        AuthContext {
            plugin_id: "com.example.p".into(), plugin_version: Some("1.0.0".into()), runtime_id: Some("r".into()),
            runtime_kind: Some("browser".into()), manifest: Arc::new(manifest()),
            security_principal: Some(default_security_principal(&manifest(), Some(&"c".repeat(64))).unwrap()),
            source_owner: None, signal: None, operation_key: None,
        }
    }

    struct Approve(&'static str);
    impl DecisionProvider for Approve {
        fn request(&self, request: Value, _signal: CancellationToken) -> BoxFuture<'static, PluginResult<Value>> {
            let scope = self.0;
            Box::pin(async move { Ok(json!({ "requestId": request["requestId"], "decision": "allow", "scope": scope })) })
        }
    }

    #[test]
    fn resources_and_hash() {
        assert_eq!(canonicalize_resource("network", "https://API.example.com:443/").unwrap(), "https://api.example.com");
        assert!(canonicalize_resource("network", "https://a.com/path").is_err());
        assert_eq!(canonicalize_stream_endpoint("tls://Example.com:443").unwrap().0, "tls://example.com:443");
        assert!(canonicalize_stream_endpoint("tcp://1.2.3:80").is_ok());
        assert!(canonicalize_stream_endpoint("tcp://host:0").is_err());
        assert!(resource_covers("filesystem.read", "/data", "/data/x/y", "directory", "exact"));
        assert!(!resource_covers("filesystem.read", "/data", "/database", "directory", "exact"));
        let d = Declaration { permission: "storage".into(), required: true, resources: vec![], reason: String::new() };
        // Must match JSON.stringify({permission,required,resources,securityPrincipal}).
        let expected = hash_hex(r#"{"permission":"storage","required":true,"resources":[],"securityPrincipal":"unsigned-package:abc0000000000000"}"#);
        assert_eq!(declaration_hash(&d, "unsigned-package:abc0000000000000"), expected);
    }

    #[tokio::test]
    async fn allow_deny_and_ask_modes() {
        let (_dir, _db, engine) = engine();
        let request = AuthorizationRequest { permission: "storage".into(), resources: vec!["*".into()], ..Default::default() };
        assert_eq!(engine.authorize(&ctx(), &request).await.unwrap().scope, "policy");
        let undeclared = AuthorizationRequest { permission: "secrets".into(), ..Default::default() };
        assert_eq!(engine.authorize(&ctx(), &undeclared).await.unwrap_err().code(), Some(codes::PERMISSION_DENIED));
        engine.set_mode("com.example.p", &manifest(), "storage", "deny").unwrap();
        assert!(engine.authorize(&ctx(), &request).await.is_err());
        engine.set_mode("com.example.p", &manifest(), "storage", "ask").unwrap();
        // No approver: denied.
        assert!(engine.authorize(&ctx(), &request).await.is_err());
        engine.set_decision_provider(Arc::new(Approve("always")));
        assert_eq!(engine.authorize(&ctx(), &request).await.unwrap().scope, "always");
        // Persisted grant now satisfies without prompting.
        engine.set_decision_provider(Arc::new(Approve("bogus")));
        assert_eq!(engine.authorize(&ctx(), &request).await.unwrap().scope, "existing");
        engine.revoke_all("com.example.p").unwrap();
        assert!(engine.authorize(&ctx(), &request).await.is_err());
    }

    #[tokio::test]
    async fn undeclared_resources_are_denied() {
        let (_dir, _db, engine) = engine();
        let request = AuthorizationRequest { permission: "network".into(), resources: vec!["https://evil.example".into()], ..Default::default() };
        assert!(engine.authorize(&ctx(), &request).await.is_err());
        let ok = AuthorizationRequest { permission: "network".into(), resources: vec!["https://api.example.com/".into()], ..Default::default() };
        assert!(engine.authorize(&ctx(), &ok).await.is_ok());
    }
}
