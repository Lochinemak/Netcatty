//! Secure capabilities (ports of `secureCapabilities.cjs`,
//! `secretLease.cjs`, `credentialBroker.cjs`, `credentialCatalog.cjs`,
//! `networkBroker.cjs` and `filesystemBroker.cjs`).
//!
//! * `secrets.get/set/delete` — OS-encrypted plugin secrets.
//! * `credentials.createLease` — one-use, operation / runtime / plugin bound
//!   leases for plugin secrets or Vault credentials (`vault.credentials`).
//! * `network.request` — HTTP(S) broker: per-origin authorization, every
//!   redirect origin re-authorized, no ambient cookies, bounded bodies,
//!   lease-injected `Authorization`.
//! * `filesystem.readFile/stat/writeFile` — exact-path grants, realpath
//!   checks, no symlink targets, overwrite-only writes, protected host dirs.
//!
//! Directory enumeration and companion executables are not offered (the
//! Electron host also gates enumeration on a secure handle adapter it does
//! not ship; companions require the advanced Node runtime and are reported
//! as unsupported).

use crate::constants::{now_ms, PLUGIN_RPC_MAX_RAW_BYTES};
use crate::contract;
use crate::error::{codes, PluginError, PluginResult};
use crate::permissions::{canonicalize_network_origin, AuthorizationRequest};
use crate::quota::QuotaManager;
use crate::registry::{AuthorizationSpec, CallContext, HostRpcRegistry, RegisterOptions};
use crate::secrets::{assert_secret_key, assert_secret_ref, PluginSecretStore, SecretCipher, MAX_SECRET_BYTES};
use base64::Engine;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn invalid(message: impl Into<String>) -> PluginError {
    PluginError::invalid(message)
}

// ---- secret leases ---------------------------------------------------------

pub const DEFAULT_SECRET_LEASE_TTL_MS: i64 = 30_000;
pub const MAX_SECRET_LEASE_TTL_MS: i64 = 60_000;
pub const MAX_SECRET_LEASES_PER_RUNTIME: usize = 128;

/// What a lease resolves to.
#[derive(Clone)]
pub enum LeaseCredential {
    Secret(Value),
    Vault(String),
    /// Host-held plaintext (authentication challenge answers).
    Inline(String),
}

struct LeaseRecord {
    plugin_id: String,
    runtime_id: String,
    credential: LeaseCredential,
    operation_id: String,
    expires_at: i64,
}

/// `SecretLeaseStore`.
pub struct SecretLeaseStore {
    secrets: Arc<PluginSecretStore>,
    catalog: Arc<CredentialCatalog>,
    leases: Mutex<HashMap<String, LeaseRecord>>,
    closed: Mutex<bool>,
}

impl SecretLeaseStore {
    pub fn new(secrets: Arc<PluginSecretStore>, catalog: Arc<CredentialCatalog>) -> Self {
        Self { secrets, catalog, leases: Mutex::new(HashMap::new()), closed: Mutex::new(false) }
    }

    pub fn issue(&self, plugin_id: &str, runtime_id: &str, credential: LeaseCredential, operation_id: &str, ttl_ms: Option<i64>) -> PluginResult<Value> {
        if *self.closed.lock() {
            return Err(PluginError::unavailable("Secret lease broker is closed"));
        }
        let now = now_ms();
        let mut leases = self.leases.lock();
        leases.retain(|_, l| l.expires_at > now);
        if leases.values().filter(|l| l.runtime_id == runtime_id).count() >= MAX_SECRET_LEASES_PER_RUNTIME {
            return Err(PluginError::exhausted("Too many active secret leases"));
        }
        let ttl = ttl_ms.unwrap_or(DEFAULT_SECRET_LEASE_TTL_MS);
        if !(1..=MAX_SECRET_LEASE_TTL_MS).contains(&ttl) {
            return Err(invalid("Secret lease lifetime is invalid"));
        }
        let bytes: [u8; 24] = rand::random();
        let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let expires_at = now + ttl;
        leases.insert(
            id.clone(),
            LeaseRecord { plugin_id: plugin_id.into(), runtime_id: runtime_id.into(), credential, operation_id: operation_id.into(), expires_at },
        );
        Ok(json!({ "kind": "secret-lease", "id": id, "operationId": operation_id, "expiresAt": expires_at }))
    }

    /// One-use consumption bound to plugin, runtime and operation.
    pub fn consume(&self, plugin_id: &str, runtime_id: &str, lease: &Value, operation_id: &str) -> PluginResult<String> {
        let id = lease.get("id").and_then(Value::as_str).unwrap_or("");
        if lease.get("kind").and_then(Value::as_str) != Some("secret-lease") || id.len() < 32 || id.len() > 256 {
            return Err(invalid("Secret lease reference is invalid"));
        }
        let record = {
            let mut leases = self.leases.lock();
            let record = leases.get(id).filter(|r| r.expires_at > now_ms()).ok_or_else(|| PluginError::not_found("Secret lease is missing or expired"))?;
            if record.plugin_id != plugin_id || record.runtime_id != runtime_id || record.operation_id != operation_id {
                return Err(PluginError::denied("Secret lease scope does not match the operation"));
            }
            leases.remove(id).expect("present")
        };
        match record.credential {
            LeaseCredential::Secret(reference) => self.secrets.resolve(&record.plugin_id, &reference),
            LeaseCredential::Vault(credential_id) => self.catalog.resolve(&credential_id),
            LeaseCredential::Inline(secret) => Ok(secret),
        }
    }

    pub fn revoke_operation(&self, plugin_id: &str, operation_id: &str) {
        self.leases.lock().retain(|_, l| !(l.plugin_id == plugin_id && l.operation_id == operation_id));
    }

    pub fn revoke_runtime(&self, runtime_id: &str) {
        self.leases.lock().retain(|_, l| l.runtime_id != runtime_id);
    }

    pub fn shutdown(&self) {
        *self.closed.lock() = true;
        self.leases.lock().clear();
    }
}

// ---- Vault credential catalog -------------------------------------------------

pub const MAX_CREDENTIAL_CATALOG_ENTRIES: usize = 4096;

/// `PluginCredentialCatalog`: renderer-supplied map of Vault credential IDs
/// to OS-encrypted ciphertexts (the app's credential cipher format).
pub struct CredentialCatalog {
    cipher: Arc<dyn SecretCipher>,
    records: Mutex<HashMap<String, Vec<u8>>>,
}

fn assert_credential_id(id: &str) -> PluginResult<()> {
    if id.len() < 16 || id.len() > 256 || id.contains('\0') {
        return Err(invalid("Vault credential reference is invalid"));
    }
    Ok(())
}

impl CredentialCatalog {
    pub fn new(cipher: Arc<dyn SecretCipher>) -> Self {
        Self { cipher, records: Mutex::new(HashMap::new()) }
    }

    pub fn is_available(&self) -> bool {
        self.cipher.available()
    }

    pub fn update(&self, entries: &Value) -> PluginResult<usize> {
        let entries = entries.as_array().filter(|a| a.len() <= MAX_CREDENTIAL_CATALOG_ENTRIES).ok_or_else(|| invalid("Vault credential catalog is invalid or too large"))?;
        if !self.cipher.available() {
            self.records.lock().clear();
            return Err(PluginError::unavailable("Secure OS-backed Vault credential decryption is unavailable"));
        }
        let mut next = HashMap::new();
        for entry in entries {
            let object = entry.as_object().filter(|o| o.keys().all(|k| k == "id" || k == "ciphertext")).ok_or_else(|| invalid("Vault credential catalog entry is invalid"))?;
            let id = object.get("id").and_then(Value::as_str).unwrap_or("");
            assert_credential_id(id)?;
            let ciphertext = object.get("ciphertext").and_then(Value::as_str).unwrap_or("");
            if !netcatty_store::CredentialCipher::is_encrypted(ciphertext) || ciphertext.len() > 4 * 1024 * 1024 {
                return Err(invalid("Vault credential must use OS-backed encryption"));
            }
            if next.insert(id.to_string(), ciphertext.as_bytes().to_vec()).is_some() {
                return Err(invalid("Vault credential catalog contains duplicate references"));
            }
        }
        let count = next.len();
        *self.records.lock() = next;
        Ok(count)
    }

    pub fn assert_reference(&self, id: &str) -> PluginResult<()> {
        assert_credential_id(id)?;
        if !self.records.lock().contains_key(id) {
            return Err(PluginError::not_found("Vault credential reference was not found"));
        }
        Ok(())
    }

    pub fn resolve(&self, id: &str) -> PluginResult<String> {
        assert_credential_id(id)?;
        let ciphertext = self.records.lock().get(id).cloned().ok_or_else(|| PluginError::not_found("Vault credential reference was not found"))?;
        let value = self.cipher.decrypt(&ciphertext).map_err(|_| PluginError::rpc(codes::DATA_LOSS, "Vault credential could not be decrypted"))?;
        if value.is_empty() || value.len() > MAX_SECRET_BYTES {
            return Err(PluginError::rpc(codes::DATA_LOSS, "Vault credential is invalid or too large"));
        }
        Ok(value)
    }

    pub fn clear(&self) {
        self.records.lock().clear();
    }
}

// ---- lease params -------------------------------------------------------------

struct LeaseParams {
    credential: LeaseCredential,
    secret_key: Option<String>,
    credential_id: Option<String>,
    operation_id: String,
    purpose: String,
    ttl_ms: Option<i64>,
}

fn assert_lease_params(params: &Value) -> PluginResult<LeaseParams> {
    if !params.is_object() {
        return Err(invalid("Credential lease parameters are invalid"));
    }
    let secret = &params["secret"];
    let (credential, secret_key, credential_id) = if secret["kind"] == "secret" {
        let (_, key) = assert_secret_ref(secret)?;
        (LeaseCredential::Secret(secret.clone()), Some(key), None)
    } else {
        let id = secret["id"].as_str().unwrap_or("");
        if secret["kind"] != "credential" || id.len() < 16 || id.len() > 256 {
            return Err(invalid("Credential reference is invalid"));
        }
        (LeaseCredential::Vault(id.into()), None, Some(id.to_string()))
    };
    let operation_id = params["operationId"].as_str().unwrap_or("");
    if operation_id.is_empty() || operation_id.encode_utf16().count() > 128 {
        return Err(invalid("Credential lease operation ID is invalid"));
    }
    let purpose = params["purpose"].as_str().unwrap_or("");
    if purpose.is_empty() || purpose.encode_utf16().count() > 256 {
        return Err(invalid("Credential lease purpose is invalid"));
    }
    let ttl_ms = match params.get("ttlMs") {
        None | Some(Value::Null) => None,
        Some(v) => Some(v.as_i64().filter(|t| (1..=60_000).contains(t)).ok_or_else(|| invalid("Credential lease lifetime is invalid"))?),
    };
    Ok(LeaseParams { credential, secret_key, credential_id, operation_id: operation_id.into(), purpose: purpose.into(), ttl_ms })
}

fn lease_authorization(params: &Value) -> PluginResult<Value> {
    let p = assert_lease_params(params)?;
    Ok(match (&p.credential_id, &p.secret_key) {
        (Some(id), _) => json!({
            "permission": "vault.credentials", "resources": [format!("credential:{id}")],
            "reason": format!("Use Netcatty credential for {}", p.purpose), "operationId": p.operation_id,
        }),
        (_, Some(key)) => json!({
            "permission": "secrets", "resources": [format!("secret:{key}")],
            "reason": format!("Use plugin secret for {}", p.purpose), "operationId": p.operation_id,
        }),
        _ => return Err(invalid("Credential reference is invalid")),
    })
}

// ---- network broker ------------------------------------------------------------

pub const MAX_NETWORK_BODY_BYTES: usize = PLUGIN_RPC_MAX_RAW_BYTES;
const MAX_NETWORK_HEADERS: usize = 64;
const MAX_NETWORK_HEADER_BYTES: usize = 64 * 1024;
const MAX_NETWORK_REDIRECTS: usize = 5;
const FORBIDDEN_REQUEST_HEADERS: &[&str] = &["connection", "content-length", "cookie", "host", "proxy-authorization", "transfer-encoding"];
const SENSITIVE_REDIRECT_HEADERS: &[&str] = &["authorization", "cookie", "proxy-authorization"];
const ENTITY_REDIRECT_HEADERS: &[&str] = &["content-encoding", "content-language", "content-type"];

struct NetworkRequest {
    url: url::Url,
    origin: String,
    method: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    timeout_ms: u64,
}

fn header_name_ok(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$%&'*+.^_`|~-".contains(&b))
}

fn assert_network_request(params: &Value) -> PluginResult<NetworkRequest> {
    if !params.is_object() {
        return Err(invalid("Plugin network request is invalid"));
    }
    let raw = params["url"].as_str().filter(|u| u.len() <= 8192).ok_or_else(|| invalid("Plugin network URL is invalid"))?;
    let url = url::Url::parse(raw).map_err(|_| invalid("Plugin network URL is invalid"))?;
    let origin = canonicalize_network_origin(&url.origin().ascii_serialization())?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("Plugin network URL cannot contain credentials"));
    }
    let method = params["method"].as_str().unwrap_or("GET").to_string();
    if !["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"].contains(&method.as_str()) {
        return Err(invalid("Plugin network method is unsupported"));
    }
    let timeout_ms = match params.get("timeoutMs") {
        None | Some(Value::Null) => 30_000,
        Some(v) => v.as_u64().filter(|t| (1..=300_000).contains(t)).ok_or_else(|| invalid("Plugin network timeout is invalid"))?,
    };
    let body = match params.get("body") {
        None | Some(Value::Null) => None,
        Some(body) => {
            let data = body["data"].as_str().ok_or_else(|| invalid("Plugin network request body is invalid"))?;
            let bytes = match body["encoding"].as_str() {
                Some("utf8") => data.as_bytes().to_vec(),
                Some("base64") => {
                    let bytes = B64.decode(data).map_err(|_| invalid("Plugin network base64 body is not canonical"))?;
                    if B64.encode(&bytes) != data {
                        return Err(invalid("Plugin network base64 body is not canonical"));
                    }
                    bytes
                }
                _ => return Err(invalid("Plugin network request body encoding is unsupported")),
            };
            if bytes.len() > MAX_NETWORK_BODY_BYTES {
                return Err(PluginError::exhausted("Plugin network request body is too large"));
            }
            Some(bytes)
        }
    };
    if body.is_some() && (method == "GET" || method == "HEAD") {
        return Err(invalid(format!("Plugin network {method} requests cannot contain a body")));
    }
    let mut headers = Vec::new();
    if let Some(h) = params.get("headers").filter(|h| !h.is_null()) {
        let map = h.as_object().ok_or_else(|| invalid("Plugin network headers are invalid"))?;
        if map.len() > MAX_NETWORK_HEADERS {
            return Err(invalid("Plugin network request has too many headers"));
        }
        let mut total = 0;
        for (raw_name, value) in map {
            let name = raw_name.to_ascii_lowercase();
            if !header_name_ok(&name) || FORBIDDEN_REQUEST_HEADERS.contains(&name.as_str()) {
                return Err(invalid(format!("Plugin network request header is forbidden: {raw_name}")));
            }
            let value = value
                .as_str()
                .filter(|v| v.encode_utf16().count() <= 8192 && !v.chars().any(|c| (c as u32) <= 0x08 || (0x0a..=0x1f).contains(&(c as u32)) || c as u32 == 0x7f))
                .ok_or_else(|| invalid(format!("Plugin network request header value is invalid: {raw_name}")))?;
            total += name.len() + value.len();
            if total > MAX_NETWORK_HEADER_BYTES {
                return Err(PluginError::exhausted("Plugin network request headers are too large"));
            }
            headers.push((name, value.to_string()));
        }
    }
    Ok(NetworkRequest { url, origin, method, headers, body, timeout_ms })
}

fn network_authorization(params: &Value) -> PluginResult<Value> {
    let request = assert_network_request(params)?;
    Ok(json!({
        "permission": "network", "resources": [request.origin],
        "reason": format!("Connect to {}", request.origin), "operationId": format!("network:{}", request.origin),
    }))
}

fn validate_network_params(params: Value) -> PluginResult<Value> {
    let request = assert_network_request(&params)?;
    let mut validated = json!({
        "url": request.url.as_str(), "method": request.method,
        "headers": request.headers.iter().map(|(k, v)| (k.clone(), json!(v))).collect::<serde_json::Map<_, _>>(),
        "timeoutMs": request.timeout_ms,
    });
    if let Some(body) = &request.body {
        validated["body"] = json!({ "encoding": "base64", "data": B64.encode(body) });
    }
    if let Some(lease) = params.get("credentialLease").filter(|l| !l.is_null()) {
        if !contract::is_valid("SecretLeaseRef", lease) {
            return Err(invalid("Plugin network credential lease is invalid"));
        }
        validated["credentialLease"] = json!({ "kind": "secret-lease", "id": lease["id"], "operationId": lease["operationId"], "expiresAt": lease["expiresAt"] });
    }
    if let Some(auth) = params.get("authorization").filter(|a| !a.is_null()) {
        if !contract::is_valid("PluginNetworkAuthorization", auth) {
            return Err(invalid("Plugin network authorization is invalid"));
        }
        let mut out = json!({ "scheme": if auth["scheme"] == "Basic" { "Basic" } else { "Bearer" } });
        if let Some(user) = auth["username"].as_str() {
            out["username"] = json!(user);
        }
        validated["authorization"] = out;
    }
    Ok(validated)
}

pub struct NetworkBroker {
    client: reqwest::Client,
    quota: Arc<QuotaManager>,
}

impl NetworkBroker {
    pub fn new(quota: Arc<QuotaManager>) -> PluginResult<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| PluginError::host(e.to_string()))?;
        Ok(Self { client, quota })
    }

    pub async fn request(&self, params: &Value, ctx: &CallContext) -> PluginResult<Value> {
        let request = assert_network_request(params)?;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(request.timeout_ms);
        let mut url = request.url.clone();
        let mut origin = request.origin.clone();
        let mut method = request.method.clone();
        let mut body = request.body.clone();
        let mut headers = request.headers.clone();
        for redirects in 0..=MAX_NETWORK_REDIRECTS {
            ctx.assert_active()?;
            if let Some(b) = &body {
                self.quota.charge_bytes(&ctx.identity.runtime_id, "network", b.len() as u64)?;
            }
            let mut builder = self.client.request(reqwest::Method::from_bytes(method.as_bytes()).expect("validated"), url.clone());
            for (k, v) in &headers {
                builder = builder.header(k, v);
            }
            if let Some(b) = &body {
                builder = builder.body(b.clone());
            }
            let send = builder.send();
            let response = tokio::select! {
                r = send => r.map_err(|e| PluginError::unavailable(format!("Plugin network request failed: {e}")))?,
                _ = tokio::time::sleep_until(deadline) => return Err(PluginError::deadline("Plugin network request timed out")),
                _ = ctx.signal.cancelled() => return Err(PluginError::cancelled()),
            };
            let status = response.status().as_u16();
            let mut response_headers = serde_json::Map::new();
            let mut header_bytes = 0;
            for (name, value) in response.headers() {
                if name.as_str() == "set-cookie" {
                    continue;
                }
                let value = value.to_str().unwrap_or("").to_string();
                header_bytes += name.as_str().len() + value.len();
                if response_headers.len() >= MAX_NETWORK_HEADERS || header_bytes > MAX_NETWORK_HEADER_BYTES {
                    return Err(PluginError::exhausted("Plugin network response headers are too large"));
                }
                response_headers.insert(name.as_str().to_string(), json!(value));
            }
            if (300..400).contains(&status) {
                if let Some(location) = response.headers().get("location").and_then(|l| l.to_str().ok()).map(str::to_string) {
                    if redirects == MAX_NETWORK_REDIRECTS {
                        return Err(PluginError::rpc(codes::OUT_OF_RANGE, "Plugin network redirect limit exceeded"));
                    }
                    let next = url.join(&location).map_err(|_| invalid("Plugin network redirect URL is invalid"))?;
                    if !next.username().is_empty() || next.password().is_some() {
                        return Err(invalid("Plugin network redirect URL cannot contain credentials"));
                    }
                    let next_origin = canonicalize_network_origin(&next.origin().ascii_serialization())?;
                    ctx.authorize(&AuthorizationRequest {
                        permission: "network".into(),
                        resources: vec![next_origin.clone()],
                        reason: Some(format!("Follow network redirect to {next_origin}")),
                        operation_id: Some(format!("network:{next_origin}")),
                        ..Default::default()
                    })
                    .await?;
                    if next_origin != origin {
                        headers.retain(|(k, _)| !SENSITIVE_REDIRECT_HEADERS.contains(&k.as_str()));
                    }
                    if status == 303 || ((status == 301 || status == 302) && method == "POST") {
                        method = if method == "HEAD" { "HEAD".into() } else { "GET".into() };
                        body = None;
                        headers.retain(|(k, _)| !ENTITY_REDIRECT_HEADERS.contains(&k.as_str()));
                    }
                    url = next;
                    origin = next_origin;
                    continue;
                }
            }
            if response.content_length().is_some_and(|l| l as usize > MAX_NETWORK_BODY_BYTES) {
                return Err(PluginError::exhausted("Plugin network response is too large"));
            }
            let mut response = response;
            let mut bytes = Vec::new();
            loop {
                let chunk = tokio::select! {
                    c = response.chunk() => c.map_err(|e| PluginError::unavailable(format!("Plugin network response failed: {e}")))?,
                    _ = tokio::time::sleep_until(deadline) => return Err(PluginError::deadline("Plugin network request timed out")),
                    _ = ctx.signal.cancelled() => return Err(PluginError::cancelled()),
                };
                let Some(chunk) = chunk else { break };
                bytes.extend_from_slice(&chunk);
                if bytes.len() > MAX_NETWORK_BODY_BYTES {
                    return Err(PluginError::exhausted("Plugin network response is too large"));
                }
            }
            self.quota.charge_bytes(&ctx.identity.runtime_id, "network", bytes.len() as u64)?;
            ctx.assert_active()?;
            return Ok(json!({
                "url": url.as_str(), "status": status, "headers": response_headers,
                "body": { "encoding": "base64", "data": B64.encode(&bytes) },
            }));
        }
        Err(PluginError::host("Plugin network redirect handling failed"))
    }
}

// ---- filesystem broker -----------------------------------------------------------

pub const MAX_FILESYSTEM_BYTES: usize = PLUGIN_RPC_MAX_RAW_BYTES;

fn assert_absolute_path(value: &Value) -> PluginResult<PathBuf> {
    let text = value.as_str().filter(|s| !s.is_empty() && s.len() <= 8192 && !s.contains('\0')).ok_or_else(|| invalid("Plugin filesystem path must be absolute"))?;
    let path = Path::new(text);
    if !path.is_absolute() {
        return Err(invalid("Plugin filesystem path must be absolute"));
    }
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    Ok(out)
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

pub struct FilesystemBroker {
    quota: Arc<QuotaManager>,
    protected_dirs: Vec<PathBuf>,
    protected_read_dirs: Vec<PathBuf>,
    protected_files: Vec<PathBuf>,
}

fn inside(parent: &Path, candidate: &Path) -> bool {
    candidate.starts_with(parent)
}

fn assert_authorized_path(ctx: &CallContext, permission: &str, canonical: &Path) -> PluginResult<()> {
    let auth = ctx.authorization.as_ref();
    let ok = auth.is_some_and(|a| {
        a["permission"] == permission
            && a["resources"].as_array().is_some_and(|r| r.len() == 1 && r[0].as_str() == Some(path_string(canonical).as_str()))
    });
    if ok {
        Ok(())
    } else {
        Err(PluginError::denied("Plugin filesystem path changed after authorization"))
    }
}

impl FilesystemBroker {
    pub fn new(quota: Arc<QuotaManager>, protected_dirs: Vec<PathBuf>, protected_read_dirs: Vec<PathBuf>, protected_files: Vec<PathBuf>) -> Self {
        Self { quota, protected_dirs, protected_read_dirs, protected_files }
    }

    fn variants(path: &Path) -> Vec<PathBuf> {
        let mut out = vec![path.to_path_buf()];
        if let Ok(real) = std::fs::canonicalize(path) {
            out.push(real);
        }
        out
    }

    fn assert_readable(&self, candidate: &Path) -> PluginResult<()> {
        for dir in &self.protected_read_dirs {
            if Self::variants(dir).iter().any(|p| inside(p, candidate)) {
                return Err(PluginError::denied("Private host conversation storage is protected"));
            }
        }
        Ok(())
    }

    fn assert_writable(&self, candidate: &Path) -> PluginResult<()> {
        for file in &self.protected_files {
            if Self::variants(file).iter().any(|p| p == candidate) {
                return Err(PluginError::denied("Host audit storage is protected"));
            }
        }
        for dir in &self.protected_dirs {
            if Self::variants(dir).iter().any(|p| inside(p, candidate)) {
                return Err(PluginError::denied("Host audit storage is protected"));
            }
        }
        Ok(())
    }

    fn resolve_existing(path: &Path) -> PluginResult<(PathBuf, std::fs::Metadata)> {
        let canonical = std::fs::canonicalize(path)?;
        let meta = std::fs::symlink_metadata(&canonical)?;
        if meta.file_type().is_symlink() {
            return Err(invalid("Plugin filesystem path cannot resolve to a symbolic link"));
        }
        Ok((canonical, meta))
    }

    pub async fn read_file(&self, params: &Value, ctx: &CallContext) -> PluginResult<Value> {
        let path = assert_absolute_path(&params["path"])?;
        let encoding = params["encoding"].as_str().unwrap_or("utf8");
        if encoding != "utf8" && encoding != "base64" {
            return Err(invalid("Plugin filesystem read encoding is invalid"));
        }
        let max = match params.get("maxBytes") {
            None | Some(Value::Null) => MAX_FILESYSTEM_BYTES,
            Some(v) => v.as_u64().filter(|m| *m >= 1 && *m as usize <= MAX_FILESYSTEM_BYTES).ok_or_else(|| invalid("Plugin filesystem read limit is invalid"))? as usize,
        };
        self.assert_readable(&path)?;
        assert_authorized_path(ctx, "filesystem.read", &path)?;
        let (canonical, meta) = Self::resolve_existing(&path)?;
        self.assert_readable(&canonical)?;
        assert_authorized_path(ctx, "filesystem.read", &canonical)?;
        if !meta.is_file() {
            return Err(invalid("Plugin filesystem read target is not a file"));
        }
        if meta.len() as usize > max {
            return Err(PluginError::exhausted("Plugin filesystem file is too large"));
        }
        let bytes = {
            use std::io::Read;
            let mut file = std::fs::File::open(&canonical)?;
            let mut buffer = Vec::new();
            file.by_ref().take(max as u64 + 1).read_to_end(&mut buffer)?;
            if buffer.len() > max {
                return Err(PluginError::exhausted("Plugin filesystem file changed or is too large"));
            }
            buffer
        };
        self.quota.charge_bytes(&ctx.identity.runtime_id, "filesystem", bytes.len() as u64)?;
        ctx.assert_active()?;
        let data = if encoding == "base64" { B64.encode(&bytes) } else { String::from_utf8_lossy(&bytes).into_owned() };
        Ok(json!({ "data": data }))
    }

    pub async fn stat(&self, params: &Value, ctx: &CallContext) -> PluginResult<Value> {
        let path = assert_absolute_path(&params["path"])?;
        self.assert_readable(&path)?;
        assert_authorized_path(ctx, "filesystem.read", &path)?;
        let (canonical, meta) = Self::resolve_existing(&path)?;
        self.assert_readable(&canonical)?;
        assert_authorized_path(ctx, "filesystem.read", &canonical)?;
        ctx.assert_active()?;
        let modified = meta.modified().ok().and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as u64).unwrap_or(0);
        Ok(json!({
            "kind": if meta.is_file() { "file" } else if meta.is_dir() { "directory" } else { "other" },
            "size": meta.len(),
            "modifiedAt": modified,
        }))
    }

    pub async fn write_file(&self, params: &Value, ctx: &CallContext) -> PluginResult<Value> {
        let (path, bytes) = assert_write_params(params)?;
        if params["overwrite"] != json!(true) {
            return Err(PluginError::precondition("Plugin filesystem writes require explicit overwrite of an existing file"));
        }
        self.assert_writable(&path)?;
        assert_authorized_path(ctx, "filesystem.write", &path)?;
        let (canonical, meta) = Self::resolve_existing(&path).map_err(|e| {
            if e.message().contains("No such file") {
                PluginError::precondition("Plugin filesystem writes require an existing regular file")
            } else {
                e
            }
        })?;
        if !meta.is_file() {
            return Err(invalid("Plugin filesystem write target is not a file"));
        }
        self.assert_writable(&canonical)?;
        assert_authorized_path(ctx, "filesystem.write", &canonical)?;
        self.quota.charge_bytes(&ctx.identity.runtime_id, "filesystem", bytes.len() as u64)?;
        ctx.assert_active()?;
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new().write(true).truncate(true).open(&canonical)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        ctx.assert_active()?;
        Ok(Value::Null)
    }
}

fn assert_write_params(params: &Value) -> PluginResult<(PathBuf, Vec<u8>)> {
    if !params.is_object() {
        return Err(invalid("Plugin filesystem write parameters are invalid"));
    }
    let data = params["data"].as_str().ok_or_else(|| invalid("Plugin filesystem write data is invalid"))?;
    let bytes = match params["encoding"].as_str().unwrap_or("utf8") {
        "utf8" => data.as_bytes().to_vec(),
        "base64" => {
            let bytes = B64.decode(data).map_err(|_| invalid("Plugin filesystem base64 data is not canonical"))?;
            if B64.encode(&bytes) != data {
                return Err(invalid("Plugin filesystem base64 data is not canonical"));
            }
            bytes
        }
        _ => return Err(invalid("Plugin filesystem write encoding is invalid")),
    };
    if bytes.len() > MAX_FILESYSTEM_BYTES {
        return Err(PluginError::exhausted("Plugin filesystem write is too large"));
    }
    if params.get("overwrite").is_some_and(|o| !o.is_boolean() && !o.is_null()) {
        return Err(invalid("Plugin filesystem overwrite flag is invalid"));
    }
    Ok((assert_absolute_path(&params["path"])?, bytes))
}

fn path_authorization(params: &Value, permission: &str, kind: &str) -> PluginResult<Value> {
    let path = path_string(&assert_absolute_path(&params["path"])?);
    let verb = if permission == "filesystem.write" { "Write" } else { "Read" };
    Ok(json!({
        "permission": permission, "resources": [path], "resourceKinds": [kind],
        "reason": format!("{verb} {path}"), "operationId": format!("{permission}:{path}"),
    }))
}

// ---- registration ------------------------------------------------------------------

/// Services backing the secure capabilities.
pub struct SecureCapabilities {
    pub secrets: Arc<PluginSecretStore>,
    pub leases: Arc<SecretLeaseStore>,
    pub catalog: Arc<CredentialCatalog>,
    pub network: Arc<NetworkBroker>,
    pub filesystem: Arc<FilesystemBroker>,
}

fn secret_params(params: &Value, value: bool) -> PluginResult<Value> {
    if !params.is_object() {
        return Err(invalid("Plugin secret parameters are invalid"));
    }
    let key = params["key"].as_str().unwrap_or("");
    assert_secret_key(key)?;
    if value && !params["value"].is_string() {
        return Err(invalid("Plugin secret value is invalid"));
    }
    Ok(if value { json!({ "key": key, "value": params["value"] }) } else { json!({ "key": key }) })
}

fn secret_auth(action: &'static str) -> AuthorizationSpec {
    AuthorizationSpec::Dynamic(Arc::new(move |params: Value, _ctx| {
        Box::pin(async move {
            let key = params["key"].as_str().unwrap_or("").to_string();
            Ok(Some(json!({
                "permission": "secrets", "resources": [format!("secret:{key}")],
                "reason": format!("{action} plugin secret {key}"), "operationId": format!("secret:{}:{key}", action.to_lowercase()),
            })))
        })
    }))
}

fn dynamic(f: fn(&Value) -> PluginResult<Value>) -> AuthorizationSpec {
    AuthorizationSpec::Dynamic(Arc::new(move |params: Value, _ctx| Box::pin(async move { f(&params).map(Some) })))
}

pub fn register(registry: &HostRpcRegistry, services: &SecureCapabilities) -> PluginResult<()> {
    let secrets = services.secrets.clone();
    registry.register_request(
        "secrets.get",
        RegisterOptions::new(json!({ "capability": "secrets", "mutating": false, "permission": "secrets" }), secret_auth("Read")).validate(|p| secret_params(&p, false)),
        move |params, ctx| {
            let secrets = secrets.clone();
            async move {
                Ok(match secrets.get_reference(ctx.plugin_id(), params["key"].as_str().unwrap_or(""))? {
                    Some(secret) => json!({ "found": true, "secret": secret }),
                    None => json!({ "found": false }),
                })
            }
        },
    )?;
    let secrets = services.secrets.clone();
    registry.register_request(
        "secrets.set",
        RegisterOptions::new(json!({ "capability": "secrets", "mutating": true, "permission": "secrets" }), secret_auth("Store")).validate(|p| secret_params(&p, true)),
        move |params, ctx| {
            let secrets = secrets.clone();
            async move {
                ctx.assert_active()?;
                Ok(json!({ "secret": secrets.set(ctx.plugin_id(), params["key"].as_str().unwrap_or(""), params["value"].as_str().unwrap_or(""), false)? }))
            }
        },
    )?;
    let secrets = services.secrets.clone();
    registry.register_request(
        "secrets.delete",
        RegisterOptions::new(json!({ "capability": "secrets", "mutating": true, "permission": "secrets" }), secret_auth("Delete")).validate(|p| secret_params(&p, false)),
        move |params, ctx| {
            let secrets = secrets.clone();
            async move {
                ctx.assert_active()?;
                secrets.delete(ctx.plugin_id(), params["key"].as_str().unwrap_or(""))?;
                Ok(Value::Null)
            }
        },
    )?;
    let (leases, catalog, secrets) = (services.leases.clone(), services.catalog.clone(), services.secrets.clone());
    registry.register_request(
        "credentials.createLease",
        RegisterOptions::new(json!({ "capability": "credentials", "mutating": true, "permission": "secrets" }), dynamic(lease_authorization))
            .validate(|p| assert_lease_params(&p).map(|_| p)),
        move |params, ctx| {
            let (leases, catalog, secrets) = (leases.clone(), catalog.clone(), secrets.clone());
            async move {
                let p = assert_lease_params(&params)?;
                ctx.assert_active()?;
                match &p.credential {
                    LeaseCredential::Vault(id) => catalog.assert_reference(id)?,
                    LeaseCredential::Secret(reference) => {
                        secrets.get_record_by_reference(ctx.plugin_id(), reference)?;
                    }
                    LeaseCredential::Inline(_) => return Err(invalid("Credential reference is invalid")),
                }
                ctx.assert_active()?;
                leases.issue(ctx.plugin_id(), &ctx.identity.runtime_id, p.credential, &p.operation_id, p.ttl_ms)
            }
        },
    )?;
    let (network, leases) = (services.network.clone(), services.leases.clone());
    registry.register_request(
        "network.request",
        RegisterOptions::new(json!({ "capability": "network", "mutating": true, "permission": "network" }), dynamic(network_authorization)).validate(validate_network_params),
        move |params, ctx| {
            let (network, leases) = (network.clone(), leases.clone());
            async move {
                let Some(lease) = params.get("credentialLease").filter(|l| !l.is_null()) else {
                    return network.request(&params, &ctx).await;
                };
                let operation = network_authorization(&params)?["operationId"].as_str().unwrap_or("").to_string();
                ctx.assert_active()?;
                let plaintext = leases.consume(ctx.plugin_id(), &ctx.identity.runtime_id, lease, &operation)?;
                ctx.assert_active()?;
                if plaintext.is_empty() {
                    return Err(PluginError::rpc(codes::DATA_LOSS, "Plugin credential lease resolved to an empty secret"));
                }
                let auth = params.get("authorization").cloned().unwrap_or_else(|| json!({ "scheme": "Bearer" }));
                let header = if auth["scheme"] == "Basic" {
                    format!("Basic {}", B64.encode(format!("{}:{plaintext}", auth["username"].as_str().unwrap_or(""))))
                } else {
                    format!("Bearer {plaintext}")
                };
                let mut request = params.clone();
                if let Some(o) = request.as_object_mut() {
                    o.remove("credentialLease");
                    o.remove("authorization");
                }
                request["headers"]["authorization"] = json!(header);
                network.request(&request, &ctx).await
            }
        },
    )?;
    let fs = services.filesystem.clone();
    registry.register_request(
        "filesystem.readFile",
        RegisterOptions::new(
            json!({ "capability": "filesystem", "mutating": false, "permission": "filesystem.read" }),
            dynamic(|p| path_authorization(p, "filesystem.read", "exact")),
        ),
        move |params, ctx| {
            let fs = fs.clone();
            async move { fs.read_file(&params, &ctx).await }
        },
    )?;
    let fs = services.filesystem.clone();
    registry.register_request(
        "filesystem.stat",
        RegisterOptions::new(
            json!({ "capability": "filesystem", "mutating": false, "permission": "filesystem.read" }),
            dynamic(|p| path_authorization(p, "filesystem.read", "exact")),
        ),
        move |params, ctx| {
            let fs = fs.clone();
            async move { fs.stat(&params, &ctx).await }
        },
    )?;
    let fs = services.filesystem.clone();
    registry.register_request(
        "filesystem.writeFile",
        RegisterOptions::new(
            json!({ "capability": "filesystem", "mutating": true, "permission": "filesystem.write" }),
            dynamic(|p| {
                assert_write_params(p)?;
                if p["overwrite"] != json!(true) {
                    return Err(PluginError::precondition("Plugin filesystem writes require explicit overwrite of an existing file"));
                }
                path_authorization(p, "filesystem.write", "exact")
            }),
        ),
        move |params, ctx| {
            let fs = fs.clone();
            async move { fs.write_file(&params, &ctx).await }
        },
    )?;
    for method in ["companion.start", "companion.request", "companion.stop", "filesystem.readDirectory"] {
        registry.register_request(
            method,
            RegisterOptions::public(json!({ "capability": method })),
            |_params, _ctx| async { Err(PluginError::rpc(codes::UNSUPPORTED, "This capability is not available in the Netcatty Tauri host")) },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_request_validation() {
        assert!(assert_network_request(&json!({ "url": "https://api.example.com/x", "headers": { "Cookie": "a" } })).is_err());
        assert!(assert_network_request(&json!({ "url": "https://u:p@api.example.com/" })).is_err());
        assert!(assert_network_request(&json!({ "url": "ftp://x.example.com/" })).is_err());
        assert!(assert_network_request(&json!({ "url": "https://a.example.com/", "method": "GET", "body": { "encoding": "utf8", "data": "x" } })).is_err());
        let ok = validate_network_params(json!({ "url": "https://a.example.com/p?q=1", "method": "POST", "body": { "encoding": "utf8", "data": "hi" } })).unwrap();
        assert_eq!(ok["body"]["data"], json!("aGk="));
        assert_eq!(network_authorization(&ok).unwrap()["resources"][0], json!("https://a.example.com"));
    }

    #[test]
    fn lease_params() {
        assert!(assert_lease_params(&json!({ "secret": { "kind": "credential", "id": "short" }, "operationId": "x", "purpose": "y" })).is_err());
        let auth = lease_authorization(&json!({ "secret": { "kind": "credential", "id": "0123456789abcdef" }, "operationId": "op", "purpose": "login" })).unwrap();
        assert_eq!(auth["permission"], json!("vault.credentials"));
    }
}
