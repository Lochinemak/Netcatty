//! Host RPC registry with middleware (port of `hostRpcRegistry.cjs` plus the
//! quota and permission middleware of `secureCapabilities.cjs`).
//!
//! Every capability is registered once with metadata and an authorization
//! descriptor (static or resolved from params). Routes are created per
//! runtime with the host-assigned identity; handlers never see a
//! plugin-supplied identity. Order per call: identity guard → param
//! validation → authorization resolution → quota → permission → handler,
//! with the identity / policy guard re-checked before and after the handler.

use crate::error::{PluginError, PluginResult};
use crate::logs::PluginLogger;
use crate::permissions::{AuthContext, AuthorizationRequest, PermissionEngine};
use crate::quota::QuotaManager;
use crate::rpc::{Handler, IncomingStream, Routes, TransportContext};
use futures::future::BoxFuture;
use parking_lot::RwLock;
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio_util::sync::CancellationToken;

/// Host-assigned identity of one running activation.
pub struct RuntimeIdentity {
    pub plugin_id: String,
    pub plugin_version: String,
    pub runtime_id: String,
    pub runtime_kind: String,
    pub security_principal: String,
    pub source_owner: Option<String>,
    pub source_id: Option<String>,
    pub manifest: Arc<Value>,
    pub package_root: PathBuf,
    pub enabled_features: Vec<String>,
    pub logger: Arc<PluginLogger>,
    pub log_identity: crate::logs::LogIdentity,
    /// Fails once this activation is stale (stopped, replaced, disabled).
    pub assert_current: Arc<dyn Fn() -> PluginResult<()> + Send + Sync>,
}

impl RuntimeIdentity {
    pub fn public(&self) -> serde_json::Value {
        let mut value = serde_json::json!({
            "pluginId": self.plugin_id, "pluginVersion": self.plugin_version,
            "runtimeId": self.runtime_id, "runtimeKind": self.runtime_kind,
            "securityPrincipal": self.security_principal,
        });
        if let Some(owner) = &self.source_owner {
            value["sourceOwner"] = serde_json::json!(owner);
            value["sourceId"] = serde_json::json!(self.source_id);
        }
        value
    }

    pub fn auth_context(&self, signal: Option<CancellationToken>, operation_key: Option<String>) -> AuthContext {
        AuthContext {
            plugin_id: self.plugin_id.clone(),
            plugin_version: Some(self.plugin_version.clone()),
            runtime_id: Some(self.runtime_id.clone()),
            runtime_kind: Some(self.runtime_kind.clone()),
            manifest: self.manifest.clone(),
            security_principal: Some(self.security_principal.clone()),
            source_owner: self.source_owner.clone(),
            signal,
            operation_key,
        }
    }
}

/// Context handed to capability handlers.
pub struct CallContext {
    pub identity: Arc<RuntimeIdentity>,
    pub transport: TransportContext,
    pub method: String,
    pub metadata: Arc<Value>,
    pub authorization: Option<Value>,
    pub signal: CancellationToken,
    pub operation_key: String,
    permissions: Arc<PermissionEngine>,
    policy_revision: u64,
    policy_owner: Option<String>,
}

impl CallContext {
    pub fn plugin_id(&self) -> &str {
        &self.identity.plugin_id
    }

    /// `assertActive`: cancellation, identity currency and policy revision.
    pub fn assert_active(&self) -> PluginResult<()> {
        if self.signal.is_cancelled() {
            return Err(PluginError::cancelled());
        }
        if self.metadata.get("public").and_then(Value::as_bool) != Some(true) {
            let owner_now = self.permissions_owner();
            if self.permissions.revision(&self.identity.plugin_id) != self.policy_revision || owner_now != self.policy_owner {
                return Err(crate::permissions::permission_denied("Plugin permission policy or source changed", None));
            }
        }
        (self.identity.assert_current)()
    }

    fn permissions_owner(&self) -> Option<String> {
        Some(self.permissions.owner_of(&self.identity.plugin_id))
    }

    pub fn auth_context(&self) -> AuthContext {
        self.identity.auth_context(Some(self.signal.clone()), Some(self.operation_key.clone()))
    }

    /// Authorize an additional (handler-level) permission within this call.
    pub async fn authorize(&self, request: &AuthorizationRequest) -> PluginResult<crate::permissions::Authorization> {
        self.permissions.authorize(&self.auth_context(), request).await
    }
}

pub type HostHandler = Arc<dyn Fn(Value, Arc<CallContext>) -> BoxFuture<'static, PluginResult<Value>> + Send + Sync>;
pub type AuthResolver = Arc<dyn Fn(Value, Arc<CallContext>) -> BoxFuture<'static, PluginResult<Option<Value>>> + Send + Sync>;
pub type ParamValidator = Arc<dyn Fn(Value) -> PluginResult<Value> + Send + Sync>;
pub type HostStreamHandler = Arc<dyn Fn(&IncomingStream, &Arc<RuntimeIdentity>) -> bool + Send + Sync>;

#[derive(Clone)]
pub enum AuthorizationSpec {
    None,
    Static(Value),
    Dynamic(AuthResolver),
}

#[derive(Clone)]
struct Registration {
    handler: HostHandler,
    metadata: Arc<Value>,
    validate: Option<ParamValidator>,
    authorization: AuthorizationSpec,
}

/// Reserved / invalid host method names (`assertHostMethod`).
pub fn assert_host_method(method: &str) -> PluginResult<()> {
    if method.is_empty()
        || method.len() > 256
        || method.starts_with("$/")
        || matches!(method, "plugin.initialize" | "plugin.activate" | "plugin.deactivate")
    {
        return Err(PluginError::host(format!("Invalid or reserved plugin host RPC method: {method}")));
    }
    Ok(())
}

pub struct HostRpcRegistry {
    requests: RwLock<HashMap<String, Registration>>,
    notifications: RwLock<HashMap<String, Registration>>,
    streams: RwLock<Vec<HostStreamHandler>>,
    quota: Arc<QuotaManager>,
    permissions: Arc<PermissionEngine>,
}

/// Builder-style registration options.
#[derive(Clone)]
pub struct RegisterOptions {
    pub metadata: Value,
    pub authorization: AuthorizationSpec,
    pub validate: Option<ParamValidator>,
}

impl RegisterOptions {
    pub fn new(metadata: Value, authorization: AuthorizationSpec) -> Self {
        Self { metadata, authorization, validate: None }
    }
    pub fn public(metadata: Value) -> Self {
        let mut metadata = metadata;
        metadata["public"] = Value::Bool(true);
        Self { metadata, authorization: AuthorizationSpec::None, validate: None }
    }
    pub fn validate(mut self, validator: impl Fn(Value) -> PluginResult<Value> + Send + Sync + 'static) -> Self {
        self.validate = Some(Arc::new(validator));
        self
    }
}

/// Static `{ permission, resources: ["*"], reason }` descriptor.
pub fn static_auth(permission: &str, reason: &str) -> AuthorizationSpec {
    AuthorizationSpec::Static(serde_json::json!({ "permission": permission, "resources": ["*"], "reason": reason }))
}

impl HostRpcRegistry {
    pub fn new(quota: Arc<QuotaManager>, permissions: Arc<PermissionEngine>) -> Self {
        Self {
            requests: RwLock::new(HashMap::new()),
            notifications: RwLock::new(HashMap::new()),
            streams: RwLock::new(Vec::new()),
            quota,
            permissions,
        }
    }

    fn register(&self, request: bool, method: &str, handler: HostHandler, options: RegisterOptions) -> PluginResult<()> {
        assert_host_method(method)?;
        if self.requests.read().contains_key(method) || self.notifications.read().contains_key(method) {
            return Err(PluginError::host(format!("Plugin host RPC method is already registered: {method}")));
        }
        let registration = Registration {
            handler,
            metadata: Arc::new(options.metadata),
            validate: options.validate,
            authorization: options.authorization,
        };
        if request {
            self.requests.write().insert(method.to_string(), registration);
        } else {
            self.notifications.write().insert(method.to_string(), registration);
        }
        Ok(())
    }

    pub fn register_request<F, Fut>(&self, method: &str, options: RegisterOptions, handler: F) -> PluginResult<()>
    where
        F: Fn(Value, Arc<CallContext>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = PluginResult<Value>> + Send + 'static,
    {
        let handler: HostHandler = Arc::new(move |params, ctx| Box::pin(handler(params, ctx)));
        self.register(true, method, handler, options)
    }

    pub fn register_notification<F, Fut>(&self, method: &str, options: RegisterOptions, handler: F) -> PluginResult<()>
    where
        F: Fn(Value, Arc<CallContext>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = PluginResult<Value>> + Send + 'static,
    {
        let handler: HostHandler = Arc::new(move |params, ctx| Box::pin(handler(params, ctx)));
        self.register(false, method, handler, options)
    }

    pub fn register_incoming_stream(&self, handler: HostStreamHandler) {
        self.streams.write().push(handler);
    }

    pub fn has_method(&self, method: &str) -> bool {
        self.requests.read().contains_key(method) || self.notifications.read().contains_key(method)
    }

    fn wrap(&self, kind_request: bool, method: String, registration: Registration, identity: Arc<RuntimeIdentity>) -> Handler {
        let quota = self.quota.clone();
        let permissions = self.permissions.clone();
        let _ = kind_request;
        Arc::new(move |params: Value, transport: TransportContext| {
            let registration = registration.clone();
            let identity = identity.clone();
            let quota = quota.clone();
            let permissions = permissions.clone();
            let method = method.clone();
            Box::pin(async move {
                let started = Instant::now();
                let signal = transport.signal.child_token();
                let public = registration.metadata.get("public").and_then(Value::as_bool) == Some(true);
                // Revocation for this plugin cancels the in-flight operation.
                let listener = if public {
                    None
                } else {
                    let plugin_id = identity.plugin_id.clone();
                    let cancel = signal.clone();
                    Some(permissions.on_did_revoke(Arc::new(move |event: &Value| {
                        if event["pluginId"].as_str() == Some(plugin_id.as_str()) {
                            cancel.cancel();
                        }
                    })))
                };
                let ctx = Arc::new(CallContext {
                    identity: identity.clone(),
                    method: method.clone(),
                    metadata: registration.metadata.clone(),
                    authorization: None,
                    signal: signal.clone(),
                    operation_key: uuid::Uuid::new_v4().to_string(),
                    policy_revision: permissions.revision(&identity.plugin_id),
                    policy_owner: Some(permissions.owner_of(&identity.plugin_id)),
                    permissions: permissions.clone(),
                    transport,
                });
                let mut authorization_outcome = "not-reached";
                let mut audit_resources: Vec<String> = Vec::new();
                let result: PluginResult<Value> = async {
                    ctx.assert_active()?;
                    let params = match &registration.validate {
                        Some(validate) => validate(params)?,
                        None => params,
                    };
                    let authorization = match &registration.authorization {
                        AuthorizationSpec::None => None,
                        AuthorizationSpec::Static(v) => Some(v.clone()),
                        AuthorizationSpec::Dynamic(resolver) => resolver(params.clone(), ctx.clone()).await?,
                    };
                    if let Some(a) = &authorization {
                        audit_resources = a["resources"].as_array().map(|r| r.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default();
                    }
                    ctx.assert_active()?;
                    let ctx = Arc::new(CallContext {
                        identity: ctx.identity.clone(),
                        transport: ctx.transport.clone(),
                        method: ctx.method.clone(),
                        metadata: ctx.metadata.clone(),
                        authorization: authorization.clone(),
                        signal: ctx.signal.clone(),
                        operation_key: ctx.operation_key.clone(),
                        permissions: ctx.permissions.clone(),
                        policy_revision: ctx.policy_revision,
                        policy_owner: ctx.policy_owner.clone(),
                    });
                    let _slot = quota.enter_capability(&identity.runtime_id, &method)?;
                    if public {
                        authorization_outcome = "not-required";
                    } else {
                        let Some(descriptor) = &authorization else {
                            authorization_outcome = "denied";
                            return Err(crate::permissions::permission_denied(
                                format!("Plugin host method has no authorization policy: {method}"),
                                None,
                            ));
                        };
                        let request = AuthorizationRequest::from_value(descriptor)?;
                        match permissions.authorize(&ctx.auth_context(), &request).await {
                            Ok(_) => authorization_outcome = "allowed",
                            Err(err) => {
                                if err.code() == Some(crate::codes::PERMISSION_DENIED) {
                                    authorization_outcome = "denied";
                                }
                                return Err(err);
                            }
                        }
                        ctx.assert_active()?;
                    }
                    let value = (registration.handler)(params, ctx.clone()).await?;
                    ctx.assert_active()?;
                    Ok(value)
                }
                .await;
                if let Some(id) = listener {
                    permissions.remove_listener(id);
                }
                permissions.forget_operation(&ctx.operation_key);
                identity.logger.audit_call(
                    &method,
                    authorization_outcome,
                    result.is_ok(),
                    result.as_ref().err().and_then(PluginError::code),
                    &audit_resources,
                    started.elapsed().as_millis() as u64,
                );
                result
            })
        })
    }

    /// `createRoutes(identity)`.
    pub fn create_routes(&self, identity: Arc<RuntimeIdentity>) -> Routes {
        let mut routes = Routes::default();
        for (method, registration) in self.requests.read().iter() {
            routes.requests.insert(method.clone(), self.wrap(true, method.clone(), registration.clone(), identity.clone()));
        }
        for (method, registration) in self.notifications.read().iter() {
            routes.notifications.insert(method.clone(), self.wrap(false, method.clone(), registration.clone(), identity.clone()));
        }
        let handlers: Vec<HostStreamHandler> = self.streams.read().clone();
        let stream_identity = identity.clone();
        routes.on_incoming_stream = Some(Arc::new(move |stream: &IncomingStream| {
            if (stream_identity.assert_current)().is_err() {
                return false;
            }
            handlers.iter().any(|h| h(stream, &stream_identity))
        }));
        let quota = self.quota.clone();
        let runtime_id = identity.runtime_id.clone();
        routes.on_before_message = Some(Arc::new(move |_message: &Value| quota.guard_message(&runtime_id)));
        routes
    }
}

/// `assertStorageParams`.
pub fn assert_storage_params(params: &Value, require_value: bool) -> PluginResult<()> {
    let object = params.as_object().ok_or_else(|| PluginError::invalid("Plugin storage parameters must be an object"))?;
    let key = object.get("key").and_then(Value::as_str).unwrap_or("");
    let len = key.encode_utf16().count();
    if len < 1 || len > 256 || key.contains('\0') {
        return Err(PluginError::invalid("Plugin storage key is invalid"));
    }
    if require_value && !object.contains_key("value") {
        return Err(PluginError::invalid("Plugin storage value is required"));
    }
    Ok(())
}

/// Register `storage.*` and `log.write` (`createDefaultPluginHostRpcRegistry`).
pub fn register_default_capabilities(registry: &HostRpcRegistry, database: Arc<crate::database::PluginDatabase>) -> PluginResult<()> {
    use serde_json::json;
    let db = database.clone();
    registry.register_request(
        "storage.get",
        RegisterOptions::new(json!({ "capability": "storage", "mutating": false, "permission": "storage" }), static_auth("storage", "Access plugin storage"))
            .validate(|p| assert_storage_params(&p, false).map(|_| p)),
        move |params, ctx| {
            let db = db.clone();
            async move {
                Ok(match db.get_value(ctx.plugin_id(), params["key"].as_str().unwrap_or(""))? {
                    Some(value) => json!({ "found": true, "value": value }),
                    None => json!({ "found": false }),
                })
            }
        },
    )?;
    let db = database.clone();
    registry.register_request(
        "storage.set",
        RegisterOptions::new(json!({ "capability": "storage", "mutating": true, "permission": "storage" }), static_auth("storage", "Modify plugin storage"))
            .validate(|p| assert_storage_params(&p, true).map(|_| p)),
        move |params, ctx| {
            let db = db.clone();
            async move {
                db.set_value(ctx.plugin_id(), params["key"].as_str().unwrap_or(""), &params["value"])?;
                Ok(Value::Null)
            }
        },
    )?;
    let db = database.clone();
    registry.register_request(
        "storage.delete",
        RegisterOptions::new(json!({ "capability": "storage", "mutating": true, "permission": "storage" }), static_auth("storage", "Modify plugin storage"))
            .validate(|p| assert_storage_params(&p, false).map(|_| p)),
        move |params, ctx| {
            let db = db.clone();
            async move {
                db.delete_value(ctx.plugin_id(), params["key"].as_str().unwrap_or(""))?;
                Ok(Value::Null)
            }
        },
    )?;
    let db = database;
    registry.register_request(
        "storage.keys",
        RegisterOptions::new(json!({ "capability": "storage", "mutating": false, "permission": "storage" }), static_auth("storage", "List plugin storage keys"))
            .validate(|p| match &p {
                Value::Null => Ok(p),
                Value::Object(m) if m.is_empty() => Ok(p),
                _ => Err(PluginError::invalid("storage.keys does not accept parameters")),
            }),
        move |_params, ctx| {
            let db = db.clone();
            async move { Ok(json!({ "keys": db.list_keys(ctx.plugin_id())? })) }
        },
    )?;
    registry.register_notification(
        "log.write",
        RegisterOptions::public(json!({ "capability": "logging", "mutating": false })),
        |params, ctx| async move {
            if params.is_object() {
                ctx.identity.logger.write(
                    params["level"].as_str().unwrap_or("info"),
                    params["message"].as_str().unwrap_or("[INVALID MESSAGE]"),
                    params.get("fields"),
                );
            }
            Ok(Value::Null)
        },
    )?;
    Ok(())
}
