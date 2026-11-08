//! Plugin RPC error model (port of `RPC_ERRORS` / `PluginRpcError` in
//! `electron/plugins/rpcRouter.cjs`).

use serde_json::{json, Value};

/// JSON-RPC error codes of the plugin contract.
pub mod codes {
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL: i64 = -32603;
    pub const CANCELLED: i64 = -32001;
    pub const INVALID_ARGUMENT: i64 = -32003;
    pub const DEADLINE_EXCEEDED: i64 = -32004;
    pub const NOT_FOUND: i64 = -32005;
    pub const ALREADY_EXISTS: i64 = -32006;
    pub const PERMISSION_DENIED: i64 = -32007;
    pub const RESOURCE_EXHAUSTED: i64 = -32008;
    pub const FAILED_PRECONDITION: i64 = -32009;
    pub const ABORTED: i64 = -32010;
    pub const OUT_OF_RANGE: i64 = -32011;
    pub const UNSUPPORTED: i64 = -32012;
    pub const UNAVAILABLE: i64 = -32014;
    pub const DATA_LOSS: i64 = -32015;
    pub const UNAUTHENTICATED: i64 = -32016;

    pub const ALL: &[i64] = &[
        METHOD_NOT_FOUND,
        INVALID_PARAMS,
        INTERNAL,
        CANCELLED,
        INVALID_ARGUMENT,
        DEADLINE_EXCEEDED,
        NOT_FOUND,
        ALREADY_EXISTS,
        PERMISSION_DENIED,
        RESOURCE_EXHAUSTED,
        FAILED_PRECONDITION,
        ABORTED,
        OUT_OF_RANGE,
        UNSUPPORTED,
        UNAVAILABLE,
        DATA_LOSS,
        UNAUTHENTICATED,
    ];
}

/// Host-side error. `Rpc` errors are forwarded to plugins verbatim; every
/// other variant is masked as `INTERNAL` "Plugin host request failed" on the
/// wire (same as `toRpcError`), but keeps its message for host callers.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PluginError {
    #[error("{message}")]
    Rpc {
        code: i64,
        message: String,
        data: Option<Value>,
    },
    #[error("{0}")]
    Host(String),
}

pub type PluginResult<T> = Result<T, PluginError>;

impl PluginError {
    pub fn rpc(code: i64, message: impl Into<String>) -> Self {
        Self::Rpc {
            code,
            message: message.into(),
            data: None,
        }
    }
    pub fn rpc_with(code: i64, message: impl Into<String>, data: Value) -> Self {
        Self::Rpc {
            code,
            message: message.into(),
            data: Some(data),
        }
    }
    pub fn host(message: impl Into<String>) -> Self {
        Self::Host(message.into())
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::rpc(codes::INVALID_ARGUMENT, message)
    }
    pub fn denied(message: impl Into<String>) -> Self {
        Self::rpc(codes::PERMISSION_DENIED, message)
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::rpc(codes::NOT_FOUND, message)
    }
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::rpc(codes::UNAVAILABLE, message)
    }
    pub fn cancelled() -> Self {
        Self::rpc(codes::CANCELLED, "Plugin request was cancelled")
    }
    pub fn deadline(message: impl Into<String>) -> Self {
        Self::rpc(codes::DEADLINE_EXCEEDED, message)
    }
    pub fn exhausted(message: impl Into<String>) -> Self {
        Self::rpc(codes::RESOURCE_EXHAUSTED, message)
    }
    pub fn precondition(message: impl Into<String>) -> Self {
        Self::rpc(codes::FAILED_PRECONDITION, message)
    }

    /// The RPC code, or `None` for host-internal errors.
    pub fn code(&self) -> Option<i64> {
        match self {
            Self::Rpc { code, .. } => Some(*code),
            Self::Host(_) => None,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Rpc { message, .. } => message,
            Self::Host(message) => message,
        }
    }

    /// Wire form (`toRpcError`).
    pub fn to_wire(&self) -> Value {
        match self {
            Self::Rpc {
                code,
                message,
                data,
            } => {
                let mut text: String = message.chars().take(2048).collect();
                if text.is_empty() {
                    text = "Plugin RPC failed".into();
                }
                let mut value = json!({ "code": code, "message": text });
                if let Some(data) = data {
                    value["data"] = data.clone();
                }
                value
            }
            Self::Host(_) => json!({ "code": codes::INTERNAL, "message": "Plugin host request failed" }),
        }
    }

    /// Error from a plugin's wire response.
    pub fn from_wire(value: &Value) -> Self {
        Self::Rpc {
            code: value.get("code").and_then(Value::as_i64).unwrap_or(codes::INTERNAL),
            message: value
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("Plugin request failed")
                .to_string(),
            data: value.get("data").cloned(),
        }
    }
}

impl From<rusqlite::Error> for PluginError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Host(format!("plugin database error: {err}"))
    }
}

impl From<std::io::Error> for PluginError {
    fn from(err: std::io::Error) -> Self {
        Self::Host(err.to_string())
    }
}

impl From<serde_json::Error> for PluginError {
    fn from(err: serde_json::Error) -> Self {
        Self::Host(format!("invalid JSON: {err}"))
    }
}

impl From<PluginError> for netcatty_core::CoreError {
    fn from(err: PluginError) -> Self {
        use netcatty_core::CoreError as E;
        match &err {
            PluginError::Rpc { code, message, .. } => match *code {
                codes::INVALID_ARGUMENT | codes::INVALID_PARAMS => E::invalid(message.clone()),
                codes::NOT_FOUND => E::not_found(message.clone()),
                codes::CANCELLED => E::cancelled(message.clone()),
                codes::DEADLINE_EXCEEDED => E::timeout(message.clone()),
                codes::UNSUPPORTED | codes::METHOD_NOT_FOUND => E::unsupported(message.clone()),
                _ => E::internal(message.clone()),
            },
            PluginError::Host(message) => E::internal(message.clone()),
        }
    }
}

/// Shorthand: `bail!(code, "message")`.
#[macro_export]
macro_rules! rpc_bail {
    ($code:expr, $($arg:tt)*) => {
        return Err($crate::error::PluginError::rpc($code, format!($($arg)*)))
    };
}
