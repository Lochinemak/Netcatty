//! Shared error type used across crates.
//!
//! Each capability crate defines its own richer error enum but converts into
//! `CoreError` at the Tauri command boundary so the renderer always receives a
//! `{ code, message }` shaped error string.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Stable machine-readable error codes surfaced to the renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    /// Caller supplied an invalid argument.
    InvalidArgument,
    /// Referenced session / connection / tunnel does not exist.
    NotFound,
    /// Remote side refused authentication.
    AuthFailed,
    /// Host key was rejected by the user or did not match known hosts.
    HostKeyRejected,
    /// Network-level failure (connect, DNS, reset).
    Network,
    /// Operation timed out.
    Timeout,
    /// The operation was cancelled by the user.
    Cancelled,
    /// Local filesystem failure.
    Io,
    /// Operation is not supported on this platform / protocol.
    Unsupported,
    /// Anything else.
    Internal,
}

/// Error type shared by all crates at the IPC boundary.
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "camelCase")]
pub struct CoreError {
    pub code: ErrorCode,
    pub message: String,
}

impl CoreError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgument, message)
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }
    pub fn auth(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::AuthFailed, message)
    }
    pub fn host_key(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::HostKeyRejected, message)
    }
    pub fn network(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Network, message)
    }
    pub fn timeout(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Timeout, message)
    }
    pub fn cancelled(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Cancelled, message)
    }
    pub fn io(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Io, message)
    }
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unsupported, message)
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<std::io::Error> for CoreError {
    fn from(err: std::io::Error) -> Self {
        use std::io::ErrorKind as K;
        let code = match err.kind() {
            K::NotFound => ErrorCode::NotFound,
            K::TimedOut => ErrorCode::Timeout,
            K::ConnectionRefused | K::ConnectionReset | K::ConnectionAborted | K::NotConnected => {
                ErrorCode::Network
            }
            K::Interrupted => ErrorCode::Cancelled,
            _ => ErrorCode::Io,
        };
        CoreError::new(code, err.to_string())
    }
}

impl From<serde_json::Error> for CoreError {
    fn from(err: serde_json::Error) -> Self {
        CoreError::invalid(err.to_string())
    }
}

pub type CoreResult<T> = Result<T, CoreError>;
