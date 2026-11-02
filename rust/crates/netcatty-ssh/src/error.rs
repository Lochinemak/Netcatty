//! Error type for the SSH crate.

use netcatty_core::{CoreError, ErrorCode};

#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("connection failed: {0}")]
    Connect(String),
    #[error("proxy error: {0}")]
    Proxy(String),
    #[error("timed out: {0}")]
    Timeout(String),
    #[error("authentication failed: {0}")]
    AuthFailed(String),
    #[error("host key rejected: {0}")]
    HostKeyRejected(String),
    #[error("cancelled: {0}")]
    Cancelled(String),
    #[error("channel error: {0}")]
    Channel(String),
    #[error("key error: {0}")]
    Key(String),
    #[error("disconnected: {0}")]
    Disconnected(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Russh(#[from] russh::Error),
}

pub type SshResult<T> = Result<T, SshError>;

impl From<SshError> for CoreError {
    fn from(err: SshError) -> Self {
        let code = match &err {
            SshError::InvalidArgument(_) => ErrorCode::InvalidArgument,
            SshError::Connect(_) | SshError::Proxy(_) | SshError::Disconnected(_) => {
                ErrorCode::Network
            }
            SshError::Timeout(_) => ErrorCode::Timeout,
            SshError::AuthFailed(_) => ErrorCode::AuthFailed,
            SshError::HostKeyRejected(_) => ErrorCode::HostKeyRejected,
            SshError::Cancelled(_) => ErrorCode::Cancelled,
            SshError::Channel(_) | SshError::Russh(_) => ErrorCode::Network,
            SshError::Key(_) => ErrorCode::InvalidArgument,
            SshError::Io(e) => {
                return CoreError::from(std::io::Error::new(e.kind(), e.to_string()))
            }
        };
        CoreError::new(code, err.to_string())
    }
}

impl From<russh::keys::Error> for SshError {
    fn from(err: russh::keys::Error) -> Self {
        SshError::Key(err.to_string())
    }
}
