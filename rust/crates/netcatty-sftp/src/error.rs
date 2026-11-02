use netcatty_core::{CoreError, ErrorCode};

#[derive(Debug, thiserror::Error)]
pub enum SftpError {
    #[error("sftp subsystem unavailable: {0}")]
    Unavailable(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("target changed before operation: expected {expected}, found {found}")]
    Stale { expected: String, found: String },
    #[error("cancelled")]
    Cancelled,
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("sftp protocol error: {0}")]
    Protocol(String),
    #[error(transparent)]
    Ssh(#[from] netcatty_ssh::SshError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type SftpResult<T> = Result<T, SftpError>;

impl From<russh_sftp::client::error::Error> for SftpError {
    fn from(err: russh_sftp::client::error::Error) -> Self {
        SftpError::Protocol(err.to_string())
    }
}

impl From<SftpError> for CoreError {
    fn from(err: SftpError) -> Self {
        let code = match &err {
            SftpError::Unavailable(_) => ErrorCode::Unsupported,
            SftpError::NotFound(_) => ErrorCode::NotFound,
            SftpError::PermissionDenied(_) => ErrorCode::Io,
            SftpError::Stale { .. } => ErrorCode::InvalidArgument,
            SftpError::Cancelled => ErrorCode::Cancelled,
            SftpError::InvalidArgument(_) => ErrorCode::InvalidArgument,
            SftpError::Protocol(_) => ErrorCode::Network,
            SftpError::Ssh(e) => return CoreError::from(netcatty_ssh::SshError::Channel(e.to_string())),
            SftpError::Io(e) => return CoreError::from(std::io::Error::new(e.kind(), e.to_string())),
        };
        CoreError::new(code, err.to_string())
    }
}
