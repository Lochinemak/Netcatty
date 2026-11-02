use netcatty_core::{CoreError, ErrorCode};
use russh_sftp::protocol::StatusCode;

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
    /// A remote shell command (archive extraction) exited unsuccessfully.
    #[error("remote command failed: {0}")]
    Command(String),
    #[error(transparent)]
    Ssh(#[from] netcatty_ssh::SshError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type SftpResult<T> = Result<T, SftpError>;

impl From<russh_sftp::client::error::Error> for SftpError {
    fn from(err: russh_sftp::client::error::Error) -> Self {
        use russh_sftp::client::error::Error as Raw;
        match err {
            Raw::Status(status) => {
                let message = if status.error_message.is_empty() {
                    status.status_code.to_string()
                } else {
                    status.error_message.clone()
                };
                match status.status_code {
                    StatusCode::NoSuchFile => SftpError::NotFound(message),
                    StatusCode::PermissionDenied => SftpError::PermissionDenied(message),
                    StatusCode::OpUnsupported => SftpError::Unavailable(message),
                    StatusCode::NoConnection | StatusCode::ConnectionLost => {
                        SftpError::Ssh(netcatty_ssh::SshError::Disconnected(message))
                    }
                    code => SftpError::Protocol(format!("{code}: {message}")),
                }
            }
            Raw::Timeout => SftpError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "sftp request timed out",
            )),
            Raw::IO(message) => SftpError::Io(std::io::Error::other(message)),
            other => SftpError::Protocol(other.to_string()),
        }
    }
}

impl From<russh::Error> for SftpError {
    fn from(err: russh::Error) -> Self {
        SftpError::Ssh(netcatty_ssh::SshError::from(err))
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
            SftpError::Command(_) => ErrorCode::Io,
            SftpError::Ssh(e) => {
                return CoreError::from(netcatty_ssh::SshError::Channel(e.to_string()))
            }
            SftpError::Io(e) => {
                return CoreError::from(std::io::Error::new(e.kind(), e.to_string()))
            }
        };
        CoreError::new(code, err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh_sftp::protocol::Status;

    fn status(code: StatusCode, msg: &str) -> russh_sftp::client::error::Error {
        russh_sftp::client::error::Error::Status(Status {
            id: 1,
            status_code: code,
            error_message: msg.to_string(),
            language_tag: String::new(),
        })
    }

    #[test]
    fn status_codes_map_to_variants() {
        assert!(matches!(
            SftpError::from(status(StatusCode::NoSuchFile, "x")),
            SftpError::NotFound(_)
        ));
        assert!(matches!(
            SftpError::from(status(StatusCode::PermissionDenied, "x")),
            SftpError::PermissionDenied(_)
        ));
        assert!(
            matches!(SftpError::from(status(StatusCode::Failure, "boom")), SftpError::Protocol(m) if m.contains("boom"))
        );
        let core: CoreError = SftpError::from(status(StatusCode::NoSuchFile, "")).into();
        assert_eq!(core.code, ErrorCode::NotFound);
        let core: CoreError = SftpError::from(russh_sftp::client::error::Error::Timeout).into();
        assert_eq!(core.code, ErrorCode::Timeout);
    }
}
