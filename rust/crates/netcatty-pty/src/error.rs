use netcatty_core::{CoreError, ErrorCode};

#[derive(Debug, thiserror::Error)]
pub enum PtyError {
    #[error("failed to open pty: {0}")]
    Open(String),
    #[error("failed to spawn shell `{shell}`: {reason}")]
    Spawn { shell: String, reason: String },
    #[error("pty closed")]
    Closed,
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type PtyResult<T> = Result<T, PtyError>;

impl From<PtyError> for CoreError {
    fn from(err: PtyError) -> Self {
        let code = match &err {
            PtyError::Open(_) | PtyError::Spawn { .. } => ErrorCode::Io,
            PtyError::Closed => ErrorCode::NotFound,
            PtyError::InvalidArgument(_) => ErrorCode::InvalidArgument,
            PtyError::Io(e) => {
                return CoreError::from(std::io::Error::new(e.kind(), e.to_string()))
            }
        };
        CoreError::new(code, err.to_string())
    }
}
