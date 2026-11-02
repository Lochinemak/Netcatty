use netcatty_core::{CoreError, ErrorCode};

#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("address in use: {0}")]
    AddressInUse(String),
    #[error("bind failed: {0}")]
    Bind(String),
    #[error("tunnel not found: {0}")]
    NotFound(String),
    #[error("remote forward request rejected by server")]
    RemoteForwardRejected,
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("cancelled")]
    Cancelled,
    #[error(transparent)]
    Ssh(#[from] netcatty_ssh::SshError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type ForwardResult<T> = Result<T, ForwardError>;

impl From<ForwardError> for CoreError {
    fn from(err: ForwardError) -> Self {
        let code = match &err {
            ForwardError::AddressInUse(_) | ForwardError::Bind(_) => ErrorCode::Network,
            ForwardError::NotFound(_) => ErrorCode::NotFound,
            ForwardError::RemoteForwardRejected => ErrorCode::Network,
            ForwardError::InvalidArgument(_) => ErrorCode::InvalidArgument,
            ForwardError::Cancelled => ErrorCode::Cancelled,
            ForwardError::Ssh(e) => return CoreError::from(netcatty_ssh::SshError::Channel(e.to_string())),
            ForwardError::Io(e) => return CoreError::from(std::io::Error::new(e.kind(), e.to_string())),
        };
        CoreError::new(code, err.to_string())
    }
}
