#[derive(Debug, thiserror::Error)]
pub enum NtraceError {
    #[error("failed to create socket: {0}")]
    SocketCreate(String),

    #[error("failed to send probe: {0}")]
    Send(String),

    #[error("failed to receive: {0}")]
    Recv(String),

    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),

    #[error("operation timed out")]
    Timeout,

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("invalid packet: {0}")]
    InvalidPacket(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, NtraceError>;
