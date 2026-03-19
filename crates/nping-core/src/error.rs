use std::net::IpAddr;

#[derive(Debug, thiserror::Error)]
pub enum NpingError {
    #[error("failed to create socket: {0}")]
    SocketCreate(#[source] std::io::Error),

    #[error("failed to send ping to {target}: {source}")]
    Send {
        target: IpAddr,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to receive ping reply: {0}")]
    Recv(#[source] std::io::Error),

    #[error("DNS resolution failed for '{hostname}': {source}")]
    DnsResolution {
        hostname: String,
        #[source]
        source: std::io::Error,
    },

    #[error("ping timed out after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("invalid packet: {0}")]
    InvalidPacket(String),

    #[error("unsupported platform for this operation")]
    UnsupportedPlatform,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, NpingError>;
