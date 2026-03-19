#[derive(Debug, thiserror::Error)]
pub enum NmapperError {
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    #[error("socket error: {0}")]
    Socket(#[from] std::io::Error),
    #[error("ping error: {0}")]
    Ping(#[from] nping_core::NpingError),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("export error: {0}")]
    Export(String),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, NmapperError>;
