pub mod alert;
pub mod config;
pub mod db;
pub mod error;
pub use error::{NpingError, Result};
pub mod icmp;
pub mod monitor;
pub mod packet;
pub mod pinger;
pub mod result;
pub mod socket;
pub mod stats;
pub mod tcp;
pub mod timing;
pub mod udp;

// Platform-specific socket implementations
#[cfg(unix)]
mod socket_unix;
#[cfg(unix)]
pub use socket_unix::IcmpSocket;

#[cfg(windows)]
mod socket_windows;
#[cfg(windows)]
pub use socket_windows::IcmpSocket;
