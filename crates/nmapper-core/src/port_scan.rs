use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tracing::debug;

use crate::result::{PortResult, PortStatus};

/// Scan a list of ports on a single host.
pub async fn scan_ports(
    ip: IpAddr,
    ports: &[u16],
    timeout: Duration,
    concurrency: usize,
) -> Vec<PortResult> {
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::with_capacity(ports.len());

    for &port in ports {
        let sem = semaphore.clone();
        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            scan_one_port(ip, port, timeout).await
        });
        handles.push(handle);
    }

    let mut results = Vec::with_capacity(ports.len());
    for handle in handles {
        if let Ok(result) = handle.await {
            if result.status == PortStatus::Open {
                results.push(result);
            }
        }
    }

    results.sort_by_key(|r| r.port);
    results
}

async fn scan_one_port(ip: IpAddr, port: u16, timeout: Duration) -> PortResult {
    let addr = SocketAddr::new(ip, port);

    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            debug!("{}:{} open", ip, port);

            // Try banner grab
            let banner = grab_banner(&mut stream, port).await;

            PortResult {
                port,
                status: PortStatus::Open,
                service: service_name(port).map(String::from),
                banner,
            }
        }
        Ok(Err(_)) => PortResult {
            port,
            status: PortStatus::Closed,
            service: None,
            banner: None,
        },
        Err(_) => PortResult {
            port,
            status: PortStatus::Filtered,
            service: None,
            banner: None,
        },
    }
}

async fn grab_banner(stream: &mut TcpStream, port: u16) -> Option<String> {
    // Some services send banner on connect; others need a nudge
    let mut buf = [0u8; 512];
    match tokio::time::timeout(Duration::from_millis(300), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let text = String::from_utf8_lossy(&buf[..n]);
            let trimmed = text.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.chars().take(200).collect())
            }
        }
        _ => {
            // For HTTP, send a HEAD request
            if port == 80 || port == 8080 || port == 443 {
                return None; // Don't send data on connect scan
            }
            None
        }
    }
}

/// Map well-known port numbers to service names.
fn service_name(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("dns"),
        80 => Some("http"),
        110 => Some("pop3"),
        143 => Some("imap"),
        161 => Some("snmp"),
        443 => Some("https"),
        445 => Some("smb"),
        515 => Some("lpd"),
        631 => Some("ipp"),
        993 => Some("imaps"),
        995 => Some("pop3s"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        5432 => Some("postgresql"),
        5900 => Some("vnc"),
        8080 => Some("http-alt"),
        8443 => Some("https-alt"),
        9100 => Some("jetdirect"),
        _ => None,
    }
}
