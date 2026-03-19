use std::net::IpAddr;
use std::time::Duration;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::snmp::v3::{AuthProtocol, PrivProtocol, SecurityLevel, SnmpV3Config};

/// A scan target: CIDR subnet, IP range, or single host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanTarget {
    Cidr(Ipv4Net),
    Range { start: IpAddr, end: IpAddr },
    Single(IpAddr),
}

impl ScanTarget {
    /// Parse a target string (e.g. "192.168.1.0/24", "10.0.0.1-10.0.0.50", "192.168.1.1").
    pub fn parse(s: &str) -> crate::Result<Self> {
        if let Ok(cidr) = s.parse::<Ipv4Net>() {
            return Ok(ScanTarget::Cidr(cidr));
        }
        if s.contains('-') {
            let parts: Vec<&str> = s.splitn(2, '-').collect();
            let start: IpAddr = parts[0]
                .parse()
                .map_err(|_| crate::NmapperError::InvalidTarget(s.to_string()))?;
            let end: IpAddr = parts[1]
                .parse()
                .map_err(|_| crate::NmapperError::InvalidTarget(s.to_string()))?;
            return Ok(ScanTarget::Range { start, end });
        }
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(ScanTarget::Single(ip));
        }
        // Try as hostname
        Err(crate::NmapperError::InvalidTarget(s.to_string()))
    }

    /// Expand this target into individual IP addresses.
    pub fn expand(&self) -> Vec<IpAddr> {
        match self {
            ScanTarget::Cidr(net) => net.hosts().map(IpAddr::V4).collect(),
            ScanTarget::Range { start, end } => {
                let mut ips = Vec::new();
                if let (IpAddr::V4(s), IpAddr::V4(e)) = (start, end) {
                    let s_u32 = u32::from(*s);
                    let e_u32 = u32::from(*e);
                    for i in s_u32..=e_u32 {
                        ips.push(IpAddr::V4(std::net::Ipv4Addr::from(i)));
                    }
                }
                ips
            }
            ScanTarget::Single(ip) => vec![*ip],
        }
    }
}

/// Top 16 commonly scanned ports.
pub const DEFAULT_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 143, 161, 443, 445, 515, 631, 3389, 8080, 9100,
];

/// SNMP configuration — either v2c (community string) or v3 (USM).
#[derive(Debug, Clone)]
pub enum SnmpConfig {
    /// SNMPv2c with a community string.
    V2c { community: String },
    /// SNMPv3 with USM authentication/privacy.
    V3(SnmpV3Config),
}

impl SnmpConfig {
    /// Build an SnmpConfig from CLI flags.
    ///
    /// If `snmp_v3_user` is provided, uses v3. Otherwise if `snmp_community`
    /// is provided, uses v2c. Otherwise returns None.
    pub fn from_flags(
        snmp_community: Option<String>,
        snmp_v3_user: Option<String>,
        snmp_v3_auth_proto: Option<String>,
        snmp_v3_auth_pass: Option<String>,
        snmp_v3_priv_proto: Option<String>,
        snmp_v3_priv_pass: Option<String>,
    ) -> Option<Self> {
        if let Some(user) = snmp_v3_user {
            let auth_proto = match snmp_v3_auth_proto.as_deref() {
                Some("md5") => AuthProtocol::Md5,
                Some("sha1") | Some("sha") => AuthProtocol::Sha1,
                _ => AuthProtocol::None,
            };
            let priv_proto = match snmp_v3_priv_proto.as_deref() {
                Some("des") => PrivProtocol::Des,
                Some("aes128") | Some("aes") => PrivProtocol::Aes128,
                _ => PrivProtocol::None,
            };
            let security_level = match (auth_proto, priv_proto) {
                (AuthProtocol::None, _) => SecurityLevel::NoAuthNoPriv,
                (_, PrivProtocol::None) => SecurityLevel::AuthNoPriv,
                _ => SecurityLevel::AuthPriv,
            };
            Some(SnmpConfig::V3(SnmpV3Config {
                username: user,
                auth_protocol: auth_proto,
                auth_password: snmp_v3_auth_pass,
                priv_protocol: priv_proto,
                priv_password: snmp_v3_priv_pass,
                security_level,
            }))
        } else {
            snmp_community.map(|c| SnmpConfig::V2c { community: c })
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub targets: Vec<ScanTarget>,
    pub ping_timeout: Duration,
    pub ping_concurrency: usize,
    pub ports: Vec<u16>,
    pub port_timeout: Duration,
    pub port_concurrency: usize,
    pub arp_lookup: bool,
    pub rdns: bool,
    /// Legacy v2c community string (kept for backward compat).
    pub snmp_community: Option<String>,
    /// New unified SNMP config — preferred over snmp_community.
    pub snmp_config: Option<SnmpConfig>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            ping_timeout: Duration::from_secs(1),
            ping_concurrency: 64,
            ports: DEFAULT_PORTS.to_vec(),
            port_timeout: Duration::from_millis(500),
            port_concurrency: 128,
            arp_lookup: true,
            rdns: true,
            snmp_community: None,
            snmp_config: None,
        }
    }
}
