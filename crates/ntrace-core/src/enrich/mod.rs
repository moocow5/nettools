//! Enrichment modules for traceroute hop data.
//!
//! Provides reverse DNS, ASN lookups, and optional GeoIP lookups.

pub mod dns;
pub mod asn;
#[cfg(feature = "enrichment")]
pub mod geo;

use std::collections::HashMap;
use std::net::IpAddr;
use serde::{Serialize, Deserialize};

/// Enrichment data collected for a single hop.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HopEnrichment {
    pub hostname: Option<String>,
    pub asn_info: Option<AsnInfo>,
    #[cfg(feature = "enrichment")]
    pub geo_info: Option<GeoInfo>,
}

/// Autonomous System Number information from Team Cymru.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnInfo {
    pub asn: u32,
    pub name: Option<String>,
    pub prefix: String,
    pub country: String,
}

/// Geographic location information from ip-api.com.
#[cfg(feature = "enrichment")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoInfo {
    pub country: String,
    pub region: Option<String>,
    pub city: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub isp: Option<String>,
}

/// Coordinator that caches enrichment lookups for IP addresses.
pub struct Enricher {
    dns_cache: HashMap<IpAddr, Option<String>>,
    asn_cache: HashMap<IpAddr, Option<AsnInfo>>,
    #[cfg(feature = "enrichment")]
    geo_cache: HashMap<IpAddr, Option<GeoInfo>>,
}

impl Enricher {
    /// Create a new enricher with empty caches.
    pub fn new() -> Self {
        Self {
            dns_cache: HashMap::new(),
            asn_cache: HashMap::new(),
            #[cfg(feature = "enrichment")]
            geo_cache: HashMap::new(),
        }
    }

    /// Perform a cached reverse DNS lookup.
    pub async fn lookup_dns(&mut self, ip: IpAddr) -> Option<String> {
        if let Some(cached) = self.dns_cache.get(&ip) {
            return cached.clone();
        }
        let result = dns::reverse_dns(ip).await;
        self.dns_cache.insert(ip, result.clone());
        result
    }

    /// Perform a cached ASN lookup.
    pub async fn lookup_asn(&mut self, ip: IpAddr) -> Option<AsnInfo> {
        if let Some(cached) = self.asn_cache.get(&ip) {
            return cached.clone();
        }
        let result = asn::lookup_asn(ip).await;
        self.asn_cache.insert(ip, result.clone());
        result
    }

    /// Perform a cached GeoIP lookup (requires `enrichment` feature).
    #[cfg(feature = "enrichment")]
    pub async fn lookup_geo(&mut self, ip: IpAddr) -> Option<GeoInfo> {
        if let Some(cached) = self.geo_cache.get(&ip) {
            return cached.clone();
        }
        let result = geo::lookup_geo(ip).await;
        self.geo_cache.insert(ip, result.clone());
        result
    }

    /// Enrich a single IP address with all available data.
    pub async fn enrich(
        &mut self,
        ip: IpAddr,
        resolve_dns: bool,
        lookup_asn: bool,
        #[cfg(feature = "enrichment")] lookup_geo: bool,
    ) -> HopEnrichment {
        let hostname = if resolve_dns {
            self.lookup_dns(ip).await
        } else {
            None
        };

        let asn_info = if lookup_asn {
            self.lookup_asn(ip).await
        } else {
            None
        };

        #[cfg(feature = "enrichment")]
        let geo_info = if lookup_geo {
            self.lookup_geo(ip).await
        } else {
            None
        };

        HopEnrichment {
            hostname,
            asn_info,
            #[cfg(feature = "enrichment")]
            geo_info,
        }
    }
}
