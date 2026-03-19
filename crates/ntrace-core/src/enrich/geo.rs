//! GeoIP lookup via ip-api.com (requires `enrichment` feature).

use std::net::IpAddr;

use super::GeoInfo;

/// Look up geographic information for an IP address using ip-api.com.
/// Returns None on error or if the API returns a failure status.
pub async fn lookup_geo(ip: IpAddr) -> Option<GeoInfo> {
    let url = format!("http://ip-api.com/json/{}?fields=status,country,regionName,city,lat,lon,isp", ip);

    let resp = reqwest::get(&url).await.ok()?;
    let json: serde_json::Value = resp.json().await.ok()?;

    if json.get("status")?.as_str()? != "success" {
        return None;
    }

    Some(GeoInfo {
        country: json.get("country")?.as_str()?.to_string(),
        region: json.get("regionName").and_then(|v| v.as_str()).map(String::from),
        city: json.get("city").and_then(|v| v.as_str()).map(String::from),
        lat: json.get("lat").and_then(|v| v.as_f64()),
        lon: json.get("lon").and_then(|v| v.as_f64()),
        isp: json.get("isp").and_then(|v| v.as_str()).map(String::from),
    })
}
