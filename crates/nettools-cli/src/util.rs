use std::time::Duration;

use ntrace_core::config::ProbeMethod;

/// Parse a duration string like "1s", "500ms", "2.5s", or a bare number (treated as seconds).
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if let Some(ms_str) = s.strip_suffix("ms") {
        let ms: f64 = ms_str
            .trim()
            .parse()
            .map_err(|_| format!("invalid duration: {s}"))?;
        Ok(Duration::from_secs_f64(ms / 1000.0))
    } else if let Some(sec_str) = s.strip_suffix('s') {
        let secs: f64 = sec_str
            .trim()
            .parse()
            .map_err(|_| format!("invalid duration: {s}"))?;
        Ok(Duration::from_secs_f64(secs))
    } else {
        // Bare number — treat as seconds
        let secs: f64 = s.parse().map_err(|_| format!("invalid duration: {s}"))?;
        Ok(Duration::from_secs_f64(secs))
    }
}

/// Parse a probe method string into a `ProbeMethod`.
pub fn parse_method(s: &str) -> Result<ProbeMethod, String> {
    match s.to_lowercase().as_str() {
        "icmp" => Ok(ProbeMethod::Icmp),
        "udp" => Ok(ProbeMethod::Udp),
        "tcp" | "tcp-syn" => Ok(ProbeMethod::TcpSyn),
        _ => Err(format!("unknown method '{}': use icmp, udp, or tcp", s)),
    }
}
