use crate::result::ScanResult;

/// Serialize a scan result to a pretty-printed JSON string.
pub fn export_json(result: &ScanResult) -> crate::Result<String> {
    serde_json::to_string_pretty(result).map_err(|e| crate::NmapperError::Export(e.to_string()))
}
