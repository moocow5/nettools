use std::fmt::Write as FmtWrite;
use std::io::Write;
use std::path::Path;

use zip::write::SimpleFileOptions;
use zip::ZipWriter;

use crate::layout::Layout;
use crate::result::{DeviceType, DiscoveredDevice};

/// Pixels-to-inches conversion factor (96 DPI).
const PX_TO_IN: f64 = 1.0 / 96.0;

/// Return a Visio-compatible RGB hex color string for the given device type.
fn device_color_hex(dt: DeviceType) -> &'static str {
    match dt {
        DeviceType::Router => "#4CAF50",
        DeviceType::Switch => "#00BCD4",
        DeviceType::Firewall => "#F44336",
        DeviceType::Server => "#FFEB3B",
        DeviceType::Printer => "#E91E63",
        DeviceType::AccessPoint => "#2196F3",
        DeviceType::Workstation => "#9E9E9E",
        DeviceType::IoT => "#FF9800",
        DeviceType::Unknown => "#9E9E9E",
    }
}

/// Export the layout to VSDX bytes in memory.
///
/// Returns the raw VSDX (ZIP) bytes suitable for HTTP responses or saving to disk.
pub fn export_vsdx_bytes(
    layout: &Layout,
    devices: &[DiscoveredDevice],
) -> crate::Result<Vec<u8>> {
    let buf = std::io::Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(buf);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    let hostname_map: std::collections::HashMap<std::net::IpAddr, Option<&str>> = devices
        .iter()
        .map(|d| (d.ip, d.hostname.as_deref()))
        .collect();

    zip.start_file("[Content_Types].xml", options)
        .map_err(|e| crate::NmapperError::Export(e.to_string()))?;
    zip.write_all(CONTENT_TYPES_XML.as_bytes())?;

    zip.start_file("_rels/.rels", options)
        .map_err(|e| crate::NmapperError::Export(e.to_string()))?;
    zip.write_all(ROOT_RELS_XML.as_bytes())?;

    zip.start_file("visio/document.xml", options)
        .map_err(|e| crate::NmapperError::Export(e.to_string()))?;
    zip.write_all(DOCUMENT_XML.as_bytes())?;

    zip.start_file("visio/_rels/document.xml.rels", options)
        .map_err(|e| crate::NmapperError::Export(e.to_string()))?;
    zip.write_all(DOCUMENT_RELS_XML.as_bytes())?;

    zip.start_file("visio/pages/pages.xml", options)
        .map_err(|e| crate::NmapperError::Export(e.to_string()))?;
    zip.write_all(PAGES_XML.as_bytes())?;

    zip.start_file("visio/pages/_rels/pages.xml.rels", options)
        .map_err(|e| crate::NmapperError::Export(e.to_string()))?;
    zip.write_all(PAGES_RELS_XML.as_bytes())?;

    let page_xml = build_page_xml(layout, &hostname_map);
    zip.start_file("visio/pages/page1.xml", options)
        .map_err(|e| crate::NmapperError::Export(e.to_string()))?;
    zip.write_all(page_xml.as_bytes())?;

    let cursor = zip.finish().map_err(|e| crate::NmapperError::Export(e.to_string()))?;
    Ok(cursor.into_inner())
}

/// Export the layout to a minimal VSDX (Visio) file at the given path.
///
/// VSDX is an Open Packaging Convention (OPC / ZIP) archive containing XML
/// parts. This produces a minimal but valid file that Visio can open.
pub fn export_vsdx(
    layout: &Layout,
    devices: &[DiscoveredDevice],
    path: &Path,
) -> crate::Result<()> {
    let file = std::fs::File::create(path)?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    // Build hostname lookup.
    let hostname_map: std::collections::HashMap<std::net::IpAddr, Option<&str>> = devices
        .iter()
        .map(|d| (d.ip, d.hostname.as_deref()))
        .collect();

    // [Content_Types].xml
    zip.start_file("[Content_Types].xml", options)
        .map_err(|e| crate::NmapperError::Export(e.to_string()))?;
    zip.write_all(CONTENT_TYPES_XML.as_bytes())?;

    // _rels/.rels
    zip.start_file("_rels/.rels", options)
        .map_err(|e| crate::NmapperError::Export(e.to_string()))?;
    zip.write_all(ROOT_RELS_XML.as_bytes())?;

    // visio/document.xml
    zip.start_file("visio/document.xml", options)
        .map_err(|e| crate::NmapperError::Export(e.to_string()))?;
    zip.write_all(DOCUMENT_XML.as_bytes())?;

    // visio/_rels/document.xml.rels
    zip.start_file("visio/_rels/document.xml.rels", options)
        .map_err(|e| crate::NmapperError::Export(e.to_string()))?;
    zip.write_all(DOCUMENT_RELS_XML.as_bytes())?;

    // visio/pages/pages.xml
    zip.start_file("visio/pages/pages.xml", options)
        .map_err(|e| crate::NmapperError::Export(e.to_string()))?;
    zip.write_all(PAGES_XML.as_bytes())?;

    // visio/pages/_rels/pages.xml.rels
    zip.start_file("visio/pages/_rels/pages.xml.rels", options)
        .map_err(|e| crate::NmapperError::Export(e.to_string()))?;
    zip.write_all(PAGES_RELS_XML.as_bytes())?;

    // visio/pages/page1.xml — the actual shapes.
    let page_xml = build_page_xml(layout, &hostname_map);
    zip.start_file("visio/pages/page1.xml", options)
        .map_err(|e| crate::NmapperError::Export(e.to_string()))?;
    zip.write_all(page_xml.as_bytes())?;

    zip.finish().map_err(|e| crate::NmapperError::Export(e.to_string()))?;
    Ok(())
}

fn build_page_xml(
    layout: &Layout,
    hostname_map: &std::collections::HashMap<std::net::IpAddr, Option<&str>>,
) -> String {
    let page_width = layout.width * PX_TO_IN;
    let page_height = layout.height * PX_TO_IN;

    let mut xml = String::with_capacity(4096);
    write!(
        xml,
        r#"<?xml version="1.0" encoding="UTF-8"?>
<PageContents xmlns="http://schemas.microsoft.com/office/visio/2012/main"
              xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<Page ID="0" NameU="Page-1">
<PageSheet>
<Cell N="PageWidth" V="{page_width}" />
<Cell N="PageHeight" V="{page_height}" />
</PageSheet>
</Page>
<Shapes>
"#,
    )
    .unwrap();

    let mut shape_id: u32 = 1;

    // Device shapes.
    for node in &layout.nodes {
        let w = node.width * PX_TO_IN;
        let h = node.height * PX_TO_IN;
        let pin_x = node.x * PX_TO_IN;
        // Visio Y is bottom-up, so invert.
        let pin_y = page_height - node.y * PX_TO_IN;
        let color = device_color_hex(node.device_type);
        let hostname = hostname_map
            .get(&node.ip)
            .copied()
            .flatten()
            .unwrap_or("");

        let text = if hostname.is_empty() {
            format!("{}\n{}", node.device_type, node.ip)
        } else {
            format!("{}\n{}\n{}", node.device_type, node.ip, hostname)
        };

        write!(
            xml,
            r#"<Shape ID="{shape_id}" NameU="Device" Type="Shape">
<Cell N="PinX" V="{pin_x}" />
<Cell N="PinY" V="{pin_y}" />
<Cell N="Width" V="{w}" />
<Cell N="Height" V="{h}" />
<Cell N="FillForegnd" V="{color}" />
<Cell N="Rounding" V="0.05" />
<Text>{text}</Text>
</Shape>
"#,
            text = escape_xml(&text),
        )
        .unwrap();
        shape_id += 1;
    }

    // Edge / connector shapes.
    for edge in &layout.edges {
        let bx = edge.source_x * PX_TO_IN;
        let by = page_height - edge.source_y * PX_TO_IN;
        let ex = edge.target_x * PX_TO_IN;
        let ey = page_height - edge.target_y * PX_TO_IN;

        write!(
            xml,
            r#"<Shape ID="{shape_id}" NameU="Connector" Type="Shape">
<Cell N="BeginX" V="{bx}" />
<Cell N="BeginY" V="{by}" />
<Cell N="EndX" V="{ex}" />
<Cell N="EndY" V="{ey}" />
<Cell N="EndArrow" V="5" />
</Shape>
"#,
        )
        .unwrap();
        shape_id += 1;
    }

    xml.push_str("</Shapes>\n</PageContents>\n");
    xml
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// --- Static XML templates ---

const CONTENT_TYPES_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml" />
  <Default Extension="xml" ContentType="application/xml" />
  <Override PartName="/visio/document.xml" ContentType="application/vnd.ms-visio.drawing.main+xml" />
  <Override PartName="/visio/pages/pages.xml" ContentType="application/vnd.ms-visio.pages+xml" />
  <Override PartName="/visio/pages/page1.xml" ContentType="application/vnd.ms-visio.page+xml" />
</Types>"#;

const ROOT_RELS_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.microsoft.com/visio/2010/relationships/document" Target="visio/document.xml" />
</Relationships>"#;

const DOCUMENT_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<VisioDocument xmlns="http://schemas.microsoft.com/office/visio/2012/main"
               xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <DocumentSettings />
</VisioDocument>"#;

const DOCUMENT_RELS_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.microsoft.com/visio/2010/relationships/pages" Target="pages/pages.xml" />
</Relationships>"#;

const PAGES_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<Pages xmlns="http://schemas.microsoft.com/office/visio/2012/main"
       xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <Page ID="0" NameU="Page-1">
    <Rel r:id="rId1" />
  </Page>
</Pages>"#;

const PAGES_RELS_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.microsoft.com/visio/2010/relationships/page" Target="page1.xml" />
</Relationships>"#;
