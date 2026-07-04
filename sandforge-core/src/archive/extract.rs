//! Archive extraction and materialization helpers.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};

use super::reader::{parse_archive, ArchiveEntry, ArchiveReader};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedFile {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub bytes: Vec<u8>,
}

impl ExtractedFile {
    pub fn is_wasm(&self) -> bool {
        self.name.ends_with(".wasm") || self.bytes.starts_with(&[0x00, 0x61, 0x73, 0x6d])
    }

    pub fn is_manifest(&self) -> bool {
        self.name.ends_with(".smnf") || self.bytes.starts_with(b"SMNF")
    }

    pub fn extension(&self) -> Option<&str> {
        self.name.rsplit('.').next()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractionReport {
    pub files: Vec<ExtractedFile>,
    pub total_bytes: u64,
    pub skipped: usize,
}

impl ExtractionReport {
    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn find(&self, name: &str) -> Option<&ExtractedFile> {
        self.files.iter().find(|f| f.name == name)
    }

    pub fn wasm_modules(&self) -> impl Iterator<Item = &ExtractedFile> {
        self.files.iter().filter(|f| f.is_wasm())
    }

    pub fn manifests(&self) -> impl Iterator<Item = &ExtractedFile> {
        self.files.iter().filter(|f| f.is_manifest())
    }
}

/// Parse an archive and copy all entry payloads into owned buffers.
pub fn extract_all(input: &[u8]) -> Result<ExtractionReport> {
    let reader = parse_archive(input)?;
    extract_from_reader(&reader)
}

pub fn extract_from_reader(reader: &ArchiveReader<'_>) -> Result<ExtractionReport> {
    let index = reader.index();
    let mut files = Vec::with_capacity(index.len());
    let mut total_bytes: u64 = 0;
    let mut skipped = 0;

    for entry in &index.entries {
        match materialize_entry(reader, entry) {
            Ok(file) => {
                total_bytes = total_bytes
                    .checked_add(file.size)
                    .ok_or_else(|| Error::length_overflow("total_bytes", file.size, u64::MAX))?;
                files.push(file);
            }
            Err(Error::ArchiveLayout { .. }) => {
                skipped += 1;
            }
            Err(e) => return Err(e),
        }
    }

    verify_extraction_integrity(&files, index.total_payload_bytes())?;

    Ok(ExtractionReport {
        files,
        total_bytes,
        skipped,
    })
}

fn materialize_entry(reader: &ArchiveReader<'_>, entry: &ArchiveEntry) -> Result<ExtractedFile> {
    validate_entry_name(&entry.name)?;
    let slice = reader.entry_data(entry)?;
    if slice.len() != entry.size as usize {
        return Err(Error::archive_layout("entry size mismatch during extract"));
    }
    Ok(ExtractedFile {
        name: entry.name.clone(),
        offset: entry.offset,
        size: entry.size,
        bytes: slice.to_vec(),
    })
}

fn validate_entry_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::archive_layout("empty filename"));
    }
    if name.contains('\\') {
        return Err(Error::archive_layout("backslash in entry name"));
    }
    if name.contains("..") {
        return Err(Error::archive_layout("path traversal in entry name"));
    }
    if name.starts_with('/') {
        return Err(Error::archive_layout("absolute path in entry name"));
    }
    if name.len() > 512 {
        return Err(Error::archive_layout("entry name too long"));
    }
    Ok(())
}

fn verify_extraction_integrity(files: &[ExtractedFile], expected_payload: u64) -> Result<()> {
    let sum: u64 = files.iter().map(|f| f.size).sum();
    if sum != expected_payload {
        return Err(Error::archive_layout("extracted byte count mismatch"));
    }

    for window in files.windows(2) {
        let prev = &window[0];
        let next = &window[1];
        let prev_end = prev
            .offset
            .checked_add(prev.size)
            .ok_or_else(|| Error::length_overflow("prev_end", prev.size, u64::MAX))?;
        if next.offset != prev_end {
            return Err(Error::archive_layout("extracted ordering gap"));
        }
    }
    Ok(())
}

/// Extract only entries matching a predicate.
pub fn extract_filtered<F>(input: &[u8], mut pred: F) -> Result<ExtractionReport>
where
    F: FnMut(&ArchiveEntry) -> bool,
{
    let reader = parse_archive(input)?;
    let index = reader.index();
    let mut files = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut skipped = 0;

    for entry in &index.entries {
        if !pred(entry) {
            skipped += 1;
            continue;
        }
        let file = materialize_entry(&reader, entry)?;
        total_bytes = total_bytes
            .checked_add(file.size)
            .ok_or_else(|| Error::length_overflow("total_bytes", file.size, u64::MAX))?;
        files.push(file);
    }

    Ok(ExtractionReport {
        files,
        total_bytes,
        skipped,
    })
}

/// Extract a single named member without loading the full report.
pub fn extract_one(input: &[u8], name: &str) -> Result<ExtractedFile> {
    let reader = parse_archive(input)?;
    let entry = reader
        .index()
        .find(name)
        .ok_or_else(|| Error::archive_layout("named entry missing"))?;
    materialize_entry(&reader, entry)
}

/// Build a map from entry name to raw bytes for downstream verification.
pub fn extract_map(input: &[u8]) -> Result<alloc::collections::BTreeMap<String, Vec<u8>>> {
    use alloc::collections::BTreeMap;
    let report = extract_all(input)?;
    let mut map = BTreeMap::new();
    for file in report.files {
        map.insert(file.name, file.bytes);
    }
    Ok(map)
}

/// Verify every extracted payload matches the archive index sizes.
pub fn verify_extraction(report: &ExtractionReport, index: &super::reader::ArchiveIndex) -> Result<()> {
    if report.len() != index.len() {
        return Err(Error::archive_layout("extracted file count mismatch"));
    }
    let expected: u64 = index.entries.iter().map(|e| e.size).sum();
    if report.total_bytes != expected {
        return Err(Error::archive_layout("extracted payload size mismatch"));
    }
    for (file, entry) in report.files.iter().zip(index.entries.iter()) {
        if file.name != entry.name {
            return Err(Error::archive_layout("extracted name order mismatch"));
        }
        if file.size != entry.size || file.bytes.len() as u64 != entry.size {
            return Err(Error::archive_layout("extracted member size mismatch"));
        }
    }
    Ok(())
}

/// Classify archive members for downstream artifact routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveClassification {
    pub wasm: Vec<String>,
    pub manifests: Vec<String>,
    pub other: Vec<String>,
}

impl ArchiveClassification {
    pub fn from_report(report: &ExtractionReport) -> Self {
        let mut wasm = Vec::new();
        let mut manifests = Vec::new();
        let mut other = Vec::new();
        for file in &report.files {
            if file.is_wasm() {
                wasm.push(file.name.clone());
            } else if file.is_manifest() {
                manifests.push(file.name.clone());
            } else {
                other.push(file.name.clone());
            }
        }
        Self { wasm, manifests, other }
    }

    pub fn total(&self) -> usize {
        self.wasm.len() + self.manifests.len() + self.other.len()
    }
}

/// Parse, extract, and classify in one pass.
pub fn extract_and_classify(input: &[u8]) -> Result<(ExtractionReport, ArchiveClassification)> {
    let reader = super::reader::parse_archive(input)?;
    let index = reader.index().clone();
    let report = extract_from_reader(&reader)?;
    verify_extraction(&report, &index)?;
    let class = ArchiveClassification::from_report(&report);
    Ok((report, class))
}

/// Extract members whose names match a prefix (e.g. `policy/`).
pub fn extract_prefix(input: &[u8], prefix: &str) -> Result<ExtractionReport> {
    extract_filtered(input, |entry| entry.name.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::super::reader::ARCHIVE_MAGIC;
    use super::*;

    fn build_archive(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&ARCHIVE_MAGIC);
        out.extend_from_slice(&(files.len() as u32).to_le_bytes());
        let mut offset: u64 = 0;
        for (name, data) in files {
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(&(data.len() as u64).to_le_bytes());
            offset += data.len() as u64;
        }
        for (_, data) in files {
            out.extend_from_slice(data);
        }
        out
    }

    #[test]
    fn extract_all_roundtrip() {
        let bytes = build_archive(&[
            ("policy.smnf", b"SMNF"),
            ("guest.wasm", b"\0asm\x01"),
        ]);
        let report = extract_all(&bytes).unwrap();
        assert_eq!(report.len(), 2);
        assert_eq!(report.total_bytes, 8);
    }

    #[test]
    fn extract_one_by_name() {
        let bytes = build_archive(&[("only.dat", b"payload")]);
        let file = extract_one(&bytes, "only.dat").unwrap();
        assert_eq!(file.bytes, b"payload");
    }

    #[test]
    fn rejects_path_traversal_name() {
        let bytes = build_archive(&[("../etc/passwd", b"x")]);
        assert!(extract_all(&bytes).is_err());
    }

    #[test]
    fn wasm_detection() {
        let f = ExtractedFile {
            name: String::from("a.wasm"),
            offset: 0,
            size: 4,
            bytes: vec![0, 0x61, 0x73, 0x6d],
        };
        assert!(f.is_wasm());
    }
}
