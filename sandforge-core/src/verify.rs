//! Cross-format verification helpers tying parsers together.

use crate::error::Result;

/// Summary of a multi-format scan pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanSummary {
    pub elf_ok: bool,
    pub pe_ok: bool,
    pub wasm_ok: bool,
    pub der_ok: bool,
    pub manifest_ok: bool,
    pub archive_ok: bool,
    pub journal_events: u32,
}

/// Probe unknown bytes against each parser; errors are ignored (best-effort).
pub fn probe_blob(data: &[u8]) -> ScanSummary {
    let mut s = ScanSummary::default();
    if crate::elf::parse_and_validate(data).is_ok() {
        s.elf_ok = true;
    }
    if crate::pe::parse_and_validate(data).is_ok() {
        s.pe_ok = true;
    }
    if crate::wasm::parse_and_validate(data).is_ok() {
        s.wasm_ok = true;
    }
    if crate::der::parse_certificate(data).is_ok() {
        s.der_ok = true;
    }
    if crate::manifest::parse_and_normalize(data).is_ok() {
        s.manifest_ok = true;
    }
    if crate::archive::extract_all(data).is_ok() {
        s.archive_ok = true;
    }
    if let Ok(j) = crate::journal::run_journal(data) {
        s.journal_events = j.flushes;
    }
    s
}

/// Return human-readable labels for formats that parsed successfully.
pub fn probe_labels(data: &[u8]) -> alloc::vec::Vec<&'static str> {
    let s = probe_blob(data);
    let mut out = alloc::vec::Vec::new();
    if s.elf_ok {
        out.push("elf");
    }
    if s.pe_ok {
        out.push("pe");
    }
    if s.wasm_ok {
        out.push("wasm");
    }
    if s.der_ok {
        out.push("der");
    }
    if s.manifest_ok {
        out.push("manifest");
    }
    if s.archive_ok {
        out.push("archive");
    }
    if s.journal_events > 0 {
        out.push("journal");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_probe() {
        let s = probe_blob(&[]);
        assert!(!s.elf_ok);
    }
}
