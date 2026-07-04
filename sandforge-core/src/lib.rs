//! # sandforge-core
//!
//! `sandforge-core` is a sandbox artifact verification library. It ingests
//! ELF, PE, WASM, DER, and policy manifests, drives verification journals
//! over generational ticket tables, and decodes CBOR attestation records.
//!
//! ## Module map
//!
//! | Module | Role |
//! |--------|------|
//! | [`pool`] | blob store, arena, scratch, generational ticket table |
//! | [`journal`] | binary `JRN2` script driver for session replay |
//! | [`cbor`] | handwritten attestation record decoder |
//! | [`codec`] | percent, base64, hex helpers |
//! | [`util`] | slice cursor, growable buffer |
//! | [`elf`] | ELF64 header, program/section tables, notes |
//! | [`pe`] | PE/COFF headers, sections, imports |
//! | [`der`] | ASN.1 DER TLV and X.509 certificate skeleton |
//! | [`wasm`] | WebAssembly module section parser |
//! | [`manifest`] | SMNF sandbox policy manifest |
//! | [`archive`] | ARSF multi-file archive reader |
//! | [`verify`] | cross-format artifact probing |

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod archive;
pub mod cbor;
pub mod codec;
pub mod der;
pub mod elf;
pub mod error;
pub mod journal;
pub mod manifest;
pub mod pe;
pub mod pool;
pub mod util;
pub mod verify;
pub mod wasm;

pub use archive::{extract_all, parse_archive, ArchiveEntry, ArchiveReader, ExtractedFile};
pub use der::{parse_certificate, parse_der, Certificate, DerValue};
pub use elf::{parse_and_validate as parse_elf_validated, parse_elf, ElfImage};
pub use manifest::{
    parse_and_normalize as parse_and_normalize_manifest, parse_manifest, Manifest, ManifestEntry,
    ManifestFlags, NormalizedManifest, PolicyKind,
};
pub use pe::{parse_and_validate as parse_pe_validated, parse_pe, PeImage};
pub use wasm::{parse_and_validate as parse_wasm_validated, parse_wasm, WasmModule};

pub use error::{Error, ErrorKind, Result};

/// Crate version from the manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Drive the verification journal with a scripted byte stream.
pub fn run_journal(data: &[u8]) -> Result<journal::Summary> {
    journal::run_journal(data)
}

/// Parse CBOR attestation records.
pub fn parse_cbor(data: &[u8]) -> Result<cbor::AttestationBundle> {
    cbor::parse_cbor(data)
}

/// Parse and normalize CBOR attestation records.
pub fn parse_and_normalize(data: &[u8]) -> Result<cbor::AttestationBundle> {
    cbor::parse_and_normalize(data)
}

/// Probe unknown artifact bytes against all supported parsers.
pub fn probe_artifact(data: &[u8]) -> verify::ScanSummary {
    verify::probe_blob(data)
}

/// Return short format labels for parsers that accept `data`.
pub fn probe_artifact_labels(data: &[u8]) -> alloc::vec::Vec<&'static str> {
    verify::probe_labels(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn top_level_journal_api() {
        let s = run_journal(&[]).unwrap();
        assert_eq!(s.opens, 0);
    }

    #[test]
    fn top_level_cbor_api() {
        let bundle = parse_cbor(&[]).unwrap();
        assert!(bundle.is_empty());
    }
}
