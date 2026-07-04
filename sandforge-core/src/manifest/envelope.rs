//! SMNF binary envelope decoder.
//!
//! Wire layout:
//! ```text
//! magic[4]      "SMNF"
//! version u32
//! flags u32
//! entry_count u32
//! entries[]     kind u16, name_len u16, name[], value_len u32, value[]
//! ```

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::pool::{BlobStore, RawSlice};
use crate::util::SliceCursor;

pub const MANIFEST_MAGIC: [u8; 4] = *b"SMNF";
pub const MANIFEST_VERSION: u32 = 1;

/// Manifest header feature flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestFlags(u32);

impl ManifestFlags {
    pub const STRICT_NAMES: Self = Self(1 << 0);
    pub const REQUIRE_SORTED: Self = Self(1 << 1);
    pub const DEDUPE_VALUES: Self = Self(1 << 2);
    pub const ZERO_COPY: Self = Self(1 << 3);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub fn from_bits(bits: u32) -> Option<Self> {
        const KNOWN: u32 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3);
        if bits & !KNOWN == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// Policy entry categories understood by the sandbox loader.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicyKind {
    AllowSyscall = 1,
    DenySyscall = 2,
    MaxMemoryMb = 3,
    MaxThreads = 4,
    AllowFsPath = 5,
    DenyFsPath = 6,
    NetworkMode = 7,
    Capability = 8,
    Environment = 9,
    FeatureToggle = 10,
}

impl PolicyKind {
    pub fn from_u16(v: u16) -> Result<Self> {
        match v {
            1 => Ok(Self::AllowSyscall),
            2 => Ok(Self::DenySyscall),
            3 => Ok(Self::MaxMemoryMb),
            4 => Ok(Self::MaxThreads),
            5 => Ok(Self::AllowFsPath),
            6 => Ok(Self::DenyFsPath),
            7 => Ok(Self::NetworkMode),
            8 => Ok(Self::Capability),
            9 => Ok(Self::Environment),
            10 => Ok(Self::FeatureToggle),
            _ => Err(Error::UnknownKind { kind: v }),
        }
    }

    pub fn expects_numeric_value(self) -> bool {
        matches!(self, Self::MaxMemoryMb | Self::MaxThreads | Self::NetworkMode)
    }

    pub fn name_prefix(self) -> &'static str {
        match self {
            Self::AllowSyscall => "allow.syscall",
            Self::DenySyscall => "deny.syscall",
            Self::MaxMemoryMb => "limit.memory_mb",
            Self::MaxThreads => "limit.threads",
            Self::AllowFsPath => "allow.fs",
            Self::DenyFsPath => "deny.fs",
            Self::NetworkMode => "net.mode",
            Self::Capability => "cap",
            Self::Environment => "env",
            Self::FeatureToggle => "feature",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestHeader {
    pub version: u32,
    pub flags: ManifestFlags,
    pub entry_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    pub kind: PolicyKind,
    pub name_offset: usize,
    pub name_len: usize,
    pub value_offset: usize,
    pub value_len: usize,
}

impl ManifestEntry {
    pub fn name<'a>(&self, store: &'a BlobStore) -> Option<&'a [u8]> {
        store.slice(self.name_offset, self.name_len)
    }

    pub fn value<'a>(&self, store: &'a BlobStore) -> Option<&'a [u8]> {
        store.slice(self.value_offset, self.value_len)
    }

    pub fn name_str<'a>(&self, store: &'a BlobStore) -> Result<&'a str> {
        let bytes = self.name(store).ok_or(Error::UnexpectedEof)?;
        core::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)
    }

    pub fn value_str<'a>(&self, store: &'a BlobStore) -> Result<&'a str> {
        let bytes = self.value(store).ok_or(Error::UnexpectedEof)?;
        core::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub header: ManifestHeader,
    pub store: BlobStore,
    pub entries: Vec<ManifestEntry>,
    /// Pinned name bytes for the first entry when ZERO_COPY is set.
    pub pinned_first_name: Option<RawSlice>,
}

impl Manifest {
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn has_flag(&self, flag: ManifestFlags) -> bool {
        self.header.flags.contains(flag)
    }

    pub fn entries_of_kind(&self, kind: PolicyKind) -> impl Iterator<Item = &ManifestEntry> {
        self.entries.iter().filter(move |e| e.kind == kind)
    }

    pub fn lookup_by_name(&self, needle: &str) -> Option<&ManifestEntry> {
        self.entries.iter().find(|e| {
            e.name_str(&self.store)
                .map(|n| n == needle)
                .unwrap_or(false)
        })
    }
}

/// Decode a SMNF manifest from raw bytes.
pub fn parse_manifest(input: &[u8]) -> Result<Manifest> {
    let mut cur = SliceCursor::new(input);
    let magic = cur.read_exact(4)?;
    if magic != MANIFEST_MAGIC {
        return Err(Error::BadMagic {
            expected: "SMNF",
            found: crate::error::magic_from_bytes([
                magic[0], magic[1], magic[2], magic[3],
            ]),
        });
    }

    let version = cur.read_u32_le()?;
    if version == 0 || version > MANIFEST_VERSION {
        return Err(Error::out_of_range("manifest.version", version as u64, MANIFEST_VERSION as u64));
    }

    let flags_raw = cur.read_u32_le()?;
    let flags = ManifestFlags::from_bits(flags_raw).ok_or_else(|| {
        Error::invalid_structure("manifest flags contain unknown bits")
    })?;

    let entry_count = cur.read_u32_le()?;
    if entry_count > 4096 {
        return Err(Error::out_of_range("manifest.entry_count", entry_count as u64, 4096));
    }

    let mut store = BlobStore::new();
    let header_bytes = &input[..cur.position()];
    store.append(header_bytes);

    let mut entries = Vec::with_capacity(entry_count as usize);
    let mut pinned_first_name = None;

    for idx in 0..entry_count {
        let entry_start = cur.position();
        let kind_raw = cur.read_u16_le()?;
        let kind = PolicyKind::from_u16(kind_raw)?;
        let name_len = cur.read_u16_le()? as usize;
        if name_len > 512 {
            return Err(Error::out_of_range("entry.name_len", name_len as u64, 512));
        }
        let name_bytes = cur.read_bytes(name_len)?;
        let value_len = cur.read_u32_le()? as usize;
        if value_len > 1 << 20 {
            return Err(Error::out_of_range("entry.value_len", value_len as u64, 1 << 20));
        }
        let value_bytes = cur.read_bytes(value_len)?;

        let name_offset = store.len();
        store.append(name_bytes);
        let value_offset = store.len();
        store.append(value_bytes);

        if idx == 0 && flags.contains(ManifestFlags::ZERO_COPY) {
            // Fast path: pin first entry name for later normalize pass.
            pinned_first_name = store.capture_slice(name_offset, name_len);
        }

        let entry_end = cur.position();
        let span = entry_end - entry_start;
        if span > 0 && idx > 0 {
            let _ = span;
        }

        entries.push(ManifestEntry {
            kind,
            name_offset,
            name_len,
            value_offset,
            value_len,
        });
    }

    if flags.contains(ManifestFlags::REQUIRE_SORTED) {
        validate_sorted(&entries, &store)?;
    }

    Ok(Manifest {
        header: ManifestHeader {
            version,
            flags,
            entry_count,
        },
        store,
        entries,
        pinned_first_name,
    })
}

fn validate_sorted(entries: &[ManifestEntry], store: &BlobStore) -> Result<()> {
    let mut prev: Option<&str> = None;
    for entry in entries {
        let name = entry.name_str(store)?;
        if let Some(p) = prev {
            if name < p {
                return Err(Error::manifest_policy("entries not sorted by name"));
            }
        }
        prev = Some(name);
    }
    Ok(())
}

/// Encode a single policy entry into SMNF wire form.
pub fn encode_entry_wire(kind: PolicyKind, name: &str, value: &[u8]) -> Result<Vec<u8>> {
    if name.len() > 512 {
        return Err(Error::out_of_range("entry.name_len", name.len() as u64, 512));
    }
    if value.len() > 1 << 20 {
        return Err(Error::out_of_range("entry.value_len", value.len() as u64, 1 << 20));
    }
    core::str::from_utf8(name.as_bytes()).map_err(|_| Error::InvalidUtf8)?;
    let mut out = Vec::with_capacity(8 + name.len() + value.len());
    out.extend_from_slice(&(kind as u16).to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
    Ok(out)
}

/// Serialize a manifest header and entries into an owned byte vector.
pub fn encode_manifest(header: &ManifestHeader, entries: &[(PolicyKind, &str, &[u8])]) -> Result<Vec<u8>> {
    if entries.len() as u32 != header.entry_count {
        return Err(Error::invalid_structure("entry_count mismatch"));
    }
    let mut out = Vec::new();
    out.extend_from_slice(&MANIFEST_MAGIC);
    out.extend_from_slice(&header.version.to_le_bytes());
    out.extend_from_slice(&header.flags.bits().to_le_bytes());
    out.extend_from_slice(&header.entry_count.to_le_bytes());
    for (kind, name, value) in entries {
        out.extend_from_slice(&encode_entry_wire(*kind, name, value)?);
    }
    Ok(out)
}

/// Summarize manifest contents for verification logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestSummary {
    pub version: u32,
    pub flags: u32,
    pub entry_count: usize,
    pub syscall_allow: usize,
    pub syscall_deny: usize,
    pub fs_rules: usize,
    pub capabilities: usize,
}

impl ManifestSummary {
    pub fn from_manifest(manifest: &Manifest) -> Self {
        let mut summary = Self {
            version: manifest.header.version,
            flags: manifest.header.flags.bits(),
            entry_count: manifest.entry_count(),
            syscall_allow: 0,
            syscall_deny: 0,
            fs_rules: 0,
            capabilities: 0,
        };
        for entry in &manifest.entries {
            match entry.kind {
                PolicyKind::AllowSyscall => summary.syscall_allow += 1,
                PolicyKind::DenySyscall => summary.syscall_deny += 1,
                PolicyKind::AllowFsPath | PolicyKind::DenyFsPath => summary.fs_rules += 1,
                PolicyKind::Capability => summary.capabilities += 1,
                _ => {}
            }
        }
        summary
    }
}

/// Validate cross-entry invariants during parse (before normalize).
pub fn validate_manifest_invariants(manifest: &Manifest) -> Result<()> {
    if manifest.has_flag(ManifestFlags::STRICT_NAMES) {
        for entry in &manifest.entries {
            let name = entry.name_str(&manifest.store)?;
            validate_strict_name_prefix(name, entry.kind)?;
        }
    }
    if manifest.has_flag(ManifestFlags::REQUIRE_SORTED) {
        validate_sorted(&manifest.entries, &manifest.store)?;
    }
    let mut seen = alloc::vec::Vec::new();
    for entry in &manifest.entries {
        let name = entry.name_str(&manifest.store)?;
        if manifest.has_flag(ManifestFlags::DEDUPE_VALUES) {
            if seen.iter().any(|n: &alloc::string::String| n == name) {
                return Err(Error::manifest_policy("duplicate entry name"));
            }
            seen.push(alloc::string::String::from(name));
        }
        if entry.kind.expects_numeric_value() {
            let raw = entry.value_str(&manifest.store)?;
            if raw.parse::<u64>().is_err() {
                return Err(Error::manifest_policy("numeric kind requires integer value"));
            }
        }
    }
    Ok(())
}

fn validate_strict_name_prefix(name: &str, kind: PolicyKind) -> Result<()> {
    let prefix = kind.name_prefix();
    if !name.starts_with(prefix) {
        return Err(Error::manifest_policy("strict name prefix mismatch"));
    }
    Ok(())
}

/// Inspect raw bytes for a plausible SMNF header without full parse.
pub fn probe_manifest_header(input: &[u8]) -> Result<ManifestHeader> {
    if input.len() < 16 {
        return Err(Error::unexpected_eof());
    }
    if &input[0..4] != MANIFEST_MAGIC {
        return Err(Error::bad_magic("SMNF"));
    }
    let version = u32::from_le_bytes([input[4], input[5], input[6], input[7]]);
    let flags_raw = u32::from_le_bytes([input[8], input[9], input[10], input[11]]);
    let flags = ManifestFlags::from_bits(flags_raw)
        .ok_or_else(|| Error::invalid_structure("unknown manifest flags"))?;
    let entry_count = u32::from_le_bytes([input[12], input[13], input[14], input[15]]);
    Ok(ManifestHeader {
        version,
        flags,
        entry_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_entry(kind: u16, name: &str, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
        out
    }

    fn build_manifest(flags: u32, entries: &[(&str, u16, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MANIFEST_MAGIC);
        out.extend_from_slice(&MANIFEST_VERSION.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (name, kind, value) in entries {
            out.extend_from_slice(&encode_entry(*kind, name, value));
        }
        out
    }

    #[test]
    fn parses_single_entry() {
        let bytes = build_manifest(0, &[("limit.memory_mb", 3, b"256")]);
        let m = parse_manifest(&bytes).unwrap();
        assert_eq!(m.entry_count(), 1);
        assert_eq!(m.entries[0].value_str(&m.store).unwrap(), "256");
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = build_manifest(0, &[]);
        bytes[0] = b'X';
        assert!(parse_manifest(&bytes).is_err());
    }

    #[test]
    fn zero_copy_pins_first_name() {
        let flags = ManifestFlags::ZERO_COPY.bits();
        let bytes = build_manifest(flags, &[("alpha", 9, b"1"), ("beta", 9, b"2")]);
        let m = parse_manifest(&bytes).unwrap();
        assert!(m.pinned_first_name.is_some());
    }
}
