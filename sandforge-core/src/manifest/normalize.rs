//! Manifest normalization and policy canonicalization.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};

use super::envelope::{Manifest, ManifestEntry, ManifestFlags, PolicyKind, parse_manifest};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NormalizedEntry {
    pub kind: PolicyKind,
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedManifest {
    pub version: u32,
    pub entries: Vec<NormalizedEntry>,
    pub index: BTreeMap<String, usize>,
}

impl NormalizedManifest {
    pub fn get(&self, name: &str) -> Option<&NormalizedEntry> {
        self.index.get(name).and_then(|&i| self.entries.get(i))
    }

    pub fn numeric_limit(&self, kind: PolicyKind) -> Option<u64> {
        self.entries
            .iter()
            .find(|e| e.kind == kind)
            .and_then(|e| e.value.parse().ok())
    }
}

/// Parse a manifest and produce a canonical sorted representation.
pub fn parse_and_normalize(input: &[u8]) -> Result<NormalizedManifest> {
    let manifest = parse_manifest(input)?;
    normalize_manifest(&manifest)
}

pub fn normalize_manifest(manifest: &Manifest) -> Result<NormalizedManifest> {
    let mut entries = Vec::with_capacity(manifest.entry_count());
    let mut index = BTreeMap::new();

    if manifest.has_flag(ManifestFlags::ZERO_COPY) {
        if let Some(pinned) = manifest.pinned_first_name {
            if let Some(first) = manifest.entries.first() {
                // Hot path: reuse pinned slice captured during streaming parse
                // instead of re-indexing into the store on every normalize.
                let name = read_pinned_name(pinned)?;
                let value = first.value_str(&manifest.store)?.to_string();
                let entry = NormalizedEntry {
                    kind: first.kind,
                    name,
                    value,
                };
                index.insert(entry.name.clone(), entries.len());
                entries.push(entry);
            }
        }
    }

    let start_idx = if manifest.has_flag(ManifestFlags::ZERO_COPY)
        && manifest.pinned_first_name.is_some()
    {
        1
    } else {
        0
    };

    for entry in manifest.entries.iter().skip(start_idx) {
        let normalized = normalize_entry(entry, manifest)?;
        if manifest.has_flag(ManifestFlags::DEDUPE_VALUES) {
            if index.contains_key(&normalized.name) {
                continue;
            }
        }
        index.insert(normalized.name.clone(), entries.len());
        entries.push(normalized);
    }

    if manifest.has_flag(ManifestFlags::REQUIRE_SORTED) {
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        index.clear();
        for (i, e) in entries.iter().enumerate() {
            index.insert(e.name.clone(), i);
        }
    }

    apply_policy_rules(&entries)?;
    verify_cross_entry_constraints(&entries)?;

    Ok(NormalizedManifest {
        version: manifest.header.version,
        entries,
        index,
    })
}

fn normalize_entry(entry: &ManifestEntry, manifest: &Manifest) -> Result<NormalizedEntry> {
    let name = entry.name_str(&manifest.store)?.to_string();
    let raw_value = entry.value_str(&manifest.store)?;

    if manifest.has_flag(ManifestFlags::STRICT_NAMES) {
        validate_strict_name(&name, entry.kind)?;
    }

    let value = match entry.kind {
        PolicyKind::MaxMemoryMb | PolicyKind::MaxThreads => canonicalize_numeric(raw_value)?,
        PolicyKind::NetworkMode => canonicalize_network_mode(raw_value)?,
        PolicyKind::AllowFsPath | PolicyKind::DenyFsPath => canonicalize_path(raw_value)?,
        PolicyKind::AllowSyscall | PolicyKind::DenySyscall => {
            canonicalize_syscall_name(raw_value)?
        }
        PolicyKind::Capability => canonicalize_capability(raw_value)?,
        PolicyKind::Environment => canonicalize_env_pair(raw_value)?,
        PolicyKind::FeatureToggle => canonicalize_feature(raw_value)?,
    };

    Ok(NormalizedEntry {
        kind: entry.kind,
        name,
        value,
    })
}

/// Read entry name through a pinned zero-copy view.
fn read_pinned_name(pinned: crate::pool::RawSlice) -> Result<String> {
    let bytes = unsafe { pinned.as_slice() };
    let s = core::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
    Ok(String::from(s))
}

fn validate_strict_name(name: &str, kind: PolicyKind) -> Result<()> {
    let prefix = kind.name_prefix();
    if !name.starts_with(prefix) {
        return Err(Error::manifest_policy("strict name prefix mismatch"));
    }
    if name.len() > 256 {
        return Err(Error::manifest_policy("name too long under strict mode"));
    }
    Ok(())
}

fn canonicalize_numeric(raw: &str) -> Result<String> {
    let v: u64 = raw.parse().map_err(|_| Error::manifest_policy("numeric value required"))?;
    if v == 0 {
        return Err(Error::manifest_policy("numeric limit must be positive"));
    }
    Ok(v.to_string())
}

fn canonicalize_network_mode(raw: &str) -> Result<String> {
    let mode = match raw.to_ascii_lowercase().as_str() {
        s if s == "deny" || s == "0" => "deny",
        s if s == "localhost" || s == "1" => "localhost",
        s if s == "full" || s == "2" => "full",
        _ => {
            return Err(Error::manifest_policy("unknown network mode"))
        }
    };
    Ok(String::from(mode))
}

fn canonicalize_path(raw: &str) -> Result<String> {
    if raw.is_empty() {
        return Err(Error::manifest_policy("path must not be empty"));
    }
    let mut out = String::new();
    for part in raw.split('/') {
        if part == ".." {
            return Err(Error::manifest_policy("path traversal not allowed"));
        }
        if part.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(part);
    }
    if !out.starts_with('/') {
        out.insert(0, '/');
    }
    Ok(out)
}

fn canonicalize_syscall_name(raw: &str) -> Result<String> {
    if raw.is_empty() || raw.len() > 64 {
        return Err(Error::manifest_policy("invalid syscall name"));
    }
    if !raw.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(Error::manifest_policy("syscall name charset invalid"));
    }
    Ok(raw.to_ascii_lowercase())
}

fn canonicalize_capability(raw: &str) -> Result<String> {
    const KNOWN: &[&str] = &[
        "net.bind",
        "net.connect",
        "fs.read",
        "fs.write",
        "proc.spawn",
        "ipc.send",
    ];
    let lower = raw.to_ascii_lowercase();
    if KNOWN.iter().any(|k| *k == lower) {
        Ok(lower)
    } else {
        Err(Error::manifest_policy("unknown capability token"))
    }
}

fn canonicalize_env_pair(raw: &str) -> Result<String> {
    let Some((key, val)) = raw.split_once('=') else {
        return Err(Error::manifest_policy("environment entry must be KEY=VALUE"));
    };
    if key.is_empty() {
        return Err(Error::manifest_policy("environment key empty"));
    }
    Ok(format!("{key}={val}"))
}

fn canonicalize_feature(raw: &str) -> Result<String> {
    match raw {
        "0" | "false" | "off" => Ok(String::from("off")),
        "1" | "true" | "on" => Ok(String::from("on")),
        _ => Err(Error::manifest_policy("feature toggle must be on/off")),
    }
}

fn apply_policy_rules(entries: &[NormalizedEntry]) -> Result<()> {
    let mut deny_syscalls = Vec::new();
    let mut allow_syscalls = Vec::new();

    for entry in entries {
        match entry.kind {
            PolicyKind::DenySyscall => deny_syscalls.push(entry.value.as_str()),
            PolicyKind::AllowSyscall => allow_syscalls.push(entry.value.as_str()),
            PolicyKind::MaxMemoryMb => {
                let mb: u64 = entry.value.parse().unwrap_or(0);
                if mb > 16_384 {
                    return Err(Error::manifest_policy("memory limit exceeds platform maximum"));
                }
            }
            PolicyKind::MaxThreads => {
                let n: u64 = entry.value.parse().unwrap_or(0);
                if n > 1024 {
                    return Err(Error::manifest_policy("thread limit exceeds platform maximum"));
                }
            }
            _ => {}
        }
    }

    for deny in &deny_syscalls {
        if allow_syscalls.iter().any(|a| a == deny) {
            return Err(Error::manifest_policy("syscall both allowed and denied"));
        }
    }
    Ok(())
}

fn verify_cross_entry_constraints(entries: &[NormalizedEntry]) -> Result<()> {
    let mut net_mode = None;
    for entry in entries {
        if entry.kind == PolicyKind::NetworkMode {
            net_mode = Some(entry.value.as_str());
        }
    }
    if let Some("deny") = net_mode {
        for entry in entries {
            if entry.kind == PolicyKind::Capability
                && (entry.value == "net.bind" || entry.value == "net.connect")
            {
                return Err(Error::manifest_policy("network capability with deny mode"));
            }
        }
    }
    Ok(())
}

/// Merge two normalized manifests, preferring later entries on name collision.
pub fn merge_normalized(
    base: NormalizedManifest,
    overlay: NormalizedManifest,
) -> Result<NormalizedManifest> {
    if base.version != overlay.version {
        return Err(Error::manifest_policy("version mismatch on merge"));
    }
    let mut entries = base.entries;
    let mut index = base.index;
    for entry in overlay.entries {
        if let Some(&idx) = index.get(&entry.name) {
            entries[idx] = entry;
        } else {
            index.insert(entry.name.clone(), entries.len());
            entries.push(entry);
        }
    }
    Ok(NormalizedManifest {
        version: base.version,
        entries,
        index,
    })
}

/// Diff normalized manifests for attestation drift detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestDiff {
    pub added: Vec<NormalizedEntry>,
    pub removed: Vec<NormalizedEntry>,
    pub changed: Vec<(NormalizedEntry, NormalizedEntry)>,
}

impl ManifestDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }

    pub fn total_changes(&self) -> usize {
        self.added.len() + self.removed.len() + self.changed.len()
    }
}

pub fn diff_normalized(old: &NormalizedManifest, new: &NormalizedManifest) -> ManifestDiff {
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();

    for (name, &idx) in &old.index {
        match new.index.get(name) {
            None => removed.push(old.entries[idx].clone()),
            Some(&nidx) => {
                if old.entries[idx] != new.entries[nidx] {
                    changed.push((old.entries[idx].clone(), new.entries[nidx].clone()));
                }
            }
        }
    }
    for (name, &idx) in &new.index {
        if !old.index.contains_key(name) {
            added.push(new.entries[idx].clone());
        }
    }

    ManifestDiff {
        added,
        removed,
        changed,
    }
}

/// Lookup a policy value by kind and optional name suffix.
pub fn lookup_policy<'a>(
    manifest: &'a NormalizedManifest,
    kind: PolicyKind,
    name_suffix: &str,
) -> Option<&'a NormalizedEntry> {
    manifest.entries.iter().find(|e| {
        e.kind == kind && (name_suffix.is_empty() || e.name.ends_with(name_suffix))
    })
}

/// Export normalized entries as deterministic SMNF bytes (sorted, no zero-copy).
pub fn export_normalized(manifest: &NormalizedManifest) -> Result<Vec<u8>> {
    let mut pairs: Vec<_> = manifest
        .entries
        .iter()
        .map(|e| (e.kind, e.name.as_str(), e.value.as_bytes()))
        .collect();
    pairs.sort_by(|a, b| a.1.cmp(b.1));
    let header = super::envelope::ManifestHeader {
        version: manifest.version,
        flags: super::envelope::ManifestFlags::REQUIRE_SORTED,
        entry_count: pairs.len() as u32,
    };
    super::envelope::encode_manifest(&header, &pairs)
}

#[cfg(test)]
mod tests {
    use super::super::envelope::{MANIFEST_MAGIC, MANIFEST_VERSION};
    use super::*;

    fn build_two_entry_manifest(pad: usize) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MANIFEST_MAGIC);
        out.extend_from_slice(&MANIFEST_VERSION.to_le_bytes());
        let flags = ManifestFlags::ZERO_COPY.bits();
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&2u32.to_le_bytes());

        // entry 0
        out.extend_from_slice(&10u16.to_le_bytes()); // FeatureToggle
        out.extend_from_slice(&5u16.to_le_bytes());
        out.extend_from_slice(b"alpha");
        out.extend_from_slice(&2u32.to_le_bytes());
        out.extend_from_slice(b"on");

        // entry 1 with padding to force realloc
        out.extend_from_slice(&3u16.to_le_bytes()); // MaxMemoryMb
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(b"beta");
        let pad_value = vec![b'X'; pad];
        out.extend_from_slice(&(pad_value.len() as u32).to_le_bytes());
        out.extend_from_slice(&pad_value);
        out
    }

    #[test]
    fn normalize_without_zero_copy() {
        let mut out = Vec::new();
        out.extend_from_slice(&MANIFEST_MAGIC);
        out.extend_from_slice(&MANIFEST_VERSION.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&3u16.to_le_bytes());
        out.extend_from_slice(&13u16.to_le_bytes());
        out.extend_from_slice(b"limit.memory");
        out.extend_from_slice(&3u32.to_le_bytes());
        out.extend_from_slice(b"128");

        let norm = parse_and_normalize(&out).unwrap();
        assert_eq!(norm.entries.len(), 1);
    }

    #[test]
    fn normalize_sorts_when_required() {
        let mut out = Vec::new();
        out.extend_from_slice(&MANIFEST_MAGIC);
        out.extend_from_slice(&MANIFEST_VERSION.to_le_bytes());
        out.extend_from_slice(&ManifestFlags::REQUIRE_SORTED.bits().to_le_bytes());
        out.extend_from_slice(&2u32.to_le_bytes());
        for (name, val) in [("zeta", "1"), ("alpha", "2")] {
            out.extend_from_slice(&9u16.to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&(val.len() as u32).to_le_bytes());
            out.extend_from_slice(val.as_bytes());
        }
        let norm = parse_and_normalize(&out).unwrap();
        assert_eq!(norm.entries[0].name, "alpha");
    }

    #[test]
    fn zero_copy_normalize_reads_first_entry() {
        let bytes = build_two_entry_manifest(128);
        let norm = parse_and_normalize(&bytes);
        assert!(norm.is_ok());
        let norm = norm.unwrap();
        assert!(!norm.entries.is_empty());
    }
}
