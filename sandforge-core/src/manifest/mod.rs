//! Sandbox policy manifest parsing and normalization.

mod envelope;
mod normalize;

pub use envelope::{
    encode_manifest, parse_manifest, probe_manifest_header, Manifest, ManifestEntry, ManifestFlags,
    ManifestHeader, ManifestSummary, PolicyKind, validate_manifest_invariants,
};
pub use normalize::{
    diff_normalized, export_normalized, lookup_policy, merge_normalized, parse_and_normalize,
    ManifestDiff, NormalizedEntry, NormalizedManifest,
};
