//! ARSF sandbox artifact archive handling.

mod extract;
mod reader;

pub use extract::{extract_all, extract_and_classify, ArchiveClassification, ExtractedFile, ExtractionReport};
pub use reader::{
    build_archive, parse_archive, parse_archive_with_stats, ArchiveEntry, ArchiveIndex,
    ArchiveReader, ArchiveStats, is_archive,
};
