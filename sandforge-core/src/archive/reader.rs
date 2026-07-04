//! ARSF archive index and entry metadata.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::util::SliceCursor;

pub const ARCHIVE_MAGIC: [u8; 4] = *b"ARSF";
pub const MAX_ARCHIVE_FILES: u32 = 65535;
pub const MAX_NAME_LEN: u16 = 4096;
pub const MAX_FILE_SIZE: u64 = 1 << 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntry {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub data_offset: usize,
}

impl ArchiveEntry {
    pub fn name_bytes(&self) -> &[u8] {
        self.name.as_bytes()
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub fn ends_before(&self, boundary: u64) -> bool {
        self.offset.checked_add(self.size).is_some_and(|end| end <= boundary)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveIndex {
    pub file_count: u32,
    pub entries: Vec<ArchiveEntry>,
    pub payload_start: usize,
    pub total_size: usize,
}

impl ArchiveIndex {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, idx: usize) -> Option<&ArchiveEntry> {
        self.entries.get(idx)
    }

    pub fn find(&self, name: &str) -> Option<&ArchiveEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|e| e.name.as_str())
    }

    pub fn total_payload_bytes(&self) -> u64 {
        self.entries.iter().map(|e| e.size).sum()
    }
}

#[derive(Debug, Clone)]
pub struct ArchiveReader<'a> {
    data: &'a [u8],
    index: ArchiveIndex,
}

impl<'a> ArchiveReader<'a> {
    pub fn new(data: &'a [u8], index: ArchiveIndex) -> Self {
        Self { data, index }
    }

    pub fn index(&self) -> &ArchiveIndex {
        &self.index
    }

    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    pub fn entry_data(&self, entry: &ArchiveEntry) -> Result<&'a [u8]> {
        let start = entry.data_offset;
        let end = start
            .checked_add(entry.size as usize)
            .ok_or_else(|| Error::length_overflow("entry.data", entry.size, u64::MAX))?;
        if end > self.data.len() {
            return Err(Error::archive_layout("entry data extends past archive end"));
        }
        Ok(&self.data[start..end])
    }

    pub fn read_entry(&self, name: &str) -> Result<&'a [u8]> {
        let entry = self
            .index
            .find(name)
            .ok_or_else(|| Error::archive_layout("entry not found"))?;
        self.entry_data(entry)
    }
}

/// Parse an ARSF archive header and entry table.
pub fn parse_archive(input: &[u8]) -> Result<ArchiveReader<'_>> {
    let mut cur = SliceCursor::new(input);
    let magic = cur.read_exact(4)?;
    if magic != ARCHIVE_MAGIC {
        return Err(Error::BadMagic {
            expected: "ARSF",
            found: crate::error::magic_from_bytes([
                magic[0], magic[1], magic[2], magic[3],
            ]),
        });
    }

    let file_count = cur.read_u32_le()?;
    if file_count > MAX_ARCHIVE_FILES {
        return Err(Error::out_of_range(
            "archive.file_count",
            file_count as u64,
            MAX_ARCHIVE_FILES as u64,
        ));
    }

    let table_start = cur.position();
    let mut entries = Vec::with_capacity(file_count as usize);
    let mut rolling_offset: u64 = 0;

    for _ in 0..file_count {
        let name_len = cur.read_u16_le()?;
        if name_len == 0 {
            return Err(Error::archive_layout("empty entry name"));
        }
        if name_len > MAX_NAME_LEN {
            return Err(Error::out_of_range(
                "entry.name_len",
                name_len as u64,
                MAX_NAME_LEN as u64,
            ));
        }
        let name_bytes = cur.read_bytes(name_len as usize)?;
        let name = core::str::from_utf8(name_bytes)
            .map_err(|_| Error::InvalidUtf8)?
            .to_string();

        let offset = cur.read_u64_le()?;
        let size = cur.read_u64_le()?;

        if size > MAX_FILE_SIZE {
            return Err(Error::out_of_range(
                "entry.size",
                size,
                MAX_FILE_SIZE,
            ));
        }

        if offset != rolling_offset {
            return Err(Error::archive_layout("non-contiguous entry offset"));
        }

        entries.push(ArchiveEntry {
            name,
            offset,
            size,
            data_offset: 0,
        });

        rolling_offset = rolling_offset
            .checked_add(size)
            .ok_or_else(|| Error::length_overflow("rolling_offset", size, u64::MAX))?;
    }

    let payload_start = cur.position();
    let total_size = input.len();

    if payload_start
        .checked_add(rolling_offset as usize)
        .is_none_or(|need| need > total_size)
    {
        return Err(Error::archive_layout("payload truncated"));
    }

    let mut data_cursor = payload_start;
    for entry in &mut entries {
        entry.data_offset = data_cursor;
        data_cursor = data_cursor
            .checked_add(entry.size as usize)
            .ok_or_else(|| Error::length_overflow("data_cursor", entry.size, u64::MAX))?;
    }

    validate_unique_names(&entries)?;
    validate_no_overlap(&entries, rolling_offset)?;

    let index = ArchiveIndex {
        file_count,
        entries,
        payload_start,
        total_size,
    };

    let _ = table_start;
    Ok(ArchiveReader::new(input, index))
}

fn validate_unique_names(entries: &[ArchiveEntry]) -> Result<()> {
    for (i, a) in entries.iter().enumerate() {
        for b in entries.iter().skip(i + 1) {
            if a.name == b.name {
                return Err(Error::archive_layout("duplicate entry name"));
            }
        }
    }
    Ok(())
}

fn validate_no_overlap(entries: &[ArchiveEntry], total_payload: u64) -> Result<()> {
    let mut end: u64 = 0;
    for entry in entries {
        if entry.offset != end {
            return Err(Error::archive_layout("entry overlap detected"));
        }
        end = end
            .checked_add(entry.size)
            .ok_or_else(|| Error::length_overflow("overlap.end", entry.size, u64::MAX))?;
    }
    if end != total_payload {
        return Err(Error::archive_layout("payload size mismatch"));
    }
    Ok(())
}

/// Statistics gathered while scanning an archive index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveStats {
    pub file_count: u32,
    pub total_payload: u64,
    pub largest_entry: u64,
    pub smallest_entry: u64,
    pub average_size: u64,
}

impl ArchiveStats {
    pub fn from_index(index: &ArchiveIndex) -> Self {
        let mut largest = 0u64;
        let mut smallest = u64::MAX;
        let total = index.total_payload_bytes();
        for entry in &index.entries {
            largest = largest.max(entry.size);
            if entry.size > 0 {
                smallest = smallest.min(entry.size);
            }
        }
        if index.is_empty() {
            smallest = 0;
        }
        let average = if index.is_empty() {
            0
        } else {
            total / index.len() as u64
        };
        Self {
            file_count: index.file_count,
            total_payload: total,
            largest_entry: largest,
            smallest_entry: smallest,
            average_size: average,
        }
    }
}

/// Iterate archive entries in table order.
pub struct ArchiveIter<'a> {
    reader: &'a ArchiveReader<'a>,
    pos: usize,
}

impl<'a> ArchiveIter<'a> {
    pub fn new(reader: &'a ArchiveReader<'a>) -> Self {
        Self { reader, pos: 0 }
    }
}

impl<'a> Iterator for ArchiveIter<'a> {
    type Item = Result<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.reader.index();
        if self.pos >= index.len() {
            return None;
        }
        let entry = &index.entries[self.pos];
        self.pos += 1;
        Some(self.reader.entry_data(entry))
    }
}

/// Verify archive layout and return index statistics.
pub fn parse_archive_with_stats(input: &[u8]) -> Result<(ArchiveReader<'_>, ArchiveStats)> {
    let reader = parse_archive(input)?;
    let stats = ArchiveStats::from_index(reader.index());
    Ok((reader, stats))
}

/// Check whether input begins with the ARSF magic without full parse.
pub fn is_archive(input: &[u8]) -> bool {
    input.len() >= 4 && &input[0..4] == ARCHIVE_MAGIC
}

/// Validate archive member names against sandbox path rules.
pub fn validate_archive_names(index: &ArchiveIndex) -> Result<()> {
    for entry in &index.entries {
        if entry.name.contains("..") {
            return Err(Error::archive_layout("path traversal in member name"));
        }
        if entry.name.starts_with('/') || entry.name.contains('\\') {
            return Err(Error::archive_layout("absolute or windows path in member"));
        }
        if entry.name.len() > 512 {
            return Err(Error::archive_layout("member name too long"));
        }
    }
    Ok(())
}

/// Build an ARSF archive from named member payloads.
pub fn build_archive(files: &[(&str, &[u8])]) -> Result<Vec<u8>> {
    if files.len() > MAX_ARCHIVE_FILES as usize {
        return Err(Error::out_of_range(
            "archive.file_count",
            files.len() as u64,
            MAX_ARCHIVE_FILES as u64,
        ));
    }
    let mut out = Vec::new();
    out.extend_from_slice(&ARCHIVE_MAGIC);
    out.extend_from_slice(&(files.len() as u32).to_le_bytes());
    let mut offset: u64 = 0;
    for (name, data) in files {
        if name.is_empty() || name.len() > MAX_NAME_LEN as usize {
            return Err(Error::archive_layout("invalid member name"));
        }
        if data.len() as u64 > MAX_FILE_SIZE {
            return Err(Error::out_of_range(
                "entry.size",
                data.len() as u64,
                MAX_FILE_SIZE,
            ));
        }
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        offset = offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| Error::length_overflow("build.offset", data.len() as u64, u64::MAX))?;
    }
    for (_, data) in files {
        out.extend_from_slice(data);
    }
    Ok(out)
}

/// Round-trip check: build then parse.
pub fn verify_archive_builder(files: &[(&str, &[u8])]) -> Result<ArchiveStats> {
    let bytes = build_archive(files)?;
    let (_, stats) = parse_archive_with_stats(&bytes)?;
    Ok(stats)
}

#[cfg(test)]
mod tests {
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
    fn parses_single_file_archive() {
        let bytes = build_archive(&[("module.wasm", b"\0asm")]);
        let reader = parse_archive(&bytes).unwrap();
        assert_eq!(reader.index().len(), 1);
        assert_eq!(reader.read_entry("module.wasm").unwrap(), b"\0asm");
    }

    #[test]
    fn rejects_duplicate_names() {
        let bytes = build_archive(&[("a.txt", b"1"), ("a.txt", b"2")]);
        assert!(parse_archive(&bytes).is_err());
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = build_archive(&[]);
        bytes[0] = b'X';
        assert!(parse_archive(&bytes).is_err());
    }
}
