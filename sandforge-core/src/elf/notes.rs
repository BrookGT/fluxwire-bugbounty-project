//! ELF note segment parsing (PT_NOTE and SHT_NOTE).

use alloc::string::String;
use alloc::vec::Vec;

use crate::elf::header::FileHeader;
use crate::elf::program::{ProgramHeader, PT_NOTE};
use crate::elf::section::{section_payload, SectionHeader, SHT_NOTE};
use crate::error::{Error, Result};
use crate::util::{check_bounds, SliceCursor};

pub const NT_GNU_ABI_TAG: u32 = 1;
pub const NT_GNU_BUILD_ID: u32 = 3;
pub const NT_GNU_GOLD_VERSION: u32 = 4;

pub const ELF_NOTE_OS_LINUX: u32 = 0;
pub const ELF_NOTE_OS_GNU: u32 = 1;
pub const ELF_NOTE_OS_SOLARIS: u32 = 2;
pub const ELF_NOTE_OS_FREEBSD: u32 = 3;

/// A single note descriptor inside a note segment or section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub namesz: u32,
    pub descsz: u32,
    pub typ: u32,
    pub name: Vec<u8>,
    pub desc: Vec<u8>,
}

impl Note {
    pub fn name_str(&self) -> Option<&str> {
        if self.name.is_empty() {
            return None;
        }
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(self.name.len());
        core::str::from_utf8(&self.name[..end]).ok()
    }

    pub fn is_gnu(&self) -> bool {
        self.name_str() == Some("GNU")
    }

    pub fn build_id_hex(&self) -> Option<String> {
        if self.typ != NT_GNU_BUILD_ID || !self.is_gnu() {
            return None;
        }
        let mut s = String::with_capacity(self.desc.len() * 2);
        for b in &self.desc {
            push_hex_byte(&mut s, *b);
        }
        Some(s)
    }
}

fn push_hex_byte(s: &mut String, b: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    s.push(HEX[(b >> 4) as usize] as char);
    s.push(HEX[(b & 0xf) as usize] as char);
}

fn align4(n: u32) -> u32 {
    (n + 3) & !3
}

pub fn parse_note(data: &[u8], little_endian: bool) -> Result<Note> {
    if data.len() < 12 {
        return Err(Error::UnexpectedEof);
    }
    let mut cur = SliceCursor::new(data);
    let namesz = if little_endian {
        cur.read_u32_le()?
    } else {
        cur.read_u32_be()?
    };
    let descsz = if little_endian {
        cur.read_u32_le()?
    } else {
        cur.read_u32_be()?
    };
    let typ = if little_endian {
        cur.read_u32_le()?
    } else {
        cur.read_u32_be()?
    };

    let name_len = align4(namesz);
    let desc_len = align4(descsz);
    let total = 12u64
        .checked_add(name_len as u64)
        .and_then(|v| v.checked_add(desc_len as u64))
        .ok_or(Error::UnexpectedEof)?;
    if total as usize > data.len() {
        return Err(Error::UnexpectedEof);
    }

    let name = cur.read_vec(name_len as usize)?;
    let desc = cur.read_vec(desc_len as usize)?;
    let name = name[..namesz as usize].to_vec();
    let desc = desc[..descsz as usize].to_vec();

    Ok(Note {
        namesz,
        descsz,
        typ,
        name,
        desc,
    })
}

pub fn parse_notes_blob(blob: &[u8], little_endian: bool) -> Result<Vec<Note>> {
    let mut notes = Vec::new();
    let mut offset = 0usize;
    while offset + 12 <= blob.len() {
        let slice = &blob[offset..];
        let note = parse_note(slice, little_endian)?;
        let consumed = 12 + align4(note.namesz) as usize + align4(note.descsz) as usize;
        if consumed == 0 {
            break;
        }
        offset = offset
            .checked_add(consumed)
            .ok_or(Error::UnexpectedEof)?;
        notes.push(note);
    }
    Ok(notes)
}

pub fn parse_notes_from_program(
    data: &[u8],
    hdr: &FileHeader,
    phdrs: &[ProgramHeader],
) -> Result<Vec<Note>> {
    let le = hdr.ident.is_little_endian();
    let mut all = Vec::new();
    for ph in phdrs {
        if ph.typ != PT_NOTE || ph.filesz == 0 {
            continue;
        }
        check_bounds("note segment", ph.offset, ph.filesz, data.len())?;
        let start = ph.offset as usize;
        let end = start + ph.filesz as usize;
        let mut notes = parse_notes_blob(&data[start..end], le)?;
        all.append(&mut notes);
    }
    Ok(all)
}

pub fn parse_notes_from_sections(
    data: &[u8],
    hdr: &FileHeader,
    shdrs: &[SectionHeader],
) -> Result<Vec<Note>> {
    let le = hdr.ident.is_little_endian();
    let mut all = Vec::new();
    for sh in shdrs {
        if sh.typ != SHT_NOTE {
            continue;
        }
        let payload = section_payload(data, sh)?;
        if payload.is_empty() {
            continue;
        }
        let mut notes = parse_notes_blob(payload, le)?;
        all.append(&mut notes);
    }
    Ok(all)
}

pub fn parse_gnu_abi_tag(note: &Note) -> Result<(u32, u32, u32)> {
    if note.typ != NT_GNU_ABI_TAG || !note.is_gnu() {
        return Err(Error::structure("not GNU ABI tag note"));
    }
    if note.desc.len() < 16 {
        return Err(Error::UnexpectedEof);
    }
    let mut cur = SliceCursor::new(&note.desc);
    let os = cur.read_u32_le()?;
    let major = cur.read_u32_le()?;
    let minor = cur.read_u32_le()?;
    Ok((os, major, minor))
}

pub fn abi_os_name(os: u32) -> &'static str {
    match os {
        ELF_NOTE_OS_LINUX => "Linux",
        ELF_NOTE_OS_GNU => "GNU",
        ELF_NOTE_OS_SOLARIS => "Solaris",
        ELF_NOTE_OS_FREEBSD => "FreeBSD",
        _ => "unknown",
    }
}

pub fn note_type_name(typ: u32, vendor_gnu: bool) -> &'static str {
    if vendor_gnu {
        return match typ {
            NT_GNU_ABI_TAG => "NT_GNU_ABI_TAG",
            NT_GNU_BUILD_ID => "NT_GNU_BUILD_ID",
            NT_GNU_GOLD_VERSION => "NT_GNU_GOLD_VERSION",
            _ => "GNU_UNKNOWN",
        };
    }
    "NOTE"
}

pub fn collect_build_ids(notes: &[Note]) -> Vec<String> {
    notes
        .iter()
        .filter_map(|n| n.build_id_hex())
        .collect()
}

pub fn validate_notes(notes: &[Note]) -> Result<()> {
    for note in notes {
        if note.namesz > 4096 || note.descsz > 1_048_576 {
            return Err(Error::validation("note size cap"));
        }
        if note.namesz > 0 && note.name.is_empty() {
            return Err(Error::validation("note name empty"));
        }
        if note.typ == NT_GNU_ABI_TAG && note.is_gnu() {
            parse_gnu_abi_tag(note)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_note_blob() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&4u32.to_le_bytes());
        v.extend_from_slice(&4u32.to_le_bytes());
        v.extend_from_slice(&NT_GNU_ABI_TAG.to_le_bytes());
        v.extend_from_slice(b"GNU\0");
        v.extend_from_slice(&ELF_NOTE_OS_LINUX.to_le_bytes());
        v.extend_from_slice(&2u32.to_le_bytes());
        v.extend_from_slice(&34u32.to_le_bytes());
        v
    }

    #[test]
    fn parse_gnu_abi() {
        let blob = sample_note_blob();
        let notes = parse_notes_blob(&blob, true).unwrap();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].is_gnu());
        let (os, maj, min) = parse_gnu_abi_tag(&notes[0]).unwrap();
        assert_eq!(os, ELF_NOTE_OS_LINUX);
        assert_eq!(maj, 2);
        assert_eq!(min, 34);
    }

    #[test]
    fn build_id_hex() {
        let note = Note {
            namesz: 3,
            descsz: 3,
            typ: NT_GNU_BUILD_ID,
            name: b"GNU\0".to_vec(),
            desc: vec![0xab, 0xcd, 0xef],
        };
        assert_eq!(note.build_id_hex().unwrap(), "abcdef");
    }
}
