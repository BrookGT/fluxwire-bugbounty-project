//! ELF64 parsing and validation for sandbox artifact inspection.

mod header;
mod notes;
mod program;
mod section;

use alloc::string::String;
use alloc::vec::Vec;

pub use header::{
    parse_file_header, parse_ident, FileHeader, Ident, EM_AARCH64, EM_RISCV, EM_X86_64, ET_DYN,
    ET_EXEC, ET_REL, ELFCLASS64,
};
pub use notes::{collect_build_ids, parse_notes_from_program, parse_notes_from_sections, Note};
pub use program::{parse_program_headers, ProgramHeader, PT_LOAD, PT_NOTE};
pub use section::{
    parse_section_headers, read_section_names, section_payload, SectionHeader, SHT_PROGBITS,
    SHT_DYNSYM, SHT_SYMTAB,
};

use crate::error::Result;
use crate::util::SliceCursor;

use header::validate_header;
use notes::validate_notes;
use program::validate_program_headers;
use section::validate_section_headers;

/// Fully parsed ELF64 image with derived metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfImage {
    pub raw_len: usize,
    pub header: FileHeader,
    pub program_headers: Vec<ProgramHeader>,
    pub section_headers: Vec<SectionHeader>,
    pub section_names: Vec<String>,
    pub notes: Vec<Note>,
    pub build_ids: Vec<String>,
}

impl ElfImage {
    pub fn is_executable(&self) -> bool {
        self.header.typ == ET_EXEC || self.header.typ == ET_DYN
    }

    pub fn machine(&self) -> u16 {
        self.header.machine
    }

    pub fn entry_point(&self) -> u64 {
        self.header.entry
    }

    pub fn has_build_id(&self) -> bool {
        !self.build_ids.is_empty()
    }

    pub fn load_segments(&self) -> impl Iterator<Item = &ProgramHeader> {
        self.program_headers.iter().filter(|p| p.is_load())
    }

    pub fn find_section<'a>(&'a self, name: &str) -> Option<&'a SectionHeader> {
        section::find_section_by_name(&self.section_names, &self.section_headers, name)
    }

    pub fn section_data<'a>(&'a self, data: &'a [u8], name: &str) -> Result<&'a [u8]> {
        let sh = self
            .find_section(name)
            .ok_or(crate::error::Error::structure("section not found"))?;
        section_payload(data, sh)
    }
}

/// Parse ELF64 ident, header, program headers, section headers, and notes.
pub fn parse_elf(data: &[u8]) -> Result<ElfImage> {
    if data.len() < 64 {
        return Err(crate::error::Error::UnexpectedEof);
    }
    let mut cur = SliceCursor::new(data);
    let ident = parse_ident(&mut cur)?;
    if !ident.is_64bit() {
        return Err(crate::error::Error::Unsupported {
            what: "ELF class",
            detail: ident.class as u32,
        });
    }
    let header = parse_file_header(data, &ident)?;
    let program_headers = parse_program_headers(data, &header)?;
    let section_headers = parse_section_headers(data, &header)?;
    let section_names = if section_headers.is_empty() {
        Vec::new()
    } else {
        read_section_names(data, &section_headers, header.shstrndx)?
    };

    let mut notes = parse_notes_from_program(data, &header, &program_headers)?;
    let mut sec_notes = parse_notes_from_sections(data, &header, &section_headers)?;
    notes.append(&mut sec_notes);

    let build_ids = collect_build_ids(&notes);

    Ok(ElfImage {
        raw_len: data.len(),
        header,
        program_headers,
        section_headers,
        section_names,
        notes,
        build_ids,
    })
}

/// Parse and apply structural validation rules suitable for sandbox intake.
pub fn parse_and_validate(data: &[u8]) -> Result<ElfImage> {
    let image = parse_elf(data)?;
    validate_header(&image.header, data.len())?;
    validate_program_headers(&image.program_headers, data.len())?;
    validate_section_headers(&image.section_headers, data.len())?;
    validate_notes(&image.notes)?;
    if image.header.ehsize as usize > data.len() {
        return Err(crate::error::Error::validation("ehsize"));
    }
    Ok(image)
}

/// Summarize an ELF image for logging (ASCII only).
pub fn summarize(image: &ElfImage) -> String {
    let mut s = String::new();
    s.push_str("ELF64 ");
    s.push_str(header::machine_name(image.header.machine));
    s.push(' ');
    s.push_str(header::type_name(image.header.typ));
    s.push_str(" entry=0x");
    push_hex_u64(&mut s, image.header.entry);
    s.push_str(" phdrs=");
    push_decimal(&mut s, image.program_headers.len() as u64);
    s.push_str(" shdrs=");
    push_decimal(&mut s, image.section_headers.len() as u64);
    if image.has_build_id() {
        s.push_str(" build_id=");
        s.push_str(&image.build_ids[0]);
    }
    s
}

fn push_hex_u64(s: &mut String, v: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    s.push('0');
    s.push('x');
    let mut started = false;
    for i in (0..16).rev() {
        let nibble = ((v >> (i * 4)) & 0xf) as usize;
        if nibble != 0 || started || i == 0 {
            s.push(HEX[nibble] as char);
            started = true;
        }
    }
}

fn push_decimal(s: &mut String, mut v: u64) {
    if v == 0 {
        s.push('0');
        return;
    }
    let mut digits = [0u8; 20];
    let mut len = 0usize;
    while v > 0 {
        digits[len] = (v % 10) as u8 + b'0';
        len += 1;
        v /= 10;
    }
    while len > 0 {
        len -= 1;
        s.push(digits[len] as char);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::header::{ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3, ELFDATA2LSB, EV_CURRENT};

    fn tiny_elf() -> Vec<u8> {
        let mut v = vec![0u8; 512];
        v[0] = ELFMAG0;
        v[1] = ELFMAG1;
        v[2] = ELFMAG2;
        v[3] = ELFMAG3;
        v[4] = ELFCLASS64;
        v[5] = ELFDATA2LSB;
        v[6] = EV_CURRENT;
        v[0x10] = ET_DYN as u8;
        v[0x12] = 62;
        v[0x14] = 1;
        v[0x28] = 0x40;
        v[0x3a] = 0x40;
        v
    }

    #[test]
    fn parse_minimal() {
        let data = tiny_elf();
        let img = parse_elf(&data).unwrap();
        assert_eq!(img.header.machine, EM_X86_64);
        assert!(img.section_headers.is_empty());
    }

    #[test]
    fn validate_minimal() {
        let data = tiny_elf();
        assert!(parse_and_validate(&data).is_ok());
    }

    #[test]
    fn summarize_ascii() {
        let data = tiny_elf();
        let img = parse_elf(&data).unwrap();
        let sum = summarize(&img);
        assert!(sum.is_ascii());
        assert!(sum.contains("x86-64"));
    }
}
