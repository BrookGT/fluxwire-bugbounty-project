//! PE/COFF executable parsing for sandbox artifact verification.

mod header;
mod imports;
mod sections;

use alloc::string::String;
use alloc::vec::Vec;

pub use header::{
    parse_coff_header, parse_dos_header, parse_optional_header, CoffHeader, DataDirectory, DosHeader,
    OptionalHeader, IMAGE_FILE_MACHINE_AMD64,
};
pub use imports::{parse_imports_from_optional, ImportTable};
pub use sections::{parse_section_table, rva_to_offset, SectionHeader};

use crate::error::Result;

use header::{validate_coff, verify_pe_signature};
use imports::validate_imports;
use sections::validate_sections;

/// Parsed PE image with headers, sections, and imports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeImage {
    pub raw_len: usize,
    pub dos: DosHeader,
    pub coff: CoffHeader,
    pub optional: OptionalHeader,
    pub sections: Vec<SectionHeader>,
    pub imports: ImportTable,
    pub pe_offset: u32,
}

impl PeImage {
    pub fn is_64bit(&self) -> bool {
        self.optional.is_pe32_plus()
    }

    pub fn entry_point_rva(&self) -> u32 {
        self.optional.address_of_entry_point
    }

    pub fn image_base(&self) -> u64 {
        self.optional.image_base
    }

    pub fn machine(&self) -> u16 {
        self.coff.machine
    }

    pub fn is_dll(&self) -> bool {
        self.coff.is_dll()
    }

    pub fn section_named(&self, name: &str) -> Option<&SectionHeader> {
        sections::find_section(&self.sections, name)
    }

    pub fn section_bytes<'a>(&'a self, data: &'a [u8], name: &str) -> Result<&'a [u8]> {
        let sh = self
            .section_named(name)
            .ok_or(crate::error::Error::structure("pe section missing"))?;
        sections::section_data(data, sh)
    }
}

/// Parse DOS stub, PE signature, COFF header, optional header, sections, and imports.
pub fn parse_pe(data: &[u8]) -> Result<PeImage> {
    let dos = parse_dos_header(data)?;
    if dos.e_lfanew == 0 {
        return Err(crate::error::Error::validation("e_lfanew zero"));
    }
    verify_pe_signature(data, dos.e_lfanew)?;
    let pe_offset = dos.e_lfanew;
    let coff = parse_coff_header(data, pe_offset)?;
    let opt_offset = pe_offset + 24;
    let optional = parse_optional_header(data, pe_offset, coff.size_of_optional_header)?;
    let section_offset = opt_offset + coff.size_of_optional_header as u32;
    let sections = parse_section_table(data, section_offset, coff.number_of_sections)?;
    let imports = parse_imports_from_optional(data, &sections, &optional)?;
    Ok(PeImage {
        raw_len: data.len(),
        dos,
        coff,
        optional,
        sections,
        imports,
        pe_offset,
    })
}

/// Parse and validate structural PE constraints for sandbox intake.
pub fn parse_and_validate(data: &[u8]) -> Result<PeImage> {
    let image = parse_pe(data)?;
    validate_coff(&image.coff, data.len())?;
    validate_sections(&image.sections, &image.optional, data.len())?;
    validate_imports(&image.imports)?;
    if image.optional.size_of_headers as usize > data.len() {
        return Err(crate::error::Error::validation("size_of_headers"));
    }
    if image.optional.file_alignment == 0 || image.optional.section_alignment == 0 {
        return Err(crate::error::Error::validation("alignment zero"));
    }
    Ok(image)
}

/// ASCII summary for logging.
pub fn summarize(image: &PeImage) -> String {
    let mut s = String::new();
    s.push_str("PE ");
    s.push_str(header::machine_name(image.coff.machine));
    if image.is_64bit() {
        s.push_str(" PE32+");
    } else {
        s.push_str(" PE32");
    }
    if image.is_dll() {
        s.push_str(" DLL");
    }
    s.push_str(" sections=");
    push_dec(&mut s, image.sections.len() as u64);
    s.push_str(" imports=");
    push_dec(&mut s, image.imports.dll_count() as u64);
    s
}

fn push_dec(s: &mut String, mut v: u64) {
    if v == 0 {
        s.push('0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut n = 0usize;
    while v > 0 {
        buf[n] = (v % 10) as u8 + b'0';
        n += 1;
        v /= 10;
    }
    while n > 0 {
        n -= 1;
        s.push(buf[n] as char);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pe64() -> Vec<u8> {
        let mut v = vec![0u8; 0x600];
        v[0] = 0x4d;
        v[1] = 0x5a;
        v[0x3c] = 0x80;
        v[0x80] = b'P';
        v[0x81] = b'E';
        v[0x82] = 0;
        v[0x83] = 0;
        v[0x84] = 0x64;
        v[0x85] = 0x86;
        v[0x86] = 1;
        v[0x88] = 0xf0;
        v[0x8a] = 0x0b;
        v[0x8c] = 0x0b;
        v[0x90] = 0x0b;
        v[0x92] = 0x02;
        v
    }

    #[test]
    fn parse_minimal_pe() {
        let data = minimal_pe64();
        let img = parse_pe(&data).unwrap();
        assert_eq!(img.coff.machine, IMAGE_FILE_MACHINE_AMD64);
        assert!(img.is_64bit());
    }

    #[test]
    fn validate_minimal() {
        let data = minimal_pe64();
        assert!(parse_and_validate(&data).is_ok());
    }
}
