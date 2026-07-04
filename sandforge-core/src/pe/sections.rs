//! PE section table parsing and RVA/file offset mapping.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::pe::header::OptionalHeader;
use crate::util::{check_bounds, SliceCursor};

pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// One PE section table row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

impl SectionHeader {
    pub fn name_str(&self) -> String {
        let end = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.name.len());
        let bytes = &self.name[..end];
        core::str::from_utf8(bytes)
            .map(String::from)
            .unwrap_or_else(|_| String::from("?"))
    }

    pub fn is_code(&self) -> bool {
        self.characteristics & IMAGE_SCN_CNT_CODE != 0
    }

    pub fn is_readable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_READ != 0
    }

    pub fn is_writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }

    pub fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }
}

pub fn parse_section_header(entry: &[u8]) -> Result<SectionHeader> {
    if entry.len() < 40 {
        return Err(Error::UnexpectedEof);
    }
    let mut cur = SliceCursor::new(entry);
    let mut name = [0u8; 8];
    let raw_name = cur.read_exact(8)?;
    name.copy_from_slice(raw_name);
    let virtual_size = cur.read_u32_le()?;
    let virtual_address = cur.read_u32_le()?;
    let size_of_raw_data = cur.read_u32_le()?;
    let pointer_to_raw_data = cur.read_u32_le()?;
    let pointer_to_relocations = cur.read_u32_le()?;
    let pointer_to_linenumbers = cur.read_u32_le()?;
    let number_of_relocations = cur.read_u16_le()?;
    let number_of_linenumbers = cur.read_u16_le()?;
    let characteristics = cur.read_u32_le()?;
    Ok(SectionHeader {
        name,
        virtual_size,
        virtual_address,
        size_of_raw_data,
        pointer_to_raw_data,
        pointer_to_relocations,
        pointer_to_linenumbers,
        number_of_relocations,
        number_of_linenumbers,
        characteristics,
    })
}

pub fn parse_section_table(
    data: &[u8],
    section_offset: u32,
    count: u16,
) -> Result<Vec<SectionHeader>> {
    let table_len = count as u64 * 40;
    check_bounds("sections", section_offset as u64, table_len, data.len())?;
    let mut sections = Vec::with_capacity(count as usize);
    for i in 0..count as u32 {
        let base = section_offset + i * 40;
        let end = base + 40;
        let entry = &data[base as usize..end as usize];
        sections.push(parse_section_header(entry)?);
    }
    Ok(sections)
}

pub fn section_data<'a>(data: &'a [u8], sh: &SectionHeader) -> Result<&'a [u8]> {
    if sh.size_of_raw_data == 0 {
        return Ok(&[]);
    }
    check_bounds(
        "section raw",
        sh.pointer_to_raw_data as u64,
        sh.size_of_raw_data as u64,
        data.len(),
    )?;
    let start = sh.pointer_to_raw_data as usize;
    let end = start + sh.size_of_raw_data as usize;
    Ok(&data[start..end])
}

pub fn rva_to_offset(sections: &[SectionHeader], rva: u32) -> Option<u32> {
    for sh in sections {
        let size = core::cmp::max(sh.virtual_size, sh.size_of_raw_data);
        if rva >= sh.virtual_address && rva < sh.virtual_address.saturating_add(size) {
            let delta = rva - sh.virtual_address;
            return Some(sh.pointer_to_raw_data.saturating_add(delta));
        }
    }
    None
}

pub fn offset_at_rva<'a>(data: &'a [u8], sections: &[SectionHeader], rva: u32) -> Result<&'a [u8]> {
    let off = rva_to_offset(sections, rva).ok_or(Error::structure("rva not mapped"))?;
    check_bounds("rva slice", off as u64, 1, data.len())?;
    Ok(&data[off as usize..])
}

pub fn validate_sections(sections: &[SectionHeader], opt: &OptionalHeader, data_len: usize) -> Result<()> {
    for sh in sections {
        if sh.is_executable() && sh.is_writable() {
            return Err(Error::validation("WX PE section"));
        }
        if sh.size_of_raw_data > 0 {
            check_bounds(
                "section",
                sh.pointer_to_raw_data as u64,
                sh.size_of_raw_data as u64,
                data_len,
            )?;
        }
        if sh.virtual_address >= opt.size_of_image {
            return Err(Error::validation("section rva"));
        }
    }
    Ok(())
}

pub fn find_section<'a>(sections: &'a [SectionHeader], name: &str) -> Option<&'a SectionHeader> {
    sections.iter().find(|s| s.name_str() == name)
}

pub fn total_raw_size(sections: &[SectionHeader]) -> u64 {
    sections.iter().map(|s| s.size_of_raw_data as u64).sum()
}

pub fn executable_sections(sections: &[SectionHeader]) -> Vec<&SectionHeader> {
    sections.iter().filter(|s| s.is_executable()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_section() -> [u8; 40] {
        let mut b = [0u8; 40];
        b[0] = b'.';
        b[1] = b't';
        b[2] = b'e';
        b[3] = b'x';
        b[4] = b't';
        let chars = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        b[8..12].copy_from_slice(&0x100u32.to_le_bytes());
        b[12..16].copy_from_slice(&0x1000u32.to_le_bytes());
        b[16..20].copy_from_slice(&0x200u32.to_le_bytes());
        b[20..24].copy_from_slice(&0x400u32.to_le_bytes());
        b[36..40].copy_from_slice(&chars.to_le_bytes());
        b
    }

    #[test]
    fn parse_section() {
        let sh = parse_section_header(&sample_section()).unwrap();
        assert_eq!(sh.name_str(), ".text");
        assert!(sh.is_executable());
    }

    #[test]
    fn rva_map() {
        let sh = parse_section_header(&sample_section()).unwrap();
        let off = rva_to_offset(&[sh.clone()], 0x1100).unwrap();
        assert_eq!(off, 0x500);
    }
}
