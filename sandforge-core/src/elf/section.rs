//! ELF section header (Shdr) parsing and name resolution.

use alloc::string::String;
use alloc::vec::Vec;

use crate::elf::header::FileHeader;
use crate::error::{Error, Result};
use crate::util::{check_bounds, SliceCursor};

pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_HASH: u32 = 5;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_NOTE: u32 = 7;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;
pub const SHT_DYNSYM: u32 = 11;

pub const SHF_WRITE: u64 = 0x1;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;

/// One ELF64 section header entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionHeader {
    pub name_offset: u32,
    pub typ: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub addralign: u64,
    pub entsize: u64,
}

impl SectionHeader {
    pub fn is_allocated(&self) -> bool {
        self.flags & SHF_ALLOC != 0
    }

    pub fn is_executable(&self) -> bool {
        self.flags & SHF_EXECINSTR != 0
    }

    pub fn is_writable(&self) -> bool {
        self.flags & SHF_WRITE != 0
    }

    pub fn is_nobits(&self) -> bool {
        self.typ == SHT_NOBITS
    }
}

fn read_u32(hdr: &FileHeader, cur: &mut SliceCursor<'_>) -> Result<u32> {
    if hdr.ident.is_little_endian() {
        cur.read_u32_le()
    } else {
        cur.read_u32_be()
    }
}

fn read_u64(hdr: &FileHeader, cur: &mut SliceCursor<'_>) -> Result<u64> {
    if hdr.ident.is_little_endian() {
        cur.read_u64_le()
    } else {
        cur.read_u64_be()
    }
}

pub fn parse_section_header(hdr: &FileHeader, entry: &[u8]) -> Result<SectionHeader> {
    if entry.len() < 64 {
        return Err(Error::UnexpectedEof);
    }
    let mut cur = SliceCursor::new(entry);
    let name_offset = read_u32(hdr, &mut cur)?;
    let typ = read_u32(hdr, &mut cur)?;
    let flags = read_u64(hdr, &mut cur)?;
    let addr = read_u64(hdr, &mut cur)?;
    let offset = read_u64(hdr, &mut cur)?;
    let size = read_u64(hdr, &mut cur)?;
    let link = read_u32(hdr, &mut cur)?;
    let info = read_u32(hdr, &mut cur)?;
    let addralign = read_u64(hdr, &mut cur)?;
    let entsize = read_u64(hdr, &mut cur)?;
    Ok(SectionHeader {
        name_offset,
        typ,
        flags,
        addr,
        offset,
        size,
        link,
        info,
        addralign,
        entsize,
    })
}

pub fn parse_section_headers(data: &[u8], hdr: &FileHeader) -> Result<Vec<SectionHeader>> {
    if hdr.shnum == 0 {
        return Ok(Vec::new());
    }
    if hdr.shentsize < 64 {
        return Err(Error::OutOfRange {
            field: "shentsize",
            value: hdr.shentsize as u64,
            limit: 64,
        });
    }
    let table_len = hdr.shentsize as u64 * hdr.shnum as u64;
    check_bounds("shdr", hdr.shoff, table_len, data.len())?;

    let mut out = Vec::with_capacity(hdr.shnum as usize);
    for i in 0..hdr.shnum as u64 {
        let base = hdr.shoff + i * hdr.shentsize as u64;
        let end = base + 64;
        if end as usize > data.len() {
            return Err(Error::UnexpectedEof);
        }
        let entry = &data[base as usize..end as usize];
        out.push(parse_section_header(hdr, entry)?);
    }
    Ok(out)
}

pub fn section_type_name(typ: u32) -> &'static str {
    match typ {
        SHT_NULL => "NULL",
        SHT_PROGBITS => "PROGBITS",
        SHT_SYMTAB => "SYMTAB",
        SHT_STRTAB => "STRTAB",
        SHT_RELA => "RELA",
        SHT_HASH => "HASH",
        SHT_DYNAMIC => "DYNAMIC",
        SHT_NOTE => "NOTE",
        SHT_NOBITS => "NOBITS",
        SHT_REL => "REL",
        SHT_DYNSYM => "DYNSYM",
        _ => "unknown",
    }
}

pub fn read_section_names(
    data: &[u8],
    shdrs: &[SectionHeader],
    shstrndx: u16,
) -> Result<Vec<String>> {
    if shstrndx as usize >= shdrs.len() {
        return Err(Error::validation("shstrndx"));
    }
    let strtab = &shdrs[shstrndx as usize];
    if strtab.typ != SHT_STRTAB {
        return Err(Error::validation("shstrtab type"));
    }
    if strtab.size == 0 {
        return Ok(vec![String::new(); shdrs.len()]);
    }
    check_bounds("shstrtab", strtab.offset, strtab.size, data.len())?;
    let base = strtab.offset as usize;
    let table = &data[base..base + strtab.size as usize];

    let mut names = Vec::with_capacity(shdrs.len());
    for sh in shdrs {
        let name = read_name_from_strtab(table, sh.name_offset)?;
        names.push(name);
    }
    Ok(names)
}

fn read_name_from_strtab(table: &[u8], offset: u32) -> Result<String> {
    let start = offset as usize;
    if start >= table.len() {
        return Ok(String::new());
    }
    let mut end = start;
    while end < table.len() && table[end] != 0 {
        if table[end] > 0x7f {
            return Err(Error::structure("non-ascii section name"));
        }
        end += 1;
    }
    let bytes = &table[start..end];
    let s = core::str::from_utf8(bytes).map_err(|_| Error::structure("section name utf8"))?;
    Ok(String::from(s))
}

pub fn section_payload<'a>(data: &'a [u8], sh: &SectionHeader) -> Result<&'a [u8]> {
    if sh.is_nobits() || sh.size == 0 {
        return Ok(&[]);
    }
    check_bounds("section", sh.offset, sh.size, data.len())?;
    let start = sh.offset as usize;
    let end = start + sh.size as usize;
    Ok(&data[start..end])
}

pub fn validate_section_headers(shdrs: &[SectionHeader], buf_len: usize) -> Result<()> {
    for sh in shdrs {
        if sh.typ == SHT_NULL {
            continue;
        }
        if !sh.is_nobits() && sh.size > 0 {
            check_bounds("section data", sh.offset, sh.size, buf_len)?;
        }
        if sh.addralign > 1 && sh.offset % sh.addralign != 0 && sh.size > 0 {
            return Err(Error::validation("section offset alignment"));
        }
        if sh.is_executable() && sh.is_writable() {
            return Err(Error::validation("WX section"));
        }
    }
    Ok(())
}

pub fn find_section_by_name<'a>(
    names: &'a [String],
    shdrs: &'a [SectionHeader],
    needle: &str,
) -> Option<&'a SectionHeader> {
    for (name, sh) in names.iter().zip(shdrs.iter()) {
        if name == needle {
            return Some(sh);
        }
    }
    None
}

pub fn count_symbol_sections(shdrs: &[SectionHeader]) -> usize {
    shdrs
        .iter()
        .filter(|s| s.typ == SHT_SYMTAB || s.typ == SHT_DYNSYM)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::header::{Ident, ELFCLASS64, ELFDATA2LSB, EV_CURRENT};

    fn ident() -> Ident {
        Ident {
            class: ELFCLASS64,
            data: ELFDATA2LSB,
            version: EV_CURRENT,
            osabi: 0,
            abiversion: 0,
            pad: vec![0; 7],
        }
    }

    #[test]
    fn parse_shdr() {
        let mut entry = [0u8; 64];
        entry[4..8].copy_from_slice(&SHT_PROGBITS.to_le_bytes());
        entry[8..16].copy_from_slice(&SHF_ALLOC.to_le_bytes());
        entry[0x18..0x20].copy_from_slice(&0x200u64.to_le_bytes());
        entry[0x20..0x28].copy_from_slice(&0x100u64.to_le_bytes());
        let hdr = FileHeader {
            ident: ident(),
            typ: 3,
            machine: 62,
            version: 1,
            entry: 0,
            phoff: 0,
            shoff: 0x1000,
            flags: 0,
            ehsize: 64,
            phentsize: 0,
            phnum: 0,
            shentsize: 64,
            shnum: 1,
            shstrndx: 0,
        };
        let sh = parse_section_header(&hdr, &entry).unwrap();
        assert_eq!(sh.typ, SHT_PROGBITS);
        assert_eq!(sh.size, 0x100);
    }

    #[test]
    fn read_names() {
        let mut data = vec![0u8; 256];
        data[0] = 0;
        data[1] = b'.';
        data[2] = b't';
        data[3] = b'e';
        data[4] = b'x';
        data[5] = b't';
        data[6] = 0;
        let strtab = SectionHeader {
            name_offset: 0,
            typ: SHT_STRTAB,
            flags: 0,
            addr: 0,
            offset: 0,
            size: 7,
            link: 0,
            info: 0,
            addralign: 1,
            entsize: 0,
        };
        let text = SectionHeader {
            name_offset: 1,
            typ: SHT_PROGBITS,
            flags: SHF_ALLOC | SHF_EXECINSTR,
            addr: 0x1000,
            offset: 0x100,
            size: 0x50,
            link: 0,
            info: 0,
            addralign: 16,
            entsize: 0,
        };
        let names = read_section_names(&data, &[strtab.clone(), text], 0).unwrap();
        assert_eq!(names[1], ".text");
    }
}
