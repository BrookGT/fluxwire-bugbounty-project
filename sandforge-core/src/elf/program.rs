//! ELF program header (Phdr) parsing.

use alloc::vec::Vec;

use crate::elf::header::FileHeader;
use crate::error::{Error, Result};
use crate::util::{check_bounds, SliceCursor};

pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_SHLIB: u32 = 5;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
pub const PT_GNU_STACK: u32 = 0x6474_e551;
pub const PT_GNU_RELRO: u32 = 0x6474_e552;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

/// One ELF64 program header entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramHeader {
    pub typ: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

impl ProgramHeader {
    pub fn is_load(&self) -> bool {
        self.typ == PT_LOAD
    }

    pub fn is_note(&self) -> bool {
        self.typ == PT_NOTE
    }

    pub fn is_readable(&self) -> bool {
        self.flags & PF_R != 0
    }

    pub fn is_writable(&self) -> bool {
        self.flags & PF_W != 0
    }

    pub fn is_executable(&self) -> bool {
        self.flags & PF_X != 0
    }

    pub fn bss_size(&self) -> u64 {
        self.memsz.saturating_sub(self.filesz)
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

pub fn parse_program_header(hdr: &FileHeader, entry: &[u8]) -> Result<ProgramHeader> {
    if entry.len() < 56 {
        return Err(Error::UnexpectedEof);
    }
    let mut cur = SliceCursor::new(entry);
    let typ = read_u32(hdr, &mut cur)?;
    let flags = read_u32(hdr, &mut cur)?;
    let offset = read_u64(hdr, &mut cur)?;
    let vaddr = read_u64(hdr, &mut cur)?;
    let paddr = read_u64(hdr, &mut cur)?;
    let filesz = read_u64(hdr, &mut cur)?;
    let memsz = read_u64(hdr, &mut cur)?;
    let align = read_u64(hdr, &mut cur)?;
    Ok(ProgramHeader {
        typ,
        flags,
        offset,
        vaddr,
        paddr,
        filesz,
        memsz,
        align,
    })
}

pub fn parse_program_headers(data: &[u8], hdr: &FileHeader) -> Result<Vec<ProgramHeader>> {
    if hdr.phnum == 0 {
        return Ok(Vec::new());
    }
    if hdr.phentsize < 56 {
        return Err(Error::OutOfRange {
            field: "phentsize",
            value: hdr.phentsize as u64,
            limit: 56,
        });
    }
    let table_len = hdr.phentsize as u64 * hdr.phnum as u64;
    check_bounds("phdr", hdr.phoff, table_len, data.len())?;

    let mut out = Vec::with_capacity(hdr.phnum as usize);
    for i in 0..hdr.phnum as u64 {
        let base = hdr.phoff + i * hdr.phentsize as u64;
        let end = base + 56;
        if end as usize > data.len() {
            return Err(Error::UnexpectedEof);
        }
        let entry = &data[base as usize..end as usize];
        out.push(parse_program_header(hdr, entry)?);
    }
    Ok(out)
}

pub fn segment_type_name(typ: u32) -> &'static str {
    match typ {
        PT_NULL => "NULL",
        PT_LOAD => "LOAD",
        PT_DYNAMIC => "DYNAMIC",
        PT_INTERP => "INTERP",
        PT_NOTE => "NOTE",
        PT_SHLIB => "SHLIB",
        PT_PHDR => "PHDR",
        PT_TLS => "TLS",
        PT_GNU_EH_FRAME => "GNU_EH_FRAME",
        PT_GNU_STACK => "GNU_STACK",
        PT_GNU_RELRO => "GNU_RELRO",
        _ => "unknown",
    }
}

pub fn validate_program_headers(phdrs: &[ProgramHeader], buf_len: usize) -> Result<()> {
    for (idx, ph) in phdrs.iter().enumerate() {
        if ph.typ == PT_NULL {
            continue;
        }
        if ph.filesz > ph.memsz {
            return Err(Error::validation("phdr filesz > memsz"));
        }
        if ph.filesz > 0 {
            check_bounds(
                "phdr segment",
                ph.offset,
                ph.filesz,
                buf_len,
            )?;
        }
        if ph.align > 1 {
            if ph.offset % ph.align != 0 {
                return Err(Error::validation("phdr offset alignment"));
            }
            if ph.vaddr % ph.align != 0 {
                return Err(Error::validation("phdr vaddr alignment"));
            }
        }
        if ph.is_load() && ph.is_writable() && ph.is_executable() {
            return Err(Error::validation("WX LOAD segment"));
        }
        let _ = idx;
    }
    Ok(())
}

pub fn total_load_size(phdrs: &[ProgramHeader]) -> u64 {
    phdrs
        .iter()
        .filter(|p| p.is_load())
        .map(|p| p.memsz)
        .sum()
}

pub fn find_interp(phdrs: &[ProgramHeader], data: &[u8]) -> Result<Option<Vec<u8>>> {
    for ph in phdrs {
        if ph.typ == PT_INTERP && ph.filesz > 0 {
            check_bounds("interp", ph.offset, ph.filesz, data.len())?;
            let start = ph.offset as usize;
            let end = start + ph.filesz as usize;
            return Ok(Some(data[start..end].to_vec()));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::header::{Ident, ELFCLASS64, ELFDATA2LSB, EV_CURRENT};

    fn make_ident() -> Ident {
        Ident {
            class: ELFCLASS64,
            data: ELFDATA2LSB,
            version: EV_CURRENT,
            osabi: 0,
            abiversion: 0,
            pad: vec![0; 7],
        }
    }

    fn phdr_bytes() -> [u8; 56] {
        let mut b = [0u8; 56];
        let flags = PF_R | PF_X;
        b[0] = PT_LOAD as u8;
        b[4..8].copy_from_slice(&flags.to_le_bytes());
        b[0x08..0x10].copy_from_slice(&0x1000u64.to_le_bytes());
        b[0x10..0x18].copy_from_slice(&0x1000u64.to_le_bytes());
        b[0x18..0x20].copy_from_slice(&0x200u64.to_le_bytes());
        b[0x20..0x28].copy_from_slice(&0x200u64.to_le_bytes());
        b[0x28..0x30].copy_from_slice(&0x1000u64.to_le_bytes());
        b
    }

    #[test]
    fn parse_single_phdr() {
        let hdr = FileHeader {
            ident: make_ident(),
            typ: 3,
            machine: 62,
            version: 1,
            entry: 0x1000,
            phoff: 64,
            shoff: 0,
            flags: 0,
            ehsize: 64,
            phentsize: 56,
            phnum: 1,
            shentsize: 0,
            shnum: 0,
            shstrndx: 0,
        };
        let mut data = vec![0u8; 0x1200];
        data[64..120].copy_from_slice(&phdr_bytes());
        let phdrs = parse_program_headers(&data, &hdr).unwrap();
        assert_eq!(phdrs.len(), 1);
        assert!(phdrs[0].is_load());
        assert!(phdrs[0].is_executable());
    }

    #[test]
    fn wx_rejected() {
        let mut ph = parse_program_header(
            &FileHeader {
                ident: make_ident(),
                typ: 0,
                machine: 0,
                version: 1,
                entry: 0,
                phoff: 0,
                shoff: 0,
                flags: 0,
                ehsize: 64,
                phentsize: 56,
                phnum: 1,
                shentsize: 0,
                shnum: 0,
                shstrndx: 0,
            },
            &phdr_bytes(),
        )
        .unwrap();
        ph.flags |= PF_W;
        assert!(validate_program_headers(&[ph], 0x2000).is_err());
    }
}
