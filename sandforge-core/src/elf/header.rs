//! ELF identification bytes and file header parsing.

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::util::{check_bounds, SliceCursor};

pub const ELFMAG0: u8 = 0x7f;
pub const ELFMAG1: u8 = b'E';
pub const ELFMAG2: u8 = b'L';
pub const ELFMAG3: u8 = b'F';

pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const ELFDATA2MSB: u8 = 2;
pub const EV_CURRENT: u8 = 1;

pub const ET_NONE: u16 = 0;
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const ET_CORE: u16 = 4;

pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;
pub const EM_RISCV: u16 = 243;

/// Parsed EI_* identification block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ident {
    pub class: u8,
    pub data: u8,
    pub version: u8,
    pub osabi: u8,
    pub abiversion: u8,
    pub pad: Vec<u8>,
}

impl Ident {
    pub fn is_64bit(&self) -> bool {
        self.class == ELFCLASS64
    }

    pub fn is_little_endian(&self) -> bool {
        self.data == ELFDATA2LSB
    }
}

/// ELF64 file header (ehdr).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    pub ident: Ident,
    pub typ: u16,
    pub machine: u16,
    pub version: u32,
    pub entry: u64,
    pub phoff: u64,
    pub shoff: u64,
    pub flags: u32,
    pub ehsize: u16,
    pub phentsize: u16,
    pub phnum: u16,
    pub shentsize: u16,
    pub shnum: u16,
    pub shstrndx: u16,
}

pub fn parse_ident(cursor: &mut SliceCursor<'_>) -> Result<Ident> {
    let b0 = cursor.read_u8()?;
    let b1 = cursor.read_u8()?;
    let b2 = cursor.read_u8()?;
    let b3 = cursor.read_u8()?;
    if b0 != ELFMAG0 || b1 != ELFMAG1 || b2 != ELFMAG2 || b3 != ELFMAG3 {
        let found = ((b0 as u64) << 24) | ((b1 as u64) << 16) | ((b2 as u64) << 8) | (b3 as u64);
        return Err(Error::BadMagic {
            expected: "0x7f454c46",
            found,
        });
    }
    let class = cursor.read_u8()?;
    let data = cursor.read_u8()?;
    let version = cursor.read_u8()?;
    let osabi = cursor.read_u8()?;
    let abiversion = cursor.read_u8()?;
    let pad = cursor.read_vec(7)?;
    Ok(Ident {
        class,
        data,
        version,
        osabi,
        abiversion,
        pad,
    })
}

pub fn parse_file_header(data: &[u8], ident: &Ident) -> Result<FileHeader> {
    if !ident.is_64bit() {
        return Err(Error::Unsupported {
            what: "ELF class",
            detail: ident.class as u32,
        });
    }
    if ident.data != ELFDATA2LSB && ident.data != ELFDATA2MSB {
        return Err(Error::Unsupported {
            what: "ELF endian",
            detail: ident.data as u32,
        });
    }
    let mut cur = SliceCursor::new(data);
    cur.seek(16)?;

    let read_u16 = |c: &mut SliceCursor| -> Result<u16> {
        if ident.is_little_endian() {
            c.read_u16_le()
        } else {
            c.read_u16_be()
        }
    };
    let read_u32 = |c: &mut SliceCursor| -> Result<u32> {
        if ident.is_little_endian() {
            c.read_u32_le()
        } else {
            c.read_u32_be()
        }
    };
    let read_u64 = |c: &mut SliceCursor| -> Result<u64> {
        if ident.is_little_endian() {
            c.read_u64_le()
        } else {
            c.read_u64_be()
        }
    };

    let typ = read_u16(&mut cur)?;
    let machine = read_u16(&mut cur)?;
    let version = read_u32(&mut cur)?;
    let entry = read_u64(&mut cur)?;
    let phoff = read_u64(&mut cur)?;
    let shoff = read_u64(&mut cur)?;
    let flags = read_u32(&mut cur)?;
    let ehsize = read_u16(&mut cur)?;
    let phentsize = read_u16(&mut cur)?;
    let phnum = read_u16(&mut cur)?;
    let shentsize = read_u16(&mut cur)?;
    let shnum = read_u16(&mut cur)?;
    let shstrndx = read_u16(&mut cur)?;

    if ehsize < 64 {
        return Err(Error::OutOfRange {
            field: "ehsize",
            value: ehsize as u64,
            limit: 64,
        });
    }

    Ok(FileHeader {
        ident: ident.clone(),
        typ,
        machine,
        version,
        entry,
        phoff,
        shoff,
        flags,
        ehsize,
        phentsize,
        phnum,
        shentsize,
        shnum,
        shstrndx,
    })
}

pub fn validate_header(hdr: &FileHeader, buf_len: usize) -> Result<()> {
    if hdr.ident.version != EV_CURRENT && hdr.version != EV_CURRENT as u32 {
        return Err(Error::validation("ELF version"));
    }
    if hdr.phnum > 0 {
        check_bounds("phdr table", hdr.phoff, hdr.phentsize as u64 * hdr.phnum as u64, buf_len)?;
    }
    if hdr.shnum > 0 {
        check_bounds("shdr table", hdr.shoff, hdr.shentsize as u64 * hdr.shnum as u64, buf_len)?;
    }
    if hdr.shstrndx as usize >= hdr.shnum as usize && hdr.shnum > 0 {
        return Err(Error::validation("shstrndx"));
    }
    Ok(())
}

pub fn machine_name(machine: u16) -> &'static str {
    match machine {
        EM_X86_64 => "x86-64",
        EM_AARCH64 => "AArch64",
        EM_RISCV => "RISC-V",
        _ => "unknown",
    }
}

pub fn type_name(typ: u16) -> &'static str {
    match typ {
        ET_NONE => "NONE",
        ET_REL => "REL",
        ET_EXEC => "EXEC",
        ET_DYN => "DYN",
        ET_CORE => "CORE",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_elf64_header() -> Vec<u8> {
        let mut v = vec![0u8; 64];
        v[0] = ELFMAG0;
        v[1] = ELFMAG1;
        v[2] = ELFMAG2;
        v[3] = ELFMAG3;
        v[4] = ELFCLASS64;
        v[5] = ELFDATA2LSB;
        v[6] = EV_CURRENT;
        v[0x10] = ET_DYN as u8;
        v[0x11] = 0;
        v[0x12] = (EM_X86_64 & 0xff) as u8;
        v[0x13] = (EM_X86_64 >> 8) as u8;
        v[0x14] = 1;
        v[0x28] = 0x40;
        v[0x29] = 0;
        v[0x3a] = 0x40;
        v[0x3b] = 0;
        v
    }

    #[test]
    fn parse_ident_ok() {
        let data = minimal_elf64_header();
        let mut c = SliceCursor::new(&data);
        let id = parse_ident(&mut c).unwrap();
        assert!(id.is_64bit());
        assert!(id.is_little_endian());
    }

    #[test]
    fn bad_magic() {
        let data = [0u8; 16];
        let mut c = SliceCursor::new(&data);
        assert!(parse_ident(&mut c).is_err());
    }

    #[test]
    fn parse_ehdr() {
        let data = minimal_elf64_header();
        let mut c = SliceCursor::new(&data);
        let id = parse_ident(&mut c).unwrap();
        let hdr = parse_file_header(&data, &id).unwrap();
        assert_eq!(hdr.machine, EM_X86_64);
        assert_eq!(hdr.typ, ET_DYN);
    }
}
