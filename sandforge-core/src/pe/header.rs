//! PE DOS stub, COFF file header, and optional header parsing.

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::util::{check_bounds, SliceCursor};

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5a4d;
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;

pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;

pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
pub const IMAGE_FILE_DLL: u16 = 0x2000;

/// DOS MZ header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: u32,
}

/// COFF file header immediately after PE signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoffHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

impl CoffHeader {
    pub fn is_dll(&self) -> bool {
        self.characteristics & IMAGE_FILE_DLL != 0
    }

    pub fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_FILE_EXECUTABLE_IMAGE != 0
    }
}

/// PE32 optional header (also used as base for PE32+).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalHeader {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directories: Vec<DataDirectory>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl OptionalHeader {
    pub fn is_pe32_plus(&self) -> bool {
        self.magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
    }

    pub fn import_directory(&self) -> Option<&DataDirectory> {
        self.data_directories.get(1).filter(|d| d.size > 0)
    }

    pub fn export_directory(&self) -> Option<&DataDirectory> {
        self.data_directories.get(0).filter(|d| d.size > 0)
    }
}

pub fn parse_dos_header(data: &[u8]) -> Result<DosHeader> {
    if data.len() < 64 {
        return Err(Error::UnexpectedEof);
    }
    let mut cur = SliceCursor::new(data);
    let e_magic = cur.read_u16_le()?;
    if e_magic != IMAGE_DOS_SIGNATURE {
        return Err(Error::BadMagic {
            expected: "MZ",
            found: e_magic as u64,
        });
    }
    let e_cblp = cur.read_u16_le()?;
    let e_cp = cur.read_u16_le()?;
    let e_crlc = cur.read_u16_le()?;
    let e_cparhdr = cur.read_u16_le()?;
    let e_minalloc = cur.read_u16_le()?;
    let e_maxalloc = cur.read_u16_le()?;
    let e_ss = cur.read_u16_le()?;
    let e_sp = cur.read_u16_le()?;
    let e_csum = cur.read_u16_le()?;
    let e_ip = cur.read_u16_le()?;
    let e_cs = cur.read_u16_le()?;
    let e_lfarlc = cur.read_u16_le()?;
    let e_ovno = cur.read_u16_le()?;
    let mut e_res = [0u16; 4];
    for item in &mut e_res {
        *item = cur.read_u16_le()?;
    }
    let e_oemid = cur.read_u16_le()?;
    let e_oeminfo = cur.read_u16_le()?;
    let mut e_res2 = [0u16; 10];
    for item in &mut e_res2 {
        *item = cur.read_u16_le()?;
    }
    let e_lfanew = cur.read_u32_le()?;
    Ok(DosHeader {
        e_magic,
        e_cblp,
        e_cp,
        e_crlc,
        e_cparhdr,
        e_minalloc,
        e_maxalloc,
        e_ss,
        e_sp,
        e_csum,
        e_ip,
        e_cs,
        e_lfarlc,
        e_ovno,
        e_res,
        e_oemid,
        e_oeminfo,
        e_res2,
        e_lfanew,
    })
}

pub fn parse_coff_header(data: &[u8], offset: u32) -> Result<CoffHeader> {
    check_bounds("coff", offset as u64, 20, data.len())?;
    let mut cur = SliceCursor::new(data);
    cur.seek(offset as usize + 4)?;
    let machine = cur.read_u16_le()?;
    let number_of_sections = cur.read_u16_le()?;
    let time_date_stamp = cur.read_u32_le()?;
    let pointer_to_symbol_table = cur.read_u32_le()?;
    let number_of_symbols = cur.read_u32_le()?;
    let size_of_optional_header = cur.read_u16_le()?;
    let characteristics = cur.read_u16_le()?;
    Ok(CoffHeader {
        machine,
        number_of_sections,
        time_date_stamp,
        pointer_to_symbol_table,
        number_of_symbols,
        size_of_optional_header,
        characteristics,
    })
}

pub fn parse_optional_header(data: &[u8], offset: u32, size: u16) -> Result<OptionalHeader> {
    if size < 2 {
        return Err(Error::UnexpectedEof);
    }
    check_bounds("optional", offset as u64, size as u64, data.len())?;
    let base = offset as usize + 24;
    let mut cur = SliceCursor::new(data);
    cur.seek(base)?;
    let magic = cur.read_u16_le()?;
    let is_plus = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    let is_32 = magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    if !is_plus && !is_32 {
        return Err(Error::Unsupported {
            what: "PE optional magic",
            detail: magic as u32,
        });
    }
    let major_linker_version = cur.read_u8()?;
    let minor_linker_version = cur.read_u8()?;
    let size_of_code = cur.read_u32_le()?;
    let size_of_initialized_data = cur.read_u32_le()?;
    let size_of_uninitialized_data = cur.read_u32_le()?;
    let address_of_entry_point = cur.read_u32_le()?;
    let base_of_code = cur.read_u32_le()?;
    let base_of_data = if is_32 { cur.read_u32_le()? } else { 0 };
    let image_base = if is_plus {
        cur.read_u64_le()?
    } else {
        cur.read_u32_le()? as u64
    };
    let section_alignment = cur.read_u32_le()?;
    let file_alignment = cur.read_u32_le()?;
    let major_os_version = cur.read_u16_le()?;
    let minor_os_version = cur.read_u16_le()?;
    let major_image_version = cur.read_u16_le()?;
    let minor_image_version = cur.read_u16_le()?;
    let major_subsystem_version = cur.read_u16_le()?;
    let minor_subsystem_version = cur.read_u16_le()?;
    let win32_version_value = cur.read_u32_le()?;
    let size_of_image = cur.read_u32_le()?;
    let size_of_headers = cur.read_u32_le()?;
    let check_sum = cur.read_u32_le()?;
    let subsystem = cur.read_u16_le()?;
    let dll_characteristics = cur.read_u16_le()?;
    let size_of_stack_reserve = if is_plus {
        cur.read_u64_le()?
    } else {
        cur.read_u32_le()? as u64
    };
    let size_of_stack_commit = if is_plus {
        cur.read_u64_le()?
    } else {
        cur.read_u32_le()? as u64
    };
    let size_of_heap_reserve = if is_plus {
        cur.read_u64_le()?
    } else {
        cur.read_u32_le()? as u64
    };
    let size_of_heap_commit = if is_plus {
        cur.read_u64_le()?
    } else {
        cur.read_u32_le()? as u64
    };
    let loader_flags = cur.read_u32_le()?;
    let number_of_rva_and_sizes = cur.read_u32_le()?;

    let dir_count = core::cmp::min(number_of_rva_and_sizes as usize, 16);
    let mut data_directories = Vec::with_capacity(dir_count);
    for _ in 0..dir_count {
        let virtual_address = cur.read_u32_le()?;
        let dir_size = cur.read_u32_le()?;
        data_directories.push(DataDirectory {
            virtual_address,
            size: dir_size,
        });
    }

    Ok(OptionalHeader {
        magic,
        major_linker_version,
        minor_linker_version,
        size_of_code,
        size_of_initialized_data,
        size_of_uninitialized_data,
        address_of_entry_point,
        base_of_code,
        base_of_data,
        image_base,
        section_alignment,
        file_alignment,
        major_os_version,
        minor_os_version,
        major_image_version,
        minor_image_version,
        major_subsystem_version,
        minor_subsystem_version,
        win32_version_value,
        size_of_image,
        size_of_headers,
        check_sum,
        subsystem,
        dll_characteristics,
        size_of_stack_reserve,
        size_of_stack_commit,
        size_of_heap_reserve,
        size_of_heap_commit,
        loader_flags,
        number_of_rva_and_sizes,
        data_directories,
    })
}

pub fn verify_pe_signature(data: &[u8], lfanew: u32) -> Result<()> {
    check_bounds("pe sig", lfanew as u64, 4, data.len())?;
    let mut cur = SliceCursor::new(data);
    cur.seek(lfanew as usize)?;
    let sig = cur.read_u32_le()?;
    if sig != IMAGE_NT_SIGNATURE {
        return Err(Error::BadMagic {
            expected: "PE\\0\\0",
            found: sig as u64,
        });
    }
    Ok(())
}

pub fn machine_name(machine: u16) -> &'static str {
    match machine {
        IMAGE_FILE_MACHINE_I386 => "i386",
        IMAGE_FILE_MACHINE_AMD64 => "x86-64",
        IMAGE_FILE_MACHINE_ARM64 => "ARM64",
        _ => "unknown",
    }
}

pub fn validate_coff(coff: &CoffHeader, data_len: usize) -> Result<()> {
    if coff.number_of_sections > 96 {
        return Err(Error::validation("section count"));
    }
    if coff.pointer_to_symbol_table != 0 {
        let sym_size = coff.number_of_symbols as u64 * 18;
        check_bounds("symbols", coff.pointer_to_symbol_table as u64, sym_size, data_len)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dos() {
        let mut data = vec![0u8; 128];
        data[0] = 0x4d;
        data[1] = 0x5a;
        data[0x3c] = 0x80;
        let dos = parse_dos_header(&data).unwrap();
        assert_eq!(dos.e_lfanew, 0x80);
    }

    #[test]
    fn bad_mz() {
        assert!(parse_dos_header(&[0u8; 64]).is_err());
    }
}
