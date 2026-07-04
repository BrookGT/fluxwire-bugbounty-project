//! PE import directory and thunk parsing.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::pe::header::{DataDirectory, OptionalHeader};
use crate::pe::sections::{rva_to_offset, SectionHeader};
use crate::util::{check_bounds, read_ascii_cstr, SliceCursor};

pub const IMAGE_ORDINAL_FLAG64: u64 = 1u64 << 63;
pub const IMAGE_ORDINAL_FLAG32: u32 = 1u32 << 31;

/// One imported symbol (by name or ordinal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportSymbol {
    ByName { hint: u16, name: String },
    ByOrdinal { ordinal: u16 },
}

/// Function imported from a DLL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportEntry {
    pub symbol: ImportSymbol,
}

/// Descriptor for one DLL import block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportDescriptor {
    pub dll_name: String,
    pub entries: Vec<ImportEntry>,
    pub original_first_thunk_rva: u32,
    pub first_thunk_rva: u32,
}

/// Parsed import directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportTable {
    pub descriptors: Vec<ImportDescriptor>,
}

impl ImportTable {
    pub fn dll_count(&self) -> usize {
        self.descriptors.len()
    }

    pub fn total_symbols(&self) -> usize {
        self.descriptors.iter().map(|d| d.entries.len()).sum()
    }

    pub fn dll_names(&self) -> Vec<&str> {
        self.descriptors.iter().map(|d| d.dll_name.as_str()).collect()
    }
}

#[derive(Debug, Clone, Copy)]
struct RawImportDesc {
    original_first_thunk: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name_rva: u32,
    first_thunk: u32,
}

fn parse_import_descriptor(data: &[u8], offset: u32) -> Result<RawImportDesc> {
    check_bounds("import desc", offset as u64, 20, data.len())?;
    let mut cur = SliceCursor::new(data);
    cur.seek(offset as usize)?;
    Ok(RawImportDesc {
        original_first_thunk: cur.read_u32_le()?,
        time_date_stamp: cur.read_u32_le()?,
        forwarder_chain: cur.read_u32_le()?,
        name_rva: cur.read_u32_le()?,
        first_thunk: cur.read_u32_le()?,
    })
}

fn read_dll_name(data: &[u8], sections: &[SectionHeader], name_rva: u32) -> Result<String> {
    let off = rva_to_offset(sections, name_rva).ok_or(Error::structure("import name rva"))?;
    check_bounds("dll name", off as u64, 1, data.len())?;
    let mut cur = SliceCursor::new(data);
    cur.seek(off as usize)?;
    let bytes = read_ascii_cstr(&mut cur, "dll name")?;
    let s = core::str::from_utf8(&bytes).map_err(|_| Error::structure("dll name utf8"))?;
    Ok(String::from(s))
}

fn parse_thunks(
    data: &[u8],
    sections: &[SectionHeader],
    thunk_rva: u32,
    is_64: bool,
) -> Result<Vec<ImportEntry>> {
    if thunk_rva == 0 {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    let mut rva = thunk_rva;
    loop {
        let file_off = match rva_to_offset(sections, rva) {
            Some(v) => v,
            None => break,
        };
        check_bounds("thunk", file_off as u64, if is_64 { 8 } else { 4 }, data.len())?;
        let mut cur = SliceCursor::new(data);
        cur.seek(file_off as usize)?;
        if is_64 {
            let val = cur.read_u64_le()?;
            if val == 0 {
                break;
            }
            if val & IMAGE_ORDINAL_FLAG64 != 0 {
                let ord = (val & 0xffff) as u16;
                entries.push(ImportEntry {
                    symbol: ImportSymbol::ByOrdinal { ordinal: ord },
                });
            } else {
                let hint_rva = val as u32;
                let entry = parse_import_by_name(data, sections, hint_rva)?;
                entries.push(entry);
            }
            rva += 8;
        } else {
            let val = cur.read_u32_le()?;
            if val == 0 {
                break;
            }
            if val & IMAGE_ORDINAL_FLAG32 != 0 {
                let ord = (val & 0xffff) as u16;
                entries.push(ImportEntry {
                    symbol: ImportSymbol::ByOrdinal { ordinal: ord },
                });
            } else {
                let entry = parse_import_by_name(data, sections, val)?;
                entries.push(entry);
            }
            rva += 4;
        }
        if entries.len() > 65536 {
            return Err(Error::validation("import thunk cap"));
        }
    }
    Ok(entries)
}

fn parse_import_by_name(
    data: &[u8],
    sections: &[SectionHeader],
    rva: u32,
) -> Result<ImportEntry> {
    let off = rva_to_offset(sections, rva).ok_or(Error::structure("hint/name rva"))?;
    check_bounds("hint/name", off as u64, 3, data.len())?;
    let mut cur = SliceCursor::new(data);
    cur.seek(off as usize)?;
    let hint = cur.read_u16_le()?;
    let name_bytes = read_ascii_cstr(&mut cur, "import name")?;
    let name = core::str::from_utf8(&name_bytes).map_err(|_| Error::structure("import utf8"))?;
    Ok(ImportEntry {
        symbol: ImportSymbol::ByName {
            hint,
            name: String::from(name),
        },
    })
}

pub fn parse_import_directory(
    data: &[u8],
    sections: &[SectionHeader],
    opt: &OptionalHeader,
    dir: &DataDirectory,
) -> Result<ImportTable> {
    if dir.size == 0 || dir.virtual_address == 0 {
        return Ok(ImportTable {
            descriptors: Vec::new(),
        });
    }
    let is_64 = opt.is_pe32_plus();
    let mut descriptors = Vec::new();
    let mut idx = 0u32;
    loop {
        let desc_off = match rva_to_offset(sections, dir.virtual_address) {
            Some(base) => base + idx * 20,
            None => break,
        };
        let raw = parse_import_descriptor(data, desc_off)?;
        if raw.name_rva == 0 && raw.first_thunk == 0 {
            break;
        }
        let dll_name = read_dll_name(data, sections, raw.name_rva)?;
        let thunk_rva = if raw.original_first_thunk != 0 {
            raw.original_first_thunk
        } else {
            raw.first_thunk
        };
        let entries = parse_thunks(data, sections, thunk_rva, is_64)?;
        descriptors.push(ImportDescriptor {
            dll_name,
            entries,
            original_first_thunk_rva: raw.original_first_thunk,
            first_thunk_rva: raw.first_thunk,
        });
        idx += 1;
        if idx > 256 {
            return Err(Error::validation("import descriptor cap"));
        }
    }
    Ok(ImportTable { descriptors })
}

pub fn parse_imports_from_optional(
    data: &[u8],
    sections: &[SectionHeader],
    opt: &OptionalHeader,
) -> Result<ImportTable> {
    match opt.import_directory() {
        Some(dir) => parse_import_directory(data, sections, opt, dir),
        None => Ok(ImportTable {
            descriptors: Vec::new(),
        }),
    }
}

pub fn validate_imports(imports: &ImportTable) -> Result<()> {
    for desc in &imports.descriptors {
        if desc.dll_name.is_empty() {
            return Err(Error::validation("empty dll name"));
        }
        if !desc.dll_name.is_ascii() {
            return Err(Error::validation("dll name ascii"));
        }
        for entry in &desc.entries {
            match &entry.symbol {
                ImportSymbol::ByName { name, .. } => {
                    if name.is_empty() || !name.is_ascii() {
                        return Err(Error::validation("import symbol name"));
                    }
                }
                ImportSymbol::ByOrdinal { ordinal } => {
                    if *ordinal == 0 {
                        return Err(Error::validation("ordinal zero"));
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn imports_contain_dll(imports: &ImportTable, dll: &str) -> bool {
    let needle = dll.to_ascii_lowercase();
    imports.descriptors.iter().any(|d| d.dll_name.to_ascii_lowercase() == needle)
}

pub fn format_import_summary(imports: &ImportTable) -> String {
    let mut s = String::new();
    s.push_str("imports=");
    push_u64(&mut s, imports.dll_count() as u64);
    for desc in &imports.descriptors {
        s.push(' ');
        s.push_str(&desc.dll_name);
        s.push('(');
        push_u64(&mut s, desc.entries.len() as u64);
        s.push(')');
    }
    s
}

fn push_u64(s: &mut String, mut v: u64) {
    if v == 0 {
        s.push('0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut len = 0;
    while v > 0 {
        buf[len] = (v % 10) as u8 + b'0';
        len += 1;
        v /= 10;
    }
    while len > 0 {
        len -= 1;
        s.push(buf[len] as char);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::header::{DataDirectory, IMAGE_NT_OPTIONAL_HDR64_MAGIC};

    #[test]
    fn empty_imports() {
        let opt = OptionalHeader {
            magic: IMAGE_NT_OPTIONAL_HDR64_MAGIC,
            major_linker_version: 0,
            minor_linker_version: 0,
            size_of_code: 0,
            size_of_initialized_data: 0,
            size_of_uninitialized_data: 0,
            address_of_entry_point: 0,
            base_of_code: 0,
            base_of_data: 0,
            image_base: 0x140000000,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            major_os_version: 0,
            minor_os_version: 0,
            major_image_version: 0,
            minor_image_version: 0,
            major_subsystem_version: 0,
            minor_subsystem_version: 0,
            win32_version_value: 0,
            size_of_image: 0x3000,
            size_of_headers: 0x400,
            check_sum: 0,
            subsystem: 3,
            dll_characteristics: 0,
            size_of_stack_reserve: 0,
            size_of_stack_commit: 0,
            size_of_heap_reserve: 0,
            size_of_heap_commit: 0,
            loader_flags: 0,
            number_of_rva_and_sizes: 16,
            data_directories: vec![
                DataDirectory {
                    virtual_address: 0,
                    size: 0,
                },
                DataDirectory {
                    virtual_address: 0,
                    size: 0,
                },
            ],
        };
        let table = parse_imports_from_optional(&[], &[], &opt).unwrap();
        assert_eq!(table.dll_count(), 0);
    }
}
