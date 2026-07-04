//! WASM section identifiers and payload decoders.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::util::SliceCursor;

/// Known WASM section identifiers (WebAssembly core spec).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionId {
    Custom = 0,
    Type = 1,
    Import = 2,
    Function = 3,
    Table = 4,
    Memory = 5,
    Global = 6,
    Export = 7,
    Start = 8,
    Element = 9,
    Code = 10,
    Data = 11,
    DataCount = 12,
}

impl SectionId {
    pub fn from_u8(id: u8) -> Result<Self> {
        match id {
            0 => Ok(Self::Custom),
            1 => Ok(Self::Type),
            2 => Ok(Self::Import),
            3 => Ok(Self::Function),
            4 => Ok(Self::Table),
            5 => Ok(Self::Memory),
            6 => Ok(Self::Global),
            7 => Ok(Self::Export),
            8 => Ok(Self::Start),
            9 => Ok(Self::Element),
            10 => Ok(Self::Code),
            11 => Ok(Self::Data),
            12 => Ok(Self::DataCount),
            _ => Err(Error::UnknownSection { id }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionHeader {
    pub id: SectionId,
    pub payload_len: u32,
    pub payload_offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValType {
    I32 = 0x7f,
    I64 = 0x7e,
    F32 = 0x7d,
    F64 = 0x7c,
    V128 = 0x7b,
    FuncRef = 0x70,
    ExternRef = 0x6f,
}

impl ValType {
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0x7f => Ok(Self::I32),
            0x7e => Ok(Self::I64),
            0x7d => Ok(Self::F32),
            0x7c => Ok(Self::F64),
            0x7b => Ok(Self::V128),
            0x70 => Ok(Self::FuncRef),
            0x6f => Ok(Self::ExternRef),
            _ => Err(Error::wasm_validation("unknown value type")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeEntry {
    pub params: Vec<ValType>,
    pub results: Vec<ValType>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeSection {
    pub entries: Vec<TypeEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportDesc {
    Function { type_index: u32 },
    Table { elem_type: ValType, limits: MemoryLimits },
    Memory { limits: MemoryLimits },
    Global { val_type: ValType, mutable: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportEntry {
    pub module: String,
    pub name: String,
    pub desc: ImportDesc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSection {
    pub entries: Vec<ImportEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSection {
    pub type_indices: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryLimits {
    pub min_pages: u32,
    pub max_pages: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryEntry {
    pub limits: MemoryLimits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemorySection {
    pub memories: Vec<MemoryEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportDesc {
    Function(u32),
    Table(u32),
    Memory(u32),
    Global(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportEntry {
    pub name: String,
    pub desc: ExportDesc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportSection {
    pub entries: Vec<ExportEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeBody {
    pub locals_count: u32,
    pub body_len: u32,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSection {
    pub bodies: Vec<CodeBody>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSegment {
    pub memory_index: u32,
    pub offset_expr: Vec<u8>,
    pub init_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSection {
    pub segments: Vec<DataSegment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomSection {
    pub name: String,
    pub payload: Vec<u8>,
}

pub fn parse_section_header(cur: &mut SliceCursor<'_>) -> Result<SectionHeader> {
    let id_byte = cur.read_u8()?;
    let id = SectionId::from_u8(id_byte)?;
    let payload_len = cur.read_leb128_u32()?;
    let payload_offset = cur.position();
    Ok(SectionHeader {
        id,
        payload_len,
        payload_offset,
    })
}

pub fn parse_limits(cur: &mut SliceCursor<'_>) -> Result<MemoryLimits> {
    let flags = cur.read_u8()?;
    let min_pages = cur.read_leb128_u32()?;
    let max_pages = if flags & 1 != 0 {
        Some(cur.read_leb128_u32()?)
    } else {
        None
    };
    Ok(MemoryLimits {
        min_pages,
        max_pages,
    })
}

pub fn parse_type_section(payload: &[u8]) -> Result<TypeSection> {
    let mut cur = SliceCursor::new(payload);
    let count = cur.read_leb128_u32()? as usize;
    let mut entries = Vec::with_capacity(count.min(256));
    for _ in 0..count {
        let form = cur.read_u8()?;
        if form != 0x60 {
            return Err(Error::wasm_validation("unsupported function type form"));
        }
        let param_count = cur.read_leb128_u32()? as usize;
        let mut params = Vec::with_capacity(param_count.min(32));
        for _ in 0..param_count {
            params.push(ValType::from_byte(cur.read_u8()?)?);
        }
        let result_count = cur.read_leb128_u32()? as usize;
        if result_count > 1 {
            return Err(Error::wasm_validation("multi-value not supported in this validator"));
        }
        let mut results = Vec::with_capacity(result_count);
        for _ in 0..result_count {
            results.push(ValType::from_byte(cur.read_u8()?)?);
        }
        entries.push(TypeEntry { params, results });
    }
    Ok(TypeSection { entries })
}

pub fn parse_import_section(payload: &[u8]) -> Result<ImportSection> {
    let mut cur = SliceCursor::new(payload);
    let count = cur.read_leb128_u32()? as usize;
    let mut entries = Vec::with_capacity(count.min(128));
    for _ in 0..count {
        let module = read_wasm_name(&mut cur)?;
        let name = read_wasm_name(&mut cur)?;
        let desc_byte = cur.read_u8()?;
        let desc = match desc_byte {
            0x00 => ImportDesc::Function {
                type_index: cur.read_leb128_u32()?,
            },
            0x01 => {
                let elem_type = ValType::from_byte(cur.read_u8()?)?;
                let limits = parse_limits(&mut cur)?;
                ImportDesc::Table {
                    elem_type,
                    limits,
                }
            }
            0x02 => ImportDesc::Memory {
                limits: parse_limits(&mut cur)?,
            },
            0x03 => ImportDesc::Global {
                val_type: ValType::from_byte(cur.read_u8()?)?,
                mutable: cur.read_u8()? != 0,
            },
            _ => {
                return Err(Error::wasm_validation("unknown import descriptor"))
            }
        };
        entries.push(ImportEntry { module, name, desc });
    }
    Ok(ImportSection { entries })
}

pub fn parse_function_section(payload: &[u8]) -> Result<FunctionSection> {
    let mut cur = SliceCursor::new(payload);
    let count = cur.read_leb128_u32()? as usize;
    let mut type_indices = Vec::with_capacity(count.min(512));
    for _ in 0..count {
        type_indices.push(cur.read_leb128_u32()?);
    }
    Ok(FunctionSection { type_indices })
}

pub fn parse_memory_section(payload: &[u8]) -> Result<MemorySection> {
    let mut cur = SliceCursor::new(payload);
    let count = cur.read_leb128_u32()? as usize;
    let mut memories = Vec::with_capacity(count.min(8));
    for _ in 0..count {
        memories.push(MemoryEntry {
            limits: parse_limits(&mut cur)?,
        });
    }
    Ok(MemorySection { memories })
}

pub fn parse_export_section(payload: &[u8]) -> Result<ExportSection> {
    let mut cur = SliceCursor::new(payload);
    let count = cur.read_leb128_u32()? as usize;
    let mut entries = Vec::with_capacity(count.min(256));
    for _ in 0..count {
        let name = read_wasm_name(&mut cur)?;
        let kind = cur.read_u8()?;
        let index = cur.read_leb128_u32()?;
        let desc = match kind {
            0x00 => ExportDesc::Function(index),
            0x01 => ExportDesc::Table(index),
            0x02 => ExportDesc::Memory(index),
            0x03 => ExportDesc::Global(index),
            _ => {
                return Err(Error::wasm_validation("unknown export kind"))
            }
        };
        entries.push(ExportEntry { name, desc });
    }
    Ok(ExportSection { entries })
}

pub fn parse_code_section(payload: &[u8]) -> Result<CodeSection> {
    let mut cur = SliceCursor::new(payload);
    let count = cur.read_leb128_u32()? as usize;
    let mut bodies = Vec::with_capacity(count.min(512));
    for _ in 0..count {
        let body_size = cur.read_leb128_u32()? as usize;
        let body_start = cur.position();
        let local_count = cur.read_leb128_u32()?;
        for _ in 0..local_count {
            let _n = cur.read_leb128_u32()?;
            let _ty = cur.read_u8()?;
        }
        let consumed = cur.position() - body_start;
        let code_len = body_size.saturating_sub(consumed);
        let code = cur.read_bytes(code_len)?.to_vec();
        bodies.push(CodeBody {
            locals_count: local_count,
            body_len: code_len as u32,
            body: code,
        });
    }
    Ok(CodeSection { bodies })
}

pub fn parse_data_section(payload: &[u8]) -> Result<DataSection> {
    let mut cur = SliceCursor::new(payload);
    let count = cur.read_leb128_u32()? as usize;
    let mut segments = Vec::with_capacity(count.min(64));
    for _ in 0..count {
        let memory_index = cur.read_leb128_u32()?;
        let offset_expr = read_init_expr(&mut cur)?;
        let init_len = cur.read_leb128_u32()? as usize;
        let init_bytes = cur.read_bytes(init_len)?.to_vec();
        segments.push(DataSegment {
            memory_index,
            offset_expr,
            init_bytes,
        });
    }
    Ok(DataSection { segments })
}

pub fn parse_custom_section(payload: &[u8]) -> Result<CustomSection> {
    let mut cur = SliceCursor::new(payload);
    let name = read_wasm_name(&mut cur)?;
    let rest = cur.rest().to_vec();
    Ok(CustomSection {
        name,
        payload: rest,
    })
}

fn read_wasm_name(cur: &mut SliceCursor<'_>) -> Result<String> {
    let len = cur.read_leb128_u32()? as usize;
    let bytes = cur.read_bytes(len)?;
    let s = core::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
    Ok(String::from(s))
}

fn read_init_expr(cur: &mut SliceCursor<'_>) -> Result<Vec<u8>> {
    let mut expr = Vec::new();
    loop {
        let op = cur.read_u8()?;
        expr.push(op);
        if op == 0x0b {
            break;
        }
        if op == 0x41 || op == 0x42 {
            let _ = cur.read_leb128_i32()?;
        }
    }
    Ok(expr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_empty_type_section() {
        let payload = [0x00];
        let sec = parse_type_section(&payload).unwrap();
        assert!(sec.entries.is_empty());
    }

    #[test]
    fn rejects_unknown_section_id() {
        assert!(SectionId::from_u8(99).is_err());
    }
}
