//! Top-level WASM module container and validation pipeline.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::util::SliceCursor;

use super::sections::{
    parse_code_section, parse_custom_section, parse_data_section, parse_export_section,
    parse_function_section, parse_import_section, parse_memory_section, parse_section_header,
    parse_type_section, CodeSection, CustomSection, DataSection, ExportSection, FunctionSection,
    ImportSection, MemorySection, SectionHeader, SectionId, TypeSection,
};

pub const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6d];
pub const WASM_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSection {
    pub header: SectionHeader,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WasmModule {
    pub version: u32,
    pub custom_sections: Vec<CustomSection>,
    pub types: Option<TypeSection>,
    pub imports: Option<ImportSection>,
    pub functions: Option<FunctionSection>,
    pub memories: Option<MemorySection>,
    pub exports: Option<ExportSection>,
    pub code: Option<CodeSection>,
    pub data: Option<DataSection>,
    pub raw_sections: Vec<RawSection>,
}

impl WasmModule {
    pub fn function_count(&self) -> usize {
        self.functions
            .as_ref()
            .map(|f| f.type_indices.len())
            .unwrap_or(0)
    }

    pub fn import_function_count(&self) -> usize {
        self.imports
            .as_ref()
            .map(|i| {
                i.entries
                    .iter()
                    .filter(|e| matches!(e.desc, super::sections::ImportDesc::Function { .. }))
                    .count()
            })
            .unwrap_or(0)
    }

    pub fn export_names(&self) -> Vec<&str> {
        self.exports
            .as_ref()
            .map(|e| e.entries.iter().map(|x| x.name.as_str()).collect())
            .unwrap_or_default()
    }

    pub fn has_memory(&self) -> bool {
        self.memories
            .as_ref()
            .is_some_and(|m| !m.memories.is_empty())
    }

    pub fn total_code_bytes(&self) -> usize {
        self.code
            .as_ref()
            .map(|c| c.bodies.iter().map(|b| b.body.len()).sum())
            .unwrap_or(0)
    }
}

/// Parse a WASM binary into a structured module without deep validation.
pub fn parse_wasm(input: &[u8]) -> Result<WasmModule> {
    let mut cur = SliceCursor::new(input);
    let magic = cur.read_exact(4)?;
    if magic != WASM_MAGIC {
        return Err(Error::BadMagic {
            expected: "0x0061736d",
            found: crate::error::magic_from_bytes([
                magic[0], magic[1], magic[2], magic[3],
            ]),
        });
    }
    let version = cur.read_u32_le()?;
    let mut module = WasmModule {
        version,
        ..Default::default()
    };

    while !cur.is_empty() {
        let header = parse_section_header(&mut cur)?;
        let payload = cur.read_bytes(header.payload_len as usize)?.to_vec();
        let raw = RawSection {
            header: header.clone(),
            payload: payload.clone(),
        };
        match header.id {
            SectionId::Custom => {
                module.custom_sections.push(parse_custom_section(&payload)?);
            }
            SectionId::Type => module.types = Some(parse_type_section(&payload)?),
            SectionId::Import => module.imports = Some(parse_import_section(&payload)?),
            SectionId::Function => module.functions = Some(parse_function_section(&payload)?),
            SectionId::Memory => module.memories = Some(parse_memory_section(&payload)?),
            SectionId::Export => module.exports = Some(parse_export_section(&payload)?),
            SectionId::Code => module.code = Some(parse_code_section(&payload)?),
            SectionId::Data => module.data = Some(parse_data_section(&payload)?),
            _ => {}
        }
        module.raw_sections.push(raw);
    }

    Ok(module)
}

/// Parse and run structural validation checks required for sandbox loading.
pub fn parse_and_validate(input: &[u8]) -> Result<WasmModule> {
    let module = parse_wasm(input)?;
    validate_module(&module)?;
    Ok(module)
}

fn validate_module(module: &WasmModule) -> Result<()> {
    if module.version != WASM_VERSION {
        return Err(Error::wasm_validation("unsupported wasm version"));
    }

    validate_section_order(module)?;
    validate_types(module)?;
    validate_imports(module)?;
    validate_functions(module)?;
    validate_memory(module)?;
    validate_exports(module)?;
    validate_code(module)?;
    validate_data(module)?;
    validate_custom_names(module)?;
    Ok(())
}

fn validate_section_order(module: &WasmModule) -> Result<()> {
    let mut last = 0u8;
    for raw in &module.raw_sections {
        let id = raw.header.id as u8;
        if id != 0 && id <= last {
            return Err(Error::wasm_validation("sections out of canonical order"));
        }
        if id != 0 {
            last = id;
        }
    }
    Ok(())
}

fn validate_types(module: &WasmModule) -> Result<()> {
    if let Some(types) = &module.types {
        for (idx, entry) in types.entries.iter().enumerate() {
            if entry.params.len() > 256 {
                return Err(Error::wasm_validation("type param count excessive"));
            }
            if entry.results.len() > 1 {
                return Err(Error::wasm_validation("multi-value result in type entry"));
            }
            let _ = idx;
        }
    }
    Ok(())
}

fn validate_imports(module: &WasmModule) -> Result<()> {
    if let Some(imports) = &module.imports {
        for entry in &imports.entries {
            if entry.module.is_empty() {
                return Err(Error::wasm_validation("import module name empty"));
            }
            if entry.name.is_empty() {
                return Err(Error::wasm_validation("import field name empty"));
            }
            if let super::sections::ImportDesc::Memory { limits } = entry.desc {
                validate_memory_limits(&limits)?;
            }
        }
    }
    Ok(())
}

fn validate_functions(module: &WasmModule) -> Result<()> {
    let type_count = module
        .types
        .as_ref()
        .map(|t| t.entries.len())
        .unwrap_or(0);
    if let Some(functions) = &module.functions {
        for &idx in &functions.type_indices {
            if idx as usize >= type_count {
                return Err(Error::wasm_validation("function type index out of range"));
            }
        }
    }
    Ok(())
}

fn validate_memory(module: &WasmModule) -> Result<()> {
    if let Some(memories) = &module.memories {
        if memories.memories.len() > 1 {
            return Err(Error::wasm_validation("multiple memories not supported"));
        }
        for mem in &memories.memories {
            validate_memory_limits(&mem.limits)?;
        }
    }
    Ok(())
}

fn validate_memory_limits(limits: &super::sections::MemoryLimits) -> Result<()> {
    const MAX_PAGES: u32 = 65536;
    if limits.min_pages > MAX_PAGES {
        return Err(Error::wasm_validation("memory min pages exceed limit"));
    }
    if let Some(max) = limits.max_pages {
        if max < limits.min_pages || max > MAX_PAGES {
            return Err(Error::wasm_validation("memory max pages invalid"));
        }
    }
    Ok(())
}

fn validate_exports(module: &WasmModule) -> Result<()> {
    let import_funcs = module.import_function_count();
    let defined_funcs = module.function_count();
    let total_funcs = import_funcs + defined_funcs;

    if let Some(exports) = &module.exports {
        let mut seen = Vec::new();
        for entry in &exports.entries {
            if entry.name.is_empty() {
                return Err(Error::wasm_validation("export name empty"));
            }
            if seen.iter().any(|n: &String| n == &entry.name) {
                return Err(Error::wasm_validation("duplicate export name"));
            }
            seen.push(entry.name.clone());
            if let super::sections::ExportDesc::Function(idx) = entry.desc {
                if idx as usize >= total_funcs {
                    return Err(Error::wasm_validation("export function index out of range"));
                }
            }
        }
    }
    Ok(())
}

fn validate_code(module: &WasmModule) -> Result<()> {
    let defined = module.function_count();
    if let Some(code) = &module.code {
        if code.bodies.len() != defined {
            return Err(Error::wasm_validation("code section count mismatch"));
        }
        for body in &code.bodies {
            if body.body.is_empty() {
                return Err(Error::wasm_validation("empty function body"));
            }
            if body.body.last() != Some(&0x0b) {
                return Err(Error::wasm_validation("function body missing end opcode"));
            }
        }
    } else if defined > 0 {
        return Err(Error::wasm_validation("functions declared without code section"));
    }
    Ok(())
}

fn validate_data(module: &WasmModule) -> Result<()> {
    if let Some(data) = &module.data {
        let mem_count = module
            .memories
            .as_ref()
            .map(|m| m.memories.len())
            .unwrap_or(0);
        for seg in &data.segments {
            if mem_count == 0 {
                return Err(Error::wasm_validation("data segment without memory"));
            }
            if seg.memory_index as usize >= mem_count {
                return Err(Error::wasm_validation("data segment memory index invalid"));
            }
            if seg.offset_expr.is_empty() || seg.offset_expr.last() != Some(&0x0b) {
                return Err(Error::wasm_validation("data offset expr malformed"));
            }
        }
    }
    Ok(())
}

fn validate_custom_names(module: &WasmModule) -> Result<()> {
    for custom in &module.custom_sections {
        if custom.name.len() > 1024 {
            return Err(Error::wasm_validation("custom section name too long"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_wasm() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&WASM_MAGIC);
        out.extend_from_slice(&WASM_VERSION.to_le_bytes());
        // type section: 0 types
        out.push(1);
        out.push(1);
        out.push(0);
        // function section: 0 functions
        out.push(3);
        out.push(1);
        out.push(0);
        // export section: 0 exports
        out.push(7);
        out.push(1);
        out.push(0);
        // code section: 0 bodies
        out.push(10);
        out.push(1);
        out.push(0);
        out
    }

    #[test]
    fn parses_minimal_module() {
        let wasm = minimal_wasm();
        let module = parse_wasm(&wasm).unwrap();
        assert_eq!(module.version, 1);
        assert_eq!(module.function_count(), 0);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut wasm = minimal_wasm();
        wasm[0] = 0xff;
        assert!(parse_wasm(&wasm).is_err());
    }

    #[test]
    fn validate_accepts_minimal() {
        let wasm = minimal_wasm();
        assert!(parse_and_validate(&wasm).is_ok());
    }
}
