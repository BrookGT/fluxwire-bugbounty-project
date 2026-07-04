//! WebAssembly module parsing and structural validation.

mod module;
mod sections;

pub use module::{WasmModule, parse_and_validate, parse_wasm};
pub use sections::{
    CodeSection, CustomSection, DataSection, ExportDesc, ExportEntry, ExportSection,
    FunctionSection, ImportDesc, ImportEntry, ImportSection, MemoryEntry, MemoryLimits,
    MemorySection, SectionHeader, SectionId, TypeEntry, TypeSection, ValType,
};
