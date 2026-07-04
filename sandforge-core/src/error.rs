//! Error types for sandbox artifact verification parsers.

extern crate alloc;

use alloc::string::String;
use core::fmt;

/// Lightweight error kind used across sandforge-core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    UnexpectedEof,
    InvalidSyntax,
    OutOfRange,
    LimitExceeded,
    BadMagic,
    BadTag,
    InvalidTicket,
    Validation,
    Internal,
}

/// Crate-wide result type.
pub type Result<T> = core::result::Result<T, Error>;

/// Structured error with kind and optional context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    UnexpectedEof,
    InvalidSyntax,
    InvalidUtf8,
    LimitExceeded { context: Option<String> },
    BadMagic {
        expected: &'static str,
        found: u64,
    },
    BadTag {
        expected: u64,
        found: u64,
    },
    InvalidTicket,
    Validation(&'static str),
    Structure(&'static str),
    Unsupported {
        what: &'static str,
        detail: u32,
    },
    OutOfRange {
        field: &'static str,
        value: u64,
        limit: u64,
    },
    Bounds {
        field: &'static str,
        offset: u64,
        len: u64,
    },
    UnknownSection {
        id: u8,
    },
    UnknownKind {
        kind: u16,
    },
    WasmValidation(&'static str),
    ManifestPolicy(&'static str),
    ArchiveLayout(&'static str),
    Internal(String),
}

impl Error {
    pub fn new(kind: ErrorKind) -> Self {
        match kind {
            ErrorKind::UnexpectedEof => Self::UnexpectedEof,
            ErrorKind::InvalidSyntax => Self::InvalidSyntax,
            ErrorKind::OutOfRange => Self::OutOfRange {
                field: "unknown",
                value: 0,
                limit: 0,
            },
            ErrorKind::LimitExceeded => Self::LimitExceeded { context: None },
            ErrorKind::BadMagic => Self::BadMagic {
                expected: "unknown",
                found: 0,
            },
            ErrorKind::BadTag => Self::BadTag {
                expected: 0,
                found: 0,
            },
            ErrorKind::InvalidTicket => Self::InvalidTicket,
            ErrorKind::Validation => Self::Validation("validation failed"),
            ErrorKind::Internal => Self::Internal(String::new()),
        }
    }

    pub fn with_context(kind: ErrorKind, context: impl Into<String>) -> Self {
        let ctx = context.into();
        match kind {
            ErrorKind::LimitExceeded => Self::LimitExceeded {
                context: Some(ctx),
            },
            ErrorKind::BadMagic => Self::BadMagic {
                expected: "unknown",
                found: 0,
            },
            ErrorKind::Validation => Self::Validation(leak_static(&ctx)),
            ErrorKind::Internal => Self::Internal(ctx),
            other => {
                let _ = ctx;
                Self::new(other)
            }
        }
    }

    pub fn unexpected_eof() -> Self {
        Self::UnexpectedEof
    }

    pub fn invalid_syntax() -> Self {
        Self::InvalidSyntax
    }

    pub fn limit_exceeded() -> Self {
        Self::LimitExceeded { context: None }
    }

    pub fn bad_magic(expected: &'static str) -> Self {
        Self::BadMagic {
            expected,
            found: 0,
        }
    }

    pub fn invalid_ticket() -> Self {
        Self::InvalidTicket
    }

    pub fn validation(rule: &'static str) -> Self {
        Self::Validation(rule)
    }

    pub fn structure(detail: &'static str) -> Self {
        Self::Structure(detail)
    }

    pub fn bounds(field: &'static str, offset: u64, len: u64) -> Self {
        Self::Bounds { field, offset, len }
    }

    pub fn length_overflow(field: &'static str, declared: u64, available: u64) -> Self {
        Self::OutOfRange {
            field,
            value: declared,
            limit: available,
        }
    }

    pub fn out_of_range(field: &'static str, value: u64, max: u64) -> Self {
        Self::OutOfRange {
            field,
            value,
            limit: max,
        }
    }

    pub fn invalid_structure(detail: &'static str) -> Self {
        Self::Structure(detail)
    }

    pub fn wasm_validation(detail: &'static str) -> Self {
        Self::WasmValidation(detail)
    }

    pub fn manifest_policy(detail: &'static str) -> Self {
        Self::ManifestPolicy(detail)
    }

    pub fn archive_layout(detail: &'static str) -> Self {
        Self::ArchiveLayout(detail)
    }

    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::UnexpectedEof => ErrorKind::UnexpectedEof,
            Self::InvalidSyntax | Self::InvalidUtf8 => ErrorKind::InvalidSyntax,
            Self::LimitExceeded { .. } => ErrorKind::LimitExceeded,
            Self::BadMagic { .. } => ErrorKind::BadMagic,
            Self::BadTag { .. } => ErrorKind::BadTag,
            Self::InvalidTicket => ErrorKind::InvalidTicket,
            Self::Validation(_) | Self::Structure(_) | Self::WasmValidation(_)
            | Self::ManifestPolicy(_) | Self::ArchiveLayout(_) | Self::UnknownSection { .. }
            | Self::UnknownKind { .. } => ErrorKind::Validation,
            Self::Unsupported { .. } | Self::OutOfRange { .. } | Self::Bounds { .. } => {
                ErrorKind::OutOfRange
            }
            Self::Internal(_) => ErrorKind::Internal,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of input"),
            Self::InvalidSyntax => write!(f, "invalid syntax"),
            Self::InvalidUtf8 => write!(f, "invalid utf-8"),
            Self::LimitExceeded { context } => {
                write!(f, "limit exceeded")?;
                if let Some(c) = context {
                    write!(f, ": {c}")?;
                }
                Ok(())
            }
            Self::BadMagic { expected, found } => {
                write!(f, "bad magic: expected {expected}, found {found:#x}")
            }
            Self::BadTag { expected, found } => {
                write!(f, "bad tag: expected {expected}, found {found}")
            }
            Self::InvalidTicket => write!(f, "invalid ticket"),
            Self::Validation(rule) => write!(f, "validation: {rule}"),
            Self::Structure(detail) => write!(f, "structure: {detail}"),
            Self::Unsupported { what, detail } => {
                write!(f, "unsupported {what}: {detail}")
            }
            Self::OutOfRange { field, value, limit } => {
                write!(f, "{field}: value {value} exceeds limit {limit}")
            }
            Self::Bounds { field, offset, len } => {
                write!(f, "{field}: bounds [{offset}, {len})")
            }
            Self::UnknownSection { id } => write!(f, "unknown section {id}"),
            Self::UnknownKind { kind } => write!(f, "unknown kind {kind}"),
            Self::WasmValidation(d) => write!(f, "wasm: {d}"),
            Self::ManifestPolicy(d) => write!(f, "manifest: {d}"),
            Self::ArchiveLayout(d) => write!(f, "archive: {d}"),
            Self::Internal(msg) => write!(f, "internal: {msg}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

fn leak_static(s: &str) -> &'static str {
    let _ = s;
    "validation failed"
}

pub fn magic_from_bytes(magic: [u8; 4]) -> u64 {
    u32::from_le_bytes(magic) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_includes_kind() {
        let e = Error::validation("bad opcode");
        assert!(e.to_string().contains("bad opcode"));
    }

    #[test]
    fn ticket_error() {
        assert_eq!(Error::invalid_ticket().kind(), ErrorKind::InvalidTicket);
    }
}
