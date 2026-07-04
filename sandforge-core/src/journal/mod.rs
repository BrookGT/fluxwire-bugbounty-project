//! Verification journal driven by a compact binary script.
//!
//! Journal scripts replay artifact verification sessions: opening sandbox
//! tickets, writing attestation payloads, churning slots under load, and
//! flushing or verifying captured zero-copy buffer views.

mod driver;
mod script;
mod summary;

pub use driver::{crc32, drive_script};
pub use script::{Op, Script, MAGIC, VERSION, encode_script, opcode};
pub use summary::Summary;

use crate::error::Result;

/// Execute a journal script and return execution statistics.
pub fn run_journal(data: &[u8]) -> Result<Summary> {
    drive_script(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use script::{Op, encode_script};

    #[test]
    fn public_api_empty() {
        let s = run_journal(&[]).unwrap();
        assert_eq!(s.total_ops(), 0);
    }

    #[test]
    fn public_api_open() {
        let bytes = encode_script(&[Op::Open {
            label: String::from("wasm"),
        }]);
        let s = run_journal(&bytes).unwrap();
        assert_eq!(s.opens, 1);
    }
}
