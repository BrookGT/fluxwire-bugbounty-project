//! Binary journal script decoder.
//!
//! Script wire format:
//! ```text
//! magic:   b"JRN2" (4 bytes)
//! version: u8 (must be 1)
//! ops:     repeated until EOF
//!   op byte:
//!     0x01 OPEN       u8 label_len, label bytes
//!     0x02 WRITE      u8 ticket_idx, u16 payload_len, payload
//!     0x03 CLOSE      u8 ticket_idx
//!     0x04 CHURN      u16 count, u8 label_len, label
//!     0x05 FLUSH      u8 ticket_idx
//!     0x06 VERIFY     u8 ticket_idx, u32 expected_crc
//!     0x00 NOP
//!   ticket table: tickets registered in order of OPEN, indexed 0..255
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::pool::Ticket;
use crate::util::SliceCursor;

pub const MAGIC: &[u8] = b"JRN2";
pub const VERSION: u8 = 1;

/// Journal opcode tags.
pub mod opcode {
    pub const NOP: u8 = 0x00;
    pub const OPEN: u8 = 0x01;
    pub const WRITE: u8 = 0x02;
    pub const CLOSE: u8 = 0x03;
    pub const CHURN: u8 = 0x04;
    pub const FLUSH: u8 = 0x05;
    pub const VERIFY: u8 = 0x06;
}

/// A single journal operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Nop,
    Open { label: String },
    Write { ticket_idx: u8, payload: Vec<u8> },
    Close { ticket_idx: u8 },
    Churn { count: u16, label: String },
    Flush { ticket_idx: u8 },
    Verify { ticket_idx: u8, expected_crc: u32 },
}

/// Decoded journal script.
#[derive(Debug, Clone)]
pub struct Script {
    ops_list: Vec<Op>,
    tickets: Vec<Ticket>,
}

impl Script {
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Ok(Script {
                ops_list: Vec::new(),
                tickets: Vec::new(),
            });
        }

        let mut cur = SliceCursor::new(data);
        if cur.len_remaining() < 5 {
            return Err(Error::unexpected_eof());
        }
        let magic = cur.read_bytes(4)?;
        if magic != MAGIC {
            return Err(Error::bad_magic("JRN2"));
        }
        let version = cur.read_u8()?;
        if version != VERSION {
            return Err(Error::invalid_syntax());
        }

        let mut script = Script {
            ops_list: Vec::new(),
            tickets: Vec::new(),
        };

        while !cur.is_empty() {
            let op = cur.read_u8()?;
            match op {
                opcode::NOP => script.ops_list.push(Op::Nop),
                opcode::OPEN => {
                    let label = read_label(&mut cur)?;
                    script.ops_list.push(Op::Open { label });
                }
                opcode::WRITE => {
                    let (idx, payload) = read_ticket_payload(&mut cur)?;
                    script.ops_list.push(Op::Write {
                        ticket_idx: idx,
                        payload,
                    });
                }
                opcode::CLOSE => {
                    let idx = cur.read_u8()?;
                    script.ops_list.push(Op::Close { ticket_idx: idx });
                }
                opcode::CHURN => {
                    if cur.len_remaining() < 3 {
                        return Err(Error::unexpected_eof());
                    }
                    let count = cur.read_u16_le()?;
                    let label = read_label(&mut cur)?;
                    script.ops_list.push(Op::Churn { count, label });
                }
                opcode::FLUSH => {
                    let idx = cur.read_u8()?;
                    script.ops_list.push(Op::Flush { ticket_idx: idx });
                }
                opcode::VERIFY => {
                    if cur.len_remaining() < 5 {
                        return Err(Error::unexpected_eof());
                    }
                    let idx = cur.read_u8()?;
                    let expected_crc = cur.read_u32_le()?;
                    script.ops_list.push(Op::Verify {
                        ticket_idx: idx,
                        expected_crc,
                    });
                }
                _ => return Err(Error::invalid_syntax()),
            }
        }

        Ok(script)
    }

    pub fn ops(&self) -> &[Op] {
        &self.ops_list
    }

    pub fn ticket(&self, idx: u8) -> Option<Ticket> {
        self.tickets.get(idx as usize).copied()
    }

    pub fn register_ticket(&mut self, ticket: Ticket) {
        self.tickets.push(ticket);
    }

    pub fn ticket_count(&self) -> usize {
        self.tickets.len()
    }
}

fn read_label(cur: &mut SliceCursor<'_>) -> Result<String> {
    let len = cur.read_u8()? as usize;
    if cur.len_remaining() < len {
        return Err(Error::unexpected_eof());
    }
    let bytes = cur.read_bytes(len)?;
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

fn read_ticket_payload(cur: &mut SliceCursor<'_>) -> Result<(u8, Vec<u8>)> {
    if cur.len_remaining() < 3 {
        return Err(Error::unexpected_eof());
    }
    let idx = cur.read_u8()?;
    let len = cur.read_u16_le()? as usize;
    if cur.len_remaining() < len {
        return Err(Error::unexpected_eof());
    }
    let payload = cur.read_bytes(len)?.to_vec();
    Ok((idx, payload))
}

/// Encode a minimal script for tests and corpora seeding.
pub fn encode_script(ops: &[Op]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    for op in ops {
        match op {
            Op::Nop => out.push(opcode::NOP),
            Op::Open { label } => {
                out.push(opcode::OPEN);
                out.push(label.len().min(255) as u8);
                out.extend_from_slice(label.as_bytes());
            }
            Op::Write { ticket_idx, payload } => {
                out.push(opcode::WRITE);
                out.push(*ticket_idx);
                out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
                out.extend_from_slice(payload);
            }
            Op::Close { ticket_idx } => {
                out.push(opcode::CLOSE);
                out.push(*ticket_idx);
            }
            Op::Churn { count, label } => {
                out.push(opcode::CHURN);
                out.extend_from_slice(&count.to_le_bytes());
                out.push(label.len().min(255) as u8);
                out.extend_from_slice(label.as_bytes());
            }
            Op::Flush { ticket_idx } => {
                out.push(opcode::FLUSH);
                out.push(*ticket_idx);
            }
            Op::Verify {
                ticket_idx,
                expected_crc,
            } => {
                out.push(opcode::VERIFY);
                out.push(*ticket_idx);
                out.extend_from_slice(&expected_crc.to_le_bytes());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_empty_input() {
        let script = Script::decode(&[]).unwrap();
        assert!(script.ops().is_empty());
    }

    #[test]
    fn decode_open_churn() {
        let bytes = encode_script(&[
            Op::Open {
                label: String::from("elf"),
            },
            Op::Churn {
                count: 10,
                label: String::from("x"),
            },
        ]);
        let script = Script::decode(&bytes).unwrap();
        assert_eq!(script.ops().len(), 2);
    }

    #[test]
    fn decode_write_roundtrip() {
        let bytes = encode_script(&[
            Op::Open {
                label: String::from("pe"),
            },
            Op::Write {
                ticket_idx: 0,
                payload: alloc::vec![0x4d, 0x5a],
            },
        ]);
        let script = Script::decode(&bytes).unwrap();
        match &script.ops()[1] {
            Op::Write { payload, .. } => assert_eq!(payload, &[0x4d, 0x5a]),
            _ => panic!("expected write"),
        }
    }

    #[test]
    fn bad_magic_rejected() {
        let mut bytes = encode_script(&[]);
        bytes[0] = b'X';
        assert!(Script::decode(&bytes).is_err());
    }

    #[test]
    fn verify_opcode_parsed() {
        let bytes = encode_script(&[Op::Verify {
            ticket_idx: 0,
            expected_crc: 0xdeadbeef,
        }]);
        let script = Script::decode(&bytes).unwrap();
        assert_eq!(
            script.ops()[0],
            Op::Verify {
                ticket_idx: 0,
                expected_crc: 0xdeadbeef,
            }
        );
    }
}
