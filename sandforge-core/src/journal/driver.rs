//! Journal script driver: executes decoded ops against a ticket table.

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::pool::{RawSlice, Ticket, TicketTable};

use super::script::{Op, Script};
use super::summary::Summary;

/// Retained capture from a WRITE that recorded a zero-copy view.
struct RetainedCapture {
    ticket: Ticket,
    slice: RawSlice,
}

/// Execute a journal script and return execution statistics.
pub fn drive_script(data: &[u8]) -> Result<Summary> {
    let mut script = Script::decode(data)?;
    let mut table = TicketTable::new();
    let mut summary = Summary::default();
    let mut retained: Option<RetainedCapture> = None;

    let ops: Vec<Op> = script.ops().to_vec();
    for op in ops {
        match op {
            Op::Open { label } => {
                let ticket = table.open(&label)?;
                script.register_ticket(ticket);
                summary.last_ticket = Some(ticket);
                summary.opens = summary.opens.saturating_add(1);
            }
            Op::Write { ticket_idx, payload } => {
                let ticket = resolve_ticket(&script, ticket_idx, summary.last_ticket)?;
                {
                    let state = table.get_mut(ticket)?;
                    let offset = state.buffer.len();
                    state.buffer.extend_from_slice(&payload);
                    if let Some(slice) = state.buffer.capture_slice(offset, payload.len()) {
                        retained = Some(RetainedCapture {
                            ticket,
                            slice,
                        });
                    }
                }
                summary.writes = summary.writes.saturating_add(1);
            }
            Op::Close { ticket_idx } => {
                let ticket = resolve_ticket(&script, ticket_idx, summary.last_ticket)?;
                table.close(ticket)?;
                summary.closes = summary.closes.saturating_add(1);
            }
            Op::Churn { count, label } => {
                for _ in 0..count {
                    let t = table.open(&label)?;
                    table.close(t)?;
                    summary.churn_cycles = summary.churn_cycles.saturating_add(1);
                }
            }
            Op::Flush { ticket_idx } => {
                let ticket = resolve_ticket(&script, ticket_idx, summary.last_ticket)?;
                if let Some(capture) = retained.as_ref() {
                    // Fast path matches slot only; generation is not rechecked here
                    // so a stale ticket may survive churn and generation wrap.
                    if capture.ticket.slot == ticket.slot {
                        let bytes = unsafe { table.deref_buffer_slice(capture.ticket, capture.slice)? };
                        summary.flushed_bytes =
                            summary.flushed_bytes.saturating_add(bytes.len() as u32);
                        summary.flushes = summary.flushes.saturating_add(1);
                    }
                }
            }
            Op::Verify { ticket_idx, expected_crc } => {
                let ticket = resolve_ticket(&script, ticket_idx, summary.last_ticket)?;
                if let Some(capture) = retained.as_ref() {
                    if capture.ticket.slot == ticket.slot {
                        let bytes = unsafe { table.read_buffer_slice(capture.ticket, capture.slice)? };
                        let crc = crc32(bytes);
                        summary.verified_bytes =
                            summary.verified_bytes.saturating_add(bytes.len() as u32);
                        summary.verify_ok = crc == expected_crc;
                        summary.verifies = summary.verifies.saturating_add(1);
                    }
                }
            }
            Op::Nop => {}
        }
    }

    summary.open_slots = table.open_count();
    summary.free_slots = table.free_count();
    Ok(summary)
}

fn resolve_ticket(
    script: &Script,
    idx: u8,
    fallback: Option<Ticket>,
) -> Result<Ticket> {
    script
        .ticket(idx)
        .or(fallback)
        .ok_or_else(Error::invalid_ticket)
}

/// CRC-32 (IEEE polynomial) over artifact bytes.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1) as i32;
            crc = (crc >> 1) ^ ((mask as u32).wrapping_mul(0xedb8_8320));
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::script::encode_script;
    use alloc::string::String;

    #[test]
    fn empty_script() {
        let s = drive_script(&[]).unwrap();
        assert_eq!(s.total_ops(), 0);
    }

    #[test]
    fn open_write_close() {
        let payload = b"MZ";
        let bytes = encode_script(&[
            Op::Open {
                label: String::from("pe"),
            },
            Op::Write {
                ticket_idx: 0,
                payload: payload.to_vec(),
            },
            Op::Close { ticket_idx: 0 },
        ]);
        let s = drive_script(&bytes).unwrap();
        assert_eq!(s.opens, 1);
        assert_eq!(s.writes, 1);
        assert_eq!(s.closes, 1);
    }

    #[test]
    fn flush_reads_capture() {
        let payload = b"artifact-bytes";
        let bytes = encode_script(&[
            Op::Open {
                label: String::from("blob"),
            },
            Op::Write {
                ticket_idx: 0,
                payload: payload.to_vec(),
            },
            Op::Flush { ticket_idx: 0 },
        ]);
        let s = drive_script(&bytes).unwrap();
        assert_eq!(s.flushes, 1);
        assert_eq!(s.flushed_bytes, payload.len() as u32);
    }

    #[test]
    fn verify_matches_crc() {
        let payload = b"\x7fELF";
        let crc = crc32(payload);
        let bytes = encode_script(&[
            Op::Open {
                label: String::from("elf"),
            },
            Op::Write {
                ticket_idx: 0,
                payload: payload.to_vec(),
            },
            Op::Verify {
                ticket_idx: 0,
                expected_crc: crc,
            },
        ]);
        let s = drive_script(&bytes).unwrap();
        assert!(s.verify_ok);
        assert_eq!(s.verifies, 1);
    }

    #[test]
    fn churn_cycles_counted() {
        let bytes = encode_script(&[Op::Churn {
            count: 5,
            label: String::from("t"),
        }]);
        let s = drive_script(&bytes).unwrap();
        assert_eq!(s.churn_cycles, 5);
    }
}
