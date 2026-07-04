//! Hexadecimal encode and decode for digest and fingerprint fields.

use crate::error::{Error, Result};
use crate::util::GrowableBuffer;

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Encode bytes as lowercase hex.
pub fn encode(input: &[u8]) -> alloc::vec::Vec<u8> {
    let mut out = GrowableBuffer::with_capacity(input.len() * 2);
    for &b in input {
        let _ = out.push(HEX_LOWER[(b >> 4) as usize]);
        let _ = out.push(HEX_LOWER[(b & 0x0f) as usize]);
    }
    out.into_vec()
}

/// Decode hex bytes. Optional `0x` prefix is skipped.
pub fn decode(input: &[u8]) -> Result<alloc::vec::Vec<u8>> {
    let mut data = input;
    if data.len() >= 2 && data[0] == b'0' && (data[1] == b'x' || data[1] == b'X') {
        data = &data[2..];
    }
    if data.len() % 2 != 0 {
        return Err(Error::invalid_syntax());
    }
    let mut out = GrowableBuffer::with_capacity(data.len() / 2);
    let mut i = 0;
    while i < data.len() {
        let hi = hex_value(data[i]).ok_or_else(Error::invalid_syntax)?;
        let lo = hex_value(data[i + 1]).ok_or_else(Error::invalid_syntax)?;
        out.push((hi << 4) | lo)?;
        i += 2;
    }
    Ok(out.into_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let raw = b"\x01\x02\xff";
        assert_eq!(decode(&encode(raw)).unwrap(), raw);
    }

    #[test]
    fn prefix_skipped() {
        assert_eq!(decode(b"0x6162").unwrap(), b"ab");
    }

    #[test]
    fn odd_length_rejected() {
        assert!(decode(b"abc").is_err());
    }
}
