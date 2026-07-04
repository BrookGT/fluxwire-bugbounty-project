//! Percent-encoding for policy URIs and attestation claim fields.

use crate::error::{Error, Result};
use crate::util::GrowableBuffer;

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn hex_nibble(v: u8) -> u8 {
    match v {
        0..=9 => b'0' + v,
        10..=15 => b'A' + (v - 10),
        _ => b'0',
    }
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-encode bytes, leaving unreserved characters literal.
pub fn encode(input: &[u8]) -> alloc::vec::Vec<u8> {
    let mut out = GrowableBuffer::with_capacity(input.len());
    for &b in input {
        if is_unreserved(b) {
            let _ = out.push(b);
        } else {
            let _ = out.push(b'%');
            let _ = out.push(hex_nibble(b >> 4));
            let _ = out.push(hex_nibble(b & 0x0f));
        }
    }
    out.into_vec()
}

/// Decode percent-encoded bytes. `+` is treated as space when `plus_as_space` is true.
pub fn decode(input: &[u8], plus_as_space: bool) -> Result<alloc::vec::Vec<u8>> {
    let mut out = GrowableBuffer::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        if b == b'%' {
            let hi = input
                .get(i + 1)
                .copied()
                .and_then(hex_value)
                .ok_or_else(Error::invalid_syntax)?;
            let lo = input
                .get(i + 2)
                .copied()
                .and_then(hex_value)
                .ok_or_else(Error::invalid_syntax)?;
            out.push((hi << 4) | lo)?;
            i += 3;
        } else if plus_as_space && b == b'+' {
            out.push(b' ')?;
            i += 1;
        } else {
            out.push(b)?;
            i += 1;
        }
    }
    Ok(out.into_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let raw = b"sha256:dead/beef";
        let enc = encode(raw);
        assert_eq!(decode(&enc, false).unwrap(), raw);
    }

    #[test]
    fn plus_as_space() {
        assert_eq!(decode(b"policy+id", true).unwrap(), b"policy id");
    }

    #[test]
    fn invalid_escape() {
        assert!(decode(b"%GG", false).is_err());
    }
}
