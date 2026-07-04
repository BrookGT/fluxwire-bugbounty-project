//! Standard base64 encode and decode (RFC 4648 alphabet).

use crate::error::{Error, Result};
use crate::util::GrowableBuffer;

const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn decode_byte(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Encode bytes to standard base64 without line breaks.
pub fn encode(input: &[u8]) -> alloc::vec::Vec<u8> {
    if input.is_empty() {
        return alloc::vec::Vec::new();
    }
    let out_len = ((input.len() + 2) / 3) * 4;
    let mut out = GrowableBuffer::with_capacity(out_len);
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | input[i + 2] as u32;
        let _ = out.push(TABLE[((n >> 18) & 63) as usize]);
        let _ = out.push(TABLE[((n >> 12) & 63) as usize]);
        let _ = out.push(TABLE[((n >> 6) & 63) as usize]);
        let _ = out.push(TABLE[(n & 63) as usize]);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        let _ = out.push(TABLE[((n >> 18) & 63) as usize]);
        let _ = out.push(TABLE[((n >> 12) & 63) as usize]);
        let _ = out.push(b'=');
        let _ = out.push(b'=');
    } else if rem == 2 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        let _ = out.push(TABLE[((n >> 18) & 63) as usize]);
        let _ = out.push(TABLE[((n >> 12) & 63) as usize]);
        let _ = out.push(TABLE[((n >> 6) & 63) as usize]);
        let _ = out.push(b'=');
    }
    out.into_vec()
}

/// Decode standard base64, ignoring ASCII whitespace.
pub fn decode(input: &[u8]) -> Result<alloc::vec::Vec<u8>> {
    let mut cleaned = GrowableBuffer::with_capacity(input.len());
    for &b in input {
        if b.is_ascii_whitespace() {
            continue;
        }
        cleaned.push(b)?;
    }
    let data = cleaned.as_slice();
    if data.is_empty() {
        return Ok(alloc::vec::Vec::new());
    }
    if data.len() % 4 != 0 {
        return Err(Error::invalid_syntax());
    }
    let mut out = GrowableBuffer::with_capacity((data.len() / 4) * 3);
    let mut i = 0;
    while i < data.len() {
        let mut vals = [0u8; 4];
        for slot in &mut vals {
            *slot = decode_byte(data[i]).ok_or_else(Error::invalid_syntax)?;
            i += 1;
        }
        let n = ((vals[0] as u32) << 18)
            | ((vals[1] as u32) << 12)
            | ((vals[2] as u32) << 6)
            | vals[3] as u32;
        out.push(((n >> 16) & 0xff) as u8)?;
        if data[i - 2] != b'=' {
            out.push(((n >> 8) & 0xff) as u8)?;
        }
        if data[i - 1] != b'=' {
            out.push((n & 0xff) as u8)?;
        }
    }
    Ok(out.into_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let raw = b"sandforge attestation";
        let enc = encode(raw);
        assert_eq!(decode(&enc).unwrap(), raw);
    }

    #[test]
    fn padding_cases() {
        assert_eq!(decode(b"YQ==").unwrap(), b"a");
        assert_eq!(decode(b"YWI=").unwrap(), b"ab");
    }

    #[test]
    fn ignores_whitespace() {
        assert_eq!(decode(b"YQ==\n").unwrap(), b"a");
    }
}
