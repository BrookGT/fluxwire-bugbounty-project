//! Handwritten CBOR decoder (RFC 8949 subset for attestation records).

use alloc::string::String;
use alloc::vec::Vec;

use crate::cbor::value::Value;
use crate::error::{Error, Result};
use crate::util::SliceCursor;

/// Maximum nesting depth for arrays, maps, and tags.
pub const MAX_DEPTH: usize = 64;
/// Maximum items in a single array or map.
pub const MAX_ITEMS: usize = 65_536;
/// Maximum byte/text chunk length accepted in one read.
pub const MAX_CHUNK: usize = 8 * 1024 * 1024;

const MT_UINT: u8 = 0;
const MT_NEGINT: u8 = 1;
const MT_BYTES: u8 = 2;
const MT_TEXT: u8 = 3;
const MT_ARRAY: u8 = 4;
const MT_MAP: u8 = 5;
const MT_TAG: u8 = 6;
const MT_SIMPLE: u8 = 7;

const SIMPLE_FALSE: u8 = 20;
const SIMPLE_TRUE: u8 = 21;
const SIMPLE_NULL: u8 = 22;
const SIMPLE_UNDEF: u8 = 23;
const SIMPLE_FLOAT16: u8 = 25;
const SIMPLE_FLOAT32: u8 = 26;
const SIMPLE_FLOAT64: u8 = 27;
const SIMPLE_BREAK: u8 = 31;

/// Decode one CBOR item from `data`, returning the value and bytes consumed.
pub fn decode_one(data: &[u8]) -> Result<(Value, usize)> {
    let mut cur = SliceCursor::new(data);
    let value = decode_value(&mut cur, 0)?;
    Ok((value, cur.consumed()))
}

/// Decode all CBOR items in `data` until EOF.
pub fn decode_all(data: &[u8]) -> Result<Vec<Value>> {
    let mut cur = SliceCursor::new(data);
    let mut out = Vec::new();
    while !cur.is_empty() {
        out.push(decode_value(&mut cur, 0)?);
        if out.len() > MAX_ITEMS {
            return Err(Error::limit_exceeded());
        }
    }
    Ok(out)
}

fn decode_value(cur: &mut SliceCursor<'_>, depth: usize) -> Result<Value> {
    if depth > MAX_DEPTH {
        return Err(Error::limit_exceeded());
    }
    let initial = cur.consume()?;
    let major = initial >> 5;
    let info = initial & 0x1f;
    match major {
        MT_UINT => decode_uint(info, cur).map(Value::Uint),
        MT_NEGINT => decode_uint(info, cur).map(|n| Value::Int(-1 - (n as i64))),
        MT_BYTES => decode_bytes(info, cur).map(Value::Bytes),
        MT_TEXT => decode_text(info, cur).map(Value::Text),
        MT_ARRAY => decode_array(cur, info, depth).map(Value::Array),
        MT_MAP => decode_map(cur, info, depth).map(Value::Map),
        MT_TAG => {
            let tag = decode_uint(info, cur)?;
            let inner = decode_value(cur, depth + 1)?;
            Ok(Value::Tag(tag, alloc::boxed::Box::new(inner)))
        }
        MT_SIMPLE => decode_simple(info, cur),
        _ => Err(Error::invalid_syntax()),
    }
}

fn decode_uint(info: u8, cur: &mut SliceCursor<'_>) -> Result<u64> {
    match info {
        0..=23 => Ok(info as u64),
        24 => Ok(cur.read_u8()? as u64),
        25 => Ok(cur.read_u16_be()? as u64),
        26 => Ok(cur.read_u32_be()? as u64),
        27 => Ok(cur.read_u64_be()?),
        31 => Err(Error::invalid_syntax()),
        _ => Err(Error::invalid_syntax()),
    }
}

fn decode_bytes(info: u8, cur: &mut SliceCursor<'_>) -> Result<Vec<u8>> {
    if info == SIMPLE_BREAK {
        return decode_bytes_indefinite(cur);
    }
    let len = decode_uint(info, cur)? as usize;
    read_chunk(cur, len)
}

fn decode_text(info: u8, cur: &mut SliceCursor<'_>) -> Result<String> {
    if info == SIMPLE_BREAK {
        let chunks = decode_bytes_indefinite(cur)?;
        return String::from_utf8(chunks).map_err(|_| Error::invalid_syntax());
    }
    let len = decode_uint(info, cur)? as usize;
    let bytes = read_chunk(cur, len)?;
    String::from_utf8(bytes).map_err(|_| Error::invalid_syntax())
}

fn read_chunk(cur: &mut SliceCursor<'_>, len: usize) -> Result<Vec<u8>> {
    if len > MAX_CHUNK {
        return Err(Error::limit_exceeded());
    }
    let slice = cur
        .peek_slice(len)
        .ok_or_else(Error::unexpected_eof)?;
    let mut out = Vec::with_capacity(len);
    unsafe {
        out.set_len(len);
        core::ptr::copy_nonoverlapping(slice.as_ptr(), out.as_mut_ptr(), len);
    }
    cur.advance(len)?;
    Ok(out)
}

fn decode_bytes_indefinite(cur: &mut SliceCursor<'_>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let b = cur.peek().ok_or_else(Error::unexpected_eof)?;
        if b == 0xff {
            cur.advance(1)?;
            break;
        }
        let initial = cur.consume()?;
        let major = initial >> 5;
        let info = initial & 0x1f;
        if major != MT_BYTES {
            return Err(Error::invalid_syntax());
        }
        let chunk = if info == SIMPLE_BREAK {
            return Err(Error::invalid_syntax());
        } else {
            let len = decode_uint(info, cur)? as usize;
            read_chunk(cur, len)?
        };
        if out.len() + chunk.len() > MAX_CHUNK {
            return Err(Error::limit_exceeded());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

fn decode_array(cur: &mut SliceCursor<'_>, info: u8, depth: usize) -> Result<Vec<Value>> {
    if info == SIMPLE_BREAK {
        return decode_array_indefinite(cur, depth);
    }
    let count = decode_uint(info, cur)? as usize;
    if count > MAX_ITEMS {
        return Err(Error::limit_exceeded());
    }
    let mut items = Vec::with_capacity(count.min(16));
    for _ in 0..count {
        items.push(decode_value(cur, depth + 1)?);
    }
    Ok(items)
}

fn decode_array_indefinite(cur: &mut SliceCursor<'_>, depth: usize) -> Result<Vec<Value>> {
    let mut items = Vec::new();
    loop {
        let b = cur.peek().ok_or_else(Error::unexpected_eof)?;
        if b == 0xff {
            cur.advance(1)?;
            break;
        }
        items.push(decode_value(cur, depth + 1)?);
        if items.len() > MAX_ITEMS {
            return Err(Error::limit_exceeded());
        }
    }
    Ok(items)
}

fn decode_map(cur: &mut SliceCursor<'_>, info: u8, depth: usize) -> Result<Vec<(Value, Value)>> {
    if info == SIMPLE_BREAK {
        return decode_map_indefinite(cur, depth);
    }
    let count = decode_uint(info, cur)? as usize;
    if count > MAX_ITEMS {
        return Err(Error::limit_exceeded());
    }
    let mut entries = Vec::with_capacity(count.min(16));
    for _ in 0..count {
        let key = decode_value(cur, depth + 1)?;
        let val = decode_value(cur, depth + 1)?;
        entries.push((key, val));
    }
    Ok(entries)
}

fn decode_map_indefinite(cur: &mut SliceCursor<'_>, depth: usize) -> Result<Vec<(Value, Value)>> {
    let mut entries = Vec::new();
    loop {
        let b = cur.peek().ok_or_else(Error::unexpected_eof)?;
        if b == 0xff {
            cur.advance(1)?;
            break;
        }
        let key = decode_value(cur, depth + 1)?;
        let val = decode_value(cur, depth + 1)?;
        entries.push((key, val));
        if entries.len() > MAX_ITEMS {
            return Err(Error::limit_exceeded());
        }
    }
    Ok(entries)
}

fn decode_simple(info: u8, cur: &mut SliceCursor<'_>) -> Result<Value> {
    match info {
        SIMPLE_FALSE => Ok(Value::Int(0)),
        SIMPLE_TRUE => Ok(Value::Int(1)),
        SIMPLE_NULL => Ok(Value::Uint(0)),
        SIMPLE_UNDEF => Ok(Value::Text(String::new())),
        SIMPLE_FLOAT16 => {
            let bits = cur.read_u16_be()?;
            Ok(Value::Float(f16_to_f64(bits)))
        }
        SIMPLE_FLOAT32 => {
            let bytes = cur.read_bytes(4)?;
            Ok(Value::Float(f32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as f64))
        }
        SIMPLE_FLOAT64 => {
            let bytes = cur.read_bytes(8)?;
            Ok(Value::Float(f64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ])))
        }
        SIMPLE_BREAK => Err(Error::invalid_syntax()),
        0..=19 => Ok(Value::Uint(info as u64)),
        24 => Ok(Value::Uint(cur.read_u8()? as u64)),
        _ => Err(Error::invalid_syntax()),
    }
}

fn f16_to_f64(bits: u16) -> f64 {
    let sign = (bits >> 15) & 1;
    let exp = (bits >> 10) & 0x1f;
    let frac = bits & 0x3ff;
    if exp == 0 {
        if frac == 0 {
            return if sign == 1 { -0.0 } else { 0.0 };
        }
        let val = (frac as f64) * 2f64.powi(-24);
        return if sign == 1 { -val } else { val };
    }
    if exp == 31 {
        if frac == 0 {
            return if sign == 1 { f64::NEG_INFINITY } else { f64::INFINITY };
        }
        return f64::NAN;
    }
    let val = (1.0 + (frac as f64) / 1024.0) * 2f64.powi(exp as i32 - 15);
    if sign == 1 { -val } else { val }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_uint_inline() {
        let (v, n) = decode_one(&[0x00]).unwrap();
        assert_eq!(v, Value::Uint(0));
        assert_eq!(n, 1);
        let (v, _) = decode_one(&[0x18, 0xff]).unwrap();
        assert_eq!(v, Value::Uint(255));
    }

    #[test]
    fn decode_negative_int() {
        let (v, _) = decode_one(&[0x20]).unwrap();
        assert_eq!(v, Value::Int(-1));
        let (v, _) = decode_one(&[0x39, 0x03]).unwrap();
        assert_eq!(v, Value::Int(-4));
    }

    #[test]
    fn decode_text_and_bytes() {
        let (v, _) = decode_one(&[0x64, b'i', b's', b's', b'u', b'e']).unwrap();
        assert_eq!(v, Value::Text(String::from("issue")));
        let (v, _) = decode_one(&[0x44, 1, 2, 3, 4]).unwrap();
        assert_eq!(v, Value::Bytes(alloc::vec![1, 2, 3, 4]));
    }

    #[test]
    fn decode_claim_map() {
        let data = [
            0xa2, 0x66, b'i', b's', b's', b'u', b'e', b'r', 0x66, b's', b'a', b'n', b'd', b'f',
            b'o', b'r', b'g', b'e', 0x67, b's', b'u', b'b', b'j', b'e', b'c', b't', 0x63,
            b'e', b'l', b'f',
        ];
        let (v, _) = decode_one(&data).unwrap();
        let map = v.as_map().unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(v.claim("issuer").and_then(Value::as_text), Some("sandforge"));
    }

    #[test]
    fn decode_tagged_epoch() {
        let (v, _) = decode_one(&[0xc1, 0x18, 0x2a]).unwrap();
        match v {
            Value::Tag(1, inner) => assert_eq!(*inner, Value::Uint(42)),
            _ => panic!("expected tag"),
        }
    }

    #[test]
    fn depth_limit() {
        let mut data = alloc::vec::Vec::new();
        for _ in 0..(MAX_DEPTH + 2) {
            data.push(0x81);
        }
        data.push(0x00);
        for _ in 0..(MAX_DEPTH + 2) {
            data.push(0xff);
        }
        assert!(decode_one(&data).is_err());
    }
}
