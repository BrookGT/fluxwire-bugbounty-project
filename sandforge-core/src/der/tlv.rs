//! ASN.1 DER tag-length-value parsing.

extern crate alloc;

use alloc::vec::Vec;
use core::ptr;

use crate::error::{Error, Result};
use crate::util::SliceCursor;

pub const TAG_BOOLEAN: u8 = 0x01;
pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_BIT_STRING: u8 = 0x03;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_NULL: u8 = 0x05;
pub const TAG_OID: u8 = 0x06;
pub const TAG_UTF8_STRING: u8 = 0x0c;
pub const TAG_SEQUENCE: u8 = 0x30;
pub const TAG_SET: u8 = 0x31;
pub const TAG_PRINTABLE_STRING: u8 = 0x13;
pub const TAG_IA5_STRING: u8 = 0x16;
pub const TAG_UTC_TIME: u8 = 0x17;
pub const TAG_GENERALIZED_TIME: u8 = 0x18;

pub const CLASS_UNIVERSAL: u8 = 0x00;
pub const CLASS_APPLICATION: u8 = 0x40;
pub const CLASS_CONTEXT: u8 = 0x80;
pub const CLASS_PRIVATE: u8 = 0xc0;
pub const CONSTRUCTED: u8 = 0x20;

/// Parsed ASN.1 TLV element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub raw_tag: u8,
    pub class: u8,
    pub constructed: bool,
    pub tag_number: u32,
    pub length: usize,
    pub value: &'a [u8],
    pub header_len: usize,
}

impl<'a> Tlv<'a> {
    pub fn is_sequence(&self) -> bool {
        !self.constructed && self.tag_number == TAG_SEQUENCE as u32 && self.class == CLASS_UNIVERSAL
            || self.constructed && self.tag_number == TAG_SEQUENCE as u32
    }

    pub fn universal_tag(&self) -> Option<u8> {
        if self.class == CLASS_UNIVERSAL && self.tag_number < 31 {
            Some(self.tag_number as u8)
        } else {
            None
        }
    }

    pub fn total_len(&self) -> usize {
        self.header_len + self.length
    }
}

/// Decode tag byte(s) from cursor without advancing past tag.
pub fn decode_tag(cursor: &SliceCursor<'_>) -> Result<(u8, bool, u32, usize)> {
    let start = cursor.position();
    let mut cur = *cursor;
    let first = cur.read_u8()?;
    let class = first & CLASS_PRIVATE;
    let constructed = first & CONSTRUCTED != 0;
    let mut tag_number = (first & 0x1f) as u32;
    if tag_number == 0x1f {
        tag_number = 0;
        loop {
            let b = cur.read_u8()?;
            tag_number = tag_number
                .checked_mul(128)
                .and_then(|v| v.checked_add((b & 0x7f) as u32))
                .ok_or_else(Error::limit_exceeded)?;
            if b & 0x80 == 0 {
                break;
            }
            if tag_number > 0x00ff_ffff {
                return Err(Error::BadTag {
                    expected: 0,
                    found: first as u64,
                });
            }
        }
    }
    let consumed = cur.position() - start;
    Ok((class, constructed, tag_number, consumed))
}

/// Decode DER definite length.
pub fn decode_length(cursor: &mut SliceCursor<'_>) -> Result<usize> {
    let first = cursor.read_u8()?;
    if first & 0x80 == 0 {
        return Ok(first as usize);
    }
    let count = (first & 0x7f) as usize;
    if count == 0 {
        return Err(Error::structure("indefinite length"));
    }
    if count > 4 {
        return Err(Error::limit_exceeded());
    }
    let mut len = 0usize;
    for _ in 0..count {
        let b = cursor.read_u8()?;
        len = len
            .checked_mul(256)
            .and_then(|v| v.checked_add(b as usize))
            .ok_or_else(Error::limit_exceeded)?;
    }
    Ok(len)
}

/// Parse one TLV from `data` starting at `offset`.
pub fn parse_tlv_at(data: &[u8], offset: usize) -> Result<(Tlv<'_>, usize)> {
    if offset >= data.len() {
        return Err(Error::UnexpectedEof);
    }
    let mut cur = SliceCursor::new(&data[offset..]);
    let tag_start = 0usize;
    let (class, constructed, tag_number, tag_len) = decode_tag(&cur)?;
    cur.seek(tag_len)?;
    let length = decode_length(&mut cur)?;
    let header_len = cur.position() - tag_start;
    if cur.len_remaining() < length {
        return Err(Error::UnexpectedEof);
    }
    let value = cur.read_exact(length)?;
    let raw_tag = data[offset];
    let total = header_len + length;
    let tlv = Tlv {
        raw_tag,
        class,
        constructed,
        tag_number,
        length,
        value,
        header_len,
    };
    Ok((tlv, offset + total))
}

/// Parse a concatenation of TLV values inside `data`.
pub fn parse_all_tlvs(data: &[u8]) -> Result<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let (tlv, next) = parse_tlv_at(data, offset)?;
        if next <= offset {
            return Err(Error::structure("tlv stall"));
        }
        offset = next;
        out.push(tlv);
    }
    Ok(out)
}

/// Read INTEGER contents as unsigned big-endian bytes (minimal encoding checked).
pub fn parse_integer_bytes(value: &[u8]) -> Result<Vec<u8>> {
    if value.is_empty() {
        return Err(Error::structure("empty integer"));
    }
    if value.len() > 1 {
        if value[0] == 0 && value[1] & 0x80 == 0 {
            return Err(Error::structure("integer not minimal"));
        }
        if value[0] == 0xff && value[1] & 0x80 != 0 {
            return Err(Error::structure("integer not minimal"));
        }
    }
    Ok(value.to_vec())
}

/// Read INTEGER as u64 when it fits.
pub fn parse_integer_u64(value: &[u8]) -> Result<u64> {
    let bytes = parse_integer_bytes(value)?;
    if bytes.len() > 8 {
        return Err(Error::OutOfRange {
            field: "integer",
            value: bytes.len() as u64,
            limit: 8,
        });
    }
    let mut out = 0u64;
    for b in bytes {
        out = (out << 8) | b as u64;
    }
    Ok(out)
}

/// Bulk-read OCTET STRING using a single unsafe copy for the payload.
pub fn read_octet_string_bulk(src: &[u8], dst: &mut Vec<u8>) -> Result<()> {
    let n = src.len();
    dst.reserve(n);
    let old_len = dst.len();
    unsafe {
        dst.set_len(old_len + n);
        ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr().add(old_len), n);
    }
    Ok(())
}

/// Parse OCTET STRING primitive value into owned buffer.
pub fn parse_octet_string(value: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(value.len());
    read_octet_string_bulk(value, &mut out)?;
    Ok(out)
}

/// Parse SEQUENCE contents as child TLV list.
pub fn parse_sequence_children(data: &[u8]) -> Result<Vec<Tlv<'_>>> {
    parse_all_tlvs(data)
}

/// Parse BOOLEAN value (DER restricts to 0x00 and 0xff).
pub fn parse_boolean(value: &[u8]) -> Result<bool> {
    match value {
        [0] => Ok(false),
        [0xff] => Ok(true),
        _ => Err(Error::structure("bad boolean")),
    }
}

/// Parse NULL.
pub fn parse_null(value: &[u8]) -> Result<()> {
    if value.is_empty() {
        Ok(())
    } else {
        Err(Error::structure("null not empty"))
    }
}

pub fn tag_name(tag: u8) -> &'static str {
    match tag {
        TAG_BOOLEAN => "BOOLEAN",
        TAG_INTEGER => "INTEGER",
        TAG_BIT_STRING => "BIT STRING",
        TAG_OCTET_STRING => "OCTET STRING",
        TAG_NULL => "NULL",
        TAG_OID => "OBJECT IDENTIFIER",
        TAG_UTF8_STRING => "UTF8String",
        TAG_SEQUENCE => "SEQUENCE",
        TAG_SET => "SET",
        TAG_PRINTABLE_STRING => "PrintableString",
        TAG_IA5_STRING => "IA5String",
        TAG_UTC_TIME => "UTCTime",
        TAG_GENERALIZED_TIME => "GeneralizedTime",
        _ => "UNKNOWN",
    }
}

pub fn expect_tag(tlv: &Tlv<'_>, tag: u8) -> Result<()> {
    if tlv.class != CLASS_UNIVERSAL || tlv.tag_number != tag as u32 {
        return Err(Error::BadTag {
            expected: tag as u64,
            found: tlv.tag_number as u64,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(tag);
        let len = value.len();
        if len < 128 {
            v.push(len as u8);
        } else {
            v.push(0x82);
            v.push((len >> 8) as u8);
            v.push((len & 0xff) as u8);
        }
        v.extend_from_slice(value);
        v
    }

    #[test]
    fn parse_integer_tlv() {
        let blob = encode_tlv(TAG_INTEGER, &[0x2a]);
        let tlvs = parse_all_tlvs(&blob).unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(parse_integer_u64(tlvs[0].value).unwrap(), 42);
    }

    #[test]
    fn octet_bulk_copy() {
        let payload = vec![1u8, 2, 3, 4];
        let blob = encode_tlv(TAG_OCTET_STRING, &payload);
        let tlvs = parse_all_tlvs(&blob).unwrap();
        let out = parse_octet_string(tlvs[0].value).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn reject_non_minimal_int() {
        assert!(parse_integer_bytes(&[0x00, 0x7f]).is_err());
    }
}
