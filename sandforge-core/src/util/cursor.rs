//! Zero-copy read cursor over a byte slice.

use crate::error::{Error, Result};

/// Immutable cursor for sequential binary field extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SliceCursor<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> SliceCursor<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        SliceCursor { input, pos: 0 }
    }

    pub fn remaining(&self) -> &'a [u8] {
        &self.input[self.pos..]
    }

    pub fn rest(&self) -> &'a [u8] {
        self.remaining()
    }

    pub fn consumed(&self) -> usize {
        self.pos
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn len_remaining(&self) -> usize {
        self.input.len().saturating_sub(self.pos)
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.input.len()
    }

    pub fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    pub fn peek_at(&self, offset: usize) -> Option<u8> {
        self.input.get(self.pos + offset).copied()
    }

    pub fn peek_slice(&self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        if end <= self.input.len() {
            Some(&self.input[self.pos..end])
        } else {
            None
        }
    }

    pub fn advance(&mut self, n: usize) -> Result<()> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(Error::unexpected_eof)?;
        if end > self.input.len() {
            return Err(Error::unexpected_eof());
        }
        self.pos = end;
        Ok(())
    }

    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.advance(n)
    }

    pub fn seek(&mut self, pos: usize) -> Result<()> {
        if pos > self.input.len() {
            return Err(Error::out_of_range("seek", pos as u64, self.input.len() as u64));
        }
        self.pos = pos;
        Ok(())
    }

    pub fn consume(&mut self) -> Result<u8> {
        let b = self.peek().ok_or_else(Error::unexpected_eof)?;
        self.pos += 1;
        Ok(b)
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        self.consume()
    }

    pub fn read_u16_le(&mut self) -> Result<u16> {
        let bytes = self
            .peek_slice(2)
            .ok_or_else(Error::unexpected_eof)?;
        self.advance(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub fn read_u16_be(&mut self) -> Result<u16> {
        let bytes = self
            .peek_slice(2)
            .ok_or_else(Error::unexpected_eof)?;
        self.advance(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub fn read_u32_le(&mut self) -> Result<u32> {
        let bytes = self
            .peek_slice(4)
            .ok_or_else(Error::unexpected_eof)?;
        self.advance(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn read_u32_be(&mut self) -> Result<u32> {
        let bytes = self
            .peek_slice(4)
            .ok_or_else(Error::unexpected_eof)?;
        self.advance(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn read_u64_le(&mut self) -> Result<u64> {
        let bytes = self
            .peek_slice(8)
            .ok_or_else(Error::unexpected_eof)?;
        self.advance(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub fn read_u64_be(&mut self) -> Result<u64> {
        let bytes = self
            .peek_slice(8)
            .ok_or_else(Error::unexpected_eof)?;
        self.advance(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let slice = self
            .peek_slice(len)
            .ok_or_else(Error::unexpected_eof)?;
        self.advance(len)?;
        Ok(slice)
    }

    pub fn read_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        self.read_bytes(len)
    }

    pub fn expect(&mut self, expected: u8) -> Result<()> {
        let b = self.consume()?;
        if b == expected {
            Ok(())
        } else {
            Err(Error::invalid_syntax())
        }
    }

    pub fn expect_ascii(&mut self, needle: &[u8]) -> Result<()> {
        let slice = self
            .peek_slice(needle.len())
            .ok_or_else(Error::unexpected_eof)?;
        if slice == needle {
            self.advance(needle.len())
        } else {
            Err(Error::invalid_syntax())
        }
    }

    pub fn align_to(&mut self, alignment: usize) -> Result<()> {
        if alignment == 0 {
            return Err(Error::invalid_syntax());
        }
        let rem = self.pos % alignment;
        if rem != 0 {
            self.skip(alignment - rem)?;
        }
        Ok(())
    }

    /// Read a NUL-terminated byte string (PE/WASM name tables).
    pub fn read_cstr(&mut self) -> Result<&'a [u8]> {
        let start = self.pos;
        while self.pos < self.input.len() {
            if self.input[self.pos] == 0 {
                let slice = &self.input[start..self.pos];
                self.pos += 1;
                return Ok(slice);
            }
            self.pos += 1;
        }
        Err(Error::unexpected_eof())
    }

    pub fn read_vec(&mut self, n: usize) -> Result<alloc::vec::Vec<u8>> {
        Ok(self.read_bytes(n)?.to_vec())
    }

    /// Read a WASM LEB128 signed integer.
    pub fn read_leb128_i32(&mut self) -> Result<i32> {
        let mut result: i32 = 0;
        let mut shift = 0;
        let mut byte: u8;
        loop {
            byte = self.read_u8()?;
            let low = (byte & 0x7f) as i32;
            if shift >= 32 {
                return Err(Error::invalid_syntax());
            }
            result |= low << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }
        if shift < 32 && (byte & 0x40) != 0 {
            result |= !0 << shift;
        }
        Ok(result)
    }

    /// Read a WASM LEB128 unsigned integer.
    pub fn read_leb128_u32(&mut self) -> Result<u32> {
        let mut result: u32 = 0;
        let mut shift = 0;
        loop {
            let byte = self.read_u8()?;
            let low = (byte & 0x7f) as u32;
            if shift >= 32 {
                return Err(Error::invalid_syntax());
            }
            result |= low << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_endian_variants() {
        let data = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let mut cur = SliceCursor::new(&data);
        assert_eq!(cur.read_u16_le().unwrap(), 0x0201);
        assert_eq!(cur.read_u16_be().unwrap(), 0x0304);
        assert_eq!(cur.read_u32_le().unwrap(), 0x08070605);
        assert_eq!(cur.read_u32_be().unwrap(), 0x090a0b0c);
        assert_eq!(cur.read_u64_le().unwrap(), 0x100f0e0d);
    }

    #[test]
    fn read_bytes_advances() {
        let mut cur = SliceCursor::new(b"artifact");
        assert_eq!(cur.read_bytes(4).unwrap(), b"arti");
        assert_eq!(cur.remaining(), b"fact");
    }

    #[test]
    fn eof_on_short_read() {
        let mut cur = SliceCursor::new(b"\x01");
        assert!(cur.read_u32_le().is_err());
    }
}
