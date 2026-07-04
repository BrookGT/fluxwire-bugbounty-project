//! Growable byte buffer for encode and emit paths.

use crate::error::{Error, Result};

const DEFAULT_CAPACITY: usize = 64;
const MAX_CAPACITY: usize = 16 * 1024 * 1024;

/// Resizable byte buffer with explicit capacity limits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrowableBuffer {
    data: alloc::vec::Vec<u8>,
    limit: usize,
}

impl GrowableBuffer {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        GrowableBuffer {
            data: alloc::vec::Vec::with_capacity(capacity.max(8)),
            limit: MAX_CAPACITY,
        }
    }

    pub fn with_limit(capacity: usize, limit: usize) -> Self {
        GrowableBuffer {
            data: alloc::vec::Vec::with_capacity(capacity.max(8)),
            limit: limit.max(8),
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }

    pub fn try_reserve(&mut self, additional: usize) -> Result<()> {
        let needed = self
            .data
            .len()
            .checked_add(additional)
            .ok_or_else(Error::limit_exceeded)?;
        if needed > self.limit {
            return Err(Error::limit_exceeded());
        }
        if needed > self.data.capacity() {
            self.data.reserve(additional);
        }
        Ok(())
    }

    pub fn push(&mut self, byte: u8) -> Result<()> {
        self.try_reserve(1)?;
        self.data.push(byte);
        Ok(())
    }

    pub fn extend(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.try_reserve(bytes.len())?;
        self.data.extend_from_slice(bytes);
        Ok(())
    }

    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<()> {
        self.extend(bytes)
    }

    pub fn into_vec(self) -> alloc::vec::Vec<u8> {
        self.data
    }
}

impl core::fmt::Write for GrowableBuffer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.extend(s.as_bytes()).map_err(|_| core::fmt::Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_and_extend() {
        let mut buf = GrowableBuffer::new();
        buf.push(b'h').unwrap();
        buf.extend(b"ello").unwrap();
        assert_eq!(buf.as_slice(), b"hello");
    }

    #[test]
    fn limit_enforced() {
        let mut buf = GrowableBuffer::with_limit(0, 4);
        buf.extend(b"1234").unwrap();
        assert!(buf.extend(b"5").is_err());
    }

    #[test]
    fn fmt_write() {
        use core::fmt::Write;
        let mut buf = GrowableBuffer::new();
        write!(buf, "sig={}", 9).unwrap();
        assert_eq!(buf.as_slice(), b"sig=9");
    }
}
