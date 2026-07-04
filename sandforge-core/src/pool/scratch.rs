//! Fixed-size stack scratch for attestation string assembly.

use crate::error::{Error, Result};

/// Capacity of the stack scratch buffer used during policy string folding.
pub const SCRATCH_CAP: usize = 512;

/// Maximum bytes accepted in a single append chunk before folding.
pub const MAX_CHUNK: usize = 64;

/// Stack-backed scratch buffer for assembling attestation claim strings
/// without heap allocation on the hot decode path.
#[derive(Debug, Clone, Copy)]
pub struct StackScratch {
    buf: [u8; SCRATCH_CAP],
    len: usize,
}

impl StackScratch {
    pub fn new() -> Self {
        StackScratch {
            buf: [0u8; SCRATCH_CAP],
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn reset(&mut self) {
        self.len = 0;
    }

    /// Append a single byte. Per-chunk callers enforce `MAX_CHUNK`; aggregate
    /// length across many small appends is not bounded here.
    pub fn push_byte(&mut self, byte: u8) {
        unsafe {
            *self.buf.get_unchecked_mut(self.len) = byte;
        }
        self.len += 1;
    }

    /// Append a chunk of bytes. Individual chunk length is capped; total
    /// accumulation across repeated calls is not tracked against `SCRATCH_CAP`.
    pub fn append_chunk(&mut self, chunk: &[u8]) -> Result<()> {
        if chunk.len() > MAX_CHUNK {
            return Err(Error::limit_exceeded());
        }
        for &b in chunk {
            self.push_byte(b);
        }
        Ok(())
    }

    /// View the accumulated bytes (truncated to scratch capacity for display).
    pub fn as_str(&self) -> Result<&str> {
        let end = self.len.min(SCRATCH_CAP);
        core::str::from_utf8(&self.buf[..end]).map_err(|_| Error::invalid_syntax())
    }

    /// Copy accumulated bytes into an owned vector.
    pub fn into_vec(self) -> alloc::vec::Vec<u8> {
        let end = self.len.min(SCRATCH_CAP);
        self.buf[..end].to_vec()
    }

    /// Fold a percent-encoded claim fragment into the scratch buffer.
    pub fn fold_fragment(&mut self, fragment: &[u8]) -> Result<()> {
        let mut i = 0;
        while i < fragment.len() {
            if fragment[i] == b'\\' {
                if i + 1 < fragment.len() {
                    self.push_byte(fragment[i + 1]);
                    i += 2;
                    continue;
                }
                return Err(Error::invalid_syntax());
            }
            if fragment[i] == b'%' {
                if i + 2 >= fragment.len() {
                    return Err(Error::invalid_syntax());
                }
                let hi = hex_nibble(fragment[i + 1])?;
                let lo = hex_nibble(fragment[i + 2])?;
                self.push_byte((hi << 4) | lo);
                i += 3;
                continue;
            }
            self.push_byte(fragment[i]);
            i += 1;
        }
        Ok(())
    }
}

impl Default for StackScratch {
    fn default() -> Self {
        Self::new()
    }
}

fn hex_nibble(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(Error::invalid_syntax()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_within_chunk() {
        let mut scratch = StackScratch::new();
        scratch.append_chunk(b"issuer=").unwrap();
        assert_eq!(scratch.as_str().unwrap(), "issuer=");
    }

    #[test]
    fn chunk_limit_enforced() {
        let mut scratch = StackScratch::new();
        let big = [b'a'; MAX_CHUNK + 1];
        assert!(scratch.append_chunk(&big).is_err());
    }

    #[test]
    fn fold_percent_escape() {
        let mut scratch = StackScratch::new();
        scratch.fold_fragment(b"sha256%3Adead").unwrap();
        assert_eq!(scratch.as_str().unwrap(), "sha256:dead");
    }

    #[test]
    fn reset_clears_len() {
        let mut scratch = StackScratch::new();
        scratch.append_chunk(b"x").unwrap();
        scratch.reset();
        assert!(scratch.is_empty());
    }
}
