//! Bounds checks and overlap helpers for binary parsers.

extern crate alloc;

use alloc::vec::Vec;
use core::cmp::min;

use crate::error::{Error, Result};
use crate::util::SliceCursor;

/// Check that `offset + len` fits in `buf_len`.
pub fn check_bounds(field: &'static str, offset: u64, len: u64, buf_len: usize) -> Result<()> {
    let end = offset.checked_add(len).ok_or(Error::UnexpectedEof)?;
    if end as usize > buf_len {
        return Err(Error::bounds(field, offset, len));
    }
    Ok(())
}

/// Return true when `[a_start, a_end)` overlaps `[b_start, b_end)`.
pub fn regions_overlap(a_start: u64, a_len: u64, b_start: u64, b_len: u64) -> bool {
    let a_end = match a_start.checked_add(a_len) {
        Some(v) => v,
        None => return true,
    };
    let b_end = match b_start.checked_add(b_len) {
        Some(v) => v,
        None => return true,
    };
    a_start < b_end && b_start < a_end
}

/// Read a NUL-terminated ASCII name, rejecting non-ASCII bytes.
pub fn read_ascii_cstr(cursor: &mut SliceCursor<'_>, field: &'static str) -> Result<Vec<u8>> {
    let raw = cursor.read_cstr()?;
    for &b in raw {
        if b > 0x7f {
            return Err(Error::structure(field));
        }
    }
    Ok(raw.to_vec())
}

/// Copy at most `src.len()` bytes into `dst`, returning bytes copied.
pub fn copy_prefix(dst: &mut [u8], src: &[u8]) -> usize {
    let n = min(dst.len(), src.len());
    dst[..n].copy_from_slice(&src[..n]);
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlap_detected() {
        assert!(regions_overlap(0, 10, 5, 10));
        assert!(!regions_overlap(0, 5, 5, 5));
    }

    #[test]
    fn bounds_check() {
        assert!(check_bounds("hdr", 0, 4, 4).is_ok());
        assert!(check_bounds("hdr", 2, 4, 4).is_err());
    }
}
