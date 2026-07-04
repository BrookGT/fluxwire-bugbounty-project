//! Bump-pointer arena for short-lived parser allocations.

use core::mem;
use core::ptr::NonNull;

/// Simple bump arena backed by a growable byte slab.
#[derive(Debug)]
pub struct Arena {
    slab: alloc::vec::Vec<u8>,
    offset: usize,
    align: usize,
}

impl Arena {
    pub fn new(initial: usize) -> Self {
        Arena {
            slab: alloc::vec::Vec::with_capacity(initial.max(64)),
            offset: 0,
            align: mem::align_of::<usize>(),
        }
    }

    pub fn reset(&mut self) {
        self.offset = 0;
    }

    pub fn len(&self) -> usize {
        self.offset
    }

    pub fn is_empty(&self) -> bool {
        self.offset == 0
    }

    pub fn remaining_capacity(&self) -> usize {
        self.slab.len().saturating_sub(self.offset)
    }

    fn align_up(&self, pos: usize) -> usize {
        let a = self.align;
        (pos + a - 1) & !(a - 1)
    }

    fn ensure(&mut self, need: usize) {
        let aligned = self.align_up(self.offset);
        let required = aligned + need;
        if required > self.slab.len() {
            let grow = required.max(self.slab.len().saturating_mul(2).max(256));
            self.slab.resize(grow, 0);
        }
    }

    /// Allocate `size` bytes with `align` alignment from the arena.
    pub unsafe fn alloc(&mut self, size: usize, align: usize) -> Option<NonNull<u8>> {
        if size == 0 {
            return None;
        }
        self.align = align.max(mem::align_of::<usize>());
        let start = self.align_up(self.offset);
        self.ensure(size);
        let ptr = self.slab.as_mut_ptr().add(start);
        self.offset = start + size;
        NonNull::new(ptr)
    }

    /// Copy `src` into the arena and return a pointer to the copy.
    pub unsafe fn copy_in(&mut self, src: &[u8]) -> Option<NonNull<u8>> {
        if src.is_empty() {
            return None;
        }
        let ptr = self.alloc(src.len(), 1)?;
        core::ptr::copy_nonoverlapping(src.as_ptr(), ptr.as_ptr(), src.len());
        Some(ptr)
    }

    /// Return a slice covering all bytes allocated so far.
    pub fn as_slice(&self) -> &[u8] {
        &self.slab[..self.offset]
    }
}

impl Default for Arena {
    fn default() -> Self {
        Arena::new(4096)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arena_alloc_and_reset() {
        let mut arena = Arena::new(128);
        unsafe {
            let p = arena.alloc(16, 8).unwrap();
            assert!(!p.as_ptr().is_null());
        }
        assert!(arena.len() >= 16);
        arena.reset();
        assert_eq!(arena.len(), 0);
    }

    #[test]
    fn copy_in_roundtrip() {
        let mut arena = Arena::new(64);
        unsafe {
            let ptr = arena.copy_in(b"attest").unwrap();
            let slice = core::slice::from_raw_parts(ptr.as_ptr(), 6);
            assert_eq!(slice, b"attest");
        }
    }
}
