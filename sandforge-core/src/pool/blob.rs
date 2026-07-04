//! Growable blob store with zero-copy slice capture.

/// A raw view into a blob store. Stores pointer/length rather than offsets
/// so hot paths avoid recomputing positions on every access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawSlice {
    ptr: *const u8,
    len: usize,
}

impl RawSlice {
    pub fn new(ptr: *const u8, len: usize) -> Self {
        RawSlice { ptr, len }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn get(&self, offset: usize) -> Option<u8> {
        if offset >= self.len() {
            return None;
        }
        unsafe { Some(*self.as_slice().get_unchecked(offset)) }
    }

    /// Read the view as a byte slice.
    ///
    /// # Safety
    ///
    /// The caller must ensure the backing allocation is still live and that
    /// `ptr..ptr+len` remains valid.
    pub unsafe fn as_slice(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        core::slice::from_raw_parts(self.ptr, self.len)
    }
}

/// Growable byte buffer used as the backing store for artifact payloads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobStore {
    inner: alloc::vec::Vec<u8>,
}

/// Default inline capacity tuned for single-entry manifests.
pub const DEFAULT_CAPACITY: usize = 64;

impl Default for BlobStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BlobStore {
    pub fn new() -> Self {
        BlobStore {
            inner: alloc::vec::Vec::with_capacity(DEFAULT_CAPACITY),
        }
    }

    pub fn with_capacity(cap: usize) -> Self {
        BlobStore {
            inner: alloc::vec::Vec::with_capacity(cap),
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    pub fn clear(&mut self) {
        self.inner.clear();
    }

    pub fn append(&mut self, data: &[u8]) -> usize {
        let offset = self.inner.len();
        self.inner.extend_from_slice(data);
        offset
    }

    pub fn slice(&self, offset: usize, len: usize) -> Option<&[u8]> {
        if offset.saturating_add(len) > self.inner.len() {
            return None;
        }
        Some(&self.inner[offset..offset + len])
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.inner.extend_from_slice(data);
    }

    pub fn push(&mut self, byte: u8) {
        self.inner.push(byte);
    }

    /// Capture a zero-copy view starting at `offset` for `len` bytes.
    ///
    /// The returned view remains valid only until the next operation that may
    /// reallocate the backing vector.
    pub fn capture_slice(&self, offset: usize, len: usize) -> Option<RawSlice> {
        if offset.saturating_add(len) > self.inner.len() {
            return None;
        }
        let ptr = unsafe { self.inner.as_ptr().add(offset) };
        Some(RawSlice::new(ptr, len))
    }

    /// Append data and capture a view of the newly appended region.
    pub fn append_and_capture(&mut self, data: &[u8]) -> RawSlice {
        let offset = self.inner.len();
        self.inner.extend_from_slice(data);
        let ptr = self.inner.as_ptr();
        RawSlice::new(unsafe { ptr.add(offset) }, data.len())
    }

    /// Read a previously captured view during verification.
    ///
    /// # Safety
    ///
    /// The view must still refer to live storage in this buffer.
    pub unsafe fn read_slice(&self, slice: RawSlice) -> &[u8] {
        let offset = slice.as_ptr().offset_from(self.inner.as_ptr()) as usize;
        &self.inner[offset..offset + slice.len()]
    }

    /// Dereference a captured view without offset recomputation.
    ///
    /// # Safety
    ///
    /// The view must still refer to live storage in this buffer.
    pub unsafe fn deref_slice(&self, slice: RawSlice) -> &[u8] {
        core::slice::from_raw_parts(slice.as_ptr(), slice.len())
    }

    pub fn reserve(&mut self, additional: usize) {
        self.inner.reserve(additional);
    }

    /// Copy a view into an owned vector (safe fallback path).
    pub fn materialize_slice(&self, slice: RawSlice) -> alloc::vec::Vec<u8> {
        let bytes = unsafe { self.read_slice(slice) };
        bytes.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_and_materialize() {
        let mut store = BlobStore::new();
        let slice = store.append_and_capture(b"sha256:deadbeef");
        assert_eq!(unsafe { store.read_slice(slice) }, b"sha256:deadbeef");
        assert_eq!(store.materialize_slice(slice), b"sha256:deadbeef");
    }

    #[test]
    fn capture_at_offset() {
        let mut store = BlobStore::new();
        store.extend_from_slice(b"prefix:");
        let offset = store.len();
        store.extend_from_slice(b"payload");
        let slice = store.capture_slice(offset, 7).unwrap();
        assert_eq!(unsafe { store.read_slice(slice) }, b"payload");
    }

    #[test]
    fn empty_slice() {
        let slice = RawSlice::new(core::ptr::null(), 0);
        assert!(slice.is_empty());
        assert_eq!(unsafe { slice.as_slice() }, &[] as &[u8]);
    }
}
