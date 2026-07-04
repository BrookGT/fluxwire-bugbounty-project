//! Byte-level helpers shared by artifact parsers.

mod bounds;
mod buffer;
mod cursor;

pub use bounds::{check_bounds, copy_prefix, read_ascii_cstr, regions_overlap};
pub use buffer::GrowableBuffer;
pub use cursor::SliceCursor;
