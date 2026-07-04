//! Contiguous byte pool for zero-copy artifact retention.

mod arena;
mod blob;
mod scratch;
mod table;
mod ticket;

pub use arena::Arena;
pub use blob::{BlobStore, RawSlice};
pub use scratch::{StackScratch, SCRATCH_CAP, MAX_CHUNK};
pub use table::{SessionState, TicketTable};
pub use ticket::Ticket;
