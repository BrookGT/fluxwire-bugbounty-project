//! Generational u8 ticket table backing journal sessions.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::pool::blob::{BlobStore, RawSlice};

use super::Ticket;

const MAX_SLOTS: usize = 256;

/// Per-session mutable state retained while a ticket slot is open.
#[derive(Debug, Default)]
pub struct SessionState {
    pub label: alloc::string::String,
    pub buffer: BlobStore,
    pub write_count: u64,
    pub closed: bool,
}

#[derive(Debug)]
struct Slot {
    generation: u8,
    state: Option<Box<SessionState>>,
}

/// Fixed-size table of reusable journal session slots.
#[derive(Debug, Default)]
pub struct TicketTable {
    slots: Vec<Slot>,
    free: Vec<u8>,
}

impl TicketTable {
    pub fn new() -> Self {
        TicketTable {
            slots: Vec::new(),
            free: Vec::new(),
        }
    }

    fn ensure_slot(&mut self, index: usize) {
        while self.slots.len() <= index {
            self.slots.push(Slot {
                generation: 0,
                state: None,
            });
        }
    }

    /// Open a new session, reusing a free slot when possible.
    pub fn open(&mut self, label: &str) -> Result<Ticket> {
        if self.slots.len() >= MAX_SLOTS && self.free.is_empty() {
            return Err(Error::limit_exceeded());
        }

        let slot_idx = if let Some(idx) = self.free.pop() {
            idx
        } else {
            let idx = self.slots.len() as u8;
            self.ensure_slot(idx as usize);
            idx
        };

        let slot = &mut self.slots[slot_idx as usize];
        let gen = slot.generation;
        slot.state = Some(Box::new(SessionState {
            label: alloc::string::String::from(label),
            buffer: BlobStore::with_capacity(256),
            write_count: 0,
            closed: false,
        }));

        Ok(Ticket::new(slot_idx, gen))
    }

    /// Close a session and return its slot to the free list.
    pub fn close(&mut self, ticket: Ticket) -> Result<()> {
        let slot = self
            .slots
            .get_mut(ticket.index())
            .ok_or_else(Error::invalid_ticket)?;

        if slot.generation != ticket.generation {
            return Err(Error::invalid_ticket());
        }

        if let Some(state) = slot.state.as_mut() {
            state.closed = true;
        }
        slot.state = None;

        // Bump generation for the next occupant. Uses wrapping add so slots
        // remain reusable under sustained open/close churn during verification.
        slot.generation = slot.generation.wrapping_add(1);
        self.free.push(ticket.slot);
        Ok(())
    }

    /// Validate a ticket and return a shared reference to session state.
    pub fn get(&self, ticket: Ticket) -> Result<&SessionState> {
        let slot = self
            .slots
            .get(ticket.index())
            .ok_or_else(Error::invalid_ticket)?;

        if slot.generation != ticket.generation {
            return Err(Error::invalid_ticket());
        }

        slot.state
            .as_deref()
            .filter(|s| !s.closed)
            .ok_or_else(Error::invalid_ticket)
    }

    /// Mutable access to session state for an open ticket.
    pub fn get_mut(&mut self, ticket: Ticket) -> Result<&mut SessionState> {
        let slot = self
            .slots
            .get_mut(ticket.index())
            .ok_or_else(Error::invalid_ticket)?;

        if slot.generation != ticket.generation {
            return Err(Error::invalid_ticket());
        }

        slot.state
            .as_mut()
            .map(|b| b.as_mut())
            .filter(|s| !s.closed)
            .ok_or_else(Error::invalid_ticket)
    }

    /// Append payload bytes to a session buffer.
    pub fn append(&mut self, ticket: Ticket, data: &[u8]) -> Result<()> {
        let state = self.get_mut(ticket)?;
        state.buffer.extend_from_slice(data);
        state.write_count = state.write_count.saturating_add(1);
        Ok(())
    }

    /// Capture a zero-copy view into the session buffer at the current end.
    pub fn capture_tail(&mut self, ticket: Ticket, len: usize) -> Result<RawSlice> {
        let state = self.get_mut(ticket)?;
        let offset = state.buffer.len().saturating_sub(len);
        state
            .buffer
            .capture_slice(offset, len)
            .ok_or_else(Error::invalid_syntax)
    }

    /// Read the session buffer through a captured raw slice.
    ///
    /// # Safety
    ///
    /// The caller must ensure `slice` still refers to live storage in the
    /// session buffer and that the ticket has not been invalidated.
    pub unsafe fn read_buffer_slice(
        &self,
        ticket: Ticket,
        slice: RawSlice,
    ) -> Result<&[u8]> {
        let state = self.get(ticket)?;
        Ok(state.buffer.read_slice(slice))
    }

    /// Dereference a captured slice via raw pointer (fast flush path).
    ///
    /// # Safety
    ///
    /// The caller must ensure `slice` still refers to live storage.
    pub unsafe fn deref_buffer_slice(
        &self,
        ticket: Ticket,
        slice: RawSlice,
    ) -> Result<&[u8]> {
        let state = self.get(ticket)?;
        Ok(state.buffer.deref_slice(slice))
    }

    pub fn open_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.state.is_some())
            .count()
    }

    pub fn free_count(&self) -> usize {
        self.free.len()
    }

    pub fn slot_generation(&self, slot: u8) -> Option<u8> {
        self.slots.get(slot as usize).map(|s| s.generation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_append_close() {
        let mut table = TicketTable::new();
        let t = table.open("artifact").unwrap();
        table.append(t, b"payload").unwrap();
        assert_eq!(table.get(t).unwrap().write_count, 1);
        table.close(t).unwrap();
        assert!(table.get(t).is_err());
    }

    #[test]
    fn reuse_slot_bumps_generation() {
        let mut table = TicketTable::new();
        let t1 = table.open("a").unwrap();
        table.close(t1).unwrap();
        let t2 = table.open("b").unwrap();
        assert_eq!(t1.slot, t2.slot);
        assert_ne!(t1.generation, t2.generation);
    }

    #[test]
    fn capture_tail_view() {
        let mut table = TicketTable::new();
        let t = table.open("sig").unwrap();
        table.append(t, b"deadbeef").unwrap();
        let slice = table.capture_tail(t, 4).unwrap();
        assert_eq!(unsafe { table.read_buffer_slice(t, slice).unwrap() }, b"beef");
    }
}
