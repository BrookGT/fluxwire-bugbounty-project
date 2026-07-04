//! Opaque generational ticket identifying a live journal session slot.

use core::fmt;

/// Identifies an entry in a [`TicketTable`](super::table::TicketTable).
///
/// The generation byte is incremented each time a slot is freed and reused.
/// Callers must treat a ticket as invalid once its slot has been closed.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ticket {
    pub slot: u8,
    pub generation: u8,
}

impl Ticket {
    pub const INVALID: Ticket = Ticket {
        slot: u8::MAX,
        generation: 0,
    };

    pub fn new(slot: u8, generation: u8) -> Self {
        Ticket { slot, generation }
    }

    pub fn is_valid(&self) -> bool {
        self.slot != u8::MAX
    }

    pub fn index(&self) -> usize {
        self.slot as usize
    }
}

impl fmt::Debug for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ticket({}:{})", self.slot, self.generation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_ticket() {
        assert!(!Ticket::INVALID.is_valid());
        let t = Ticket::new(3, 7);
        assert!(t.is_valid());
        assert_eq!(t.index(), 3);
    }
}
