//! Journal execution statistics.

use crate::pool::Ticket;

/// Summary returned after driving a journal script.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    pub opens: u32,
    pub closes: u32,
    pub writes: u32,
    pub churn_cycles: u32,
    pub flushes: u32,
    pub verifies: u32,
    pub flushed_bytes: u32,
    pub verified_bytes: u32,
    pub verify_ok: bool,
    pub open_slots: usize,
    pub free_slots: usize,
    pub last_ticket: Option<Ticket>,
}

impl Summary {
    pub fn total_ops(&self) -> u32 {
        self.opens
            .saturating_add(self.closes)
            .saturating_add(self.writes)
            .saturating_add(self.churn_cycles)
            .saturating_add(self.flushes)
            .saturating_add(self.verifies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_zeroed() {
        let s = Summary::default();
        assert_eq!(s.total_ops(), 0);
        assert!(!s.verify_ok);
    }
}
