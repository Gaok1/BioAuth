//! Replay defence for the verifier.
//!
//! The verifier generates every request id and challenge itself, so replay
//! protection reduces to refusing to consume the same request twice. The cache
//! is bounded: an attacker who could grow it without limit would otherwise
//! have a memory exhaustion path into a process that guards login.

use std::collections::{HashSet, VecDeque};

/// Number of consumed request ids kept. Matches the phone-side window.
///
/// Eviction is safe because a request also has to be inside its two-minute
/// validity window to be accepted, and no realistic verifier issues 1024
/// requests within two minutes.
pub const DEFAULT_CAPACITY: usize = 1024;

#[derive(Debug)]
pub struct ReplayGuard {
    capacity: usize,
    seen: HashSet<String>,
    order: VecDeque<String>,
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }
}

impl ReplayGuard {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            seen: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    /// Records a request id, returning `false` if it was already consumed.
    pub fn consume(&mut self, request_id: &str) -> bool {
        if !self.seen.insert(request_id.to_owned()) {
            return false;
        }
        self.order.push_back(request_id.to_owned());
        if self.order.len() > self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.seen.remove(&evicted);
            }
        }
        true
    }

    pub fn contains(&self, request_id: &str) -> bool {
        self.seen.contains(request_id)
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_id_is_accepted_once() {
        let mut guard = ReplayGuard::default();
        assert!(guard.consume("request-1"));
        assert!(!guard.consume("request-1"));
    }

    #[test]
    fn distinct_ids_are_independent() {
        let mut guard = ReplayGuard::default();
        assert!(guard.consume("request-1"));
        assert!(guard.consume("request-2"));
    }

    #[test]
    fn the_cache_stays_bounded_and_evicts_oldest_first() {
        let mut guard = ReplayGuard::with_capacity(4);
        for index in 0..4 {
            assert!(guard.consume(&format!("request-{index}")));
        }
        assert_eq!(guard.len(), 4);

        assert!(guard.consume("request-4"));
        assert_eq!(guard.len(), 4, "cache must not grow past its capacity");
        assert!(
            !guard.contains("request-0"),
            "the oldest entry is the one evicted"
        );
        assert!(guard.contains("request-1"));
        assert!(guard.contains("request-4"));
    }

    #[test]
    fn a_flood_of_unique_ids_cannot_exhaust_memory() {
        let mut guard = ReplayGuard::with_capacity(8);
        for index in 0..10_000 {
            guard.consume(&format!("request-{index}"));
        }
        assert_eq!(guard.len(), 8);
    }
}
