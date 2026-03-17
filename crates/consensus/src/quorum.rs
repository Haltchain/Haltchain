//! Wednesday: quorum decisions — 2-of-3 agreement gate for high-stakes actions.
//!
//! A decision is "high-stakes" when:
//! * the transaction amount exceeds `HIGH_STAKES_THRESHOLD_CENTS`, or
//! * the anomaly flag is set by the validator.
//!
//! Non-high-stakes decisions are processed locally without waiting for peers.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::debug;

//Constants

pub const HIGH_STAKES_THRESHOLD_CENTS: u64 = 50_000; // $500.00
pub const CLUSTER_SIZE: usize = 3;
pub const QUORUM: usize = 2; // 2-of-3

//Decision outcome

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum QuorumDecision {
    Approved,
    Rejected,
    Pending,
    Unavailable, // cannot reach quorum
}

//Quorum request metadata

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumRequest {
    pub transaction_id: String,
    pub agent_id: String,
    pub amount_cents: u64,
    pub is_anomaly: bool,
}

impl QuorumRequest {
    pub fn requires_quorum(&self) -> bool {
        self.amount_cents >= HIGH_STAKES_THRESHOLD_CENTS || self.is_anomaly
    }
}

//Vote

#[derive(Debug, Clone, PartialEq)]
pub enum Vote {
    Approve,
    Reject,
}

//QuorumTracker

/// Collects votes from validators for a single transaction.
///
/// Thread-safety: caller must hold a lock (or use `Arc<Mutex<QuorumTracker>>`).
#[derive(Debug)]
pub struct QuorumTracker {
    pub transaction_id: String,
    votes: HashMap<u64, Vote>,
    cluster_size: usize,
    quorum: usize,
}

impl QuorumTracker {
    pub fn new(transaction_id: impl Into<String>) -> Self {
        Self::with_cluster(transaction_id, CLUSTER_SIZE, QUORUM)
    }

    pub fn with_cluster(
        transaction_id: impl Into<String>,
        cluster_size: usize,
        quorum: usize,
    ) -> Self {
        Self {
            transaction_id: transaction_id.into(),
            votes: HashMap::new(),
            cluster_size,
            quorum,
        }
    }

    pub fn vote(&mut self, node_id: u64, vote: Vote) {
        debug!(
            txn = %self.transaction_id,
            node_id,
            vote = ?vote,
            "vote recorded"
        );
        self.votes.insert(node_id, vote);
    }

    pub fn approve(&mut self, node_id: u64) {
        self.vote(node_id, Vote::Approve);
    }
    pub fn reject(&mut self, node_id: u64) {
        self.vote(node_id, Vote::Reject);
    }

    pub fn decision(&self) -> QuorumDecision {
        let approvals = self.votes.values().filter(|v| **v == Vote::Approve).count();
        let rejections = self.votes.values().filter(|v| **v == Vote::Reject).count();

        if approvals >= self.quorum {
            return QuorumDecision::Approved;
        }
        if rejections > self.cluster_size - self.quorum {
            return QuorumDecision::Rejected;
        }
        if self.votes.len() >= self.cluster_size {
            // All votes in but no quorum — treat as rejected for safety.
            return QuorumDecision::Rejected;
        }
        QuorumDecision::Pending
    }

    pub fn is_decided(&self) -> bool {
        !matches!(self.decision(), QuorumDecision::Pending)
    }

    pub fn mark_unavailable(&self) -> QuorumDecision {
        QuorumDecision::Unavailable
    }
}

//Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_stakes_detection() {
        let low = QuorumRequest {
            transaction_id: "tx-1".into(),
            agent_id: "a".into(),
            amount_cents: 49_999,
            is_anomaly: false,
        };
        assert!(!low.requires_quorum());

        let high = QuorumRequest {
            transaction_id: "tx-2".into(),
            agent_id: "a".into(),
            amount_cents: 50_000,
            is_anomaly: false,
        };
        assert!(high.requires_quorum());

        let anomaly = QuorumRequest {
            transaction_id: "tx-3".into(),
            agent_id: "a".into(),
            amount_cents: 100,
            is_anomaly: true,
        };
        assert!(anomaly.requires_quorum());
    }

    #[test]
    fn two_of_three_approve() {
        let mut q = QuorumTracker::new("tx1");
        q.approve(1);
        assert_eq!(q.decision(), QuorumDecision::Pending);
        q.approve(2);
        assert_eq!(q.decision(), QuorumDecision::Approved);
    }

    #[test]
    fn two_of_three_reject() {
        let mut q = QuorumTracker::new("tx1");
        q.reject(1);
        q.reject(2);
        assert_eq!(q.decision(), QuorumDecision::Rejected);
    }

    #[test]
    fn split_vote_with_all_votes_in() {
        let mut q = QuorumTracker::new("tx1");
        q.approve(1);
        q.reject(2);
        q.reject(3);
        assert_eq!(q.decision(), QuorumDecision::Rejected);
    }

    #[test]
    fn node_cannot_double_vote() {
        let mut q = QuorumTracker::new("tx1");
        q.approve(1);
        q.approve(1); // second approve from same node — overwrites
        q.reject(2);
        q.reject(3);
        // Only 1 approval (from node 1), 2 rejections → Rejected
        assert_eq!(q.decision(), QuorumDecision::Rejected);
    }
}
