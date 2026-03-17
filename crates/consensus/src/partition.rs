//! Thursday: network partition handling — consistency over availability.
//!
//! When a node cannot confirm a quorum of peers are reachable, it MUST:
//! 1. Step down from leader, or
//! 2. Refuse new write requests (return `ServiceUnavailable`).
//!
//! This ensures HaltChain never issues a split-brain approval on a high-stakes
//! transaction, even at the cost of temporary unavailability.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tracing::warn;

// ─── Constants ────────────────────────────────────────────────────────────────

/// A peer is considered unreachable after this silence window.
pub const PEER_TIMEOUT: Duration = Duration::from_millis(500);
/// A leader steps down if it cannot reach a quorum within this window.
pub const LEADER_STEP_DOWN_TIMEOUT: Duration = Duration::from_secs(2);

// ─── Partition policy ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum PartitionPolicy {
    /// CAP: prefer consistency.  Refuse writes when quorum is unreachable.
    ConsistencyOverAvailability,
    /// CAP: prefer availability.  Allow reads but reject high-stakes writes.
    BestEffort,
}

// ─── Partition decision ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum PartitionDecision {
    /// Proceed — quorum is healthy.
    Proceed,
    /// Refuse the request — we are partitioned and prefer consistency.
    ServiceUnavailable { reason: String },
    /// Step down from leadership immediately.
    StepDown,
}

// ─── PartitionDetector ────────────────────────────────────────────────────────

/// Tracks last-heard timestamps from each peer and decides when we are partitioned.
pub struct PartitionDetector {
    node_id: u64,
    cluster_size: usize,
    quorum: usize,
    policy: PartitionPolicy,
    pub last_heard: HashMap<u64, Instant>,
}

impl PartitionDetector {
    pub fn new(
        node_id: u64,
        peers: &[u64],
        cluster_size: usize,
        quorum: usize,
        policy: PartitionPolicy,
    ) -> Self {
        let now = Instant::now();
        let last_heard = peers.iter().map(|&p| (p, now)).collect();
        Self {
            node_id,
            cluster_size,
            quorum,
            policy,
            last_heard,
        }
    }

    /// Update heartbeat receipt time for a peer.
    pub fn record_heartbeat(&mut self, peer_id: u64) {
        self.last_heard.insert(peer_id, Instant::now());
    }

    /// Count how many peers are reachable (heard from within `PEER_TIMEOUT`).
    pub fn reachable_peer_count(&self) -> usize {
        self.last_heard
            .values()
            .filter(|t| t.elapsed() < PEER_TIMEOUT)
            .count()
    }

    /// Return the number of nodes (self + reachable peers) we believe are up.
    pub fn visible_cluster_size(&self) -> usize {
        1 + self.reachable_peer_count()
    }

    pub fn has_quorum(&self) -> bool {
        self.visible_cluster_size() >= self.quorum
    }

    /// Call before processing a write request.
    pub fn check_write(&self, is_leader: bool) -> PartitionDecision {
        if self.has_quorum() {
            return PartitionDecision::Proceed;
        }
        match self.policy {
            PartitionPolicy::ConsistencyOverAvailability => {
                warn!(
                    node = self.node_id,
                    visible = self.visible_cluster_size(),
                    quorum = self.quorum,
                    "partition detected — refusing write"
                );
                if is_leader {
                    return PartitionDecision::StepDown;
                }
                PartitionDecision::ServiceUnavailable {
                    reason: format!(
                        "partition detected: only {}/{} nodes visible",
                        self.visible_cluster_size(),
                        self.cluster_size
                    ),
                }
            }
            PartitionPolicy::BestEffort => PartitionDecision::ServiceUnavailable {
                reason: "degraded — best effort mode, high-stakes writes blocked".into(),
            },
        }
    }

    /// List peers that are currently silent.
    pub fn silent_peers(&self) -> Vec<u64> {
        self.last_heard
            .iter()
            .filter(|(_, t)| t.elapsed() >= PEER_TIMEOUT)
            .map(|(&id, _)| id)
            .collect()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn detector(policy: PartitionPolicy) -> PartitionDetector {
        PartitionDetector::new(1, &[2, 3], 3, 2, policy)
    }

    #[test]
    fn proceed_when_all_peers_healthy() {
        let d = detector(PartitionPolicy::ConsistencyOverAvailability);
        assert_eq!(d.check_write(true), PartitionDecision::Proceed);
    }

    #[test]
    fn leader_steps_down_when_isolated() {
        let mut d = detector(PartitionPolicy::ConsistencyOverAvailability);
        // Simulate peers going silent by using a fresh detector with a very short timeout.
        // We craft one with old timestamps by sleeping past PEER_TIMEOUT.
        // For unit test speed, override last_heard to old values.
        let old = Instant::now()
            .checked_sub(PEER_TIMEOUT + Duration::from_millis(10))
            .unwrap_or(Instant::now());
        d.last_heard.insert(2, old);
        d.last_heard.insert(3, old);
        assert!(!d.has_quorum());
        assert_eq!(d.check_write(true), PartitionDecision::StepDown);
    }

    #[test]
    fn follower_returns_unavailable_when_partitioned() {
        let mut d = detector(PartitionPolicy::ConsistencyOverAvailability);
        let old = Instant::now()
            .checked_sub(PEER_TIMEOUT + Duration::from_millis(10))
            .unwrap_or(Instant::now());
        d.last_heard.insert(2, old);
        d.last_heard.insert(3, old);
        let result = d.check_write(false);
        assert!(matches!(
            result,
            PartitionDecision::ServiceUnavailable { .. }
        ));
    }

    #[test]
    fn partial_partition_still_has_quorum() {
        let mut d = detector(PartitionPolicy::ConsistencyOverAvailability);
        // Only peer 3 is silent (1 + 1 reachable = 2 = quorum)
        let old = Instant::now()
            .checked_sub(PEER_TIMEOUT + Duration::from_millis(10))
            .unwrap_or(Instant::now());
        d.last_heard.insert(3, old);
        // peer 2 is fresh (just connected)
        d.record_heartbeat(2);
        assert!(d.has_quorum(), "2 nodes visible — quorum holds");
        assert_eq!(d.check_write(true), PartitionDecision::Proceed);
    }

    #[test]
    fn silent_peers_reported() {
        let mut d = detector(PartitionPolicy::ConsistencyOverAvailability);
        let old = Instant::now()
            .checked_sub(PEER_TIMEOUT + Duration::from_millis(10))
            .unwrap_or(Instant::now());
        d.last_heard.insert(2, old);
        let silent = d.silent_peers();
        assert!(silent.contains(&2));
        assert!(!silent.contains(&3));
    }
}
