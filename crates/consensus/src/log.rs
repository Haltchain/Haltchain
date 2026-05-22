//! Monday: Append-only Raft decision log.
//!
//! Each [`LogEntry`] carries a [`DecisionCommand`] (the payload) plus the
//! Raft term and a monotone index.  The log is in-memory for Phase 0; swap
//! in a mmap/fsynced file in Phase 1.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionLogSnapshot {
    pub entries: Vec<LogEntry>,
    pub commit_index: u64,
    pub last_applied: u64,
}

// ─── Command ──────────────────────────────────────────────────────────────────

/// The payload replicated across the cluster.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DecisionCommand {
    /// Replicate a validation decision for `transaction_id`.
    Validate {
        transaction_id: String,
        agent_id: String,
        action_type: String,
        amount_cents: i64,
        decision: String, // "ALLOW" | "DENY" | "CIRCUIT_BREAK"
    },
    /// Circuit-breaker trip for `agent_id`.
    CircuitBreak { agent_id: String, reason: String },
    /// Cluster membership change — add a peer.
    AddPeer { node_id: u64, addr: String },
    /// Cluster membership change — remove a peer.
    RemovePeer { node_id: u64 },
    /// No-op heartbeat entry to advance commit index on new leader.
    Noop,
}

// ─── Log entry ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Raft term this entry was created in.
    pub term: u64,
    /// 1-based monotone index within the log.
    pub index: u64,
    pub command: DecisionCommand,
}

impl LogEntry {
    pub fn new(term: u64, index: u64, command: DecisionCommand) -> Self {
        Self {
            term,
            index,
            command,
        }
    }

    pub fn noop(term: u64, index: u64) -> Self {
        Self::new(term, index, DecisionCommand::Noop)
    }
}

// ─── Decision log ─────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct DecisionLog {
    entries: Vec<LogEntry>,
    /// Highest entry known to be safely replicated on a quorum.
    commit_index: u64,
    /// Highest entry applied to the state machine.
    last_applied: u64,
}

impl DecisionLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append returns the new entry's index.
    pub fn append(&mut self, term: u64, command: DecisionCommand) -> u64 {
        let index = self.last_index() + 1;
        self.entries.push(LogEntry::new(term, index, command));
        index
    }

    pub fn last_index(&self) -> u64 {
        self.entries.last().map(|e| e.index).unwrap_or(0)
    }

    pub fn last_term(&self) -> u64 {
        self.entries.last().map(|e| e.term).unwrap_or(0)
    }

    pub fn get(&self, index: u64) -> Option<&LogEntry> {
        if index == 0 {
            return None;
        }
        // entries are 1-indexed; vec is 0-indexed
        self.entries.get((index - 1) as usize)
    }

    /// Truncate from `from_index` onward (used when a follower receives
    /// conflicting entries from the new leader).
    pub fn truncate_from(&mut self, from_index: u64) {
        if from_index == 0 {
            self.entries.clear();
            return;
        }
        self.entries.truncate((from_index - 1) as usize);
    }

    pub fn commit_index(&self) -> u64 {
        self.commit_index
    }
    pub fn last_applied(&self) -> u64 {
        self.last_applied
    }

    /// Advance commit_index if `new_ci` is higher.
    pub fn set_commit_index(&mut self, new_ci: u64) {
        if new_ci > self.commit_index {
            self.commit_index = new_ci.min(self.last_index());
        }
    }

    /// Return all committed-but-not-yet-applied entries.
    pub fn take_unapplied(&mut self) -> Vec<LogEntry> {
        let from = (self.last_applied + 1) as usize;
        let to = (self.commit_index + 1) as usize;
        if from >= to {
            return vec![];
        }
        let batch: Vec<LogEntry> =
            self.entries[from.saturating_sub(1)..to.saturating_sub(1)].to_vec();
        if let Some(last) = batch.last() {
            self.last_applied = last.index;
        }
        batch
    }

    /// Entries from `next_index` onward (for AppendEntries RPC).
    pub fn entries_from(&self, next_index: u64) -> &[LogEntry] {
        if next_index == 0 || next_index > self.last_index() {
            return &[];
        }
        let start = (next_index - 1) as usize;
        &self.entries[start..]
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn snapshot(&self) -> DecisionLogSnapshot {
        DecisionLogSnapshot {
            entries: self.entries.clone(),
            commit_index: self.commit_index,
            last_applied: self.last_applied,
        }
    }

    pub fn restore_from_snapshot(&mut self, snapshot: DecisionLogSnapshot) {
        self.entries = snapshot.entries;
        self.commit_index = snapshot.commit_index.min(self.last_index());
        self.last_applied = snapshot.last_applied.min(self.commit_index);
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn validate_cmd(id: &str) -> DecisionCommand {
        DecisionCommand::Validate {
            transaction_id: id.into(),
            agent_id: "a1".into(),
            action_type: "transfer".into(),
            amount_cents: 50000,
            decision: "ALLOW".into(),
        }
    }

    #[test]
    fn append_and_retrieve() {
        let mut log = DecisionLog::new();
        let idx = log.append(1, validate_cmd("tx1"));
        assert_eq!(idx, 1);
        assert_eq!(log.last_index(), 1);
        assert_eq!(log.last_term(), 1);
        let entry = log.get(1).unwrap();
        assert_eq!(entry.term, 1);
        assert_eq!(entry.index, 1);
    }

    #[test]
    fn truncate_removes_conflicting_entries() {
        let mut log = DecisionLog::new();
        log.append(1, validate_cmd("tx1"));
        log.append(1, validate_cmd("tx2"));
        log.append(2, validate_cmd("tx3"));
        // Leader says entries from index 2 onwards are stale
        log.truncate_from(2);
        assert_eq!(log.last_index(), 1);
        assert!(log.get(2).is_none());
    }

    #[test]
    fn commit_and_apply() {
        let mut log = DecisionLog::new();
        log.append(1, validate_cmd("tx1"));
        log.append(1, validate_cmd("tx2"));
        log.set_commit_index(2);
        let applied = log.take_unapplied();
        assert_eq!(applied.len(), 2);
        assert_eq!(log.last_applied(), 2);
        // No more unapplied
        assert!(log.take_unapplied().is_empty());
    }

    #[test]
    fn entries_from_returns_suffix() {
        let mut log = DecisionLog::new();
        for i in 1..=5u64 {
            log.append(1, validate_cmd(&format!("tx{i}")));
        }
        let suffix = log.entries_from(3);
        assert_eq!(suffix.len(), 3);
        assert_eq!(suffix[0].index, 3);
    }

    #[test]
    fn commit_index_cannot_exceed_last_index() {
        let mut log = DecisionLog::new();
        log.append(1, DecisionCommand::Noop);
        log.set_commit_index(999);
        assert_eq!(log.commit_index(), 1);
    }
}
