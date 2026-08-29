//! Monday + Tuesday: Raft consensus state machine.
//!
//! Implements the pure Raft logic (no I/O): state transitions, vote granting,
//! AppendEntries processing, and message generation.  The caller drives the
//! machine by feeding in [`RaftMessage`]s and ticking the clock.
//!
//! Key decision: strong consistency over availability (CAP/Thursday).
//! Leader election timeout: 150–300 ms.  Heartbeat interval: 100 ms.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::log::{DecisionCommand, DecisionLog, DecisionLogSnapshot, LogEntry};

// ─── Constants ────────────────────────────────────────────────────────────────

pub const HEARTBEAT_TICKS: u64 = 1; // how many ticks between heartbeats
pub const ELECTION_TIMEOUT_MIN: u64 = 5;
pub const ELECTION_TIMEOUT_MAX: u64 = 10; // randomised in [5, 10] ticks

// ─── Node role ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum RaftRole {
    Follower,
    Candidate,
    Leader,
}

// ─── RPC messages ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AppendEntriesReq {
    pub term: u64,
    pub leader_id: u64,
    pub prev_log_idx: u64,
    pub prev_log_term: u64,
    pub entries: Vec<LogEntry>,
    pub leader_commit: u64,
}

#[derive(Debug, Clone)]
pub struct AppendEntriesResp {
    pub term: u64,
    pub from_id: u64,
    pub success: bool,
    /// Next index the follower expects (used for fast next-index roll-back).
    pub match_index: u64,
}

#[derive(Debug, Clone)]
pub struct RequestVoteReq {
    pub term: u64,
    pub candidate_id: u64,
    pub last_log_idx: u64,
    pub last_log_term: u64,
}

#[derive(Debug, Clone)]
pub struct RequestVoteResp {
    pub term: u64,
    pub from_id: u64,
    pub vote_granted: bool,
}

#[derive(Debug, Clone)]
pub enum RaftMessage {
    AppendReq(AppendEntriesReq),
    AppendResp(AppendEntriesResp),
    VoteReq(RequestVoteReq),
    VoteResp(RequestVoteResp),
}

/// Output actions the caller must carry out (send messages, apply to state machine).
#[derive(Debug)]
pub enum RaftAction {
    Send { to: u64, msg: RaftMessage },
    Broadcast { msg: RaftMessage },
    Apply { entries: Vec<LogEntry> },
    BecameLeader { term: u64 },
    BecameFollower { term: u64 },
}

// ─── Per-peer tracking (leader only) ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PeerState {
    pub next_index: u64,
    pub match_index: u64,
}

// ─── Raft node (state machine) ────────────────────────────────────────────────

pub struct RaftNode {
    pub id: u64,
    pub peers: Vec<u64>,
    pub role: RaftRole,
    pub current_term: u64,
    pub voted_for: Option<u64>,
    votes_received: HashSet<u64>,
    pub log: DecisionLog,
    election_elapsed: u64,
    election_timeout: u64,
    heartbeat_elapsed: u64,
    pub peer_state: HashMap<u64, PeerState>,
    persistence_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedRaftState {
    current_term: u64,
    voted_for: Option<u64>,
    log: DecisionLogSnapshot,
}

impl RaftNode {
    pub fn new(id: u64, peers: Vec<u64>, election_timeout: u64) -> Self {
        Self {
            id,
            peers,
            role: RaftRole::Follower,
            current_term: 0,
            voted_for: None,
            log: DecisionLog::new(),
            election_elapsed: 0,
            election_timeout,
            heartbeat_elapsed: 0,
            votes_received: HashSet::new(),
            peer_state: HashMap::new(),
            persistence_path: None,
        }
    }

    pub fn with_persistence(
        id: u64,
        peers: Vec<u64>,
        election_timeout: u64,
        path: PathBuf,
    ) -> Self {
        let mut node = Self::new(id, peers, election_timeout);
        node.persistence_path = Some(path);
        node.restore_state();
        node
    }

    pub fn is_leader(&self) -> bool {
        self.role == RaftRole::Leader
    }

    // ── Clock tick ────────────────────────────────────────────────────────────

    /// Advance the logical clock by one tick.  Returns actions to perform.
    pub fn tick(&mut self) -> Vec<RaftAction> {
        match self.role {
            RaftRole::Follower | RaftRole::Candidate => {
                self.election_elapsed += 1;
                if self.election_elapsed >= self.election_timeout {
                    return self.start_election();
                }
                vec![]
            }
            RaftRole::Leader => {
                self.heartbeat_elapsed += 1;
                if self.heartbeat_elapsed >= HEARTBEAT_TICKS {
                    self.heartbeat_elapsed = 0;
                    return self.broadcast_heartbeat();
                }
                vec![]
            }
        }
    }

    // ── Propose (leader only) ─────────────────────────────────────────────────

    /// Append a command to the log and replicate.  Returns `None` if not leader.
    pub fn propose(&mut self, command: DecisionCommand) -> Option<(u64, Vec<RaftAction>)> {
        if self.role != RaftRole::Leader {
            return None;
        }
        let index = self.log.append(self.current_term, command);
        self.persist_state();
        let actions = self.replicate_to_peers();
        Some((index, actions))
    }

    // ── Message handling ──────────────────────────────────────────────────────

    pub fn step(&mut self, from: u64, msg: RaftMessage) -> Vec<RaftAction> {
        match msg {
            RaftMessage::VoteReq(req) => self.handle_vote_req(req),
            RaftMessage::VoteResp(resp) => self.handle_vote_resp(resp),
            RaftMessage::AppendReq(req) => self.handle_append_req(req),
            RaftMessage::AppendResp(resp) => self.handle_append_resp(from, resp),
        }
    }

    // ─── RequestVote ──────────────────────────────────────────────────────────

    fn handle_vote_req(&mut self, req: RequestVoteReq) -> Vec<RaftAction> {
        if req.term < self.current_term {
            return vec![RaftAction::Send {
                to: req.candidate_id,
                msg: RaftMessage::VoteResp(RequestVoteResp {
                    term: self.current_term,
                    from_id: self.id,
                    vote_granted: false,
                }),
            }];
        }
        let mut actions = vec![];
        if req.term > self.current_term {
            actions.extend(self.become_follower(req.term));
        }
        let log_ok = req.last_log_term > self.log.last_term()
            || (req.last_log_term == self.log.last_term()
                && req.last_log_idx >= self.log.last_index());
        let can_vote = self.voted_for.is_none() || self.voted_for == Some(req.candidate_id);
        let granted = log_ok && can_vote;
        if granted {
            self.voted_for = Some(req.candidate_id);
            self.election_elapsed = 0;
            self.persist_state();
        }
        debug!(from = req.candidate_id, granted, "vote request");
        actions.push(RaftAction::Send {
            to: req.candidate_id,
            msg: RaftMessage::VoteResp(RequestVoteResp {
                term: self.current_term,
                from_id: self.id,
                vote_granted: granted,
            }),
        });
        actions
    }

    fn handle_vote_resp(&mut self, resp: RequestVoteResp) -> Vec<RaftAction> {
        if resp.term > self.current_term {
            return self.become_follower(resp.term);
        }
        if self.role != RaftRole::Candidate {
            return vec![];
        }
        if resp.vote_granted {
            self.votes_received.insert(resp.from_id);
            if self.votes_received.len() >= self.quorum() {
                return self.become_leader();
            }
        }
        vec![]
    }

    // ─── AppendEntries ────────────────────────────────────────────────────────

    fn handle_append_req(&mut self, req: AppendEntriesReq) -> Vec<RaftAction> {
        if req.term < self.current_term {
            return vec![RaftAction::Send {
                to: req.leader_id,
                msg: RaftMessage::AppendResp(AppendEntriesResp {
                    term: self.current_term,
                    from_id: self.id,
                    success: false,
                    match_index: 0,
                }),
            }];
        }
        let mut actions = vec![];
        if req.term >= self.current_term {
            actions.extend(self.become_follower(req.term));
        }
        self.election_elapsed = 0;

        // Consistency check on prev entry
        let prev_ok = req.prev_log_idx == 0
            || self
                .log
                .get(req.prev_log_idx)
                .map(|e| e.term == req.prev_log_term)
                .unwrap_or(false);

        if !prev_ok {
            let match_index = self.log.last_index();
            return vec![RaftAction::Send {
                to: req.leader_id,
                msg: RaftMessage::AppendResp(AppendEntriesResp {
                    term: self.current_term,
                    from_id: self.id,
                    success: false,
                    match_index,
                }),
            }];
        }

        // Append new entries, removing conflicts first
        for entry in &req.entries {
            if let Some(existing) = self.log.get(entry.index)
                && existing.term != entry.term
            {
                self.log.truncate_from(entry.index);
            }
            if entry.index > self.log.last_index() {
                self.log.append(entry.term, entry.command.clone());
            }
        }

        self.log.set_commit_index(req.leader_commit);
        self.persist_state();
        let unapplied = self.log.take_unapplied();
        if !unapplied.is_empty() {
            actions.push(RaftAction::Apply { entries: unapplied });
        }

        let match_index = self.log.last_index();
        actions.push(RaftAction::Send {
            to: req.leader_id,
            msg: RaftMessage::AppendResp(AppendEntriesResp {
                term: self.current_term,
                from_id: self.id,
                success: true,
                match_index,
            }),
        });
        actions
    }

    fn handle_append_resp(&mut self, from: u64, resp: AppendEntriesResp) -> Vec<RaftAction> {
        if resp.term > self.current_term {
            return self.become_follower(resp.term);
        }
        if self.role != RaftRole::Leader {
            return vec![];
        }
        let ps = self.peer_state.get_mut(&from).expect("unknown peer");
        if resp.success {
            ps.match_index = resp.match_index;
            ps.next_index = resp.match_index + 1;
        } else {
            // Roll back next_index
            if resp.match_index > 0 {
                ps.next_index = resp.match_index + 1;
            } else {
                ps.next_index = ps.next_index.saturating_sub(1).max(1);
            }
            // Retry
            return self.send_append(from);
        }
        self.try_advance_commit_index()
    }

    // ─── Leader helpers ───────────────────────────────────────────────────────

    fn become_leader(&mut self) -> Vec<RaftAction> {
        info!(id = self.id, term = self.current_term, "became leader");
        self.role = RaftRole::Leader;
        // Initialise per-peer state
        let next = self.log.last_index() + 1;
        for &p in &self.peers {
            self.peer_state.insert(
                p,
                PeerState {
                    next_index: next,
                    match_index: 0,
                },
            );
        }
        let mut actions = vec![RaftAction::BecameLeader {
            term: self.current_term,
        }];
        // Append a no-op entry to commit previous terms' entries.
        let noop_idx = self.log.append(self.current_term, DecisionCommand::Noop);
        self.persist_state();
        // Update own next/match
        for ps in self.peer_state.values_mut() {
            ps.next_index = noop_idx + 1;
        }
        actions.extend(self.broadcast_heartbeat());
        actions
    }

    fn broadcast_heartbeat(&mut self) -> Vec<RaftAction> {
        let peer_ids: Vec<u64> = self.peers.to_vec();
        let mut actions = vec![];
        for p in peer_ids {
            actions.extend(self.send_append(p));
        }
        actions
    }

    fn send_append(&self, to: u64) -> Vec<RaftAction> {
        let ps = match self.peer_state.get(&to) {
            Some(p) => p,
            None => return vec![],
        };
        let prev_idx = ps.next_index.saturating_sub(1);
        let prev_term = self.log.get(prev_idx).map(|e| e.term).unwrap_or(0);
        let entries = self.log.entries_from(ps.next_index).to_vec();
        vec![RaftAction::Send {
            to,
            msg: RaftMessage::AppendReq(AppendEntriesReq {
                term: self.current_term,
                leader_id: self.id,
                prev_log_idx: prev_idx,
                prev_log_term: prev_term,
                entries,
                leader_commit: self.log.commit_index(),
            }),
        }]
    }

    fn replicate_to_peers(&self) -> Vec<RaftAction> {
        let mut actions = vec![];
        for &p in &self.peers {
            actions.extend(self.send_append(p));
        }
        actions
    }

    /// Advance commit_index if a quorum of peers have replicated up to it.
    fn try_advance_commit_index(&mut self) -> Vec<RaftAction> {
        let last = self.log.last_index();
        let quorum = self.quorum();
        // Try to commit the highest index replicated on a quorum.
        for n in (self.log.commit_index() + 1..=last).rev() {
            // Only commit entries from the current term (Raft §5.4.2).
            if self.log.get(n).map(|e| e.term) != Some(self.current_term) {
                continue;
            }
            let replicated = self
                .peer_state
                .values()
                .filter(|ps| ps.match_index >= n)
                .count();
            // +1 for the leader itself
            if replicated + 1 >= quorum {
                self.log.set_commit_index(n);
                self.persist_state();
                let unapplied = self.log.take_unapplied();
                if !unapplied.is_empty() {
                    return vec![RaftAction::Apply { entries: unapplied }];
                }
                break;
            }
        }
        vec![]
    }

    // ─── Election ─────────────────────────────────────────────────────────────

    fn start_election(&mut self) -> Vec<RaftAction> {
        self.current_term += 1;
        self.role = RaftRole::Candidate;
        self.voted_for = Some(self.id);
        self.election_elapsed = 0;
        self.votes_received.clear();
        self.votes_received.insert(self.id);
        self.persist_state();
        info!(id = self.id, term = self.current_term, "started election");

        // Might win immediately in a 1-node cluster
        if self.votes_received.len() >= self.quorum() {
            return self.become_leader();
        }

        let req = RequestVoteReq {
            term: self.current_term,
            candidate_id: self.id,
            last_log_idx: self.log.last_index(),
            last_log_term: self.log.last_term(),
        };
        vec![RaftAction::Broadcast {
            msg: RaftMessage::VoteReq(req),
        }]
    }

    fn become_follower(&mut self, term: u64) -> Vec<RaftAction> {
        warn!(id = self.id, term, "became follower");
        let was_leader = self.role == RaftRole::Leader;
        self.current_term = term;
        self.voted_for = None;
        self.role = RaftRole::Follower;
        self.election_elapsed = 0;
        self.peer_state.clear();
        self.votes_received.clear();
        self.persist_state();
        if was_leader {
            vec![RaftAction::BecameFollower { term }]
        } else {
            vec![]
        }
    }

    fn quorum(&self) -> usize {
        self.peers.len().div_ceil(2) + 1
    }

    fn persist_state(&self) {
        use std::io::Write;

        let Some(path) = &self.persistence_path else {
            return;
        };
        let snapshot = PersistedRaftState {
            current_term: self.current_term,
            voted_for: self.voted_for,
            log: self.log.snapshot(),
        };
        let Ok(data) = serde_json::to_vec(&snapshot) else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut f = match std::fs::File::create(path) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "raft persist open failed");
                return;
            }
        };
        if let Err(e) = f.write_all(&data) {
            tracing::warn!(path = %path.display(), error = %e, "raft persist write failed");
            return;
        }
        if let Err(e) = f.sync_all() {
            tracing::warn!(path = %path.display(), error = %e, "raft persist fsync failed");
        }
    }

    fn restore_state(&mut self) {
        let Some(path) = &self.persistence_path else {
            return;
        };
        let Ok(bytes) = std::fs::read(path) else {
            return;
        };
        let Ok(state) = serde_json::from_slice::<PersistedRaftState>(&bytes) else {
            return;
        };
        self.current_term = state.current_term;
        self.voted_for = state.voted_for;
        self.log.restore_from_snapshot(state.log);
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: u64, peers: &[u64]) -> RaftNode {
        RaftNode::new(id, peers.to_vec(), ELECTION_TIMEOUT_MIN)
    }

    #[test]
    fn single_node_becomes_leader() {
        let mut n = node(1, &[]);
        let mut actions = vec![];
        for _ in 0..ELECTION_TIMEOUT_MIN {
            actions.extend(n.tick());
        }
        assert_eq!(n.role, RaftRole::Leader);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, RaftAction::BecameLeader { .. }))
        );
    }

    #[test]
    fn follower_grants_vote_to_up_to_date_candidate() {
        let mut follower = node(2, &[1]);
        let req = RequestVoteReq {
            term: 1,
            candidate_id: 1,
            last_log_idx: 0,
            last_log_term: 0,
        };
        let actions = follower.step(1, RaftMessage::VoteReq(req));
        assert!(actions.iter().any(|a| matches!(
            a, RaftAction::Send { msg: RaftMessage::VoteResp(r), .. } if r.vote_granted
        )));
    }

    #[test]
    fn three_node_leader_election() {
        let mut n1 = node(1, &[2, 3]);
        let mut n2 = node(2, &[1, 3]);
        let mut n3 = node(3, &[1, 2]);

        // Tick n1 enough to start an election
        let mut actions = vec![];
        for _ in 0..ELECTION_TIMEOUT_MIN {
            actions.extend(n1.tick());
        }
        assert_eq!(n1.role, RaftRole::Candidate);

        // Deliver VoteReqs to n2, n3
        let vote_reqs: Vec<_> = actions
            .iter()
            .filter_map(|a| {
                if let RaftAction::Broadcast {
                    msg: RaftMessage::VoteReq(r),
                } = a
                {
                    Some(r.clone())
                } else {
                    None
                }
            })
            .collect();
        let mut vote_actions = vec![];
        for req in vote_reqs {
            vote_actions.extend(n2.step(1, RaftMessage::VoteReq(req.clone())));
            vote_actions.extend(n3.step(1, RaftMessage::VoteReq(req)));
        }

        // Deliver VoteResps back to n1
        for a in vote_actions {
            if let RaftAction::Send {
                msg: RaftMessage::VoteResp(r),
                ..
            } = a
            {
                let results = n1.step(r.from_id, RaftMessage::VoteResp(r));
                if n1.role == RaftRole::Leader {
                    break;
                }
                let _ = results;
            }
        }
        assert_eq!(n1.role, RaftRole::Leader, "n1 should win with 2-of-3 votes");
    }

    #[test]
    fn log_replication_reaches_quorum() {
        let mut leader = node(1, &[2, 3]);
        // Fast-track to leader
        leader.current_term = 1;
        leader.role = RaftRole::Leader;
        leader.peer_state.insert(
            2,
            crate::raft::PeerState {
                next_index: 1,
                match_index: 0,
            },
        );
        leader.peer_state.insert(
            3,
            crate::raft::PeerState {
                next_index: 1,
                match_index: 0,
            },
        );

        let (idx, replicate_actions) = leader.propose(DecisionCommand::Noop).unwrap();
        assert_eq!(idx, 1);
        // Two AppendEntries should be sent
        assert_eq!(
            replicate_actions
                .iter()
                .filter(|a| matches!(a, RaftAction::Send { .. }))
                .count(),
            2
        );

        // Both followers ack
        let resp = AppendEntriesResp {
            term: 1,
            from_id: 2,
            success: true,
            match_index: 1,
        };
        let actions = leader.step(2, RaftMessage::AppendResp(resp));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, RaftAction::Apply { .. })),
            "quorum reached, should apply"
        );
    }

    #[test]
    fn stale_term_rejected() {
        let mut n = node(1, &[]);
        n.current_term = 5;
        let req = RequestVoteReq {
            term: 3,
            candidate_id: 2,
            last_log_idx: 0,
            last_log_term: 0,
        };
        let actions = n.step(2, RaftMessage::VoteReq(req));
        assert!(actions.iter().any(|a| matches!(
            a, RaftAction::Send { msg: RaftMessage::VoteResp(r), .. } if !r.vote_granted
        )));
    }
}
