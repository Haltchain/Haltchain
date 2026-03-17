//! `haltchain-consensus` — pure-Rust Raft consensus for multi-validator agreement.
//!
//! Architecture:
//! * `log`       — append-only decision log
//! * `raft`      — Raft state machine: leader election + log replication
//! * `node`      — async tokio driver: 100 ms heartbeats, election timeouts
//! * `quorum`    — 2-of-3 high-stakes vote gate
//! * `partition` — CAP consistency preference, leader step-down

pub mod log;
pub mod node;
pub mod partition;
pub mod quorum;
pub mod raft;

pub use log::{DecisionCommand, DecisionLog, LogEntry};
pub use node::{NodeHandle, NodeHealth, NodeRunner};
pub use partition::{
    LEADER_STEP_DOWN_TIMEOUT, PEER_TIMEOUT, PartitionDecision, PartitionDetector, PartitionPolicy,
};
pub use quorum::{
    CLUSTER_SIZE, HIGH_STAKES_THRESHOLD_CENTS, QUORUM, QuorumDecision, QuorumRequest,
    QuorumTracker, Vote,
};
pub use raft::{
    AppendEntriesReq, AppendEntriesResp, RaftAction, RaftMessage, RaftNode, RaftRole,
    RequestVoteReq, RequestVoteResp,
};
