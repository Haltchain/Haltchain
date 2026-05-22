//! Tuesday: async `RaftNode` — wraps the Raft state machine behind a tokio task.
//!
//! The node runs a background loop that:
//! * ticks the state machine every 100 ms (heartbeat resolution),
//! * routes inbound messages from peers to `RaftNode::step()`,
//! * dispatches outbound messages and apply callbacks via mpsc channels.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, warn};

use crate::log::LogEntry;
use crate::raft::{
    ELECTION_TIMEOUT_MAX, ELECTION_TIMEOUT_MIN, RaftAction, RaftMessage, RaftNode, RaftRole,
};

// ─── Constants ────────────────────────────────────────────────────────────────

pub const TICK_MS: u64 = 100; // one logical tick = 100 ms real time

// ─── Node handle ─────────────────────────────────────────────────────────────

/// A message routed across the in-process network (used in tests / local sim).
#[derive(Debug, Clone)]
pub struct Envelope {
    pub from: u64,
    pub to: u64,
    pub msg: RaftMessage,
}

/// Callback invoked when entries are committed and ready to apply.
pub type ApplyFn = Box<dyn Fn(Vec<LogEntry>) + Send + Sync + 'static>;

/// Public handle to a running `RaftNode`.
#[derive(Clone)]
pub struct NodeHandle {
    pub id: u64,
    pub inbound: mpsc::Sender<Envelope>,
}

impl NodeHandle {
    pub async fn send(&self, envelope: Envelope) {
        let _ = self.inbound.send(envelope).await;
    }

    pub async fn is_alive(&self) -> bool {
        !self.inbound.is_closed()
    }
}

// ─── NodeRunner ───────────────────────────────────────────────────────────────

/// Owns the underlying `RaftNode` and drives it asynchronously.
pub struct NodeRunner {
    pub id: u64,
    pub inner: Arc<Mutex<RaftNode>>,
    inbound_rx: mpsc::Receiver<Envelope>,
    outbound_tx: mpsc::Sender<Envelope>, // to network / peers
    apply_fn: ApplyFn,
    peer_handles: HashMap<u64, mpsc::Sender<Envelope>>,
}

impl NodeRunner {
    /// Create a node and return `(runner, handle, outbound_rx)`.
    pub fn new(
        id: u64,
        peers: Vec<u64>,
        apply_fn: ApplyFn,
    ) -> (Self, NodeHandle, mpsc::Receiver<Envelope>) {
        // Randomise election timeout in [MIN, MAX]
        let timeout = election_timeout();
        let raft = if let Ok(dir) = std::env::var("RAFT_STATE_DIR") {
            let path = std::path::PathBuf::from(dir).join(format!("node-{id}.json"));
            RaftNode::with_persistence(id, peers, timeout, path)
        } else {
            RaftNode::new(id, peers, timeout)
        };
        let inner = Arc::new(Mutex::new(raft));
        let (inbound_tx, inbound_rx) = mpsc::channel::<Envelope>(256);
        let (outbound_tx, outbound_rx) = mpsc::channel::<Envelope>(256);
        let handle = NodeHandle {
            id,
            inbound: inbound_tx,
        };
        let runner = Self {
            id,
            inner,
            inbound_rx,
            outbound_tx,
            apply_fn,
            peer_handles: HashMap::new(),
        };
        (runner, handle, outbound_rx)
    }

    /// Wire a direct channel to a peer.  Bypasses the outbound queue for local sims.
    pub fn add_peer_channel(&mut self, peer_id: u64, tx: mpsc::Sender<Envelope>) {
        self.peer_handles.insert(peer_id, tx);
    }

    /// Run the event loop until the inbound channel is closed (node "dies").
    pub async fn run(mut self) {
        let mut ticker = interval(Duration::from_millis(TICK_MS));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let actions = self.inner.lock().tick();
                    self.dispatch(actions).await;
                }
                envelope = self.inbound_rx.recv() => {
                    match envelope {
                        None => break,  // channel closed — node stops
                        Some(env) => {
                            let actions = self.inner.lock().step(env.from, env.msg);
                            self.dispatch(actions).await;
                        }
                    }
                }
            }
        }
        debug!(id = self.id, "node stopped");
    }

    /// Snapshot: is this node currently the leader?
    pub fn is_leader_snapshot(&self) -> bool {
        self.inner.lock().is_leader()
    }

    async fn dispatch(&self, actions: Vec<RaftAction>) {
        for action in actions {
            match action {
                RaftAction::Send { to, msg } => self.route(to, msg).await,
                RaftAction::Broadcast { msg } => {
                    let peers: Vec<u64> = self.inner.lock().peers.clone();
                    for p in peers {
                        self.route(p, msg.clone()).await;
                    }
                }
                RaftAction::Apply { entries } => (self.apply_fn)(entries),
                RaftAction::BecameLeader { term } => {
                    debug!(id = self.id, term, "NODE IS LEADER");
                }
                RaftAction::BecameFollower { term } => {
                    debug!(id = self.id, term, "node stepped down");
                }
            }
        }
    }

    async fn route(&self, to: u64, msg: RaftMessage) {
        let env = Envelope {
            from: self.id,
            to,
            msg,
        };
        if let Some(tx) = self.peer_handles.get(&to) {
            if tx.send(env).await.is_err() {
                warn!(id = self.id, to, "peer channel closed");
            }
        } else {
            let _ = self.outbound_tx.send(env).await;
        }
    }

    /// Expose the inner lock for testing / health probes.
    pub fn role(&self) -> RaftRole {
        self.inner.lock().role.clone()
    }
    pub fn current_term(&self) -> u64 {
        self.inner.lock().current_term
    }
    pub fn commit_index(&self) -> u64 {
        self.inner.lock().log.commit_index()
    }
}

// ─── Health check ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NodeHealth {
    pub id: u64,
    pub role: String,
    pub term: u64,
    pub commit_index: u64,
}

impl NodeRunner {
    pub fn health(&self) -> NodeHealth {
        let g = self.inner.lock();
        NodeHealth {
            id: self.id,
            role: format!("{:?}", g.role),
            term: g.current_term,
            commit_index: g.log.commit_index(),
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn election_timeout() -> u64 {
    // Simple LCG for no-dep randomness
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(42) as u64;
    ELECTION_TIMEOUT_MIN + (seed % (ELECTION_TIMEOUT_MAX - ELECTION_TIMEOUT_MIN + 1))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::LogEntry;
    use crate::raft::RaftRole;
    use tokio::time::{Instant, sleep};

    async fn linked_cluster() -> (
        NodeRunner,
        NodeHandle,
        NodeRunner,
        NodeHandle,
        NodeRunner,
        NodeHandle,
    ) {
        let apply_fn = || Box::new(|_: Vec<LogEntry>| {}) as ApplyFn;
        let (mut r1, h1, _) = NodeRunner::new(1, vec![2, 3], apply_fn());
        let (mut r2, h2, _) = NodeRunner::new(2, vec![1, 3], apply_fn());
        let (mut r3, h3, _) = NodeRunner::new(3, vec![1, 2], apply_fn());
        r1.add_peer_channel(2, h2.inbound.clone());
        r1.add_peer_channel(3, h3.inbound.clone());
        r2.add_peer_channel(1, h1.inbound.clone());
        r2.add_peer_channel(3, h3.inbound.clone());
        r3.add_peer_channel(1, h1.inbound.clone());
        r3.add_peer_channel(2, h2.inbound.clone());
        (r1, h1, r2, h2, r3, h3)
    }

    #[tokio::test]
    async fn elects_leader_in_three_node_cluster() {
        let (r1, _h1, r2, _h2, r3, _h3) = linked_cluster().await;
        let inner1 = r1.inner.clone();
        let inner2 = r2.inner.clone();
        let inner3 = r3.inner.clone();
        tokio::spawn(r1.run());
        tokio::spawn(r2.run());
        tokio::spawn(r3.run());
        // Allow up to 2 seconds for election
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if Instant::now() > deadline {
                panic!("no leader elected within 2s");
            }
            let leaders: usize = [&inner1, &inner2, &inner3]
                .iter()
                .filter(|i| i.lock().role == RaftRole::Leader)
                .count();
            if leaders == 1 {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    }

    #[tokio::test]
    async fn heartbeat_keeps_followers_stable() {
        let (r1, _h1, r2, _h2, r3, _h3) = linked_cluster().await;
        let inner1 = r1.inner.clone();
        tokio::spawn(r1.run());
        tokio::spawn(r2.run());
        tokio::spawn(r3.run());
        // Wait for election
        sleep(Duration::from_secs(1)).await;
        let initial_term = inner1.lock().current_term;
        // Wait another second — term should not increase (no re-election)
        sleep(Duration::from_secs(1)).await;
        let final_term = inner1.lock().current_term;
        // Term may have jumped once during election but should stabilise
        assert!(
            final_term <= initial_term + 1,
            "term kept incrementing ({initial_term} → {final_term}): repeated elections"
        );
    }
}
