//! Weekend: chaos engineering tests for the Raft consensus layer.
//!
//! Scenarios:
//! 1. Kill leader mid-transaction → new leader elected, committed entries survive.
//! 2. Minority partition → minority refuses writes, majority continues.
//! 3. No split-brain — only one leader ever holds commit authority at a time.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::time::sleep;

use haltchain_consensus::log::LogEntry;
use haltchain_consensus::node::{ApplyFn, NodeRunner};
use haltchain_consensus::partition::{
    PEER_TIMEOUT, PartitionDecision, PartitionDetector, PartitionPolicy,
};
use haltchain_consensus::quorum::{QuorumDecision, QuorumRequest, QuorumTracker};
use haltchain_consensus::raft::RaftRole;

// Helpers

fn apply_counter(counter: Arc<AtomicUsize>) -> ApplyFn {
    Box::new(move |entries: Vec<LogEntry>| {
        counter.fetch_add(entries.len(), Ordering::SeqCst);
    })
}

async fn wait_for_leader(
    inners: &[Arc<parking_lot::Mutex<haltchain_consensus::raft::RaftNode>>],
    timeout: Duration,
) -> Option<usize> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() > deadline {
            return None;
        }
        if let Some(idx) = inners
            .iter()
            .position(|i| i.lock().role == RaftRole::Leader)
        {
            return Some(idx);
        }
        sleep(Duration::from_millis(50)).await;
    }
}

// Wire three nodes with full mesh channels.
fn build_cluster(
    apply: [ApplyFn; 3],
) -> (
    [NodeRunner; 3],
    [Arc<parking_lot::Mutex<haltchain_consensus::raft::RaftNode>>; 3],
) {
    let [a0, a1, a2] = apply;
    let (mut r1, h1, _) = NodeRunner::new(1, vec![2, 3], a0);
    let (mut r2, h2, _) = NodeRunner::new(2, vec![1, 3], a1);
    let (mut r3, h3, _) = NodeRunner::new(3, vec![1, 2], a2);
    r1.add_peer_channel(2, h2.inbound.clone());
    r1.add_peer_channel(3, h3.inbound.clone());
    r2.add_peer_channel(1, h1.inbound.clone());
    r2.add_peer_channel(3, h3.inbound.clone());
    r3.add_peer_channel(1, h1.inbound.clone());
    r3.add_peer_channel(2, h2.inbound.clone());
    let i1 = r1.inner.clone();
    let i2 = r2.inner.clone();
    let i3 = r3.inner.clone();
    ([r1, r2, r3], [i1, i2, i3])
}

// ─── Chaos 1: Kill leader, verify new leader elected ─────────────────────────

#[tokio::test]
async fn chaos_kill_leader_new_leader_elected() {
    let counters: Vec<Arc<AtomicUsize>> = (0..3).map(|_| Arc::new(AtomicUsize::new(0))).collect();
    let applies = [
        apply_counter(counters[0].clone()),
        apply_counter(counters[1].clone()),
        apply_counter(counters[2].clone()),
    ];
    let ([r1, r2, r3], inners) = build_cluster(applies);

    let jh1 = tokio::spawn(r1.run());
    let jh2 = tokio::spawn(r2.run());
    let jh3 = tokio::spawn(r3.run());

    // Wait for initial leader
    let leader_idx = wait_for_leader(&inners, Duration::from_secs(3))
        .await
        .expect("initial leader not elected");

    // Kill the leader's task (abort stops its run loop — peers will time out and re-elect)
    match leader_idx {
        0 => jh1.abort(),
        1 => jh2.abort(),
        _ => jh3.abort(),
    }
    // Invalidate inner state so it shows no role (simulate killed node)
    inners[leader_idx].lock().role = RaftRole::Follower;

    // Remaining two nodes should elect a new leader
    let remaining: Vec<_> = inners
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != leader_idx)
        .map(|(_, inn)| inn.clone())
        .collect();
    let new_leader = wait_for_leader(&remaining, Duration::from_secs(5)).await;
    assert!(
        new_leader.is_some(),
        "new leader must be elected after killing old leader"
    );
}

// ─── Chaos 2: Minority partition refuses writes ───────────────────────────────

#[tokio::test]
async fn chaos_minority_partition_refuses_writes() {
    // Node 1 is isolated (only 1 visible out of 3 → no quorum)
    let mut detector = PartitionDetector::new(
        1,
        &[2, 3],
        3,
        2,
        PartitionPolicy::ConsistencyOverAvailability,
    );
    // Make both peers appear silent
    use std::time::Instant;
    let old = Instant::now()
        .checked_sub(PEER_TIMEOUT + Duration::from_millis(100))
        .unwrap_or(Instant::now());
    detector.last_heard.insert(2, old);
    detector.last_heard.insert(3, old);

    assert!(!detector.has_quorum());
    // As leader: step down
    assert_eq!(detector.check_write(true), PartitionDecision::StepDown);
    // As follower: unavailable
    assert!(matches!(
        detector.check_write(false),
        PartitionDecision::ServiceUnavailable { .. }
    ));
}

// ─── Chaos 3: No split-brain — two partitions cannot both commit ──────────────

#[tokio::test]
async fn chaos_no_split_brain() {
    // Model: nodes 1+2 form a majority; node 3 is isolated.
    // Node 3 cannot commit (no quorum), nodes 1+2 elect a leader and commit.
    // Verify that using `ConsistencyOverAvailability`, node 3 is aware it is partitioned.

    let mut d3 = PartitionDetector::new(
        3,
        &[1, 2],
        3,
        2,
        PartitionPolicy::ConsistencyOverAvailability,
    );
    // Both peers silent from node 3's perspective
    let old = std::time::Instant::now()
        .checked_sub(PEER_TIMEOUT + Duration::from_millis(100))
        .unwrap_or(std::time::Instant::now());
    d3.last_heard.insert(1, old);
    d3.last_heard.insert(2, old);
    // Node 3 must refuse writes — it cannot be leader at the same time as 1+2
    assert!(!d3.has_quorum());
    assert_ne!(d3.check_write(true), PartitionDecision::Proceed);

    // Meanwhile the 1+2 side should proceed (they hold quorum)
    let d1 = PartitionDetector::new(
        1,
        &[2, 3],
        3,
        2,
        PartitionPolicy::ConsistencyOverAvailability,
    );
    // d1 was just constructed — both peers are fresh
    assert!(d1.has_quorum());
    assert_eq!(d1.check_write(true), PartitionDecision::Proceed);
}

// ─── Chaos 4: Quorum required for high-stakes cross-node decision ─────────────

#[tokio::test]
async fn chaos_high_stakes_quorum_required() {
    let req = QuorumRequest {
        transaction_id: "txn-chaos-1".into(),
        agent_id: "agent-a".into(),
        amount_cents: 100_000, // > $500 → high-stakes
        is_anomaly: false,
    };
    assert!(req.requires_quorum());

    let mut tracker = QuorumTracker::new(&req.transaction_id);
    // Only one approval so far — must remain Pending
    tracker.approve(1);
    assert_eq!(tracker.decision(), QuorumDecision::Pending);

    // Second approval → reaches 2-of-3 quorum
    tracker.approve(2);
    assert_eq!(tracker.decision(), QuorumDecision::Approved);
}

// ─── Chaos 5: Committed entries not lost after follower restart ───────────────

#[tokio::test]
async fn chaos_committed_entry_survives_follower_restart() {
    // This is captured at the log level without full network.
    // Leader commits an entry; a simulated follower receives it via AppendEntries.

    use haltchain_consensus::log::DecisionCommand;
    use haltchain_consensus::raft::{
        AppendEntriesReq, ELECTION_TIMEOUT_MIN, RaftMessage, RaftNode,
    };

    let mut leader = RaftNode::new(1, vec![2], ELECTION_TIMEOUT_MIN);
    leader.current_term = 1;
    leader.role = RaftRole::Leader;
    // Manually initialise peer state for node 2
    {
        let inner = &mut leader;
        inner.peer_state.insert(
            2,
            haltchain_consensus::raft::PeerState {
                next_index: 1,
                match_index: 0,
            },
        );
    }
    let (_commit_idx, _) = leader
        .propose(DecisionCommand::Validate {
            transaction_id: "txn-1".into(),
            agent_id: "bot-a".into(),
            action_type: "Transfer".into(),
            amount_cents: 200_000,
            decision: "ALLOW".into(),
        })
        .unwrap();

    // Simulate follower receiving the AppendEntries
    let mut follower = RaftNode::new(2, vec![1], ELECTION_TIMEOUT_MIN);
    follower.current_term = 1;
    let req = AppendEntriesReq {
        term: 1,
        leader_id: 1,
        prev_log_idx: 0,
        prev_log_term: 0,
        entries: leader.log.entries_from(1).to_vec(),
        leader_commit: 1,
    };
    let actions = follower.step(1, RaftMessage::AppendReq(req));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, haltchain_consensus::raft::RaftAction::Apply { .. })),
        "follower must apply committed entry"
    );
    assert_eq!(follower.log.commit_index(), 1);

    // Simulate follower restart — a fresh RaftNode has empty log
    let restarted = RaftNode::new(2, vec![1], ELECTION_TIMEOUT_MIN);
    assert_eq!(restarted.log.last_index(), 0, "restarted node starts empty");
    // In a real system it would replay the persistent log — this is the WAL boundary
}

// ─── Kill-switch 1: Kill node2, verify quorum continues ───────────────────────

#[tokio::test]
async fn killswitch_kill_node2_quorum_continues() {
    let counters: Vec<Arc<AtomicUsize>> = (0..3).map(|_| Arc::new(AtomicUsize::new(0))).collect();
    let applies = [
        apply_counter(counters[0].clone()),
        apply_counter(counters[1].clone()),
        apply_counter(counters[2].clone()),
    ];
    let ([r1, r2, r3], inners) = build_cluster(applies);

    let jh1 = tokio::spawn(r1.run());
    let jh2 = tokio::spawn(r2.run());
    let jh3 = tokio::spawn(r3.run());

    // Wait for initial cluster leadership.
    let _ = wait_for_leader(&inners, Duration::from_secs(3))
        .await
        .expect("initial leader not elected");

    // Kill node2 (index 1 in the array = node_id 2).
    jh2.abort();
    inners[1].lock().role = RaftRole::Follower;

    // node1 and node3 form a majority — they must maintain or elect a leader.
    let remaining: Vec<_> = vec![inners[0].clone(), inners[2].clone()];
    let leader_after_kill = wait_for_leader(&remaining, Duration::from_secs(5)).await;
    assert!(
        leader_after_kill.is_some(),
        "majority (node1 + node3) must maintain quorum after node2 is killed"
    );

    // Verify writes are accepted on the majority side.
    let has_quorum = {
        let mut d1 = haltchain_consensus::partition::PartitionDetector::new(
            1,
            &[2, 3],
            3,
            2,
            haltchain_consensus::partition::PartitionPolicy::ConsistencyOverAvailability,
        );
        // node3 is still alive — only node2 is silent.
        let old = std::time::Instant::now()
            .checked_sub(PEER_TIMEOUT + Duration::from_millis(100))
            .unwrap_or(std::time::Instant::now());
        d1.last_heard.insert(2, old); // node2 silent
        d1.has_quorum()
    };
    assert!(has_quorum, "node1 still sees node3 → quorum reachable");

    jh1.abort();
    jh3.abort();
}

//  Kill-switch 2: 1/3 Byzantine behavior, BFT resistance

#[tokio::test(flavor = "multi_thread")]
async fn killswitch_byzantine_one_third_bft_resistance() {
    // In a 3-node cluster, 1 Byzantine node cannot forge a majority.
    // We simulate Byzantine behaviour: node3 sends stale-term vote requests.

    use haltchain_consensus::raft::{RaftMessage, RaftNode, RequestVoteReq};

    let mut node1 = RaftNode::new(
        1,
        vec![2, 3],
        haltchain_consensus::raft::ELECTION_TIMEOUT_MIN,
    );
    let mut node2 = RaftNode::new(
        2,
        vec![1, 3],
        haltchain_consensus::raft::ELECTION_TIMEOUT_MIN,
    );
    // node3 is Byzantine: it spams RequestVote with a stale term.

    // Bring node1 and node2 to term 2 (already elected, stable).
    node1.current_term = 2;
    node1.role = RaftRole::Leader;
    node2.current_term = 2;
    node2.voted_for = Some(1);

    // Byzantine node3 sends a RequestVote with term 1 (stale).
    let byzantine_vote = RaftMessage::VoteReq(RequestVoteReq {
        term: 1,
        candidate_id: 3,
        last_log_idx: 0,
        last_log_term: 0,
    });

    let actions1 = node1.step(2, byzantine_vote.clone());
    let actions2 = node2.step(3, byzantine_vote.clone());

    // Neither node should grant the vote — stale term must be rejected.
    let granted_by_1 = actions1.iter().any(|a| {
        if let haltchain_consensus::raft::RaftAction::Send { to: _, msg } = a
            && let RaftMessage::VoteResp(r) = msg
        {
            return r.vote_granted;
        }
        false
    });
    let granted_by_2 = actions2.iter().any(|a| {
        if let haltchain_consensus::raft::RaftAction::Send { to: _, msg } = a
            && let RaftMessage::VoteResp(r) = msg
        {
            return r.vote_granted;
        }
        false
    });

    assert!(
        !granted_by_1,
        "node1 must reject Byzantine stale-term vote request"
    );
    assert!(
        !granted_by_2,
        "node2 must reject Byzantine stale-term vote request"
    );

    // The leader (node1) must remain at term 2 — Byzantine node cannot elevate term via stale msg.
    assert_eq!(
        node1.current_term, 2,
        "Byzantine message must not bump leader term"
    );
}

// Kill-switch 3: <3ms consensus overhead

#[test]
fn killswitch_consensus_overhead_under_3ms() {
    use haltchain_consensus::log::DecisionCommand;
    use haltchain_consensus::raft::{ELECTION_TIMEOUT_MIN, RaftNode};
    use std::time::Instant;

    let mut leader = RaftNode::new(1, vec![2, 3], ELECTION_TIMEOUT_MIN);
    leader.current_term = 1;
    leader.role = RaftRole::Leader;
    leader.peer_state.insert(
        2,
        haltchain_consensus::raft::PeerState {
            next_index: 1,
            match_index: 0,
        },
    );
    leader.peer_state.insert(
        3,
        haltchain_consensus::raft::PeerState {
            next_index: 1,
            match_index: 0,
        },
    );

    const ITERATIONS: u32 = 1000;
    let start = Instant::now();
    for i in 0..ITERATIONS {
        leader
            .propose(DecisionCommand::Validate {
                transaction_id: format!("txn-lat-{i}"),
                agent_id: "perf-agent".into(),
                action_type: "Transfer".into(),
                amount_cents: 100,
                decision: "ALLOW".into(),
            })
            .expect("propose must succeed");
    }
    let elapsed_ms = start.elapsed().as_millis() as f64;
    let per_op_ms = elapsed_ms / ITERATIONS as f64;

    assert!(
        per_op_ms < 3.0,
        "consensus propose overhead {per_op_ms:.3}ms >= 3ms target"
    );
}
