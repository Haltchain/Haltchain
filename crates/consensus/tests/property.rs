use haltchain_consensus::quorum::{QuorumDecision, QuorumTracker};
use proptest::prelude::*;

fn decision_from_votes(votes: &[bool]) -> QuorumDecision {
    let mut q = QuorumTracker::new("txn-prop");
    for (i, approve) in votes.iter().enumerate() {
        let node_id = (i as u64) + 1;
        if *approve {
            q.approve(node_id);
        } else {
            q.reject(node_id);
        }
    }
    q.decision()
}

proptest! {
    #[test]
    fn quorum_never_approves_without_two_approvals(votes in proptest::collection::vec(any::<bool>(), 0..=3)) {
        let approvals = votes.iter().filter(|v| **v).count();
        let decision = decision_from_votes(&votes);
        if approvals < 2 {
            prop_assert_ne!(decision, QuorumDecision::Approved);
        }
    }

    #[test]
    fn quorum_rejects_when_two_or_more_rejections(votes in proptest::collection::vec(any::<bool>(), 3..=3)) {
        let rejections = votes.iter().filter(|v| !**v).count();
        let decision = decision_from_votes(&votes);
        if rejections >= 2 {
            prop_assert_eq!(decision, QuorumDecision::Rejected);
        }
    }

    #[test]
    fn vote_order_does_not_change_terminal_decision(v1 in proptest::collection::vec(any::<bool>(), 3..=3)) {
        let mut v2 = v1.clone();
        v2.reverse();
        let d1 = decision_from_votes(&v1);
        let d2 = decision_from_votes(&v2);
        prop_assert_eq!(d1, d2);
    }
}
