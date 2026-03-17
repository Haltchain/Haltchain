//! Multi-agent orchestration tests — verify isolation, conflict resolution,
//! and velocity enforcement behave correctly under concurrent agent workloads.

use std::sync::Arc;
use std::time::Instant;

use haltchain_consensus::{QuorumDecision, QuorumRequest, QuorumTracker, HIGH_STAKES_THRESHOLD_CENTS};
use haltchain_validator::{ActionPayload, AppState, Decision, ValidationRequest};
use serde_json::json;

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn make_req(agent_id: &str, action_type: &str, amount: f64) -> ValidationRequest {
    make_req_with_recipient(agent_id, action_type, amount, "acct_target")
}

fn make_req_with_recipient(agent_id: &str, action_type: &str, amount: f64, recipient: &str) -> ValidationRequest {
    ValidationRequest {
        agent_id: agent_id.into(),
        api_key: "test-key".into(),
        action: ActionPayload {
            action_type: action_type.into(),
            amount: Some(amount),
            currency: Some("USD".into()),
            recipient: Some(recipient.into()),
            endpoint: Some("/api/transfer".into()),
            method: Some("POST".into()),
            device_id: None,
            command: None,
        },
        session_id: Some(format!("sess_{agent_id}")),
        metadata: json!({
            "tokens_per_minute": 500,
            "compute_seconds_per_hour": 5,
            "cpu_percent": 15.0,
            "memory_percent": 20.0,
            "payload_contains_pii": false,
            "destination_country": "US",
            "dependency_cascade_depth": 1,
        }),
    }
}

// ─── Cascading failure containment ────────────────────────────────────────────

/// A rogue agent flooding with oversized transfers must be denied without
/// affecting legitimately behaving agents running in parallel.
#[tokio::test]
async fn test_cascading_failure_containment() {
    let state = AppState::new();

    let rogue_id = "rogue_agent_000";
    let honest_ids: Vec<String> = (1..=50).map(|i| format!("honest_agent_{i:03}")).collect();

    // Launch honest + rogue agents concurrently.
    let mut handles = Vec::new();

    // Rogue: 100 oversized transfers.
    {
        let state = Arc::clone(&state);
        let id = rogue_id.to_string();
        handles.push(tokio::spawn(async move {
            let mut denials = 0usize;
            for _ in 0..100 {
                let resp = state.validate(&make_req(&id, "transfer", 999_999.0)).await;
                if matches!(resp.decision, Decision::Deny | Decision::CircuitBreak) {
                    denials += 1;
                }
            }
            ("rogue", denials, 100usize)
        }));
    }

    // Honest agents: normal-sized transfers to unique recipients (avoid cross-agent aggregate).
    for id in &honest_ids {
        let state = Arc::clone(&state);
        let id = id.clone();
        handles.push(tokio::spawn(async move {
            let mut allows = 0usize;
            let recipient = format!("acct_{id}");
            for _ in 0..10 {
                let resp = state.validate(&make_req_with_recipient(&id, "transfer", 50.0, &recipient)).await;
                if matches!(resp.decision, Decision::Allow) {
                    allows += 1;
                }
            }
            ("honest", allows, 10usize)
        }));
    }

    let mut results = Vec::new();
    for h in handles {
        if let Ok(r) = h.await {
            results.push(r);
        }
    }

    let rogue_denials = results.iter().find(|r| r.0 == "rogue").map(|r| r.1).unwrap_or(0);
    let honest_allows: Vec<usize> = results.iter().filter(|r| r.0 == "honest").map(|r| r.1).collect();

    // Rogue must have been denied on at least the over-limit requests.
    assert!(
        rogue_denials > 0,
        "rogue agent should have received denials for oversized transfers"
    );

    // At least 80% of honest agents must succeed on all their requests.
    let healthy = honest_allows.iter().filter(|&&a| a == 10).count();
    assert!(
        healthy >= 40,
        "{} / {} honest agents unaffected; expected >= 40",
        healthy,
        honest_ids.len()
    );
}

// ─── Quorum conflict resolution ────────────────────────────────────────────────

/// Two honest nodes approving must outweigh one malicious node rejecting.
#[test]
fn test_quorum_honest_majority_wins() {
    let req = QuorumRequest {
        transaction_id: "tx-conflict-001".into(),
        agent_id: "trader_a".into(),
        amount_cents: HIGH_STAKES_THRESHOLD_CENTS + 1, // requires quorum
        is_anomaly: false,
    };
    assert!(req.requires_quorum(), "request should be high-stakes");

    let mut tracker = QuorumTracker::new(&req.transaction_id);
    tracker.approve(1); // honest node A
    tracker.approve(2); // honest node B
    tracker.reject(3);  // malicious market-maker

    assert_eq!(
        tracker.decision(),
        QuorumDecision::Approved,
        "2-of-3 honest majority must approve"
    );
}

/// Unanimous rejection must produce Rejected immediately.
#[test]
fn test_quorum_unanimous_rejection() {
    let mut tracker = QuorumTracker::new("tx-conflict-002");
    tracker.reject(1);
    tracker.reject(2);
    tracker.reject(3);
    assert_eq!(tracker.decision(), QuorumDecision::Rejected);
}

/// Low-value transaction that does not meet the high-stakes threshold should
/// not require quorum.
#[test]
fn test_low_stakes_skips_quorum() {
    let req = QuorumRequest {
        transaction_id: "tx-low-001".into(),
        agent_id: "normal_agent".into(),
        amount_cents: HIGH_STAKES_THRESHOLD_CENTS - 1,
        is_anomaly: false,
    };
    assert!(
        !req.requires_quorum(),
        "low-value request should not require quorum"
    );
}

/// Anomalous flag forces quorum even for small amounts.
#[test]
fn test_anomaly_flag_forces_quorum() {
    let req = QuorumRequest {
        transaction_id: "tx-anom-001".into(),
        agent_id: "suspicious_agent".into(),
        amount_cents: 1, // tiny amount
        is_anomaly: true,
    };
    assert!(
        req.requires_quorum(),
        "anomaly flag must force quorum regardless of amount"
    );
}

// ─── Velocity enforcement across agent mesh ────────────────────────────────────

/// High-frequency requests from a single agent should trigger velocity denial
/// before the window resets.
#[tokio::test]
async fn test_velocity_limit_single_agent() {
    let state = AppState::new();
    let agent_id = "velocity_test_agent";

    let mut allow_count = 0usize;
    let mut deny_count = 0usize;

    // Fire twice the per-minute limit (MAX_ACTIONS_PER_MINUTE from policy crate).
    for _ in 0..25 {
        let resp = state.validate(&make_req(agent_id, "transfer", 100.0)).await;
        match resp.decision {
            Decision::Allow => allow_count += 1,
            Decision::Deny | Decision::CircuitBreak => deny_count += 1,
            _ => {}
        }
    }

    assert!(
        deny_count > 0,
        "velocity limit must deny at least some requests after 25 rapid calls; got 0 denials"
    );
    assert!(
        allow_count > 0,
        "some requests before the velocity limit must be allowed; got 0 allows"
    );
}

/// Concurrently launched agents must each have independent velocity windows —
/// one bursting agent must not affect others hitting normal rates.
#[tokio::test]
async fn test_velocity_windows_are_agent_scoped() {
    let state = AppState::new();

    // Bursting agent: fires 50 rapid requests.
    let burst_handle = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let mut denials = 0usize;
            for _ in 0..50 {
                let resp = state.validate(&make_req("burst_agent", "transfer", 100.0)).await;
                if matches!(resp.decision, Decision::Deny | Decision::CircuitBreak) {
                    denials += 1;
                }
            }
            denials
        })
    };

    // Normal agent: fires 5 requests to a separate recipient — should all be allowed.
    let normal_handle = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let mut allows = 0usize;
            for _ in 0..5 {
                let resp = state.validate(&make_req_with_recipient("normal_agent", "transfer", 100.0, "acct_normal")).await;
                if matches!(resp.decision, Decision::Allow) {
                    allows += 1;
                }
            }
            allows
        })
    };

    let (burst_denials, normal_allows) = tokio::join!(burst_handle, normal_handle);
    let burst_denials = burst_denials.unwrap();
    let normal_allows = normal_allows.unwrap();

    assert!(
        burst_denials > 0,
        "burst agent must have been rate-limited"
    );
    assert_eq!(
        normal_allows, 5,
        "normal agent must not be affected by burst agent's violations (got {normal_allows}/5 allows)"
    );
}

// ─── Parallel correctness under high concurrency ─────────────────────────────

/// 200 agents firing 20 requests each concurrently must all receive valid,
/// non-panicking responses — no data races or silent failures.
#[tokio::test]
async fn test_parallel_validation_no_panics() {
    let state = AppState::new();
    const AGENTS: usize = 200;
    const REQS: usize = 20;

    let handles: Vec<_> = (0..AGENTS)
        .map(|i| {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                for j in 0..REQS {
                    let amount = if j % 5 == 0 { 2_000.0 } else { 50.0 };
                    let resp = state
                        .validate(&make_req(&format!("par_agent_{i:03}"), "transfer", amount))
                        .await;
                    // Ensure decision is a valid variant.
                    let _ = resp.decision;
                }
            })
        })
        .collect();

    for h in handles {
        h.await.expect("concurrent validation task panicked");
    }
}

// ─── Latency under concurrent load ────────────────────────────────────────────

/// p99 latency for 100 concurrent agents must stay within 10 ms.
#[tokio::test]
async fn test_concurrent_p99_latency_under_10ms() {
    let state = AppState::new();

    // Warm up.
    for i in 0..10 {
        state.validate(&make_req(&format!("warmup_{i}"), "api_call", 0.0)).await;
    }

    let handles: Vec<_> = (0..100)
        .map(|i| {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                let t0 = Instant::now();
                state
                    .validate(&make_req(&format!("lat_agent_{i:03}"), "transfer", 100.0))
                    .await;
                t0.elapsed().as_micros() as u64
            })
        })
        .collect();

    let mut latencies: Vec<u64> = Vec::with_capacity(100);
    for h in handles {
        if let Ok(us) = h.await {
            latencies.push(us);
        }
    }
    latencies.sort_unstable();

    let p99_idx = ((0.99 * latencies.len() as f64).ceil() as usize).saturating_sub(1);
    let p99_us = latencies[p99_idx.min(latencies.len() - 1)];
    let p99_ms = p99_us as f64 / 1_000.0;

    assert!(
        p99_ms < 10.0,
        "p99 latency {p99_ms:.2} ms exceeds 10 ms target under 100 concurrent agents"
    );
}
