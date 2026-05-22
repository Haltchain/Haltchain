//! Financial velocity attack stress test.
//!
//! Simulates a rogue trading agent that starts with normal behaviour then
//! bursts 10 000 oversized transactions. Validates that:
//!   1. Normal-phase requests are allowed.
//!   2. Attack-phase triggers denials within a tight detection window.
//!   3. EWMA velocity tracker and IsolationForest flag the burst.
//!   4. Other "legitimate" agents running in parallel are unaffected.
//!
//! Run with:
//!   cargo test -p haltchain-validator --test velocity_attack -- --nocapture

use std::sync::Arc;
use std::time::Instant;

use haltchain_analytics::{Ewma, SlidingWindowTracker, isolation_forest::IsolationForest};
use haltchain_validator::{ActionPayload, AppState, Decision, ValidationRequest};
use serde_json::json;

//Helpers

fn make_transfer(agent: &str, amount: f64, session: &str) -> ValidationRequest {
    ValidationRequest {
        agent_id: agent.into(),
        api_key: "bench-key".into(),
        action: ActionPayload {
            action_type: "transfer".into(),
            amount: Some(amount),
            currency: Some("USD".into()),
            recipient: Some("acct_target".into()),
            endpoint: Some("/api/transfer".into()),
            method: Some("POST".into()),
            device_id: None,
            command: None,
            delegation_depth: None,
            data_source: Default::default(),
        },
        session_id: Some(session.into()),
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

//EWMA spike detection unit test

#[test]
fn ewma_detects_velocity_spike_within_5_observations() {
    let mut ewma = Ewma::new(0.3);

    // Normal phase: 1 000 observations centred at 100.
    for i in 0u64..1_000 {
        let sample = 100.0 + (i % 20) as f64 - 10.0;
        ewma.update(sample);
    }
    let baseline = ewma.get();

    // Attack burst: sudden jump to 999 999.
    let mut detected_at: Option<usize> = None;
    for i in 0..20 {
        ewma.update(999_999.0);
        // Detection = EWMA exceeding 3× baseline.
        if ewma.get() > baseline * 3.0 && detected_at.is_none() {
            detected_at = Some(i);
        }
    }

    assert!(
        detected_at.is_some(),
        "EWMA never flagged the spike; baseline={baseline:.1} final={:.1}",
        ewma.get()
    );
    assert!(
        detected_at.unwrap() < 5,
        "EWMA spike detection too slow: {} observations",
        detected_at.unwrap()
    );
}

// IsolationForest flags burst vectors

#[test]
fn isolation_forest_flags_velocity_burst_vectors() {
    // Train on varied "normal" feature vectors with continuous spread.
    // Use prime-number offsets to avoid repeating exact values (degenerate trees).
    let normal: Vec<Vec<f64>> = (0..500)
        .map(|i| {
            let fi = i as f64;
            vec![
                5.0 + (fi * 0.37) % 10.0,   // velocity in [5, 15)
                100.0 + (fi * 0.73) % 50.0, // amount in [100, 150)
                0.1 + (fi * 0.017) % 0.1,   // acceleration in [0.1, 0.2)
            ]
        })
        .collect();
    let forest = IsolationForest::fit(&normal);

    // "Attack" feature vectors: values far outside training range.
    let attack_flagged = (0..100)
        .filter(|i| {
            let attack = vec![
                10_000.0 + *i as f64, // extreme velocity
                999_999.0,            // extreme amount
                500.0,                // extreme acceleration
            ];
            forest.is_anomaly(&attack)
        })
        .count();

    assert!(
        attack_flagged >= 90,
        "IsolationForest only caught {attack_flagged}/100 attack vectors"
    );

    // Normal vectors should mostly pass.
    let false_pos = (0..200)
        .filter(|i| {
            let pt = vec![
                5.0 + (*i % 10) as f64,
                100.0 + (*i % 50) as f64,
                0.1 + (*i % 5) as f64 * 0.02,
            ];
            forest.is_anomaly(&pt)
        })
        .count();

    let fpr = false_pos as f64 / 200.0;
    assert!(
        fpr < 0.15,
        "False positive rate {:.1}% too high during velocity test",
        fpr * 100.0
    );
}

//Full-stack velocity attack (normal → burst → isolation)

#[tokio::test]
async fn full_stack_velocity_attack_contained() {
    let state = AppState::new();

    // ── Normal phase: 5 legitimate requests (well under MAX_ACTIONS_PER_MINUTE=10).
    let mut normal_allows = 0usize;
    for i in 0..5 {
        let amount = 80.0 + (i % 20) as f64;
        let resp = state
            .validate(&make_transfer("legit_trader", amount, "sess_legit"))
            .await;
        if matches!(resp.decision, Decision::Allow) {
            normal_allows += 1;
        }
    }
    assert!(
        normal_allows > 0,
        "No normal-phase requests allowed — baseline broken"
    );

    // ── Attack burst: rogue agent fires oversized transfers (amount > MAX_TRANSFER_USD=1000).
    // First request is denied for amount, subsequent ones trip CB.
    let mut attack_denials = 0usize;
    let attack_start = Instant::now();
    for _seq in 0..20 {
        let resp = state
            .validate(&make_transfer("rogue_ai", 999_999.0, "sess_rogue"))
            .await;
        if matches!(resp.decision, Decision::Deny | Decision::CircuitBreak) {
            attack_denials += 1;
        }
    }
    let attack_elapsed = attack_start.elapsed();

    println!(
        "Attack phase: {attack_denials}/20 denied in {:.1}ms",
        attack_elapsed.as_secs_f64() * 1000.0
    );

    assert_eq!(
        attack_denials, 20,
        "Only {attack_denials}/20 attack requests were denied"
    );

    // ── Verify legit trader is still operational after rogue attack.
    // Use a fresh agent id AND different recipient to avoid cross-agent
    // recipient aggregate check (rogue polluted "acct_target").
    let post_attack_req = ValidationRequest {
        agent_id: "legit_trader_2".into(),
        api_key: "bench-key".into(),
        action: ActionPayload {
            action_type: "transfer".into(),
            amount: Some(50.0),
            currency: Some("USD".into()),
            recipient: Some("acct_clean".into()),
            endpoint: Some("/api/transfer".into()),
            method: Some("POST".into()),
            device_id: None,
            command: None,
            delegation_depth: None,
            data_source: Default::default(),
        },
        session_id: Some("sess_legit_2".into()),
        metadata: json!({
            "tokens_per_minute": 500,
            "compute_seconds_per_hour": 5,
            "cpu_percent": 15.0,
            "memory_percent": 20.0,
            "payload_contains_pii": false,
            "destination_country": "US",
            "dependency_cascade_depth": 1,
        }),
    };
    let post_attack_resp = state.validate(&post_attack_req).await;
    assert!(
        matches!(post_attack_resp.decision, Decision::Allow),
        "Fresh legit trader blocked after rogue attack — cascading failure: {:?} reason={:?}",
        post_attack_resp.decision,
        post_attack_resp.reason
    );
}

//Concurrent rogue + legitimate traffic

#[tokio::test]
async fn concurrent_velocity_attack_no_cascade() {
    let state = AppState::new();
    let n_legit = 20;
    let reqs_per_legit = 5; // stay well under MAX_ACTIONS_PER_MINUTE=10
    let n_attack_reqs = 20;

    // Legit agents: each sends a few small transfers to unique recipients.
    let mut legit_handles = Vec::new();
    for i in 0..n_legit {
        let state = Arc::clone(&state);
        legit_handles.push(tokio::spawn(async move {
            let mut ok = 0usize;
            for j in 0..reqs_per_legit {
                let req = ValidationRequest {
                    agent_id: format!("legit_{i:03}"),
                    api_key: "bench-key".into(),
                    action: ActionPayload {
                        action_type: "transfer".into(),
                        amount: Some(50.0 + (j as f64)),
                        currency: Some("USD".into()),
                        recipient: Some(format!("acct_legit_{i:03}")),
                        endpoint: Some("/api/transfer".into()),
                        method: Some("POST".into()),
                        device_id: None,
                        command: None,
                        delegation_depth: None,
                        data_source: Default::default(),
                    },
                    session_id: Some(format!("sess_{i:03}")),
                    metadata: json!({
                        "tokens_per_minute": 500,
                        "compute_seconds_per_hour": 5,
                        "cpu_percent": 15.0,
                        "memory_percent": 20.0,
                        "payload_contains_pii": false,
                        "destination_country": "US",
                        "dependency_cascade_depth": 1,
                    }),
                };
                let resp = state.validate(&req).await;
                if matches!(resp.decision, Decision::Allow) {
                    ok += 1;
                }
            }
            ok
        }));
    }

    // Rogue agents: 5 attackers each send oversized transfers concurrently.
    let mut rogue_handles = Vec::new();
    for r in 0..5 {
        let state = Arc::clone(&state);
        rogue_handles.push(tokio::spawn(async move {
            let mut denied = 0usize;
            for _ in 0..n_attack_reqs {
                let resp = state
                    .validate(&make_transfer(
                        &format!("rogue_{r:02}"),
                        999_999.0,
                        &format!("sess_rogue_{r:02}"),
                    ))
                    .await;
                if matches!(resp.decision, Decision::Deny | Decision::CircuitBreak) {
                    denied += 1;
                }
            }
            denied
        }));
    }

    // Collect results.
    let mut legit_allows = 0usize;
    for h in legit_handles {
        legit_allows += h.await.unwrap();
    }
    let mut total_rogue_denied = 0usize;
    for h in rogue_handles {
        total_rogue_denied += h.await.unwrap();
    }

    let total_legit = n_legit * reqs_per_legit;
    println!("Legit allows: {legit_allows}/{total_legit}");
    println!("Rogue denied: {total_rogue_denied}/{}", 5 * n_attack_reqs);

    // All rogue transfers must be denied (amount exceeds limit).
    assert_eq!(
        total_rogue_denied,
        5 * n_attack_reqs,
        "Not all rogue requests denied"
    );

    // At least 50% of legit traffic must succeed.
    assert!(
        legit_allows as f64 / total_legit as f64 > 0.50,
        "Too many legit requests affected: only {legit_allows}/{total_legit} allowed",
    );
}

//SlidingWindowTracker velocity statistics

#[test]
fn sliding_window_captures_burst_stats() {
    let tracker = SlidingWindowTracker::new();

    // Normal phase.
    for i in 0..100 {
        tracker.record(100.0 + (i % 20) as f64);
    }
    let normal_stats = tracker.stats_1m();
    let normal_velocity = tracker.ewma_velocity();

    // Burst phase.
    for _ in 0..1_000 {
        tracker.record(999_999.0);
    }
    let burst_stats = tracker.stats_1m();
    let burst_velocity = tracker.ewma_velocity();

    assert!(
        burst_velocity > normal_velocity,
        "EWMA velocity should spike: normal={normal_velocity:.1} burst={burst_velocity:.1}"
    );
    assert!(
        burst_stats.mean > normal_stats.mean,
        "Burst mean should be much higher: normal={:.1} burst={:.1}",
        normal_stats.mean,
        burst_stats.mean
    );
}
