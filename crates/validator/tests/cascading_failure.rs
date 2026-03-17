//! Cascading failure containment stress test (OWASP ASI08).
//!
//! Simulates a multi-agent swarm where a subset of agents goes "rogue" with
//! different attack vectors simultaneously, verifying that:
//!   1. Each rogue agent is individually contained (denied / circuit-broken).
//!   2. Legitimate agents sharing the same AppState are unaffected.
//!   3. No resource exhaustion or deadlocks occur under concurrent load.
//!   4. The system recovers after attack traffic stops.
//!
//! Run with:
//!   cargo test -p haltchain-validator --test cascading_failure -- --nocapture

use std::sync::Arc;
use std::time::Instant;

use haltchain_validator::{ActionPayload, AppState, Decision, ValidationRequest};
use serde_json::json;

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn normal_req(agent_id: &str) -> ValidationRequest {
    ValidationRequest {
        agent_id: agent_id.into(),
        api_key: "test-key".into(),
        action: ActionPayload {
            action_type: "api_call".into(),
            amount: Some(50.0),
            currency: Some("USD".into()),
            recipient: Some("internal_acct".into()),
            endpoint: Some("/api/query".into()),
            method: Some("GET".into()),
            device_id: None,
            command: None,
        },
        session_id: Some(format!("sess_{agent_id}")),
        metadata: json!({
            "tokens_per_minute": 200,
            "compute_seconds_per_hour": 5,
            "cpu_percent": 10.0,
            "memory_percent": 15.0,
            "payload_contains_pii": false,
            "destination_country": "US",
            "dependency_cascade_depth": 1,
        }),
    }
}

fn oversized_transfer_req(agent_id: &str) -> ValidationRequest {
    ValidationRequest {
        agent_id: agent_id.into(),
        api_key: "test-key".into(),
        action: ActionPayload {
            action_type: "transfer".into(),
            amount: Some(999_999.0),
            currency: Some("USD".into()),
            recipient: Some("external_offshore".into()),
            endpoint: Some("/api/transfer".into()),
            method: Some("POST".into()),
            device_id: None,
            command: None,
        },
        session_id: Some(format!("sess_attack_{agent_id}")),
        metadata: json!({
            "tokens_per_minute": 50_000,
            "compute_seconds_per_hour": 3600,
            "cpu_percent": 99.0,
            "memory_percent": 95.0,
            "payload_contains_pii": true,
            "destination_country": "RU",
            "dependency_cascade_depth": 10,
        }),
    }
}

fn resource_exhaust_req(agent_id: &str) -> ValidationRequest {
    ValidationRequest {
        agent_id: agent_id.into(),
        api_key: "test-key".into(),
        action: ActionPayload {
            action_type: "compute".into(),
            amount: Some(0.0),
            currency: None,
            recipient: None,
            endpoint: Some("/api/compute".into()),
            method: Some("POST".into()),
            device_id: None,
            command: None,
        },
        session_id: Some(format!("sess_exhaust_{agent_id}")),
        metadata: json!({
            "tokens_per_minute": 999_999,
            "compute_seconds_per_hour": 999_999,
            "cpu_percent": 100.0,
            "memory_percent": 100.0,
            "payload_contains_pii": false,
            "destination_country": "US",
            "dependency_cascade_depth": 50,
        }),
    }
}

fn pii_exfiltration_req(agent_id: &str) -> ValidationRequest {
    ValidationRequest {
        agent_id: agent_id.into(),
        api_key: "test-key".into(),
        action: ActionPayload {
            action_type: "data_export".into(),
            amount: Some(0.0),
            currency: None,
            recipient: Some("external_system".into()),
            endpoint: Some("/api/export".into()),
            method: Some("POST".into()),
            device_id: None,
            command: None,
        },
        session_id: Some(format!("sess_pii_{agent_id}")),
        metadata: json!({
            "tokens_per_minute": 500,
            "compute_seconds_per_hour": 10,
            "cpu_percent": 30.0,
            "memory_percent": 40.0,
            "payload_contains_pii": true,
            "destination_country": "CN",
            "dependency_cascade_depth": 1,
            "ssn": "123-45-6789",
        }),
    }
}

// ─── Test 1: Single rogue agent isolation ────────────────────────────────────

#[tokio::test]
async fn single_rogue_agent_isolated() {
    let state = AppState::new();

    // 1 rogue agent: 100 oversized transfers.
    let mut denied = 0usize;
    for _ in 0..100 {
        let resp = state.validate(&oversized_transfer_req("rogue_0")).await;
        if matches!(resp.decision, Decision::Deny | Decision::CircuitBreak) {
            denied += 1;
        }
    }
    assert_eq!(denied, 100, "All rogue requests should be denied");

    // 10 normal agents: each fires 5 requests — must all succeed.
    for i in 0..10 {
        let resp = state
            .validate(&normal_req(&format!("healthy_{i:02}")))
            .await;
        assert!(
            matches!(resp.decision, Decision::Allow),
            "Healthy agent {i} blocked after rogue attack — cascade detected"
        );
    }
}

// ─── Test 2: Multi-vector concurrent attack ──────────────────────────────────

#[tokio::test]
async fn multi_vector_concurrent_attack_contained() {
    let state = AppState::new();
    let n_healthy = 50;
    let n_attacks_per_rogue = 50;

    let start = Instant::now();

    // Launch 50 healthy agents concurrently.
    let mut healthy_handles = Vec::with_capacity(n_healthy);
    for i in 0..n_healthy {
        let state = Arc::clone(&state);
        healthy_handles.push(tokio::spawn(async move {
            let mut ok = 0usize;
            for _ in 0..10 {
                let resp = state
                    .validate(&normal_req(&format!("healthy_{i:03}")))
                    .await;
                if matches!(resp.decision, Decision::Allow) {
                    ok += 1;
                }
            }
            ok
        }));
    }

    // Launch 3 attack vectors concurrently.
    let attack_handles = vec![
        // Vector 1: oversized transfers.
        {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                let mut denied = 0usize;
                for _ in 0..n_attacks_per_rogue {
                    let resp = state.validate(&oversized_transfer_req("attacker_financial")).await;
                    if !matches!(resp.decision, Decision::Allow) {
                        denied += 1;
                    }
                }
                ("financial", denied)
            })
        },
        // Vector 2: resource exhaustion.
        {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                let mut denied = 0usize;
                for _ in 0..n_attacks_per_rogue {
                    let resp = state.validate(&resource_exhaust_req("attacker_resource")).await;
                    if !matches!(resp.decision, Decision::Allow) {
                        denied += 1;
                    }
                }
                ("resource", denied)
            })
        },
        // Vector 3: PII exfiltration.
        {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                let mut denied = 0usize;
                for _ in 0..n_attacks_per_rogue {
                    let resp = state.validate(&pii_exfiltration_req("attacker_pii")).await;
                    if !matches!(resp.decision, Decision::Allow) {
                        denied += 1;
                    }
                }
                ("pii", denied)
            })
        },
    ];

    // Collect attack results.
    for h in attack_handles {
        let (vector, denied) = h.await.unwrap();
        println!("  {vector}: {denied}/{n_attacks_per_rogue} denied");
        assert!(
            denied > 0,
            "Attack vector `{vector}` was not denied at all — policy gap"
        );
    }

    // Collect healthy results.
    let mut total_allows = 0usize;
    for h in healthy_handles {
        total_allows += h.await.unwrap();
    }
    let elapsed = start.elapsed();

    let healthy_rate = total_allows as f64 / (n_healthy * 10) as f64;
    println!(
        "Healthy agents: {total_allows}/{} allowed ({:.0}%) in {:.1}ms",
        n_healthy * 10,
        healthy_rate * 100.0,
        elapsed.as_secs_f64() * 1000.0,
    );

    // At least 80% of healthy traffic must succeed.
    assert!(
        healthy_rate >= 0.80,
        "Too many healthy agents affected: {:.0}% success rate",
        healthy_rate * 100.0,
    );
}

// ─── Test 3: Post-attack recovery ────────────────────────────────────────────

#[tokio::test]
async fn system_recovers_after_attack_storm() {
    let state = AppState::new();

    // Pre-attack: verify baseline works.
    let resp = state.validate(&normal_req("baseline_agent")).await;
    assert!(
        matches!(resp.decision, Decision::Allow),
        "Baseline agent blocked before any attack"
    );

    // Attack storm: 5 rogues × 100 requests each.
    let mut handles = Vec::new();
    for r in 0..5 {
        let state = Arc::clone(&state);
        handles.push(tokio::spawn(async move {
            for _ in 0..100 {
                state.validate(&oversized_transfer_req(&format!("storm_rogue_{r}"))).await;
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    // Post-attack: fresh agents should be unaffected.
    let mut post_allows = 0usize;
    for i in 0..20 {
        let resp = state
            .validate(&normal_req(&format!("post_attack_{i:02}")))
            .await;
        if matches!(resp.decision, Decision::Allow) {
            post_allows += 1;
        }
    }
    println!("Post-attack: {post_allows}/20 fresh agents allowed");

    assert!(
        post_allows >= 18,
        "System not recovered: only {post_allows}/20 post-attack requests allowed"
    );
}

// ─── Test 4: 200-agent swarm with 10% rogue population ──────────────────────

#[tokio::test]
async fn swarm_200_agents_10pct_rogue_contained() {
    let state = AppState::new();
    let n_total = 200;
    let n_rogue = 20; // 10%
    let n_healthy = n_total - n_rogue;
    let reqs_per_agent = 10;

    let mut handles = Vec::with_capacity(n_total);

    // Rogue agents.
    for r in 0..n_rogue {
        let state = Arc::clone(&state);
        handles.push(tokio::spawn(async move {
            let mut denied = 0usize;
            for _ in 0..reqs_per_agent {
                let resp = state
                    .validate(&oversized_transfer_req(&format!("swarm_rogue_{r:03}")))
                    .await;
                if !matches!(resp.decision, Decision::Allow) {
                    denied += 1;
                }
            }
            (true, denied, reqs_per_agent)
        }));
    }

    // Healthy agents.
    for h in 0..n_healthy {
        let state = Arc::clone(&state);
        handles.push(tokio::spawn(async move {
            let mut allowed = 0usize;
            for _ in 0..reqs_per_agent {
                let resp = state
                    .validate(&normal_req(&format!("swarm_healthy_{h:03}")))
                    .await;
                if matches!(resp.decision, Decision::Allow) {
                    allowed += 1;
                }
            }
            (false, allowed, reqs_per_agent)
        }));
    }

    let mut rogue_denied_total = 0usize;
    let mut healthy_allowed_total = 0usize;
    let mut rogue_total = 0usize;
    let mut healthy_total = 0usize;

    for h in handles {
        let (is_rogue, count, total) = h.await.unwrap();
        if is_rogue {
            rogue_denied_total += count;
            rogue_total += total;
        } else {
            healthy_allowed_total += count;
            healthy_total += total;
        }
    }

    let rogue_containment = rogue_denied_total as f64 / rogue_total as f64;
    let healthy_success = healthy_allowed_total as f64 / healthy_total as f64;

    println!("Rogue containment:  {rogue_denied_total}/{rogue_total} ({:.0}%)", rogue_containment * 100.0);
    println!("Healthy success:    {healthy_allowed_total}/{healthy_total} ({:.0}%)", healthy_success * 100.0);

    // All rogue requests must be denied.
    assert_eq!(
        rogue_denied_total, rogue_total,
        "Not all rogue requests contained: {rogue_denied_total}/{rogue_total}"
    );

    // At least 80% healthy success.
    assert!(
        healthy_success >= 0.80,
        "Healthy agents too affected: {:.0}% success",
        healthy_success * 100.0,
    );
}

// ─── Test 5: No panics under concurrent mixed traffic ────────────────────────

#[tokio::test]
async fn no_panics_under_mixed_concurrent_traffic() {
    let state = AppState::new();

    let handles: Vec<_> = (0..500)
        .map(|i| {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                // Alternate between attack types to maximize diversity.
                let req = match i % 4 {
                    0 => normal_req(&format!("mix_{i:04}")),
                    1 => oversized_transfer_req(&format!("mix_{i:04}")),
                    2 => resource_exhaust_req(&format!("mix_{i:04}")),
                    _ => pii_exfiltration_req(&format!("mix_{i:04}")),
                };
                state.validate(&req).await;
            })
        })
        .collect();

    for h in handles {
        h.await.expect("task panicked under concurrent mixed traffic");
    }
}
