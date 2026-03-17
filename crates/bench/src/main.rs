//! Stress-test harness — 10 K synthetic transactions, measures p50/p95/p99 latency.
//!
//! Run with:
//!   cargo run -p haltchain-bench --release
//!
//! Two passes are run:
//!   1. Sequential  — 50 agents, one at a time, establishes a baseline.
//!   2. Concurrent  — same workload dispatched with `tokio::spawn`, reflects
//!      real p99 under contention (this is what matters for SLA gates).

use std::sync::Arc;
use std::time::Instant;

use haltchain_validator::{ActionPayload, AppState, ValidationRequest};
use serde_json::json;

const N_AGENTS: usize = 50;
const N_TRANSACTIONS: usize = 10_000;
// Session IDs: each agent gets one shared session to exercise drift detection.
const N_SESSIONS: usize = 10;

#[tokio::main]
async fn main() {
    let state = AppState::new();

    // Pre-warm: prime per-agent state so cold-start noise doesn't skew results.
    for agent_idx in 0..N_AGENTS {
        let req = make_request(agent_idx, 500.0, "transfer");
        state.validate(&req).await;
        let req = make_request(agent_idx, 500.0, "api_call");
        state.validate(&req).await;
    }

    // ── Pass 1: sequential
    println!("Pass 1 — sequential {N_TRANSACTIONS} tx across {N_AGENTS} agents …");
    let seq_latencies = run_sequential(Arc::clone(&state)).await;
    print_stats("Sequential", &seq_latencies);

    // ── Pass 2: concurrent
    println!("\nPass 2 — concurrent {N_TRANSACTIONS} tx across {N_AGENTS} agents …");
    let conc_latencies = run_concurrent(Arc::clone(&state)).await;
    print_stats("Concurrent", &conc_latencies);

    // CI gate uses the concurrent p99 (sequential hides lock contention).
    let p99_conc = percentile(&conc_latencies, 0.99);
    let target_us: u64 = std::env::var("HALTCHAIN_BENCH_P99_TARGET_US")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(5_000); // 5 ms — realistic under concurrent load
    if p99_conc <= target_us {
        println!("\n✓ concurrent p99 {p99_conc} µs ≤ target {target_us} µs");
    } else {
        println!("\n✗ concurrent p99 {p99_conc} µs exceeds target {target_us} µs");
        std::process::exit(1);
    }
}

async fn run_sequential(state: Arc<AppState>) -> Vec<u64> {
    let mut latencies: Vec<u64> = Vec::with_capacity(N_TRANSACTIONS);
    for i in 0..N_TRANSACTIONS {
        let agent_idx = i % N_AGENTS;
        let amount = if i % 7 == 0 { 1500.0 } else { 500.0 };
        let action = if i % 3 == 0 { "api_call" } else { "transfer" };
        let req = make_request(agent_idx, amount, action);
        let t0 = Instant::now();
        state.validate(&req).await;
        latencies.push(t0.elapsed().as_micros() as u64);
    }
    latencies.sort_unstable();
    latencies
}

async fn run_concurrent(state: Arc<AppState>) -> Vec<u64> {
    let mut handles = Vec::with_capacity(N_TRANSACTIONS);
    for i in 0..N_TRANSACTIONS {
        let state = Arc::clone(&state);
        let agent_idx = i % N_AGENTS;
        let amount = if i % 7 == 0 { 1500.0 } else { 500.0 };
        let action = if i % 3 == 0 { "api_call" } else { "transfer" };
        let req = make_request(agent_idx, amount, action);
        handles.push(tokio::spawn(async move {
            let t0 = Instant::now();
            state.validate(&req).await;
            t0.elapsed().as_micros() as u64
        }));
    }
    let mut latencies: Vec<u64> = Vec::with_capacity(N_TRANSACTIONS);
    for h in handles {
        if let Ok(us) = h.await {
            latencies.push(us);
        }
    }
    latencies.sort_unstable();
    latencies
}

fn print_stats(label: &str, sorted: &[u64]) {
    let total = sorted.len();
    let p50 = percentile(sorted, 0.50);
    let p95 = percentile(sorted, 0.95);
    let p99 = percentile(sorted, 0.99);
    let max = sorted.last().copied().unwrap_or(0);
    println!("\n── {label} latency (µs) — {total} samples ─────────────────");
    println!("  p50 : {p50} µs");
    println!("  p95 : {p95} µs");
    println!("  p99 : {p99} µs");
    println!("  max : {max} µs");
    println!("──────────────────────────────────────────────────────────");
}

/// Build a realistic request: metadata includes auth token, PII flag, resource
/// metrics and session ID so all 6-domain policy checks and drift detection fire.
fn make_request(agent_idx: usize, amount: f64, action_type: &str) -> ValidationRequest {
    let session_idx = agent_idx % N_SESSIONS;
    ValidationRequest {
        agent_id: format!("bench_agent_{agent_idx:03}"),
        api_key: "bench-key".into(),
        action: ActionPayload {
            action_type: action_type.into(),
            amount: Some(amount),
            currency: Some("USD".into()),
            recipient: Some(format!("acct_{}", agent_idx % 20)),
            endpoint: Some("/api/transfer".into()),
            method: Some("POST".into()),
            device_id: None,
            command: None,
        },
        session_id: Some(format!("sess_{agent_idx:03}_{session_idx}")),
        metadata: json!({
            "tokens_per_minute": 800,
            "compute_seconds_per_hour": 10,
            "cpu_percent": 30.0,
            "memory_percent": 40.0,
            "payload_contains_pii": false,
            "destination_country": "US",
            "dependency_cascade_depth": 1,
        }),
    }
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((p * sorted.len() as f64).ceil() as usize).saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)]
}
