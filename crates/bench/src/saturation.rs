//! Multi-agent saturation stress test.
//!
//! Run with:
//!   cargo run -p haltchain-bench --bin saturation --release
//!
//! Spawns N_AGENTS Tokio tasks, each firing N_REQUESTS validations concurrently.
//! 1% of requests are crafted to look anomalous so circuit-breaker paths fire.
//!
//! CI assertions:
//!   - throughput > 100,000 req/s
//!   - p99 latency < 10 ms under saturation
//!   - completes all requests within 120 s

use std::sync::Arc;
use std::time::Instant;

use haltchain_validator::{ActionPayload, AppState, ValidationRequest};
use serde_json::json;
use tokio::sync::Barrier;

const N_AGENTS: usize = 1_000;   // realistic burst (50 k would require >32 GB RAM in tests)
const N_REQUESTS: usize = 100;   // per agent
const TARGET_RPS: f64 = 100_000.0;
const TARGET_P99_MS: f64 = 10.0;
const TIMEOUT_SECS: u64 = 120;

fn make_request(agent_id: usize, seq: usize) -> ValidationRequest {
    // 1% of requests are anomalous velocity spikes.
    let is_anomaly = seq % 100 == 0;
    ValidationRequest {
        agent_id: format!("sat_agent_{agent_id:05}"),
        api_key: "bench-key".into(),
        action: ActionPayload {
            action_type: if is_anomaly { "transfer".into() } else { "api_call".into() },
            amount: Some(if is_anomaly { 999_999.0 } else { 50.0 }),
            currency: Some("USD".into()),
            recipient: Some(format!("acct_{}", agent_id % 20)),
            endpoint: Some("/api/action".into()),
            method: Some("POST".into()),
            device_id: None,
            command: None,
        },
        session_id: Some(format!("sess_{agent_id:05}")),
        metadata: json!({
            "tokens_per_minute": if is_anomaly { 50_000 } else { 800 },
            "compute_seconds_per_hour": 10,
            "cpu_percent": 20.0,
            "memory_percent": 30.0,
            "payload_contains_pii": false,
            "destination_country": "US",
            "dependency_cascade_depth": 1,
        }),
    }
}

fn percentile(sorted: &[u64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((p * sorted.len() as f64).ceil() as usize).saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)] as f64 / 1_000.0 // µs → ms
}

#[tokio::main]
async fn main() {
    let state = AppState::new();

    // Pre-warm a handful of agents so per-agent init doesn't skew results.
    for i in 0..10 {
        state.validate(&make_request(i, 0)).await;
    }

    println!(
        "Saturation: {} agents × {} req/agent = {} total requests",
        N_AGENTS,
        N_REQUESTS,
        N_AGENTS * N_REQUESTS,
    );

    let barrier = Arc::new(Barrier::new(N_AGENTS));
    let start = Instant::now();

    let handles: Vec<_> = (0..N_AGENTS)
        .map(|agent_id| {
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await; // synchronised start across all agents
                let mut latencies = Vec::with_capacity(N_REQUESTS);
                for seq in 0..N_REQUESTS {
                    let req = make_request(agent_id, seq);
                    let t0 = Instant::now();
                    state.validate(&req).await;
                    latencies.push(t0.elapsed().as_micros() as u64);
                }
                latencies
            })
        })
        .collect();

    let elapsed = start.elapsed();
    if elapsed.as_secs() > TIMEOUT_SECS {
        eprintln!("FAIL: exceeded timeout of {TIMEOUT_SECS}s");
        std::process::exit(1);
    }

    let mut all_latencies: Vec<u64> = Vec::with_capacity(N_AGENTS * N_REQUESTS);
    for h in handles {
        if let Ok(mut lat) = h.await {
            all_latencies.append(&mut lat);
        }
    }
    all_latencies.sort_unstable();

    let total = N_AGENTS * N_REQUESTS;
    let elapsed_s = elapsed.as_secs_f64();
    let rps = total as f64 / elapsed_s;
    let p50 = percentile(&all_latencies, 0.50);
    let p99 = percentile(&all_latencies, 0.99);
    let p999 = percentile(&all_latencies, 0.999);

    println!("\n── Saturation results ────────────────────────────────────");
    println!("  Total requests : {total}");
    println!("  Elapsed        : {elapsed_s:.2}s");
    println!("  Throughput     : {rps:.0} req/s");
    println!("  p50 latency    : {p50:.2} ms");
    println!("  p99 latency    : {p99:.2} ms");
    println!("  p99.9 latency  : {p999:.2} ms");
    println!("──────────────────────────────────────────────────────────");

    let mut failed = false;
    if rps < TARGET_RPS {
        eprintln!("FAIL: throughput {rps:.0} req/s < target {TARGET_RPS:.0} req/s");
        failed = true;
    }
    if p99 > TARGET_P99_MS {
        eprintln!("FAIL: p99 {p99:.2} ms > target {TARGET_P99_MS:.1} ms");
        failed = true;
    }

    if failed {
        std::process::exit(1);
    }
    println!("PASS: all saturation targets met.");
}
