use std::sync::Arc;
use std::time::Instant;

use haltchain_validator::{ActionPayload, AppState, ValidationRequest};
use serde_json::json;

const DEFAULT_SAMPLES: usize = 5_000;
const DEFAULT_TARGET_US: u64 = 1_000;

#[tokio::main]
async fn main() {
    let mut samples = std::env::var("HALTCHAIN_BENCH_CACHE_HIT_SAMPLES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_SAMPLES);
    let mut target_p99_us = std::env::var("HALTCHAIN_BENCH_CACHE_HIT_P99_TARGET_US")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_TARGET_US);
    let mut json_out = std::env::var("HALTCHAIN_BENCH_JSON_OUT").ok();
    let mut dry_run = false;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--samples" => {
                if let Some(v) = args.get(i + 1).and_then(|v| v.parse::<usize>().ok()) {
                    samples = v;
                    i += 1;
                }
            }
            "--target-p99-us" => {
                if let Some(v) = args.get(i + 1).and_then(|v| v.parse::<u64>().ok()) {
                    target_p99_us = v;
                    i += 1;
                }
            }
            "--json-out" => {
                if let Some(v) = args.get(i + 1) {
                    json_out = Some(v.clone());
                    i += 1;
                }
            }
            "--dry-run" => dry_run = true,
            _ => {}
        }
        i += 1;
    }

    if dry_run {
        println!(
            "dry-run: samples={} target_p99_us={} json_out={}",
            samples,
            target_p99_us,
            json_out.as_deref().unwrap_or("-")
        );
        return;
    }

    let state = AppState::new();
    let req = make_cacheable_request("cache_gate_agent");

    // Warm-up to populate the cache path.
    state.validate(&req).await;
    state.validate(&req).await;

    let latencies = run_samples(Arc::clone(&state), &req, samples).await;
    let p99 = percentile(&latencies, 0.99);

    println!("cache-hit gate: samples={samples} p99={p99}us target={target_p99_us}us");
    if let Some(path) = json_out.as_deref() {
        let payload = json!({
            "gate": "cache_hit_gate",
            "samples": samples,
            "p99_us": p99,
            "target_p99_us": target_p99_us
        });
        if let Err(e) = std::fs::write(path, serde_json::to_vec_pretty(&payload).unwrap()) {
            eprintln!("FAIL: could not write json artifact to {path}: {e}");
            std::process::exit(2);
        }
    }
    if p99 > target_p99_us {
        eprintln!("FAIL: cache-hit p99 {p99}us exceeds target {target_p99_us}us");
        std::process::exit(1);
    }
    println!("PASS: cache-hit p99 {p99}us <= target {target_p99_us}us");
}

async fn run_samples(state: Arc<AppState>, req: &ValidationRequest, samples: usize) -> Vec<u64> {
    let mut latencies = Vec::with_capacity(samples);
    for _ in 0..samples {
        let t0 = Instant::now();
        let _ = state.validate(req).await;
        latencies.push(t0.elapsed().as_micros() as u64);
    }
    latencies.sort_unstable();
    latencies
}

fn make_cacheable_request(agent_id: &str) -> ValidationRequest {
    ValidationRequest {
        agent_id: agent_id.to_string(),
        api_key: "bench-key".to_string(),
        action: ActionPayload {
            action_type: "heartbeat".to_string(),
            amount: None,
            currency: None,
            recipient: None,
            endpoint: Some("/api/heartbeat".to_string()),
            method: Some("POST".to_string()),
            device_id: None,
            command: None,
            delegation_depth: None,
            data_source: Default::default(),
        },
        session_id: Some("cache-gate-session".to_string()),
        metadata: json!({
            "tokens_per_minute": 100,
            "compute_seconds_per_hour": 1,
            "cpu_percent": 5.0,
            "memory_percent": 5.0,
            "payload_contains_pii": false,
            "destination_country": "US",
            "dependency_cascade_depth": 0,
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
