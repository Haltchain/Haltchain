//! Multi-agent saturation stress test.
//!
//! Primary spec path:
//!   cargo run -p haltchain-bench --bin saturation_gate --release -- --max-time 30s

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use haltchain_validator::{ActionPayload, AppState, ValidationRequest};
use serde_json::json;
use tokio::sync::Barrier;

const DEFAULT_AGENTS: usize = 1_000;
const DEFAULT_REQUESTS_PER_AGENT: usize = 100;
const DEFAULT_TARGET_RPS: f64 = 100_000.0;
const DEFAULT_TARGET_P99_MS: f64 = 10.0;
const DEFAULT_MAX_TIME: Duration = Duration::from_secs(30);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_millis(200);

#[derive(Clone, Debug)]
struct Config {
    agents: usize,
    requests_per_agent: usize,
    target_rps: f64,
    target_p99_ms: f64,
    max_time: Duration,
    request_timeout: Duration,
    json_out: Option<String>,
    dry_run: bool,
}

fn make_request(agent_id: usize, seq: usize) -> ValidationRequest {
    let is_anomaly = seq.is_multiple_of(100);
    ValidationRequest {
        agent_id: format!("sat_agent_{agent_id:05}"),
        api_key: "bench-key".into(),
        action: ActionPayload {
            action_type: if is_anomaly {
                "transfer".into()
            } else {
                "api_call".into()
            },
            amount: Some(if is_anomaly { 999_999.0 } else { 50.0 }),
            currency: Some("USD".into()),
            recipient: Some(format!("acct_{}", agent_id % 20)),
            endpoint: Some("/api/action".into()),
            method: Some("POST".into()),
            device_id: None,
            command: None,
            delegation_depth: None,
            data_source: Default::default(),
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

fn percentile_us(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((p * sorted.len() as f64).ceil() as usize).saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)]
}

#[tokio::main]
async fn main() {
    let cfg = parse_config(std::env::args().skip(1).collect());
    if cfg.dry_run {
        println!(
            "dry-run: agents={} requests_per_agent={} target_rps={} target_p99_ms={} max_time={}s request_timeout_ms={} json_out={}",
            cfg.agents,
            cfg.requests_per_agent,
            cfg.target_rps,
            cfg.target_p99_ms,
            cfg.max_time.as_secs_f64(),
            cfg.request_timeout.as_millis(),
            cfg.json_out.as_deref().unwrap_or("-"),
        );
        return;
    }

    let state = AppState::new();
    for i in 0..10 {
        state.validate(&make_request(i, 0)).await;
    }

    let total_planned = cfg.agents * cfg.requests_per_agent;
    println!(
        "saturation_gate: {} agents × {} req/agent = {} planned requests (max-time={}s)",
        cfg.agents,
        cfg.requests_per_agent,
        total_planned,
        cfg.max_time.as_secs()
    );

    let barrier = Arc::new(Barrier::new(cfg.agents));
    let start = Instant::now();
    let deadline = start + cfg.max_time;
    let timeout_count = Arc::new(AtomicUsize::new(0));
    let completed_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..cfg.agents)
        .map(|agent_id| {
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            let timeout_count = Arc::clone(&timeout_count);
            let completed_count = Arc::clone(&completed_count);
            let req_timeout = cfg.request_timeout;
            let reqs = cfg.requests_per_agent;
            tokio::spawn(async move {
                barrier.wait().await;
                let mut latencies = Vec::with_capacity(reqs);

                for seq in 0..reqs {
                    if Instant::now() >= deadline {
                        let remaining = reqs.saturating_sub(seq);
                        timeout_count.fetch_add(remaining, Ordering::Relaxed);
                        break;
                    }

                    let req = make_request(agent_id, seq);
                    let t0 = Instant::now();
                    let result = tokio::time::timeout(req_timeout, state.validate(&req)).await;
                    match result {
                        Ok(_) => {
                            completed_count.fetch_add(1, Ordering::Relaxed);
                            latencies.push(t0.elapsed().as_micros() as u64);
                        }
                        Err(_) => {
                            timeout_count.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                latencies
            })
        })
        .collect();

    let mut all_latencies: Vec<u64> = Vec::with_capacity(total_planned);
    for h in handles {
        if let Ok(mut lat) = h.await {
            all_latencies.append(&mut lat);
        }
    }
    let elapsed = start.elapsed();
    all_latencies.sort_unstable();

    let completed = completed_count.load(Ordering::Relaxed);
    let timed_out = timeout_count.load(Ordering::Relaxed);
    let elapsed_s = elapsed.as_secs_f64().max(1e-6);
    let rps = completed as f64 / elapsed_s;
    let p50_us = percentile_us(&all_latencies, 0.50);
    let p99_us = percentile_us(&all_latencies, 0.99);
    let p999_us = percentile_us(&all_latencies, 0.999);

    println!("\n-- saturation_gate results --");
    println!("planned_requests={total_planned}");
    println!("completed_requests={completed}");
    println!("timeout_count={timed_out}");
    println!("elapsed_s={elapsed_s:.3}");
    println!("throughput_rps={rps:.2}");
    println!("p50_us={p50_us}");
    println!("p99_us={p99_us}");
    println!("p999_us={p999_us}");

    if let Some(path) = cfg.json_out.as_deref() {
        let payload = json!({
            "gate": "saturation_gate",
            "planned_requests": total_planned,
            "completed_requests": completed,
            "timeout_count": timed_out,
            "elapsed_s": elapsed_s,
            "throughput_rps": rps,
            "p50_us": p50_us,
            "p99_us": p99_us,
            "p999_us": p999_us,
            "target_rps": cfg.target_rps,
            "target_p99_us": (cfg.target_p99_ms * 1000.0) as u64,
            "max_time_s": cfg.max_time.as_secs(),
            "request_timeout_ms": cfg.request_timeout.as_millis() as u64
        });
        if let Err(e) = std::fs::write(path, serde_json::to_vec_pretty(&payload).unwrap()) {
            eprintln!("FAIL: could not write json artifact to {path}: {e}");
            std::process::exit(2);
        }
    }

    let mut failed = false;
    if elapsed > cfg.max_time + Duration::from_secs(1) {
        eprintln!(
            "FAIL: benchmark exceeded max-time={}s (elapsed {:.2}s)",
            cfg.max_time.as_secs(),
            elapsed_s
        );
        failed = true;
    }
    if timed_out > 0 {
        eprintln!("FAIL: timeout_count={timed_out} (must be 0)");
        failed = true;
    }
    if rps < cfg.target_rps {
        eprintln!(
            "FAIL: throughput {rps:.0} req/s < target {:.0} req/s",
            cfg.target_rps
        );
        failed = true;
    }
    if (p99_us as f64) / 1_000.0 > cfg.target_p99_ms {
        eprintln!(
            "FAIL: p99 {:.2} ms > target {:.2} ms",
            (p99_us as f64) / 1_000.0,
            cfg.target_p99_ms
        );
        failed = true;
    }

    if failed {
        std::process::exit(1);
    }
    println!("PASS: all saturation targets met.");
}

fn parse_config(args: Vec<String>) -> Config {
    let mut cfg = Config {
        agents: std::env::var("HALTCHAIN_BENCH_SATURATION_AGENTS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_AGENTS),
        requests_per_agent: std::env::var("HALTCHAIN_BENCH_SATURATION_REQUESTS_PER_AGENT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_REQUESTS_PER_AGENT),
        target_rps: std::env::var("HALTCHAIN_BENCH_SATURATION_TARGET_RPS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_TARGET_RPS),
        target_p99_ms: std::env::var("HALTCHAIN_BENCH_SATURATION_TARGET_P99_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_TARGET_P99_MS),
        max_time: std::env::var("HALTCHAIN_BENCH_MAX_TIME")
            .ok()
            .and_then(|v| parse_duration(&v))
            .unwrap_or(DEFAULT_MAX_TIME),
        request_timeout: std::env::var("HALTCHAIN_BENCH_REQUEST_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or(DEFAULT_REQUEST_TIMEOUT),
        json_out: std::env::var("HALTCHAIN_BENCH_JSON_OUT").ok(),
        dry_run: false,
    };

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json-out" => {
                if let Some(v) = args.get(i + 1) {
                    cfg.json_out = Some(v.clone());
                    i += 1;
                }
            }
            "--max-time" => {
                if let Some(v) = args.get(i + 1) {
                    if let Some(d) = parse_duration(v) {
                        cfg.max_time = d;
                    }
                    i += 1;
                }
            }
            "--request-timeout-ms" => {
                if let Some(v) = args.get(i + 1).and_then(|v| v.parse::<u64>().ok()) {
                    cfg.request_timeout = Duration::from_millis(v);
                    i += 1;
                }
            }
            "--agents" => {
                if let Some(v) = args.get(i + 1).and_then(|v| v.parse::<usize>().ok()) {
                    cfg.agents = v;
                    i += 1;
                }
            }
            "--requests" => {
                if let Some(v) = args.get(i + 1).and_then(|v| v.parse::<usize>().ok()) {
                    cfg.requests_per_agent = v;
                    i += 1;
                }
            }
            "--target-rps" => {
                if let Some(v) = args.get(i + 1).and_then(|v| v.parse::<f64>().ok()) {
                    cfg.target_rps = v;
                    i += 1;
                }
            }
            "--target-p99-ms" => {
                if let Some(v) = args.get(i + 1).and_then(|v| v.parse::<f64>().ok()) {
                    cfg.target_p99_ms = v;
                    i += 1;
                }
            }
            "--short" => {
                cfg.agents = 50;
                cfg.requests_per_agent = 20;
                cfg.max_time = Duration::from_secs(5);
                cfg.target_rps = 1.0;
                cfg.target_p99_ms = 1_000.0;
            }
            "--dry-run" => cfg.dry_run = true,
            _ => {}
        }
        i += 1;
    }

    cfg
}

fn parse_duration(raw: &str) -> Option<Duration> {
    let value = raw.trim();
    if value.ends_with("ms") {
        let n = value.trim_end_matches("ms").parse::<u64>().ok()?;
        return Some(Duration::from_millis(n));
    }
    if value.ends_with('s') {
        let n = value.trim_end_matches('s').parse::<u64>().ok()?;
        return Some(Duration::from_secs(n));
    }
    value.parse::<u64>().ok().map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    #![allow(unused_imports)]
    use std::time::Duration;

    use crate::{parse_duration, percentile_us};

    #[test]
    fn parse_duration_variants() {
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("250ms"), Some(Duration::from_millis(250)));
        assert_eq!(parse_duration("7"), Some(Duration::from_secs(7)));
        assert_eq!(parse_duration("bad"), None);
    }

    #[test]
    fn percentile_handles_empty() {
        assert_eq!(percentile_us(&[], 0.99), 0);
    }
}
