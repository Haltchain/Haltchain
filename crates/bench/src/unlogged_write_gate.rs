use haltchain_db::{DbStore, TelemetryRecord};
use serde_json::json;
use uuid::Uuid;

const DEFAULT_SAMPLES: usize = 2_000;
const DEFAULT_TARGET_US: u64 = 10;

#[tokio::main]
async fn main() {
    let database_url = match std::env::var("DATABASE_URL") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            eprintln!("DATABASE_URL is required for unlogged_write_gate");
            std::process::exit(2);
        }
    };

    let mut samples = std::env::var("HALTCHAIN_BENCH_UNLOGGED_WRITE_SAMPLES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_SAMPLES);
    let mut target_p95_us = std::env::var("HALTCHAIN_BENCH_UNLOGGED_WRITE_P95_TARGET_US")
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
            "--target-p95-us" => {
                if let Some(v) = args.get(i + 1).and_then(|v| v.parse::<u64>().ok()) {
                    target_p95_us = v;
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
            "dry-run: samples={} target_p95_us={} json_out={}",
            samples,
            target_p95_us,
            json_out.as_deref().unwrap_or("-")
        );
        return;
    }

    let db = DbStore::connect(&database_url)
        .await
        .unwrap_or_else(|e| panic!("failed to connect db for unlogged write gate: {e}"));

    let org_id = Uuid::new_v4();
    let agent_id = format!("unlogged-gate-{}", Uuid::new_v4());
    let mut latencies_us = Vec::with_capacity(samples);
    let mut rec = TelemetryRecord {
        org_id: Some(org_id),
        agent_id,
        metric: "validation_latency_us".to_string(),
        value: 0.0,
        tags: None,
    };

    for i in 0..samples {
        rec.value = i as f64;
        let t0 = std::time::Instant::now();
        db.insert_telemetry_hot(&rec)
            .await
            .unwrap_or_else(|e| panic!("insert_telemetry_hot failed: {e}"));
        latencies_us.push(t0.elapsed().as_micros() as u64);
    }

    latencies_us.sort_unstable();
    let p95 = percentile(&latencies_us, 0.95);
    println!("unlogged-write gate: samples={samples} p95={p95}us target={target_p95_us}us");
    if let Some(path) = json_out.as_deref() {
        let payload = json!({
            "gate": "unlogged_write_gate",
            "samples": samples,
            "p95_us": p95,
            "target_p95_us": target_p95_us
        });
        if let Err(e) = std::fs::write(path, serde_json::to_vec_pretty(&payload).unwrap()) {
            eprintln!("FAIL: could not write json artifact to {path}: {e}");
            std::process::exit(2);
        }
    }

    if p95 > target_p95_us {
        eprintln!("FAIL: unlogged write p95 {p95}us exceeds target {target_p95_us}us");
        std::process::exit(1);
    }
    println!("PASS: unlogged write p95 {p95}us <= target {target_p95_us}us");
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((p * sorted.len() as f64).ceil() as usize).saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)]
}
