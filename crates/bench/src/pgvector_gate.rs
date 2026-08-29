use haltchain_db::{ActionEmbeddingRecord, DbStore};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

const DIMS: usize = 1024;
const DEFAULT_INSERT_SAMPLES: usize = 10_000;
const DEFAULT_QUERY_SAMPLES: usize = 10_000;
const DEFAULT_CONCURRENT_AGENTS: usize = 50;
const DEFAULT_TARGET_US: u64 = 2_000;

#[derive(Clone, Debug)]
struct Config {
    insert_samples: usize,
    query_samples: usize,
    concurrent_agents: usize,
    target_p99_us: u64,
    json_out: Option<String>,
    dry_run: bool,
}

#[tokio::main]
async fn main() {
    let cfg = parse_config(std::env::args().skip(1).collect());
    if cfg.dry_run {
        println!(
            "dry-run: insert_samples={} query_samples={} concurrent_agents={} target_p99_us={} json_out={}",
            cfg.insert_samples,
            cfg.query_samples,
            cfg.concurrent_agents,
            cfg.target_p99_us,
            cfg.json_out.as_deref().unwrap_or("-"),
        );
        return;
    }

    let database_url = match std::env::var("DATABASE_URL") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            eprintln!("DATABASE_URL is required for pgvector_gate");
            std::process::exit(2);
        }
    };

    let db = Arc::new(
        DbStore::connect(&database_url)
            .await
            .unwrap_or_else(|e| panic!("failed to connect db for pgvector gate: {e}")),
    );

    let org_id = Uuid::new_v4();
    let agent_id = format!("pgvector-gate-{}", Uuid::new_v4());
    let base = Arc::new(embedding_for("base", 0.0));

    for i in 0..cfg.insert_samples {
        let rec = ActionEmbeddingRecord {
            org_id: Some(org_id),
            agent_id: agent_id.clone(),
            session_id: Some("pgv-session".to_string()),
            transaction_id: Some(Uuid::new_v4()),
            embedding: embedding_for("sample", i as f32 * 0.001),
            goal_similarity: None,
            label: Some("bench".to_string()),
        };
        db.insert_action_embedding(&rec)
            .await
            .unwrap_or_else(|e| panic!("insert_action_embedding failed: {e}"));
    }

    let mut latencies_us = Vec::with_capacity(cfg.query_samples);
    let mut remaining = cfg.query_samples;
    while remaining > 0 {
        let wave = remaining.min(cfg.concurrent_agents);
        remaining -= wave;

        let mut handles = Vec::with_capacity(wave);
        for _ in 0..wave {
            let db = Arc::clone(&db);
            let base = Arc::clone(&base);
            let agent_id = agent_id.clone();
            handles.push(tokio::spawn(async move {
                let t0 = std::time::Instant::now();
                let rows = db
                    .find_similar_actions(&base, org_id, &agent_id, 10)
                    .await
                    .unwrap_or_else(|e| panic!("find_similar_actions failed: {e}"));
                if rows.is_empty() {
                    eprintln!("pgvector query returned 0 rows; expected nearest neighbors");
                    std::process::exit(1);
                }
                t0.elapsed().as_micros() as u64
            }));
        }
        for h in handles {
            if let Ok(us) = h.await {
                latencies_us.push(us);
            }
        }
    }

    latencies_us.sort_unstable();
    let p50 = percentile(&latencies_us, 0.50);
    let p95 = percentile(&latencies_us, 0.95);
    let p99 = percentile(&latencies_us, 0.99);

    println!("\n-- pgvector_search_gate results --");
    println!("query_samples={}", latencies_us.len());
    println!("concurrent_agents={}", cfg.concurrent_agents);
    println!("p50_us={p50}");
    println!("p95_us={p95}");
    println!("p99_us={p99}");
    println!("target_p99_us={}", cfg.target_p99_us);

    if let Some(path) = cfg.json_out.as_deref() {
        let payload = json!({
            "gate": "pgvector_search_gate",
            "insert_samples": cfg.insert_samples,
            "query_samples": latencies_us.len(),
            "concurrent_agents": cfg.concurrent_agents,
            "p50_us": p50,
            "p95_us": p95,
            "p99_us": p99,
            "target_p99_us": cfg.target_p99_us
        });
        if let Err(e) = std::fs::write(path, serde_json::to_vec_pretty(&payload).unwrap()) {
            eprintln!("FAIL: could not write json artifact to {path}: {e}");
            std::process::exit(2);
        }
    }

    if p99 > cfg.target_p99_us {
        eprintln!(
            "FAIL: pgvector search p99 {p99}us exceeds target {}us",
            cfg.target_p99_us
        );
        std::process::exit(1);
    }
    println!(
        "PASS: pgvector search p99 {p99}us <= target {}us",
        cfg.target_p99_us
    );
}

fn parse_config(args: Vec<String>) -> Config {
    let mut cfg = Config {
        insert_samples: std::env::var("HALTCHAIN_BENCH_PGVECTOR_INSERT_SAMPLES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_INSERT_SAMPLES),
        query_samples: std::env::var("HALTCHAIN_BENCH_PGVECTOR_QUERY_SAMPLES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_QUERY_SAMPLES),
        concurrent_agents: std::env::var("HALTCHAIN_BENCH_PGVECTOR_CONCURRENT_AGENTS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_CONCURRENT_AGENTS),
        target_p99_us: std::env::var("HALTCHAIN_BENCH_PGVECTOR_P99_TARGET_US")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_TARGET_US),
        json_out: std::env::var("HALTCHAIN_BENCH_JSON_OUT").ok(),
        dry_run: false,
    };

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--insert-samples" => {
                if let Some(v) = args.get(i + 1).and_then(|v| v.parse::<usize>().ok()) {
                    cfg.insert_samples = v;
                    i += 1;
                }
            }
            "--query-samples" => {
                if let Some(v) = args.get(i + 1).and_then(|v| v.parse::<usize>().ok()) {
                    cfg.query_samples = v;
                    i += 1;
                }
            }
            "--concurrent-agents" => {
                if let Some(v) = args.get(i + 1).and_then(|v| v.parse::<usize>().ok()) {
                    cfg.concurrent_agents = v.max(1);
                    i += 1;
                }
            }
            "--target-p99-us" => {
                if let Some(v) = args.get(i + 1).and_then(|v| v.parse::<u64>().ok()) {
                    cfg.target_p99_us = v;
                    i += 1;
                }
            }
            "--json-out" => {
                if let Some(v) = args.get(i + 1) {
                    cfg.json_out = Some(v.clone());
                    i += 1;
                }
            }
            "--short" => {
                cfg.insert_samples = 40;
                cfg.query_samples = 200;
                cfg.concurrent_agents = 10;
                cfg.target_p99_us = u64::MAX;
            }
            "--dry-run" => cfg.dry_run = true,
            _ => {}
        }
        i += 1;
    }

    cfg
}

fn embedding_for(seed: &str, offset: f32) -> Vec<f32> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut out = Vec::with_capacity(DIMS);
    for i in 0..DIMS {
        let mut hasher = DefaultHasher::new();
        seed.hash(&mut hasher);
        i.hash(&mut hasher);
        let raw = (hasher.finish() % 10_000) as f32 / 10_000.0;
        out.push((raw + offset).sin());
    }

    let norm = out
        .iter()
        .map(|v| (*v as f64) * (*v as f64))
        .sum::<f64>()
        .sqrt()
        .max(1e-12);
    out.iter_mut().for_each(|v| *v = (*v as f64 / norm) as f32);
    out
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((p * sorted.len() as f64).ceil() as usize).saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)]
}

#[cfg(test)]
mod tests {
    #[test]
    fn percentile_handles_empty() {
        assert_eq!(super::percentile(&[], 0.99), 0);
    }
}
