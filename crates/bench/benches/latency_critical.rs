//! Latency dominance benchmark suite.
//!
//! Run with:
//!   cargo bench -p haltchain-bench --bench latency_critical -- --output-format bencher
//!
//! Targets:
//!   cache hit       < 1 µs
//!   full validation < 2 ms p50
//!   drift scoring   < 1 ms
//!   quorum (3-node) < 3 ms added latency

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use haltchain_analytics::{Ewma, isolation_forest::IsolationForest};
use haltchain_cache::{CachedDecision, DecisionCache};
use haltchain_consensus::QuorumTracker;
use haltchain_embeddings::{DriftScorer, cosine_similarity};
use haltchain_validator::{ActionPayload, AppState, ValidationRequest};
use serde_json::json;
use std::sync::Arc;
use tokio::runtime::Runtime;

// Helpers

fn make_request(agent_id: &str, action_type: &str, amount: f64) -> ValidationRequest {
    ValidationRequest {
        agent_id: agent_id.into(),
        api_key: "bench-key".into(),
        action: ActionPayload {
            action_type: action_type.into(),
            amount: Some(amount),
            currency: Some("USD".into()),
            recipient: Some("acct_bench".into()),
            endpoint: Some("/api/transfer".into()),
            method: Some("POST".into()),
            device_id: None,
            command: None,
            delegation_depth: None,
            data_source: Default::default(),
        },
        session_id: Some("sess_bench".into()),
        metadata: json!({
            "tokens_per_minute": 800,
            "compute_seconds_per_hour": 10,
            "cpu_percent": 20.0,
            "memory_percent": 30.0,
            "payload_contains_pii": false,
            "destination_country": "US",
            "dependency_cascade_depth": 1,
        }),
    }
}

/// Build a unit-norm vector from a simple hash projection (mirrors LocalModel).
fn hash_embed(text: &str, dims: usize) -> Vec<f64> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut v: Vec<f64> = (0..dims)
        .map(|i| {
            let mut h = DefaultHasher::new();
            text.hash(&mut h);
            i.hash(&mut h);
            // map to [-1, 1]
            (h.finish() as i64) as f64 / i64::MAX as f64
        })
        .collect();
    let norm: f64 = v.iter().map(|x| x * x).sum::<f64>().sqrt().max(1e-12);
    v.iter_mut().for_each(|x| *x /= norm);
    v
}

//Benchmark groups

fn cache_hit_bench(c: &mut Criterion) {
    let cache = DecisionCache::new();
    let key = DecisionCache::make_key("agent_001", "transfer", 1, 0);
    cache.insert(
        key.clone(),
        CachedDecision {
            decision: "ALLOW".into(),
            circuit_breaker_active: false,
            reason: None,
            policy: None,
            rate_limit: 0,
        },
    );

    let mut group = c.benchmark_group("cache");
    group.bench_function("hit_lookup", |b| {
        b.iter(|| {
            let result = cache.get(black_box(&key));
            black_box(result);
        });
    });
    group.bench_function("miss_lookup", |b| {
        // Different key each iteration via counter avoids iterator specialisation.
        let miss_key = DecisionCache::make_key("ghost_agent", "unknown", 99, 99);
        b.iter(|| {
            let result = cache.get(black_box(&miss_key));
            black_box(result);
        });
    });
    group.finish();
}

fn validation_latency_bench(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let state: Arc<AppState> = rt.block_on(async { AppState::new() });

    // Pre-warm per-agent state so cold-start noise doesn't skew the results.
    rt.block_on(async {
        for _ in 0..20 {
            state
                .validate(&make_request("warmup", "transfer", 500.0))
                .await;
        }
    });

    let mut group = c.benchmark_group("validation_latency");
    group.measurement_time(std::time::Duration::from_secs(30));
    group.sample_size(500);

    // Normal low-value transfer — hits policy + cache path.
    group.bench_with_input(
        BenchmarkId::new("full_policy", "normal_transfer"),
        &state,
        |b, state| {
            b.to_async(&rt).iter(|| async {
                let req = make_request("bench_agent_001", "transfer", 500.0);
                let result = state.validate(black_box(&req)).await;
                black_box(result);
            });
        },
    );

    // High-stakes transfer — forces quorum path + circuit-breaker evaluation.
    group.bench_with_input(
        BenchmarkId::new("full_policy", "high_stakes"),
        &state,
        |b, state| {
            b.to_async(&rt).iter(|| async {
                let req = make_request("bench_agent_002", "transfer", 10_000.0);
                let result = state.validate(black_box(&req)).await;
                black_box(result);
            });
        },
    );

    group.finish();
}

fn drift_scoring_bench(c: &mut Criterion) {
    const DIMS: usize = 64;
    let goal = hash_embed(
        "Execute trades within risk limits for client portfolio",
        DIMS,
    );
    let aligned_action = hash_embed("Place a $500 equity order within portfolio limits", DIMS);
    let drifted_action = hash_embed("Transfer all funds to offshore account immediately", DIMS);

    let mut group = c.benchmark_group("drift_scoring");

    group.bench_function("cosine_similarity_aligned", |b| {
        b.iter(|| {
            let score = cosine_similarity(black_box(&goal), black_box(&aligned_action));
            black_box(score);
        });
    });

    group.bench_function("cosine_similarity_drifted", |b| {
        b.iter(|| {
            let score = cosine_similarity(black_box(&goal), black_box(&drifted_action));
            black_box(score);
        });
    });

    group.bench_function("drift_scorer_push_window", |b| {
        let mut scorer = DriftScorer::default();
        // Pre-populate window so we benchmark steady-state, not cold start.
        for i in 0..10 {
            let action = hash_embed(&format!("normal action {i}"), DIMS);
            scorer.push("agent:sess", &goal, &action);
        }
        b.iter(|| {
            let result = scorer.push(
                black_box("agent:sess"),
                black_box(&goal),
                black_box(&aligned_action),
            );
            black_box(result);
        });
    });

    group.finish();
}

fn quorum_overhead_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("consensus");

    // Simulate a 2-of-3 quorum round without network I/O (pure in-process).
    group.bench_function("quorum_3node_in_process", |b| {
        b.iter(|| {
            let mut tracker = QuorumTracker::new(black_box("tx-bench-001"));
            tracker.approve(1);
            tracker.approve(2);
            tracker.reject(3);
            let decision = tracker.decision();
            black_box(decision);
        });
    });

    group.bench_function("ewma_velocity_update", |b| {
        let mut ewma = Ewma::new(0.3);
        b.iter(|| {
            ewma.update(black_box(100.0));
            black_box(ewma.get());
        });
    });

    group.finish();
}

fn anomaly_detection_bench(c: &mut Criterion) {
    // Train the forest on synthetic normal data (velocity, amount, entropy).
    let normal_data: Vec<Vec<f64>> = (0..512)
        .map(|i| {
            vec![
                50.0 + (i % 20) as f64,
                100.0 + (i % 50) as f64,
                0.5 + (i % 10) as f64 * 0.01,
            ]
        })
        .collect();
    let forest = IsolationForest::fit(&normal_data);

    let mut group = c.benchmark_group("anomaly_detection");

    group.bench_function("isolation_forest_normal", |b| {
        let point = vec![55.0, 110.0, 0.52];
        b.iter(|| {
            let score = forest.score(black_box(&point));
            black_box(score);
        });
    });

    group.bench_function("isolation_forest_anomaly", |b| {
        let anomaly = vec![5000.0, 99999.0, 9.9]; // extreme outlier
        b.iter(|| {
            let is_anom = forest.is_anomaly(black_box(&anomaly));
            black_box(is_anom);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    cache_hit_bench,
    validation_latency_bench,
    drift_scoring_bench,
    quorum_overhead_bench,
    anomaly_detection_bench,
);
criterion_main!(benches);
