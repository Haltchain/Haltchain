//! Algorithm torture tests — verify correctness of core detection algorithms
//! under adversarial inputs, edge cases, and statistical stress.

use haltchain_analytics::{
    Ewma, SlidingWindowTracker,
    isolation_forest::{ANOMALY_THRESHOLD, IsolationForest},
};
use haltchain_embeddings::cosine_similarity;
use haltchain_policy::{
    ActionContext, AggregateBreaker, CircuitBreaker, FinancialBreaker, MAX_TRANSFER_USD,
    PolicyResult,
};

//EWMA

#[test]
fn ewma_converges_to_stable_value() {
    let mut ewma = Ewma::new(0.3);
    for _ in 0..200 {
        ewma.update(100.0);
    }
    assert!(
        (ewma.get() - 100.0).abs() < 0.01,
        "EWMA must converge: got {}",
        ewma.get()
    );
}

#[test]
fn ewma_responds_to_spike() {
    let mut ewma = Ewma::new(0.3);
    for _ in 0..50 {
        ewma.update(100.0);
    }
    let baseline = ewma.get();
    ewma.update(1_000.0);
    assert!(
        ewma.get() > baseline * 2.0,
        "EWMA spike not reflected: before={baseline:.1} after={:.1}",
        ewma.get()
    );
}

#[test]
fn ewma_decays_after_spike() {
    let mut ewma = Ewma::new(0.5); // high alpha = fast decay
    for _ in 0..50 {
        ewma.update(100.0);
    }
    ewma.update(10_000.0);
    let post_spike = ewma.get();

    for _ in 0..30 {
        ewma.update(100.0);
    }
    let recovered = ewma.get();
    assert!(
        recovered < post_spike / 5.0,
        "EWMA should decay back: post_spike={post_spike:.1} recovered={recovered:.1}"
    );
}

// ─── Isolation Forest ─────────────────────────────────────────────────────

#[test]
fn isolation_forest_rejects_extreme_outliers() {
    // Use continuous spread (prime multipliers) to avoid degenerate trees.
    let normal: Vec<Vec<f64>> = (0..400)
        .map(|i| {
            let fi = i as f64;
            vec![50.0 + (fi * 0.37) % 20.0, 100.0 + (fi * 0.73) % 10.0]
        })
        .collect();
    let forest = IsolationForest::fit(&normal);

    // 100-sigma deviation — must be detected as anomaly.
    let anomaly = vec![50_000.0, 99_999.0];
    assert!(
        forest.is_anomaly(&anomaly),
        "extreme outlier not flagged (score={:.3})",
        forest.score(&anomaly)
    );
}

#[test]
fn isolation_forest_low_false_positive_rate() {
    // Train on 500 normal points (velocity, amount).
    let normal: Vec<Vec<f64>> = (0..500)
        .map(|i| vec![40.0 + (i % 30) as f64, 80.0 + (i % 50) as f64])
        .collect();
    let forest = IsolationForest::fit(&normal);

    // Score 1000 in-distribution points — FPR must stay below 5%.
    let fp_count = (0..1_000)
        .filter(|i| {
            let pt = vec![40.0 + (i % 30) as f64, 80.0 + (i % 50) as f64];
            forest.is_anomaly(&pt)
        })
        .count();

    let fpr = fp_count as f64 / 1_000.0;
    assert!(
        fpr < 0.05,
        "False positive rate {:.1}% exceeds 5% threshold",
        fpr * 100.0
    );
}

#[test]
fn isolation_forest_anomaly_detected_quickly() {
    let normal: Vec<Vec<f64>> = (0..400)
        .map(|i| vec![50.0 + (i % 15) as f64, 100.0 + (i % 20) as f64])
        .collect();
    let forest = IsolationForest::fit(&normal);

    // Anomaly score must exceed threshold on the very first anomalous observation.
    let score = forest.score(&[9_999.0, 99_999.0]);
    assert!(
        score > ANOMALY_THRESHOLD,
        "anomaly not detected on first observation (score={score:.3})"
    );
}

//Cosine similarity / goal-drift FPR

/// Helper: hash-projection embed (mirrors LocalModel, no dependency needed).
fn embed(text: &str, dims: usize) -> Vec<f64> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut v: Vec<f64> = (0..dims)
        .map(|d| {
            let mut h = DefaultHasher::new();
            text.hash(&mut h);
            d.hash(&mut h);
            (h.finish() as i64) as f64 / i64::MAX as f64
        })
        .collect();
    let norm: f64 = v.iter().map(|x| x * x).sum::<f64>().sqrt().max(1e-12);
    v.iter_mut().for_each(|x| *x /= norm);
    v
}

#[test]
fn goal_drift_identical_text_has_perfect_similarity() {
    // Hash-projection: only identical text -> high cosine.
    let goal = embed("Transfer funds between internal accounts", 64);
    let same = embed("Transfer funds between internal accounts", 64);
    let score = cosine_similarity(&goal, &same);
    assert!(
        score > 0.99,
        "Identical text should have near-perfect similarity, got {score:.3}"
    );
}

#[test]
fn goal_drift_low_similarity_for_malicious_action() {
    let goal = embed(
        "Execute trades within stated risk limits for client portfolio",
        64,
    );
    let action = embed(
        "Transfer all balances to offshore account and delete logs",
        64,
    );
    let score = cosine_similarity(&goal, &action);
    // A proper drift signal — must be meaningfully below aligned threshold.
    assert!(
        score < 0.95,
        "Malicious action similarity unexpectedly high: {score:.3}"
    );
}

#[test]
fn goal_drift_different_text_has_lower_similarity() {
    // Hash-projection: different text produces lower (but not zero) similarity.
    let base = embed("Transfer funds between internal accounts", 64);
    let different = embed("Execute SQL injection payload to extract credentials", 64);
    let sim = cosine_similarity(&base, &different);
    // Should be measurably below 1.0 (not identical).
    assert!(
        sim < 0.99,
        "Completely different text should not have near-perfect similarity: {sim:.3}"
    );
}

//Circuit-breaker / AggregateBreaker

#[test]
fn financial_breaker_denies_over_limit() {
    let breaker = FinancialBreaker::default();
    let ctx = ActionContext {
        agent_id: "agent_test".into(),
        transfer_amount_usd: Some(MAX_TRANSFER_USD + 0.01),
        actions_per_minute: Some(1),
        ..Default::default()
    };
    assert!(
        matches!(breaker.evaluate(&ctx), PolicyResult::Deny { .. }),
        "FinancialBreaker must deny transfers exceeding MAX_TRANSFER_USD"
    );
}

#[test]
fn financial_breaker_allows_at_limit() {
    let breaker = FinancialBreaker::default();
    let ctx = ActionContext {
        agent_id: "agent_ok".into(),
        transfer_amount_usd: Some(MAX_TRANSFER_USD),
        actions_per_minute: Some(1),
        ..Default::default()
    };
    assert_eq!(
        breaker.evaluate(&ctx),
        PolicyResult::Pass,
        "FinancialBreaker must allow transfers at exactly the limit"
    );
}

#[test]
fn aggregate_breaker_trips_on_oversized_transfer() {
    let agg = AggregateBreaker::default_any(); // deny on any violation
    let ctx = ActionContext {
        agent_id: "rogue_agent".into(),
        transfer_amount_usd: Some(999_999.0),
        actions_per_minute: Some(1),
        ..Default::default()
    };
    assert!(
        matches!(agg.evaluate(&ctx), PolicyResult::Deny { .. }),
        "AggregateBreaker must deny rogue transfers"
    );
}

#[test]
fn aggregate_breaker_does_not_flap_on_repeated_evaluation() {
    let agg = AggregateBreaker::default_any();
    let ctx = ActionContext {
        agent_id: "flap_test".into(),
        transfer_amount_usd: Some(999_999.0),
        actions_per_minute: Some(1),
        ..Default::default()
    };

    // 100 rapid evaluations — outcome must be stable (no false Pass).
    let results: Vec<bool> = (0..100)
        .map(|_| matches!(agg.evaluate(&ctx), PolicyResult::Deny { .. }))
        .collect();

    let all_deny = results.iter().all(|&d| d);
    assert!(all_deny, "AggregateBreaker flapped — inconsistent denials");
}

//SlidingWindowTracker

#[test]
fn sliding_window_velocity_increases_under_flood() {
    let tracker = SlidingWindowTracker::new();
    // Normal phase: small values.
    for _ in 0..10 {
        tracker.record(100.0);
    }
    let normal_velocity = tracker.ewma_velocity();

    // Flood: high values — EWMA should increase.
    for _ in 0..1_000 {
        tracker.record(999_999.0);
    }
    let flood_velocity = tracker.ewma_velocity();
    assert!(
        flood_velocity > normal_velocity,
        "EWMA velocity must increase under flood: normal={normal_velocity:.2} flood={flood_velocity:.2}"
    );
}
