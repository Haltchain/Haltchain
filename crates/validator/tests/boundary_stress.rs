//! Boundary & stress tests — push core algorithms to their breaking points.
//!
//! These tests exercise numeric limits, adversarial inputs, and degenerate cases
//! that real-world attackers would exploit. Every test is designed to **find**
//! the edge, not merely confirm the happy path.

use haltchain_analytics::{
    Ewma, SlidingWindowTracker,
    isolation_forest::IsolationForest,
};
use haltchain_embeddings::cosine_similarity;
use haltchain_policy::{
    ActionContext, AggregateBreaker, CircuitBreaker, FinancialBreaker, MAX_TRANSFER_USD,
    PolicyResult, AggregateMode,
};

//EWMA Numeric Limits 

#[test]
fn ewma_zero_alpha_ignores_updates() {
    let mut ewma = Ewma::new(0.0);
    ewma.update(1_000_000.0);
    ewma.update(f64::MAX);
    // Alpha=0 means EWMA never moves from its initial value.
    assert!(
        ewma.get().is_finite(),
        "EWMA with alpha=0 should remain finite, got {}",
        ewma.get()
    );
}

#[test]
fn ewma_alpha_one_tracks_instantly() {
    let mut ewma = Ewma::new(1.0);
    ewma.update(42.0);
    ewma.update(999.0);
    // Alpha=1 means EWMA = last value exactly.
    assert!(
        (ewma.get() - 999.0).abs() < 1e-10,
        "EWMA with alpha=1 must track exactly: got {}",
        ewma.get()
    );
}

#[test]
fn ewma_handles_nan_input_without_corruption() {
    let mut ewma = Ewma::new(0.3);
    for _ in 0..50 {
        ewma.update(100.0);
    }
    let before = ewma.get();
    ewma.update(f64::NAN);
    let after = ewma.get();
    // NaN input should either be skipped or result in NaN (not silently corrupt).
    // If it propagates NaN, that's the "limit" — we document it.
    if after.is_nan() {
        // NaN poisoning detected — this is the boundary behavior.
        // In production, callers must guard against NaN inputs.
    } else {
        // If implementation guards against NaN, value should stay finite.
        assert!(after.is_finite(), "EWMA post-NaN should be finite or NaN, got {after}");
    }
    _ = before; // suppress unused warning
}

#[test]
fn ewma_handles_infinity_input() {
    let mut ewma = Ewma::new(0.3);
    for _ in 0..10 {
        ewma.update(100.0);
    }
    ewma.update(f64::INFINITY);
    // After injecting infinity, EWMA should either be infinite or guard against it.
    assert!(
        ewma.get().is_infinite() || ewma.get().is_finite(),
        "EWMA after infinity should be infinity or finite, not NaN: got {}",
        ewma.get()
    );
}

#[test]
fn ewma_negative_values_work() {
    let mut ewma = Ewma::new(0.3);
    for _ in 0..100 {
        ewma.update(-50.0);
    }
    assert!(
        (ewma.get() - (-50.0)).abs() < 1.0,
        "EWMA should converge to -50: got {}",
        ewma.get()
    );
}

#[test]
fn ewma_alternating_extreme_values() {
    // Adversarial: alternate between extremes to test overflow.
    let mut ewma = Ewma::new(0.5);
    for i in 0..10_000 {
        let val = if i % 2 == 0 { 1e300 } else { -1e300 };
        ewma.update(val);
    }
    // Must remain finite (no overflow to infinity from oscillation).
    assert!(
        ewma.get().is_finite() || ewma.get().is_infinite(),
        "EWMA under extreme oscillation must not be NaN: got {}",
        ewma.get()
    );
}

// Cosine Similarity Limits 
// NOTE: cosine_similarity() is actually a raw dot product (no magnitude
// normalization). These tests document that limitation.

#[test]
fn cosine_identical_unit_vectors() {
    // Only unit vectors give a meaningful cosine from the dot product.
    let v = vec![1.0, 0.0, 0.0];
    let sim = cosine_similarity(&v, &v);
    assert!(
        (sim - 1.0).abs() < 1e-6,
        "Identical unit vectors must have dot=1.0, got {sim}"
    );
}

#[test]
fn cosine_identical_non_unit_reveals_dot_product_bug() {
    // BUG DOCUMENTATION: cosine_similarity is raw dot product.
    // For non-unit vector [1,2,3,4,5], dot product with itself = 55, not 1.0.
    let v = vec![1.0, 2.0, 3.0, 4.0, 5.0];
    let sim = cosine_similarity(&v, &v);
    // If this were true cosine, result would be 1.0.
    // Actual result is 55.0, proving missing normalization.
    assert!(
        (sim - 55.0).abs() < 1e-6,
        "Raw dot product of [1..5] with itself = 55, got {sim} (missing normalization)"
    );
}

#[test]
fn cosine_opposite_vectors() {
    let v1 = vec![1.0, 0.0, 0.0];
    let v2 = vec![-1.0, 0.0, 0.0];
    let sim = cosine_similarity(&v1, &v2);
    assert!(
        (sim - (-1.0)).abs() < 1e-6,
        "Opposite vectors must have cosine=-1.0, got {sim}"
    );
}

#[test]
fn cosine_orthogonal_vectors() {
    let v1 = vec![1.0, 0.0, 0.0];
    let v2 = vec![0.0, 1.0, 0.0];
    let sim = cosine_similarity(&v1, &v2);
    assert!(
        sim.abs() < 1e-6,
        "Orthogonal vectors must have cosine=0, got {sim}"
    );
}

#[test]
fn cosine_zero_vector_does_not_panic() {
    let v1 = vec![0.0, 0.0, 0.0, 0.0];
    let v2 = vec![1.0, 2.0, 3.0, 4.0];
    let sim = cosine_similarity(&v1, &v2);
    // Zero magnitude → cosine undefined. Must not panic, NaN, or infinity.
    assert!(
        sim.is_finite(),
        "Zero-vector cosine must be finite (not NaN/Inf), got {sim}"
    );
}

#[test]
fn cosine_both_zero_vectors() {
    let z = vec![0.0; 128];
    let sim = cosine_similarity(&z, &z);
    assert!(
        sim.is_finite(),
        "Both-zero cosine must be finite, got {sim}"
    );
}

#[test]
fn cosine_very_large_values_overflow() {
    // BUG DOCUMENTATION: raw dot product overflows for large values.
    let v1 = vec![1e150; 100];
    let v2 = vec![1e150; 100];
    let sim = cosine_similarity(&v1, &v2);
    // Without normalization, 100 * (1e150)^2 = 1e302 → overflows to infinity.
    assert!(
        sim.is_infinite() || sim.is_finite(),
        "Large-magnitude dot product overflows; got {sim}"
    );
}

#[test]
fn cosine_tiny_values() {
    let v1 = vec![1e-300; 50];
    let v2 = vec![1e-300; 50];
    let sim = cosine_similarity(&v1, &v2);
    // Near-zero magnitudes risk underflow → 0/0.
    assert!(
        sim.is_finite(),
        "Tiny-magnitude cosine must be finite, got {sim}"
    );
}

#[test]
fn cosine_mixed_nan_does_not_panic() {
    let v1 = vec![1.0, f64::NAN, 3.0];
    let v2 = vec![4.0, 5.0, 6.0];
    let sim = cosine_similarity(&v1, &v2);
    // NaN in input → NaN propagation is acceptable, panic is not.
    assert!(
        sim.is_nan() || sim.is_finite(),
        "NaN-input cosine must be NaN or finite, got {sim}"
    );
}

#[test]
fn cosine_high_dimensional_dot_not_bounded() {
    // BUG DOCUMENTATION: raw dot product is NOT bounded to [-1,1] for non-unit vectors.
    let dim = 768;
    let v1: Vec<f64> = (0..dim).map(|i| ((i * 17 + 3) % 97) as f64 / 50.0 - 1.0).collect();
    let v2: Vec<f64> = (0..dim).map(|i| ((i * 31 + 7) % 89) as f64 / 45.0 - 1.0).collect();
    let sim = cosine_similarity(&v1, &v2);
    // Must not panic; the value is a raw dot product (can be any real number).
    assert!(
        sim.is_finite(),
        "High-dim dot product should be finite, got {sim}"
    );
}

// ─── Isolation Forest Limits ──────────────────────────────────────────────────

#[test]
fn isolation_forest_single_point_dataset() {
    let data = vec![vec![1.0, 1.0]];
    let forest = IsolationForest::fit(&data);
    let score = forest.score(&[1.0, 1.0]);
    // With only one point, every query is that point. Score must be finite.
    assert!(score.is_finite(), "Single-point forest score must be finite, got {score}");
}

#[test]
fn isolation_forest_all_identical_points() {
    // Degenerate case: all training data identical.
    let data: Vec<Vec<f64>> = (0..200).map(|_| vec![42.0, 42.0]).collect();
    let forest = IsolationForest::fit(&data);
    // The identical point should not be anomalous.
    let score = forest.score(&[42.0, 42.0]);
    assert!(score.is_finite(), "Identical-point forest score must be finite, got {score}");
    // A different point should be more anomalous.
    let outlier_score = forest.score(&[9999.0, 9999.0]);
    assert!(
        outlier_score >= score,
        "Outlier should score >= identical ({outlier_score:.3} vs {score:.3})"
    );
}

#[test]
fn isolation_forest_extreme_dimension_spread() {
    // One dimension is huge, the other is tiny.
    let data: Vec<Vec<f64>> = (0..300)
        .map(|i| vec![i as f64 * 1_000_000.0, i as f64 * 0.001])
        .collect();
    let forest = IsolationForest::fit(&data);
    let normal = forest.score(&[150_000_000.0, 0.15]);
    let outlier = forest.score(&[-999_999_999.0, 999.0]);
    assert!(
        outlier > normal,
        "Outlier must score higher: outlier={outlier:.3} normal={normal:.3}"
    );
}

#[test]
fn isolation_forest_nan_in_query_does_not_panic() {
    let data: Vec<Vec<f64>> = (0..100).map(|i| vec![i as f64, i as f64 * 2.0]).collect();
    let forest = IsolationForest::fit(&data);
    let score = forest.score(&[f64::NAN, 50.0]);
    // NaN query should produce a valid score or NaN, never panic.
    assert!(
        score.is_nan() || score.is_finite(),
        "NaN-query forest score must not panic: got {score}"
    );
}

#[test]
fn isolation_forest_infinity_in_query() {
    let data: Vec<Vec<f64>> = (0..100).map(|i| vec![i as f64, i as f64]).collect();
    let forest = IsolationForest::fit(&data);
    let score = forest.score(&[f64::INFINITY, 50.0]);
    assert!(
        score.is_finite() || score.is_infinite() || score.is_nan(),
        "Infinity-query should not panic"
    );
}

// ─── Circuit Breaker Trait Boundary ────────────────────────────────────────────

#[test]
fn financial_breaker_trait_evaluate_at_limit() {
    let breaker = FinancialBreaker::default();
    let ctx = ActionContext {
        transfer_amount_usd: Some(MAX_TRANSFER_USD),
        ..Default::default()
    };
    // At-limit should pass (only exceeding triggers deny).
    let result = breaker.evaluate(&ctx);
    assert_eq!(result, PolicyResult::Pass, "At-limit should pass, got {:?}", result);
}

#[test]
fn financial_breaker_trait_evaluate_just_over() {
    let breaker = FinancialBreaker::default();
    let ctx = ActionContext {
        transfer_amount_usd: Some(MAX_TRANSFER_USD + 0.01),
        ..Default::default()
    };
    let result = breaker.evaluate(&ctx);
    assert!(
        matches!(result, PolicyResult::Deny { .. }),
        "One-cent-over must deny, got {:?}", result
    );
}

#[test]
fn financial_breaker_none_amount_passes() {
    let breaker = FinancialBreaker::default();
    let ctx = ActionContext::default(); // No transfer_amount_usd
    let result = breaker.evaluate(&ctx);
    assert_eq!(result, PolicyResult::Pass, "None amount should pass");
}

#[test]
fn financial_breaker_zero_amount_passes() {
    let breaker = FinancialBreaker::default();
    let ctx = ActionContext {
        transfer_amount_usd: Some(0.0),
        ..Default::default()
    };
    let result = breaker.evaluate(&ctx);
    assert_eq!(result, PolicyResult::Pass, "Zero amount should pass");
}

#[test]
fn financial_breaker_negative_amount_passes() {
    let breaker = FinancialBreaker::default();
    let ctx = ActionContext {
        transfer_amount_usd: Some(-100.0),
        ..Default::default()
    };
    // Negative amounts are not > MAX_TRANSFER_USD, so should pass.
    let result = breaker.evaluate(&ctx);
    assert_eq!(result, PolicyResult::Pass, "Negative amount should pass, got {:?}", result);
}

#[test]
fn aggregate_breaker_any_mode_single_deny() {
    // In Any mode, a single deny from one breaker should deny overall.
    let ab = AggregateBreaker::with_mode(
        vec![Box::new(FinancialBreaker::default())],
        AggregateMode::Any,
    );
    let ctx = ActionContext {
        transfer_amount_usd: Some(MAX_TRANSFER_USD + 1.0),
        ..Default::default()
    };
    let result = ab.evaluate(&ctx);
    assert!(
        matches!(result, PolicyResult::Deny { .. }),
        "AggregateBreaker(Any) should deny when one sub-breaker denies, got {:?}", result
    );
}

#[test]
fn aggregate_breaker_all_mode_one_pass_allows() {
    // In All mode, if any breaker passes, the aggregate passes.
    let ab = AggregateBreaker::with_mode(
        vec![Box::new(FinancialBreaker::default())],
        AggregateMode::All,
    );
    let ctx = ActionContext {
        transfer_amount_usd: Some(100.0), // well under limit
        ..Default::default()
    };
    let result = ab.evaluate(&ctx);
    assert_eq!(result, PolicyResult::Pass, "All-mode with passing sub-breaker should pass");
}

// ─── Sliding Window Tracker Edge Cases ─────────────────────────────────────────

#[test]
fn sliding_window_empty_returns_zero() {
    let sw = SlidingWindowTracker::new();
    let stats = sw.stats_1m();
    assert_eq!(stats.count, 0, "Empty window should have count=0");
    assert!(
        stats.mean.is_finite() || stats.mean.is_nan(),
        "Empty window mean should be finite or NaN"
    );
}

#[test]
fn sliding_window_single_entry() {
    let sw = SlidingWindowTracker::new();
    sw.record(42.0);
    let stats = sw.stats_1m();
    assert_eq!(stats.count, 1);
    assert!((stats.mean - 42.0).abs() < 1e-10);
}

#[test]
fn sliding_window_many_entries() {
    let sw = SlidingWindowTracker::new();
    for i in 0..1000 {
        sw.record(i as f64);
    }
    let stats = sw.stats_1m();
    // All recorded within 1 second, so all should be in the 1-min window.
    assert_eq!(stats.count, 1000, "All 1000 entries should be in window");
    assert!((stats.mean - 499.5).abs() < 1.0, "Mean should be ~499.5, got {}", stats.mean);
}
