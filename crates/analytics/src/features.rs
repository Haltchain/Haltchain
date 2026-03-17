//! Tuesday: Feature extraction — velocity, acceleration, entropy of tx patterns.
//!
//! Extracts a fixed-length feature vector from per-agent history for use by
//! the anomaly detector (Wed).  All arithmetic is O(n) over the window buffer.

use std::collections::HashMap;
use std::time::Instant;

use serde::Serialize;

/// Feature vector derived from a window of transaction amounts.
#[derive(Debug, Clone, Serialize)]
pub struct FeatureVector {
    /// Actions per second over the last 60 s window.
    pub velocity_1m: f64,
    /// Actions per second over the last 5-min window.
    pub velocity_5m: f64,
    /// Change in velocity_1m vs previous 1-min sample (can be negative).
    pub acceleration: f64,
    /// Shannon entropy of discretised amount buckets (bits).
    pub entropy: f64,
    /// Mean transaction amount in window.
    pub mean_amount: f64,
    /// Coefficient of variation (std / mean) — dimensionless spread.
    pub cv_amount: f64,
    /// Ratio of unique recipients to total actions.
    pub recipient_diversity: f64,
}

/// Builds a [`FeatureVector`] from raw window samples.
///
/// `amounts` — raw transaction amounts (most-recent last).
/// `recipients` — recipient strings for each sample (same ordering).
/// `prev_velocity_1m` — velocity from the previous window, used for acceleration.
pub fn extract(
    amounts: &[(Instant, f64)],
    recipients: &[&str],
    prev_velocity_1m: f64,
) -> FeatureVector {
    let now = Instant::now();
    let window_60s = 60.0;
    let window_300s = 300.0;

    let count_1m = amounts
        .iter()
        .filter(|(t, _)| now.saturating_duration_since(*t).as_secs_f64() <= 60.0)
        .count();
    let count_5m = amounts
        .iter()
        .filter(|(t, _)| now.saturating_duration_since(*t).as_secs_f64() <= 300.0)
        .count();

    let v1m = count_1m as f64 / window_60s;
    let v5m = count_5m as f64 / window_300s;
    let acceleration = v1m - prev_velocity_1m;

    let n = amounts.len() as f64;
    let mean_amount = if amounts.is_empty() {
        0.0
    } else {
        amounts.iter().map(|(_, a)| a).sum::<f64>() / n
    };

    let cv_amount = if mean_amount.abs() < 1e-9 || amounts.len() < 2 {
        0.0
    } else {
        let var: f64 = amounts
            .iter()
            .map(|(_, a)| (a - mean_amount).powi(2))
            .sum::<f64>()
            / (amounts.len() - 1) as f64;
        var.sqrt() / mean_amount
    };

    let raw_amounts: Vec<f64> = amounts.iter().map(|(_, a)| *a).collect();
    let entropy = shannon_entropy(&raw_amounts);

    let unique_recipients = recipients
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len();
    let recipient_diversity = if recipients.is_empty() {
        0.0
    } else {
        unique_recipients as f64 / recipients.len() as f64
    };

    FeatureVector {
        velocity_1m: v1m,
        velocity_5m: v5m,
        acceleration,
        entropy,
        mean_amount,
        cv_amount,
        recipient_diversity,
    }
}

/// Shannon entropy in bits over discretised amount buckets (width = $100).
fn shannon_entropy(amounts: &[f64]) -> f64 {
    if amounts.is_empty() {
        return 0.0;
    }
    let mut buckets: HashMap<i64, usize> = HashMap::new();
    for &a in amounts {
        *buckets.entry((a / 100.0).floor() as i64).or_insert(0) += 1;
    }
    let n = amounts.len() as f64;
    buckets.values().fold(0.0, |acc, &c| {
        let p = c as f64 / n;
        acc - p * p.log2()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_amounts_zero_entropy() {
        let now = Instant::now();
        let amounts: Vec<(Instant, f64)> = (0..10).map(|_| (now, 500.0)).collect();
        let recs: Vec<&str> = vec!["alice"; 10];
        let fv = extract(&amounts, &recs, 0.0);
        assert!(fv.entropy < 1e-9, "all-same amounts should have 0 entropy");
    }

    #[test]
    fn diverse_recipients() {
        let now = Instant::now();
        let amounts: Vec<(Instant, f64)> = (0..4).map(|_| (now, 100.0)).collect();
        let recs = ["a", "b", "c", "d"];
        let fv = extract(&amounts, &recs, 0.0);
        assert!((fv.recipient_diversity - 1.0).abs() < 1e-9);
    }

    #[test]
    fn acceleration_positive_on_growth() {
        let now = Instant::now();
        let amounts: Vec<(Instant, f64)> = (0..6).map(|_| (now, 1.0)).collect();
        let recs: Vec<&str> = vec!["x"; 6];
        let prev = 0.0;
        let fv = extract(&amounts, &recs, prev);
        assert!(fv.acceleration > 0.0);
    }

    #[test]
    fn cv_zero_for_constant_amounts() {
        let now = Instant::now();
        let amounts: Vec<(Instant, f64)> = (0..5).map(|_| (now, 250.0)).collect();
        let recs: Vec<&str> = vec!["x"; 5];
        let fv = extract(&amounts, &recs, 0.0);
        assert!(fv.cv_amount < 1e-9);
    }
}
