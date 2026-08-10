//! Ensemble-Based Divergence Analysis (K Core-Distance)
//!
//! Implements Section 2.1 and 5.1:
//! - K Core-Distance for OOD detection
//! - Multi-scale analysis with k ∈ {5, 20, 50}
//! - Three-way decision theory
//! - 99.5th percentile thresholding

use parking_lot::RwLock;
use std::sync::Arc;

// AC-05 FIX: Use shared canonical types
use crate::types::{AlertTier, DecisionRegion};

/// K Core-Distance for out-of-distribution detection (Section 2.1.2, 5.1.2)
pub struct KCoreDistanceDetector {
    /// Reference embeddings for baseline distribution
    reference_embeddings: Arc<RwLock<Vec<Vec<f64>>>>,
    /// Roadmap D: k ∈ {5, 20, 50, 100}
    k_values: Vec<usize>,
    /// Historical distances for percentile calculation
    historical_dists: Arc<RwLock<Vec<f64>>>,
}

/// Drift score with multi-scale information
#[derive(Debug, Clone)]
pub struct DriftScore {
    pub raw_distance: f64,
    pub percentile_rank: f64,
    pub k_distances: Vec<f64>,
    pub alert_tier: AlertTier,
}

// Note: AlertTier and DecisionRegion are now imported from crate::types (AC-05 FIX)

impl KCoreDistanceDetector {
    pub fn new() -> Self {
        Self {
            reference_embeddings: Arc::new(RwLock::new(Vec::new())),
            k_values: vec![5, 20, 50, 100],
            historical_dists: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add reference embedding to baseline
    pub fn add_reference(&self, embedding: Vec<f64>) {
        let mut refs = self.reference_embeddings.write();
        refs.push(embedding);
    }

    /// Calibrate using leave-one-out validation
    pub fn calibrate(&self) {
        let refs = self.reference_embeddings.read();
        let n = refs.len();

        if n < 50 {
            return; // Need more samples
        }

        let mut distances = Vec::with_capacity(n);

        // Leave-one-out core distance calculation
        for i in 0..n {
            let query = &refs[i];

            // Distances to all other points
            let mut point_dists: Vec<f64> = (0..n)
                .filter(|&j| j != i)
                .map(|j| euclidean_distance(query, &refs[j]))
                .collect();

            // Get k-th smallest distance (k=20 default)
            point_dists.sort_by(|a, b| a.total_cmp(b));
            let other = n.saturating_sub(1);
            let max_k = (other / 2).clamp(1, 100);
            let scales: Vec<f64> = [5usize, 20, 50, 100]
                .into_iter()
                .filter(|&k| k <= max_k && k <= other)
                .map(|k| point_dists.get(k.saturating_sub(1)).copied().unwrap_or(1.0))
                .collect();
            let row = if scales.is_empty() {
                1.0
            } else {
                Self::trimmed_mean(&scales, 0.2)
            };
            distances.push(row);
        }

        distances.sort_by(|a, b| a.total_cmp(b));

        let mut historical = self.historical_dists.write();
        *historical = distances;
    }

    /// Compute drift score using multi-scale Core Distance
    pub fn compute_drift_score(&self, embedding: &[f64]) -> DriftScore {
        let mut k_distances = Vec::new();

        // Multi-scale Core Distance (Section 5.1.3)
        for k in &self.k_values {
            let k_dist = self.kth_nearest_distance(embedding, *k);
            k_distances.push(k_dist);
        }

        // Robust aggregation: trimmed mean (remove 20% outliers)
        let mut sorted_dists = k_distances.clone();
        sorted_dists.sort_by(|a, b| a.total_cmp(b));
        let trimmed_mean = Self::trimmed_mean(&sorted_dists, 0.2);

        // Percentile rank against historical distribution (Section 2.1.3)
        let percentile = self.calculate_percentile(trimmed_mean);

        DriftScore {
            raw_distance: trimmed_mean,
            percentile_rank: percentile,
            k_distances: k_distances.clone(),
            alert_tier: self.percentile_to_tier(percentile),
        }
    }

    /// Find k-th nearest neighbor distance (Core Distance)
    /// This normalizes for local density (Section 5.1.2)
    fn kth_nearest_distance(&self, embedding: &[f64], k: usize) -> f64 {
        let refs = self.reference_embeddings.read();

        if refs.len() < k {
            return 1.0;
        }

        let mut distances: Vec<f64> = refs
            .iter()
            .map(|ref_emb| euclidean_distance(embedding, ref_emb))
            .collect();
        distances.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        distances.get(k.saturating_sub(1)).copied().unwrap_or(1.0)
    }

    /// Calculate percentile in historical distribution
    fn calculate_percentile(&self, distance: f64) -> f64 {
        let historical = self.historical_dists.read();

        if historical.is_empty() {
            return 0.0;
        }

        let count = historical.iter().filter(|&&d| d <= distance).count();
        (count as f64 / historical.len() as f64) * 100.0
    }

    /// Convert percentile to alert tier
    fn percentile_to_tier(&self, percentile: f64) -> AlertTier {
        AlertTier::from_percentile(percentile)
    }

    /// Three-way decision theory (Section 2.1.3)
    pub fn three_way_decision(&self, score: &DriftScore) -> DecisionRegion {
        DecisionRegion::from_percentile(score.percentile_rank, 0.95, 0.99)
    }

    /// Robust trimmed mean for outlier resistance
    fn trimmed_mean(data: &[f64], trim_ratio: f64) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let trim_count = (data.len() as f64 * trim_ratio) as usize;
        let trimmed = &data[trim_count..data.len() - trim_count];

        if trimmed.is_empty() {
            data.iter().sum::<f64>() / data.len() as f64
        } else {
            trimmed.iter().sum::<f64>() / trimmed.len() as f64
        }
    }

    /// Reference count
    pub fn reference_count(&self) -> usize {
        self.reference_embeddings.read().len()
    }

    /// Historical distance count
    pub fn historical_count(&self) -> usize {
        self.historical_dists.read().len()
    }
}

impl Default for KCoreDistanceDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Euclidean distance between two vectors
fn euclidean_distance(a: &[f64], b: &[f64]) -> f64 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x - y).powi(2))
        .sum::<f64>()
        .sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detector_creation() {
        let detector = KCoreDistanceDetector::new();
        assert_eq!(detector.reference_count(), 0);
    }

    #[test]
    fn add_references() {
        let detector = KCoreDistanceDetector::new();

        for i in 0..100 {
            let emb: Vec<f64> = (0..10).map(|j| (i * j) as f64 / 1000.0).collect();
            detector.add_reference(emb);
        }

        assert_eq!(detector.reference_count(), 100);
    }

    #[test]
    fn compute_drift_score() {
        let detector = KCoreDistanceDetector::new();

        // Add reference distribution
        for i in 0..100 {
            let emb: Vec<f64> = (0..10).map(|j| (i * j) as f64 / 1000.0).collect();
            detector.add_reference(emb);
        }

        detector.calibrate();

        // Test with in-distribution sample
        let in_dist: Vec<f64> = (0..10).map(|j| (50 * j) as f64 / 1000.0).collect();
        let score1 = detector.compute_drift_score(&in_dist);

        // Test with out-of-distribution sample
        let out_dist: Vec<f64> = (0..10).map(|_| 5.0).collect();
        let score2 = detector.compute_drift_score(&out_dist);

        assert!(
            score2.raw_distance > score1.raw_distance
                || score2.percentile_rank >= score1.percentile_rank,
            "OOD should not look closer than in-dist: in raw={:.4} pct={:.1} out raw={:.4} pct={:.1}",
            score1.raw_distance,
            score1.percentile_rank,
            score2.raw_distance,
            score2.percentile_rank
        );
    }

    #[test]
    fn three_way_decision() {
        let detector = KCoreDistanceDetector::new();

        let low_score = DriftScore {
            raw_distance: 0.1,
            percentile_rank: 50.0,
            k_distances: vec![0.1, 0.1, 0.1],
            alert_tier: AlertTier::None,
        };

        let high_score = DriftScore {
            raw_distance: 0.9,
            percentile_rank: 99.5,
            k_distances: vec![0.9, 0.9, 0.9],
            alert_tier: AlertTier::High,
        };

        assert_eq!(
            detector.three_way_decision(&low_score),
            DecisionRegion::Negative
        );
        assert_eq!(
            detector.three_way_decision(&high_score),
            DecisionRegion::Positive
        );
    }

    #[test]
    fn trimmed_mean_calculation() {
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        let mean = KCoreDistanceDetector::trimmed_mean(&data, 0.2);

        // Trim 20% = 2 elements from each end
        // Remaining: 3.0, 4.0, 5.0, 6.0, 7.0, 8.0
        // Mean: 33.0 / 6 = 5.5
        assert!((mean - 5.5).abs() < 0.01);
    }
}
