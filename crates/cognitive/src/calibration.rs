//! Adaptive percentile-based calibration system (ZEDD Section 5.1.2).
//!
//! Implements 99.5th percentile thresholding against reference distributions
//! of benign behavior. Replaces fixed thresholds with statistical calibration.

use crate::patterns::ReasoningPattern;
use std::collections::HashMap;

/// Reference distribution for a specific pattern
#[derive(Debug, Clone)]
pub struct ReferenceDistribution {
    /// Historical similarity scores from benign traces
    scores: Vec<f64>,
    /// Cached percentiles for performance
    cached_percentiles: HashMap<u8, f64>,
    /// Distribution statistics
    mean: f64,
    std_dev: f64,
}

impl ReferenceDistribution {
    pub fn new(benign_scores: Vec<f64>) -> Self {
        let mut sorted = benign_scores.clone();
        sorted.sort_by(|a, b| a.total_cmp(b));

        let (mean, std_dev) = if sorted.is_empty() {
            (0.0, 0.0)
        } else {
            let m = sorted.iter().sum::<f64>() / sorted.len() as f64;
            let v = sorted.iter().map(|x| (x - m).powi(2)).sum::<f64>() / sorted.len() as f64;
            (m, v.sqrt())
        };

        let mut cached = HashMap::new();
        // Pre-compute common percentiles
        for p in [50.0, 80.0, 90.0, 95.0, 99.0, 99.5, 99.9] {
            if let Some(val) = Self::compute_percentile(&sorted, p) {
                cached.insert((p * 10.0) as u8, val);
            }
        }

        Self {
            scores: sorted,
            cached_percentiles: cached,
            mean,
            std_dev,
        }
    }

    /// Compute percentile (0-100) for a given score
    pub fn percentile(&self, score: f64) -> f64 {
        // Binary search for efficiency
        let pos = match self
            .scores
            .binary_search_by(|a| a.partial_cmp(&score).unwrap())
        {
            Ok(p) => p,
            Err(p) => p,
        };

        (pos as f64 / self.scores.len().max(1) as f64) * 100.0
    }

    /// Get cached percentile value (inverse lookup)
    pub fn score_at_percentile(&self, p: f64) -> Option<f64> {
        // Check cache first
        let key = (p * 10.0).round() as u8;
        if let Some(&val) = self.cached_percentiles.get(&key) {
            return Some(val);
        }

        Self::compute_percentile(&self.scores, p)
    }

    fn compute_percentile(sorted_scores: &[f64], p: f64) -> Option<f64> {
        if sorted_scores.is_empty() {
            return None;
        }

        let idx = ((p / 100.0) * (sorted_scores.len() - 1) as f64).round() as usize;
        sorted_scores.get(idx.min(sorted_scores.len() - 1)).copied()
    }

    /// Adaptive normalization using empirical JSD (Jensen-Shannon Divergence)
    /// Section 5.1.2: "Adaptive normalization tracking empirical JSD distributions"
    pub fn normalized_score(&self, raw_score: f64) -> f64 {
        // Z-score normalization with percentile weighting
        let z_score = (raw_score - self.mean) / (self.std_dev + 1e-10);
        let percentile = self.percentile(raw_score);

        // Combine z-score and percentile for robustness
        // High percentile + positive z-score = very suspicious
        (z_score * 0.5) + ((percentile - 50.0) / 50.0 * 0.5)
    }

    pub fn is_anomalous(&self, score: f64, threshold_percentile: f64) -> bool {
        self.percentile(score) >= threshold_percentile
    }
}

/// Multi-pattern calibration database
pub struct CalibrationDB {
    distributions: HashMap<String, ReferenceDistribution>,
    /// Global benign baseline (all patterns combined)
    global_baseline: ReferenceDistribution,
}

impl CalibrationDB {
    pub fn from_benign_corpus(corpus: &[&str], embed_fn: &dyn Fn(&str) -> Vec<f64>) -> Self {
        let _pattern_scores: HashMap<String, Vec<f64>> = HashMap::new();
        let mut global_scores = Vec::new();

        // Collect embeddings from benign corpus
        for text in corpus {
            let emb = embed_fn(text);
            // Compute similarity to various pattern centroids
            // For now, use norm as a simple anomaly score
            let norm: f64 = emb.iter().map(|x| x * x).sum::<f64>().sqrt();
            global_scores.push(norm);
        }

        let global_baseline = ReferenceDistribution::new(global_scores);

        Self {
            distributions: HashMap::new(),
            global_baseline,
        }
    }

    /// Calibrate a raw score against the reference distribution
    pub fn calibrate(&self, pattern: &ReasoningPattern, raw_score: f64) -> CalibratedScore {
        let pattern_key = format!("{:?}", pattern);

        let percentile = self
            .distributions
            .get(&pattern_key)
            .map(|d| d.percentile(raw_score))
            .unwrap_or_else(|| self.global_baseline.percentile(raw_score));

        let normalized = self
            .distributions
            .get(&pattern_key)
            .map(|d| d.normalized_score(raw_score))
            .unwrap_or_else(|| self.global_baseline.normalized_score(raw_score));

        CalibratedScore {
            raw: raw_score,
            percentile,
            normalized,
        }
    }

    /// 4-tier decision system (Section 1.1.3)
    pub fn decide(&self, calibrated: &CalibratedScore) -> TieredDecision {
        // 99.5th percentile = very unusual (ZEDD requirement)
        if calibrated.percentile >= 99.5 {
            TieredDecision::Contain
        } else if calibrated.percentile >= 95.0 {
            TieredDecision::Review // Human escalation
        } else if calibrated.percentile >= 80.0 {
            TieredDecision::Monitor // Increased logging
        } else {
            TieredDecision::Allow
        }
    }
}

/// Calibrated score with multiple representations
#[derive(Debug, Clone, Copy)]
pub struct CalibratedScore {
    pub raw: f64,
    pub percentile: f64,
    pub normalized: f64,
}

/// 4-tier decision system per ZEDD framework
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TieredDecision {
    /// Tier 1: 0-50ms, conservative heuristic
    Allow,
    /// Tier 2: 50-200ms, boundary case
    Monitor,
    /// Tier 3: Human escalation
    Review,
    /// Tier 4: Automatic containment
    Contain,
}

impl TieredDecision {
    pub fn to_confidence_threshold(&self) -> f64 {
        match self {
            TieredDecision::Allow => 0.0,
            TieredDecision::Monitor => 0.7,
            TieredDecision::Review => 0.85,
            TieredDecision::Contain => 0.995,
        }
    }
}

/// Default calibration with synthetic benign data
pub fn default_calibration() -> CalibrationDB {
    // Create synthetic benign distribution
    // In production, this would be loaded from actual benign traces
    let benign_scores: Vec<f64> = (0..1000)
        .map(|i| {
            // Simulate normal distribution around 0.3 with small variance
            let base = 0.3;
            let noise = (i as f64 / 1000.0 - 0.5) * 0.2;
            (base + noise).clamp(0.0, 1.0)
        })
        .collect();

    let global = ReferenceDistribution::new(benign_scores);

    CalibrationDB {
        distributions: HashMap::new(),
        global_baseline: global,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_calculation() {
        let scores: Vec<f64> = (0..100).map(|i| i as f64 / 100.0).collect();
        let dist = ReferenceDistribution::new(scores);

        assert!((dist.percentile(0.5) - 50.0).abs() < 2.0);
        assert!((dist.percentile(0.99) - 99.0).abs() < 2.0);
    }

    #[test]
    fn tiered_decision_995() {
        let db = default_calibration();
        let score = CalibratedScore {
            raw: 0.95,
            percentile: 99.5,
            normalized: 2.0,
        };

        assert_eq!(db.decide(&score), TieredDecision::Contain);
    }

    #[test]
    fn tiered_decision_950() {
        let db = default_calibration();
        let score = CalibratedScore {
            raw: 0.85,
            percentile: 95.0,
            normalized: 1.5,
        };

        assert_eq!(db.decide(&score), TieredDecision::Review);
    }
}
