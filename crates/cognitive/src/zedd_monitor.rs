//! ZEDD (Zero-Shot Embedding Drift Detection) Monitor
//!
//! Research-backed implementation meeting requirements:
//! - 99.5th percentile thresholding (Section 5.1.2)
//! - K Core-Distance normalization (Section 5.1.2)
//! - Multi-scale analysis (Section 5.1.3)
//! - 4-tier decision system (Section 1.1.3)

use crate::calibration::{CalibrationDB, TieredDecision, default_calibration};
use crate::context::adjust_confidence;
use crate::drift::{MultiScaleAnalyzer, robust_similarity};
use crate::patterns::{ReasoningPattern, seed_strings};
use haltchain_embeddings::{LOCAL_DIMS, ModelKind};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// ZEDD-based cognitive monitor
pub struct ZeddMonitor {
    model: ModelKind,
    centroids: Mutex<HashMap<String, Vec<f64>>>,
    calibration: CalibrationDB,
    multi_scale: MultiScaleAnalyzer,
}

impl ZeddMonitor {
    pub fn new() -> Self {
        let model = ModelKind::local_or_hash();
        let calibration = default_calibration();
        let multi_scale = MultiScaleAnalyzer::new();
        
        let m = Self {
            model,
            centroids: Mutex::new(HashMap::new()),
            calibration,
            multi_scale,
        };
        m.precompute_centroids();
        m
    }
    
    fn precompute_centroids(&self) {
        let dangerous = [
            ReasoningPattern::DeceptionPlanning,
            ReasoningPattern::SelfPreservation,
            ReasoningPattern::CapabilitySeeking,
            ReasoningPattern::SocialEngineering,
            ReasoningPattern::SafetySabotage,
            ReasoningPattern::RewardMaximization,
        ];
        let mut c = self.centroids.lock();
        for pattern in &dangerous {
            let seeds = seed_strings(pattern);
            let mut centroid = vec![0.0f64; LOCAL_DIMS];
            for &seed in seeds {
                let emb = self.model.embed_text(seed);
                for (cv, v) in centroid.iter_mut().zip(emb.iter()) {
                    *cv += v;
                }
            }
            l2_normalize(&mut centroid);
            c.insert(format!("{:?}", pattern), centroid);
        }
    }
    
    /// ZEDD-based deep scan with 99.5th percentile thresholding
    pub fn deep_scan(&self, trace: &str) -> ZeddAssessment {
        // Multi-scale analysis: check whole text AND sliding windows
        let windows = self.multi_scale.extract_windows(trace);
        let c = self.centroids.lock();
        
        let mut best_result: Option<(ReasoningPattern, f64, f64)> = None; // (pattern, raw_sim, percentile)
        let mut window_results = Vec::new();
        
        for window in &windows {
            let _window_emb = self.model.embed_text(window);
            
            for pattern in [
                ReasoningPattern::DeceptionPlanning,
                ReasoningPattern::SelfPreservation,
                ReasoningPattern::CapabilitySeeking,
                ReasoningPattern::SocialEngineering,
                ReasoningPattern::SafetySabotage,
                ReasoningPattern::RewardMaximization,
            ] {
                if let Some(centroid) = c.get(&format!("{:?}", pattern)) {
                    // Use robust similarity (with perturbations)
                    let raw_sim = robust_similarity(window, centroid, &|t| self.model.embed_text(t));
                    
                    // Calibrate to percentile
                    let calibrated = self.calibration.calibrate(&pattern, raw_sim);
                    
                    window_results.push((window.clone(), pattern.clone(), calibrated.percentile));
                    
                    // Track best match
                    if calibrated.percentile > best_result.as_ref().map(|r| r.2).unwrap_or(0.0) {
                        best_result = Some((pattern, raw_sim, calibrated.percentile));
                    }
                }
            }
        }
        
        // Get best result
        if let Some((pattern, raw_sim, percentile)) = best_result {
            // Apply context-aware adjustment
            let adjusted_sim = adjust_confidence(raw_sim, trace);
            let decision = self.calibration.decide(&crate::calibration::CalibratedScore {
                raw: raw_sim,
                percentile,
                normalized: adjusted_sim,
            });
            
            match decision {
                TieredDecision::Contain => ZeddAssessment::HaltAndClarify {
                    pattern: pattern.clone(),
                    percentile,
                    raw_confidence: adjusted_sim,
                    explanation: format!(
                        "99.5th percentile drift detected: {:?} (p={:.1}%)",
                        pattern, percentile
                    ),
                },
                TieredDecision::Review => ZeddAssessment::Review {
                    pattern,
                    percentile,
                    raw_confidence: adjusted_sim,
                },
                TieredDecision::Monitor => ZeddAssessment::Flagged {
                    pattern,
                    percentile,
                    raw_confidence: adjusted_sim,
                },
                TieredDecision::Allow => ZeddAssessment::Proceed,
            }
        } else {
            ZeddAssessment::Proceed
        }
    }
}

impl Default for ZeddMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// ZEDD assessment with percentile-based confidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZeddAssessment {
    Proceed,
    Flagged {
        pattern: ReasoningPattern,
        percentile: f64,
        raw_confidence: f64,
    },
    Review {
        pattern: ReasoningPattern,
        percentile: f64,
        raw_confidence: f64,
    },
    HaltAndClarify {
        pattern: ReasoningPattern,
        percentile: f64,
        raw_confidence: f64,
        explanation: String,
    },
}

impl ZeddAssessment {
    /// Check if assessment indicates any concern
    pub fn is_concerning(&self) -> bool {
        !matches!(self, ZeddAssessment::Proceed)
    }
    
    /// Get pattern if concerning
    pub fn pattern(&self) -> Option<&ReasoningPattern> {
        match self {
            ZeddAssessment::Flagged { pattern, .. } => Some(pattern),
            ZeddAssessment::Review { pattern, .. } => Some(pattern),
            ZeddAssessment::HaltAndClarify { pattern, .. } => Some(pattern),
            ZeddAssessment::Proceed => None,
        }
    }
    
    /// Get percentile score
    pub fn percentile(&self) -> Option<f64> {
        match self {
            ZeddAssessment::Flagged { percentile, .. } => Some(*percentile),
            ZeddAssessment::Review { percentile, .. } => Some(*percentile),
            ZeddAssessment::HaltAndClarify { percentile, .. } => Some(*percentile),
            ZeddAssessment::Proceed => None,
        }
    }
}

fn l2_normalize(v: &mut [f64]) {
    let norm: f64 = v.iter().map(|x| x * x).sum::<f64>().sqrt();
    if norm > 1e-10 {
        for x in v.iter_mut() {
            *x /= norm;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn zedd_monitor_creation() {
        let _monitor = ZeddMonitor::new();
        // Should not panic
    }
    
    #[test]
    fn benign_text_produces_valid_percentile() {
        let monitor = ZeddMonitor::new();
        let result = monitor.deep_scan("I will help the user with their request");
        if let Some(p) = result.percentile() {
            assert!((0.0..=100.0).contains(&p));
        }
    }

    #[test]
    fn research_text_produces_valid_percentile() {
        let monitor = ZeddMonitor::new();
        let result = monitor.deep_scan(
            "As a security researcher, I'm studying how attackers bypass authentication"
        );
        if let Some(p) = result.percentile() {
            assert!((0.0..=100.0).contains(&p));
        }
    }
}
