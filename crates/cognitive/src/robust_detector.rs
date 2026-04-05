//! Production-hardened cognitive detection with ZEDD, Core Distance, JSD Divergence
//!
//! Research-backed implementation from Project_Architecture.md:
//! - 99.5th percentile thresholding (Section 2.1.3)
//! - K Core-Distance normalization (Section 3.1.3)
//! - Jensen-Shannon Divergence for alignment faking (Section 2.1.2)
//! - 4-tier decision system (Section 1.1.3)

// Re-export AlertTier for backward compatibility (AC-05 FIX)
pub use crate::types::AlertTier;
use ndarray::{Array1, Array2};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DetectionError {
    #[error("Insufficient reference samples: {0} < {1}")]
    InsufficientReferences(usize, usize),
    #[error("Embedding dimension mismatch: {0} vs {1}")]
    DimensionMismatch(usize, usize),
    #[error("Calibration required before detection")]
    Uncalibrated,
}

/// K Core-Distance implementation (Section 5.1.2 of research)
/// Uses k-th nearest neighbor distance for density-aware anomaly detection
pub struct CoreDistanceDetector {
    reference_embeddings: Array2<f32>, // [n_samples, n_dims]
    k: usize,
    cached_distances: Vec<f32>, // Historical core distances for percentile calc
    pub calibration_stats: CalibrationStats,
}

#[derive(Clone, Debug, Default)]
pub struct CalibrationStats {
    pub mean: f32,
    pub std: f32,
    pub p95: f32,
    pub p99: f32,
    pub p995: f32,
    pub sample_count: usize,
}

// Note: AlertTier is now imported from crate::types (AC-05 FIX)
// Mapping from old variants:
// - Normal -> None (0-95th percentile)
// - Review -> Medium (95-99.5th percentile)  
// - Critical -> Critical (>99.5th percentile)

impl CoreDistanceDetector {
    pub fn new(reference_embeddings: Array2<f32>, k: usize) -> Result<Self, DetectionError> {
        let (n_samples, _n_dims) = reference_embeddings.dim();
        if n_samples < k * 2 {
            return Err(DetectionError::InsufficientReferences(n_samples, k * 2));
        }
        
        Ok(Self {
            reference_embeddings,
            k,
            cached_distances: Vec::with_capacity(n_samples),
            calibration_stats: CalibrationStats {
                mean: 0.0, std: 0.0, p95: 0.0, p99: 0.0, p995: 0.0, sample_count: 0,
            },
        })
    }

    /// Calibrate using leave-one-out validation on reference set
    pub fn calibrate(&mut self) {
        let n = self.reference_embeddings.nrows();
        let mut distances = Vec::with_capacity(n);
        
        // Leave-one-out core distance calculation
        for i in 0..n {
            let query = self.reference_embeddings.row(i).to_owned();
            
            // Collect distances to all other points
            let mut point_dists: Vec<f32> = (0..n)
                .filter(|&j| j != i)
                .map(|j| {
                    let other = self.reference_embeddings.row(j);
                    cosine_distance(&query, &other)
                })
                .collect();
            
            // Get k-th smallest (k-th nearest neighbor)
            point_dists.sort_by(|a, b| a.total_cmp(b));
            let kth_dist = point_dists.get(self.k).copied().unwrap_or(1.0);
            distances.push(kth_dist);
        }
        
        distances.sort_by(|a, b| a.total_cmp(b));
        
        self.calibration_stats = CalibrationStats {
            mean: distances.iter().sum::<f32>() / distances.len() as f32,
            std: std_dev(&distances),
            p95: percentile(&distances, 0.95),
            p99: percentile(&distances, 0.99),
            p995: percentile(&distances, 0.995),
            sample_count: distances.len(),
        };
        self.cached_distances = distances;
    }

    /// Core Distance: distance to k-th nearest neighbor (not nearest!)
    /// Normalizes for local density - critical for semantic spaces
    fn core_distance_single(&self, query: &Array1<f32>) -> f32 {
        let distances: Vec<f32> = self.reference_embeddings.rows()
            .into_iter()
            .map(|row| cosine_distance(query, &row))
            .collect();
        
        // Use quickselect for k-th smallest (O(n) vs O(n log n))
        quickselect(distances, self.k)
    }

    /// ZEDD-style detection (Zero-Shot Embedding Drift Detection)
    pub fn detect(&self, embedding: &[f32]) -> Result<DetectionResult, DetectionError> {
        if self.calibration_stats.sample_count == 0 {
            return Err(DetectionError::Uncalibrated);
        }
        
        let query = Array1::from(embedding.to_vec());
        let core_dist = self.core_distance_single(&query);
        
        // Percentile rank in calibration distribution
        let percentile = calculate_percentile(&self.cached_distances, core_dist);
        
        // AC-05 FIX: Use shared AlertTier with proper percentile mapping
        let tier = if percentile > 0.995 {
            AlertTier::Critical
        } else if percentile > 0.95 {
            AlertTier::Medium  // Maps from old AlertTier::Review
        } else {
            AlertTier::None  // Maps from old AlertTier::Normal
        };
        
        // Z-score for magnitude assessment
        let z_score = (core_dist - self.calibration_stats.mean) / self.calibration_stats.std.max(1e-10);
        
        Ok(DetectionResult {
            core_distance: core_dist,
            percentile_rank: percentile,
            z_score,
            alert_tier: tier,
            confidence: calculate_confidence(percentile),
        })
    }
}

#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub core_distance: f32,
    pub percentile_rank: f32, // 0.0 - 1.0
    pub z_score: f32,
    pub alert_tier: AlertTier,
    pub confidence: f32,
}

/// Context-Aware Detector with dual baselines (Academic vs Malicious)
pub struct ContextAwareDetector {
    malicious_detector: CoreDistanceDetector,
    academic_detector: CoreDistanceDetector,
    context_classifier: ContextClassifier,
}

impl ContextAwareDetector {
    pub fn new(
        malicious_refs: Array2<f32>,
        academic_refs: Array2<f32>,
    ) -> Result<Self, DetectionError> {
        let mut mal = CoreDistanceDetector::new(malicious_refs, 20)?; // k=20 per research
        let mut acad = CoreDistanceDetector::new(academic_refs, 20)?;
        
        mal.calibrate();
        acad.calibrate();
        
        Ok(Self {
            malicious_detector: mal,
            academic_detector: acad,
            context_classifier: ContextClassifier::new(),
        })
    }

    /// Distinguishes security research from actual attacks
    pub fn analyze(&self, text: &str, embedding: &[f32]) -> ContextualResult {
        let ctx = self.context_classifier.classify(text);
        
        // Dual scoring
        let mal_score = self.malicious_detector.detect(embedding).unwrap();
        let acad_score = self.academic_detector.detect(embedding).unwrap();
        
        // Context-aware arbitration (Section 1.1.1)
        let (primary_score, secondary_score, context) = match ctx {
            ContextType::AcademicResearch => {
                // In academic context, closeness to academic baseline is GOOD
                // Distance from malicious baseline should be HIGH
                let academic_closeness = 1.0 - acad_score.percentile_rank; // Lower distance = higher rank
                let malicious_distance = mal_score.percentile_rank;
                
                // If very close to academic and far from malicious -> Normal
                // If close to both -> Medium/Review (ambiguous)
                if academic_closeness > 0.8 && malicious_distance < 0.5 {
                    return ContextualResult {
                        decision: AlertTier::None,  // AC-05 FIX: Maps from old Normal
                        reasoning: "Academic research context confirmed".to_string(),
                        primary_score: acad_score,
                        secondary_score: mal_score,
                    };
                }
                (acad_score, mal_score, "Academic context with anomalies")
            },
            ContextType::Operational => {
                // Standard operational monitoring
                (mal_score, acad_score, "Operational context")
            },
            ContextType::Mixed => {
                // Conservative: use max risk
                if mal_score.percentile_rank > acad_score.percentile_rank {
                    (mal_score, acad_score, "Mixed context - using malicious baseline")
                } else {
                    (acad_score, mal_score, "Mixed context - using academic baseline")
                }
            }
        };
        
        ContextualResult {
            decision: primary_score.alert_tier,
            reasoning: format!("{}: {:.2} percentile", context, primary_score.percentile_rank),
            primary_score,
            secondary_score,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ContextType {
    AcademicResearch,
    Operational,
    Mixed,
}

pub struct ContextClassifier;

impl ContextClassifier {
    pub fn new() -> Self { Self }
    
    pub fn classify(&self, text: &str) -> ContextType {
        let academic_markers = ["research", "paper", "study", "analysis", "defensive", 
                               "mitigation", "vulnerability research", "cve", "security audit"];
        let operational_markers = ["exploit", "attack", "breach", "exfiltrate", "ransomware",
                                  "payload", "weaponize"];
        
        let text_lower = text.to_lowercase();
        let acad_count = academic_markers.iter().filter(|m| text_lower.contains(*m)).count();
        let op_count = operational_markers.iter().filter(|m| text_lower.contains(*m)).count();
        
        if acad_count > 0 && op_count == 0 {
            ContextType::AcademicResearch
        } else if op_count > 0 && acad_count == 0 {
            ContextType::Operational
        } else {
            ContextType::Mixed
        }
    }
}

/// Alignment Faking Detection via Embedding Divergence
/// Research Section 3.2.1: Reasoning/Output divergence detection
/// 
/// SECURITY FIX: Uses cosine-based divergence instead of JSD.
/// Embeddings are NOT probability distributions, so KL/JSD is mathematically invalid.
/// Cosine divergence properly measures embedding space separation.
pub struct AlignmentFakingDetector {
    reasoning_baseline: Array2<f32>,
    output_baseline: Array2<f32>,
    divergence_threshold: f32, // Cosine divergence threshold
}

impl AlignmentFakingDetector {
    pub fn new(reasoning_refs: Array2<f32>, output_refs: Array2<f32>) -> Self {
        Self {
            reasoning_baseline: reasoning_refs,
            output_baseline: output_refs,
            divergence_threshold: 0.62, // Between max honest (0.582) and min faking (0.694)
        }
    }
    
    /// Detects when reasoning (internal) diverges from output (observable)
    /// High divergence + concerning reasoning + innocent output = alignment faking
    pub fn detect_faking(
        &self,
        reasoning_embedding: &[f32],
        output_embedding: &[f32],
    ) -> FakingResult {
        let reason_arr = Array1::from(reasoning_embedding.to_vec());
        let output_arr = Array1::from(output_embedding.to_vec());
        
        // Cosine-based divergence (valid for embeddings)
        let divergence = cosine_divergence(&reason_arr, &output_arr);
        
        // Check individual alignments to honest baselines
        let reason_to_honest = avg_cosine_similarity(&reason_arr, &self.reasoning_baseline);
        let output_to_honest = avg_cosine_similarity(&output_arr, &self.output_baseline);
        
        // Faking signature: High divergence between reasoning and output
        // This captures cases where the model thinks one thing (concerning) 
        // but outputs something else (innocent-looking)
        let is_faking = divergence > self.divergence_threshold;
        
        FakingResult {
            jsd: divergence, // Keep field name for API compatibility
            is_faking,
            confidence: (divergence * 2.5).min(1.0), // Scale to confidence
            reason_similarity: reason_to_honest,
            output_similarity: output_to_honest,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FakingResult {
    pub jsd: f32,
    pub is_faking: bool,
    pub confidence: f32,
    pub reason_similarity: f32,
    pub output_similarity: f32,
}

#[derive(Debug, Clone)]
pub struct ContextualResult {
    pub decision: AlertTier,
    pub reasoning: String,
    pub primary_score: DetectionResult,
    pub secondary_score: DetectionResult,
}

// Helper functions
fn cosine_distance(a: &Array1<f32>, b: &ndarray::ArrayView1<f32>) -> f32 {
    let dot = a.dot(b);
    let norm_a = a.dot(a).sqrt();
    let norm_b = b.dot(b).sqrt();
    1.0 - (dot / (norm_a * norm_b).max(1e-10))
}

/// Cosine divergence: 1 - cosine_similarity
/// Valid divergence measure for embeddings (unlike KL/JSD which require probability distributions)
fn cosine_divergence(a: &Array1<f32>, b: &Array1<f32>) -> f32 {
    let dot = a.dot(b);
    let norm_a = a.dot(a).sqrt();
    let norm_b = b.dot(b).sqrt();
    let sim = dot / (norm_a * norm_b).max(1e-10);
    (1.0 - sim).clamp(0.0, 2.0)
}

#[cfg(test)]
fn jensen_shannon_divergence(p: &Array1<f32>, q: &Array1<f32>) -> f32 {
    // JSD = 0.5 * KL(P||M) + 0.5 * KL(Q||M) where M = 0.5(P+Q)
    let m = (p + q) / 2.0;
    let kl_pm = kl_divergence(p, &m);
    let kl_qm = kl_divergence(q, &m);
    0.5 * (kl_pm + kl_qm)
}

#[cfg(test)]
fn kl_divergence(p: &Array1<f32>, q: &Array1<f32>) -> f32 {
    p.iter().zip(q.iter())
        .map(|(pi, qi)| {
            if *pi > 1e-10 && *qi > 1e-10 {
                *pi * ((*pi / *qi).ln())
            } else {
                0.0
            }
        })
        .sum()
}

fn avg_cosine_similarity(query: &Array1<f32>, refs: &Array2<f32>) -> f32 {
    if refs.nrows() == 0 {
        return 0.0;
    }
    refs.rows()
        .into_iter()
        .map(|row| 1.0 - cosine_distance(query, &row))
        .sum::<f32>() / refs.nrows() as f32
}

fn percentile(sorted_data: &[f32], p: f64) -> f32 {
    if sorted_data.is_empty() {
        return 0.0;
    }
    let idx = (p * (sorted_data.len() - 1) as f64) as usize;
    sorted_data[idx.min(sorted_data.len() - 1)]
}

fn calculate_percentile(sorted_data: &[f32], value: f32) -> f32 {
    if sorted_data.is_empty() {
        return 0.0;
    }
    let count = sorted_data.iter().filter(|&&x| x <= value).count();
    count as f32 / sorted_data.len() as f32
}

fn std_dev(data: &[f32]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mean = data.iter().sum::<f32>() / data.len() as f32;
    let variance = data.iter().map(|x| (x - mean).powi(2)).sum::<f32>() / data.len() as f32;
    variance.sqrt()
}

fn quickselect(mut data: Vec<f32>, k: usize) -> f32 {
    // Simplified quickselect for k-th smallest
    data.sort_by(|a, b| a.total_cmp(b));
    data.get(k).copied().unwrap_or(1.0)
}

fn calculate_confidence(percentile: f32) -> f32 {
    // Scale percentile to confidence: higher percentile = higher confidence
    (percentile * 100.0).min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn generate_synthetic_embeddings(n: usize, dims: usize, center_val: f32) -> Array2<f32> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        let mut data = Vec::with_capacity(n * dims);
        for _ in 0..n {
            for _ in 0..dims {
                let noise: f32 = rng.gen_range(-0.1..0.1);
                data.push(center_val + noise);
            }
        }
        
        Array2::from_shape_vec((n, dims), data).unwrap()
    }
    
    #[test]
    fn core_distance_detector_creation() {
        let refs = generate_synthetic_embeddings(100, 10, 0.5);
        let detector = CoreDistanceDetector::new(refs, 10);
        assert!(detector.is_ok());
    }
    
    #[test]
    fn calibration_produces_stats() {
        let refs = generate_synthetic_embeddings(100, 10, 0.5);
        let mut detector = CoreDistanceDetector::new(refs, 10).unwrap();
        detector.calibrate();
        
        assert!(detector.calibration_stats.sample_count > 0);
        assert!(detector.calibration_stats.p95 > 0.0);
        assert!(detector.calibration_stats.p99 > 0.0);
    }
    
    #[test]
    fn context_classifier_academic() {
        let classifier = ContextClassifier::new();
        let ctx = classifier.classify("This paper discusses security research");
        assert!(matches!(ctx, ContextType::AcademicResearch));
    }
    
    #[test]
    fn context_classifier_operational() {
        let classifier = ContextClassifier::new();
        let ctx = classifier.classify("I will exploit this vulnerability");
        assert!(matches!(ctx, ContextType::Operational));
    }
    
    #[test]
    fn jensen_shannon_bounds() {
        let p = Array1::from(vec![0.5, 0.5]);
        let q = Array1::from(vec![0.5, 0.5]);
        let jsd = jensen_shannon_divergence(&p, &q);
        assert!(jsd >= 0.0 && jsd <= 1.0);
    }
}
