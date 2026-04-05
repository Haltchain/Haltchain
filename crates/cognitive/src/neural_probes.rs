//! Neural Probing & Activation Analysis
//!
//! Implements Section 2.2:
//! - Sparse Autoencoder for interpretable activation monitoring
//! - Latent space trajectory analysis
//! - Reward hacking signal detection

use ndarray::{Array1, Array2};
use std::collections::VecDeque;

/// Sparse Autoencoder for interpretable activation monitoring (Section 2.2.1)
pub struct SparseAutoencoder {
    /// Maps activation -> sparse features
    encoder: Array2<f64>,
    /// Reconstructs activation
    decoder: Array2<f64>,
    /// L1 regularization target (typically 0.05)
    sparsity_target: f64,
}

/// Feature importance for interpretability
#[derive(Debug, Clone)]
pub struct FeatureImportance {
    pub feature_idx: usize,
    pub activation: f64,
    pub description: String,
}

/// Trajectory analyzer for reasoning path monitoring
pub struct TrajectoryAnalyzer {
    /// Sliding window of activation sequences
    recent_points: VecDeque<Array1<f64>>,
    /// Maximum window size
    max_window: usize,
}

/// Curvature information at a point in trajectory
#[derive(Debug, Clone)]
pub struct CurvatureInfo {
    pub position: usize,
    pub curvature: f64,
    pub velocity: f64,
    pub acceleration: f64,
}

impl SparseAutoencoder {
    /// Create a new sparse autoencoder
    pub fn new(input_dim: usize, hidden_dim: usize, sparsity_target: f64) -> Self {
        // Initialize with random weights (in production, these would be pre-trained)
        let encoder = Array2::from_shape_fn((hidden_dim, input_dim), |(i, j)| {
            let x = (i * input_dim + j) as f64;
            (x.sin() * 0.1).abs() // Small random initialization
        });
        
        let decoder = Array2::from_shape_fn((input_dim, hidden_dim), |(i, j)| {
            let x = (i * hidden_dim + j) as f64;
            (x.cos() * 0.1).abs()
        });
        
        Self {
            encoder,
            decoder,
            sparsity_target,
        }
    }
    
    /// Compress high-dimensional activations to sparse, interpretable features
    pub fn encode(&self, activation: &Array1<f64>) -> Array1<f64> {
        let hidden = self.encoder.dot(activation);
        // Apply ReLU + approximate L1 sparsity via thresholding
        hidden.mapv(|x| if x > 0.0 { x } else { 0.0 })
    }
    
    /// Reconstruct activation from sparse features
    pub fn decode(&self, features: &Array1<f64>) -> Array1<f64> {
        self.decoder.dot(features)
    }
    
    /// Compute reconstruction error
    pub fn reconstruction_error(&self, activation: &Array1<f64>) -> f64 {
        let encoded = self.encode(activation);
        let reconstructed = self.decode(&encoded);
        
        activation.iter()
            .zip(reconstructed.iter())
            .map(|(a, r)| (a - r).powi(2))
            .sum::<f64>()
            .sqrt()
    }
    
    /// Detect reward hacking from activation patterns (Section 4.3)
    pub fn detect_reward_hacking_signals(&self, features: &Array1<f64>) -> f32 {
        // Look for specific sparse feature combinations associated with hacking
        // These indices would be learned during training
        let reward_loop_pattern: Vec<(usize, f64)> = vec![
            (12, 0.8), (47, 0.6), (103, 0.9), // Feature indices & weights
        ];
        
        let mut score = 0.0;
        for (idx, weight) in reward_loop_pattern {
            if idx < features.len() {
                score += features[idx] * weight;
            }
        }
        
        // Normalize by sparsity target
        (score / self.sparsity_target).min(1.0) as f32
    }
    
    /// Detect deception patterns in activation
    pub fn detect_deception_signals(&self, features: &Array1<f64>) -> f32 {
        // Pattern for "thinking one thing, saying another"
        let deception_pattern: Vec<(usize, f64)> = vec![
            (23, 0.7), (56, 0.8), (89, 0.6),
        ];
        
        let mut score = 0.0;
        for (idx, weight) in deception_pattern {
            if idx < features.len() {
                score += features[idx] * weight;
            }
        }
        
        (score / self.sparsity_target).min(1.0) as f32
    }
    
    /// Get top-k most active features for interpretability
    pub fn top_features(&self, features: &Array1<f64>, k: usize) -> Vec<FeatureImportance> {
        let mut indexed: Vec<(usize, f64)> = features.iter()
            .enumerate()
            .map(|(i, &v)| (i, v))
            .collect();
        
        indexed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        
        indexed.into_iter()
            .take(k)
            .map(|(idx, activation)| FeatureImportance {
                feature_idx: idx,
                activation,
                description: format!("Feature {}", idx),
            })
            .collect()
    }
    
    /// Compute sparsity (fraction of near-zero features)
    pub fn compute_sparsity(&self, features: &Array1<f64>) -> f64 {
        let threshold = 1e-4;
        let zeros = features.iter().filter(|&&x| x < threshold).count();
        zeros as f64 / features.len() as f64
    }
}

impl TrajectoryAnalyzer {
    /// Create a new trajectory analyzer
    pub fn new(max_window: usize) -> Self {
        Self {
            recent_points: VecDeque::with_capacity(max_window),
            max_window,
        }
    }
    
    /// Add a point to the trajectory
    pub fn add_point(&mut self, point: Array1<f64>) {
        if self.recent_points.len() >= self.max_window {
            self.recent_points.pop_front();
        }
        self.recent_points.push_back(point);
    }
    
    /// Calculate path curvature to detect abrupt behavioral changes (Section 2.2.2)
    pub fn calculate_curvature(&self) -> Vec<CurvatureInfo> {
        let points: Vec<_> = self.recent_points.iter().collect();
        
        if points.len() < 3 {
            return Vec::new();
        }
        
        let mut curvatures = Vec::new();
        
        for i in 1..points.len()-1 {
            let prev = points[i-1];
            let curr = points[i];
            let next = points[i+1];
            
            // Velocity vectors
            let v1 = curr - prev;
            let v2 = next - curr;
            
            // Finite difference curvature estimation
            // κ = ||v1 × v2|| / ||v1||³
            let velocity = Self::vector_norm(&v1);
            let curvature = if velocity > 1e-10 {
                let norm_v2 = Self::vector_norm(&v2);
                let angle = Self::angle_between(&v1, &v2);
                if velocity.is_nan() || norm_v2.is_nan() || angle.is_nan() {
                    0.0
                } else {
                    let cross_product = velocity * norm_v2 * angle.sin();
                    cross_product / velocity.powi(3)
                }
            } else {
                0.0
            };
            
            // Acceleration = ||v2 - v1||
            let acceleration = Self::vector_norm(&(&v2 - &v1));
            
            curvatures.push(CurvatureInfo {
                position: i,
                curvature,
                velocity,
                acceleration,
            });
        }
        
        curvatures
    }
    
    /// Detect "reasoning corners" - sudden direction changes indicating manipulation
    pub fn detect_reasoning_corners(&self, threshold: f64) -> Vec<usize> {
        self.calculate_curvature()
            .into_iter()
            .filter(|info| info.curvature > threshold)
            .map(|info| info.position)
            .collect()
    }
    
    /// Check for sudden acceleration (rapid change in reasoning)
    pub fn detect_sudden_acceleration(&self, threshold: f64) -> Vec<usize> {
        self.calculate_curvature()
            .into_iter()
            .filter(|info| info.acceleration > threshold)
            .map(|info| info.position)
            .collect()
    }
    
    /// Calculate total path length
    pub fn total_path_length(&self) -> f64 {
        let points: Vec<_> = self.recent_points.iter().collect();
        
        if points.len() < 2 {
            return 0.0;
        }
        
        let mut length = 0.0;
        for i in 1..points.len() {
            let diff = points[i] - points[i-1];
            length += Self::vector_norm(&diff);
        }
        
        length
    }
    
    /// Vector norm (L2)
    fn vector_norm(v: &Array1<f64>) -> f64 {
        v.iter().map(|x| x * x).sum::<f64>().sqrt()
    }
    
    /// Angle between two vectors
    fn angle_between(v1: &Array1<f64>, v2: &Array1<f64>) -> f64 {
        let dot = v1.dot(v2);
        let norm1 = Self::vector_norm(v1);
        let norm2 = Self::vector_norm(v2);
        
        if norm1 < 1e-10 || norm2 < 1e-10 {
            return 0.0;
        }
        
        let cos_theta = dot / (norm1 * norm2);
        cos_theta.clamp(-1.0, 1.0).acos()
    }
    
    /// Window size
    pub fn window_size(&self) -> usize {
        self.recent_points.len()
    }
    
    /// Clear trajectory
    pub fn clear(&mut self) {
        self.recent_points.clear();
    }
}

/// Probe network ensemble for comprehensive monitoring
pub struct ProbeEnsemble {
    autoencoder: SparseAutoencoder,
    trajectory: TrajectoryAnalyzer,
}

impl ProbeEnsemble {
    pub fn new(input_dim: usize, hidden_dim: usize) -> Self {
        Self {
            autoencoder: SparseAutoencoder::new(input_dim, hidden_dim, 0.05),
            trajectory: TrajectoryAnalyzer::new(100),
        }
    }
    
    /// Analyze activation through all probes
    pub fn analyze(&mut self, activation: &Array1<f64>) -> ProbeAnalysis {
        // Sparse encoding
        let features = self.autoencoder.encode(activation);
        
        // Trajectory analysis
        self.trajectory.add_point(activation.clone());
        let curvature_info = self.trajectory.calculate_curvature();
        let corners = self.trajectory.detect_reasoning_corners(0.5);
        
        // Threat signals
        let reward_hacking = self.autoencoder.detect_reward_hacking_signals(&features);
        let deception = self.autoencoder.detect_deception_signals(&features);
        let sparsity = self.autoencoder.compute_sparsity(&features);
        
        // Top features for interpretability
        let top_features = self.autoencoder.top_features(&features, 5);
        
        ProbeAnalysis {
            reward_hacking_score: reward_hacking,
            deception_score: deception,
            sparsity,
            reasoning_corners: corners.len(),
            top_features,
            curvature_info,
            trajectory_length: self.trajectory.total_path_length(),
        }
    }
}

/// Comprehensive probe analysis result
#[derive(Debug, Clone)]
pub struct ProbeAnalysis {
    pub reward_hacking_score: f32,
    pub deception_score: f32,
    pub sparsity: f64,
    pub reasoning_corners: usize,
    pub top_features: Vec<FeatureImportance>,
    pub curvature_info: Vec<CurvatureInfo>,
    pub trajectory_length: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn autoencoder_creation() {
        let sae = SparseAutoencoder::new(100, 50, 0.05);
        assert_eq!(sae.sparsity_target, 0.05);
    }
    
    #[test]
    fn encode_decode() {
        let sae = SparseAutoencoder::new(10, 5, 0.05);
        let input = Array1::from(vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]);
        
        let encoded = sae.encode(&input);
        assert_eq!(encoded.len(), 5);
        
        let decoded = sae.decode(&encoded);
        assert_eq!(decoded.len(), 10);
    }
    
    #[test]
    fn trajectory_curvature() {
        let mut analyzer = TrajectoryAnalyzer::new(10);
        
        // Add some points forming a curve
        for i in 0..10 {
            let point = Array1::from(vec![i as f64, (i as f64).sin(), 0.0]);
            analyzer.add_point(point);
        }
        
        let curvature = analyzer.calculate_curvature();
        assert!(!curvature.is_empty());
    }
    
    #[test]
    fn detect_reasoning_corners() {
        let mut analyzer = TrajectoryAnalyzer::new(10);
        
        // Add points with a sharp turn
        analyzer.add_point(Array1::from(vec![0.0, 0.0, 0.0]));
        analyzer.add_point(Array1::from(vec![1.0, 0.0, 0.0]));
        analyzer.add_point(Array1::from(vec![1.0, 1.0, 0.0])); // Sharp 90° turn
        analyzer.add_point(Array1::from(vec![1.0, 2.0, 0.0]));
        
        let corners = analyzer.detect_reasoning_corners(0.1);
        assert!(!corners.is_empty(), "Should detect the sharp turn");
    }
    
    #[test]
    fn probe_ensemble() {
        let mut ensemble = ProbeEnsemble::new(10, 5);
        let activation = Array1::from(vec![0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]);
        
        let analysis = ensemble.analyze(&activation);
        assert!(analysis.sparsity >= 0.0 && analysis.sparsity <= 1.0);
    }
}
