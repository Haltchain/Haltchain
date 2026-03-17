//! Shared mathematical utilities for cognitive detection
//!
//! Centralizes common operations like divergence calculations and similarity
//! metrics to avoid duplication across modules.

/// Jensen-Shannon Divergence (Section 2.1.2)
/// 
/// A symmetric and smoothed version of KL divergence, bounded between 0 and 1.
/// Used for measuring divergence between reasoning trace and output embeddings.
pub fn jensen_shannon_divergence(p: &[f64], q: &[f64]) -> f64 {
    if p.is_empty() || q.is_empty() || p.len() != q.len() {
        return 0.0;
    }
    
    let m: Vec<f64> = p.iter().zip(q.iter()).map(|(pi, qi)| (pi + qi) / 2.0).collect();
    let kl_p = kl_divergence(p, &m);
    let kl_q = kl_divergence(q, &m);
    (kl_p + kl_q) / 2.0
}

/// Kullback-Leibler Divergence
/// 
/// Measures how one probability distribution diverges from a second,
/// expected probability distribution. Not symmetric.
pub fn kl_divergence(p: &[f64], q: &[f64]) -> f64 {
    p.iter().zip(q.iter())
        .map(|(pi, qi)| {
            if *pi > 1e-10 && *qi > 1e-10 {
                pi * (pi / qi).ln()
            } else {
                0.0
            }
        })
        .sum()
}

/// L2 normalize a vector in-place
/// 
/// Divides each element by the Euclidean norm of the vector.
/// If the norm is near zero, the vector is left unchanged.
pub fn l2_normalize(v: &mut [f64]) {
    let norm: f64 = v.iter().map(|x| x * x).sum::<f64>().sqrt();
    if norm > 1e-10 {
        for x in v.iter_mut() {
            *x /= norm;
        }
    }
}

/// Euclidean distance between two vectors
pub fn euclidean_distance(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b.iter())
        .map(|(x, y)| (x - y).powi(2))
        .sum::<f64>()
        .sqrt()
}

/// Cosine similarity with proper normalization
/// 
/// Computes the cosine of the angle between two vectors.
/// Returns values in [-1, 1], where 1 means identical direction.
pub fn cosine_similarity_normalized(a: &[f64], b: &[f64]) -> f64 {
    if a.is_empty() || b.is_empty() || a.len() != b.len() {
        return 0.0;
    }
    
    let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let norm_b: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();
    
    if norm_a < 1e-10 || norm_b < 1e-10 {
        return 0.0;
    }
    
    (dot / (norm_a * norm_b)).clamp(-1.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_l2_normalize() {
        let mut v = vec![3.0, 4.0];
        l2_normalize(&mut v);
        // 3-4-5 triangle: norm should be 5, so normalized is [0.6, 0.8]
        assert!((v[0] - 0.6).abs() < 1e-10);
        assert!((v[1] - 0.8).abs() < 1e-10);
    }

    #[test]
    fn test_euclidean_distance() {
        let a = vec![0.0, 0.0];
        let b = vec![3.0, 4.0];
        assert!((euclidean_distance(&a, &b) - 5.0).abs() < 1e-10);
    }

    #[test]
    fn test_cosine_similarity_normalized() {
        // Identical vectors should have similarity 1.0
        let a = vec![1.0, 0.0, 0.0];
        assert!((cosine_similarity_normalized(&a, &a) - 1.0).abs() < 1e-10);
        
        // Orthogonal vectors should have similarity 0.0
        let b = vec![0.0, 1.0, 0.0];
        assert!(cosine_similarity_normalized(&a, &b).abs() < 1e-10);
        
        // Opposite vectors should have similarity -1.0
        let c = vec![-1.0, 0.0, 0.0];
        assert!((cosine_similarity_normalized(&a, &c) + 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_jensen_shannon_bounds() {
        // JSD is bounded [0, 1]
        let p = vec![0.5, 0.5];
        let q = vec![0.5, 0.5];
        let jsd_same = jensen_shannon_divergence(&p, &q);
        assert!(jsd_same >= 0.0 && jsd_same <= 1.0);
        
        let r = vec![0.9, 0.1];
        let jsd_diff = jensen_shannon_divergence(&p, &r);
        assert!(jsd_diff >= 0.0 && jsd_diff <= 1.0);
        // Different distributions should have higher JSD
        assert!(jsd_diff > jsd_same);
    }
}
