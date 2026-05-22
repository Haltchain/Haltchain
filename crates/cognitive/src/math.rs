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

    let m: Vec<f64> = p
        .iter()
        .zip(q.iter())
        .map(|(pi, qi)| (pi + qi) / 2.0)
        .collect();
    let kl_p = kl_divergence(p, &m);
    let kl_q = kl_divergence(q, &m);
    (kl_p + kl_q) / 2.0
}

/// Kullback-Leibler Divergence
///
/// Measures how one probability distribution diverges from a second,
/// expected probability distribution. Not symmetric.
pub fn kl_divergence(p: &[f64], q: &[f64]) -> f64 {
    p.iter()
        .zip(q.iter())
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
    a.iter()
        .zip(b.iter())
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

/// Squared Euclidean distance — avoids the `sqrt` when only ordering matters.
#[inline(always)]
pub fn squared_euclidean(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b.iter()).map(|(x, y)| (x - y) * (x - y)).sum()
}

// ─── AVX-512 accelerated squared Euclidean distance ──────────────────────────
//
// Safety contract
// ───────────────
// * `a` and `b` must have identical lengths (checked by debug_assert_eq!).
// * The unsafe block uses only unaligned SIMD loads over slices whose
//   bounds are enforced by the loop structure.
// * Tailing elements (len % 8 != 0) are handled by the scalar remainder loop.

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
#[allow(unsafe_code)]
unsafe fn squared_euclidean_avx512(a: &[f64], b: &[f64]) -> f64 {
    use std::arch::x86_64::*;

    debug_assert_eq!(a.len(), b.len());

    let len = a.len();
    let chunks = len / 8; // 512-bit register holds 8 × f64
    let remainder = len % 8;

    let mut acc = _mm512_setzero_pd();

    for i in 0..chunks {
        let offset = i * 8;
        // SAFETY: offset..offset+8 is within slice bounds because i < chunks.
        let va = _mm512_loadu_pd(a.as_ptr().add(offset));
        let vb = _mm512_loadu_pd(b.as_ptr().add(offset));
        let diff = _mm512_sub_pd(va, vb);
        acc = _mm512_fmadd_pd(diff, diff, acc);
    }

    let mut result = _mm512_reduce_add_pd(acc);

    for i in (len - remainder)..len {
        let d = a[i] - b[i];
        result += d * d;
    }

    result
}

/// Compute squared Euclidean distance, using AVX-512F SIMD when available.
///
/// Dispatches to the AVX-512 implementation at runtime when `avx512f` is
/// detected; falls back to scalar otherwise.
///
/// # Performance
///
/// Processes 8 × f64 per cycle on AVX-512 hardware vs. 1 × f64 scalar,
/// yielding ~8× throughput for 1024-dim embeddings.
#[inline]
pub fn squared_euclidean_fast(a: &[f64], b: &[f64]) -> f64 {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx512f") {
            // SAFETY: feature detection above guarantees AVX-512F is available.
            return unsafe { squared_euclidean_avx512(a, b) };
        }
    }
    squared_euclidean(a, b)
}

/// K-Core distance: distance to the *k*-th nearest neighbour in `refs`.
///
/// Core primitive of the ZEDD anomaly detector (Section 5.1.2).
/// Uses [`squared_euclidean_fast`] to benefit from AVX-512 automatically.
///
/// Returns `f64::MAX` when `refs` is empty.
pub fn k_core_distance(query: &[f64], refs: &[&[f64]], k: usize) -> f64 {
    if refs.is_empty() {
        return f64::MAX;
    }
    let k = k.min(refs.len());
    let mut sq_dists: Vec<f64> = refs
        .iter()
        .map(|r| squared_euclidean_fast(query, r))
        .collect();
    // Partial O(n) sort via select_nth_unstable.
    sq_dists.select_nth_unstable_by(k - 1, |a, b| a.partial_cmp(b).unwrap());
    sq_dists[k - 1].sqrt()
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

    // ─── AVX-512 / K-Core tests ──────────────────────────────────────────

    #[test]
    fn squared_euclidean_known_value() {
        let a = vec![0.0, 0.0, 0.0];
        let b = vec![1.0, 2.0, 2.0];
        // ||a - b||² = 1 + 4 + 4 = 9
        assert!((super::squared_euclidean(&a, &b) - 9.0).abs() < 1e-10);
    }

    #[test]
    fn squared_euclidean_fast_matches_scalar() {
        // Regardless of AVX-512 availability the fast path should return the
        // same value as the scalar path.
        let a: Vec<f64> = (0..32).map(|i| i as f64 * 0.1).collect();
        let b: Vec<f64> = (0..32).map(|i| i as f64 * 0.2).collect();
        let scalar = super::squared_euclidean(&a, &b);
        let fast = super::squared_euclidean_fast(&a, &b);
        assert!((scalar - fast).abs() < 1e-6, "scalar={scalar}, fast={fast}");
    }

    #[test]
    fn k_core_distance_k1_is_nearest_neighbour() {
        let query = vec![0.0, 0.0];
        let r1 = vec![1.0, 0.0]; // dist = 1.0
        let r2 = vec![3.0, 4.0]; // dist = 5.0
        let refs: Vec<&[f64]> = vec![r1.as_slice(), r2.as_slice()];
        let d = super::k_core_distance(&query, &refs, 1);
        assert!(
            (d - 1.0).abs() < 1e-10,
            "k=1 distance should be 1.0, got {d}"
        );
    }

    #[test]
    fn k_core_distance_k2_is_second_nearest() {
        let query = vec![0.0, 0.0];
        let r1 = vec![1.0, 0.0]; // dist = 1.0
        let r2 = vec![3.0, 4.0]; // dist = 5.0
        let refs: Vec<&[f64]> = vec![r1.as_slice(), r2.as_slice()];
        let d = super::k_core_distance(&query, &refs, 2);
        assert!(
            (d - 5.0).abs() < 1e-10,
            "k=2 distance should be 5.0, got {d}"
        );
    }

    #[test]
    fn k_core_distance_empty_refs_returns_max() {
        let query = vec![1.0, 2.0];
        let refs: Vec<&[f64]> = vec![];
        assert_eq!(super::k_core_distance(&query, &refs, 1), f64::MAX);
    }

    #[test]
    fn k_core_distance_k_clamped_to_refs_len() {
        let query = vec![0.0, 0.0];
        let r1 = vec![1.0, 0.0];
        let refs: Vec<&[f64]> = vec![r1.as_slice()];
        // k=100 but only 1 ref → should not panic, returns distance to r1
        let d = super::k_core_distance(&query, &refs, 100);
        assert!((d - 1.0).abs() < 1e-10);
    }
}
