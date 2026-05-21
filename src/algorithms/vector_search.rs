//! Phase 1b vector search reference implementation.
//!
//! Production path is implemented in `crates/db/src/lib.rs` (`DbStore::find_similar_actions`).
//! This module documents the L2-first + cosine fallback strategy used in the DB layer.

/// Convert normalized L2 distance to cosine similarity:
/// `cos(theta) = 1 - (||a-b||^2 / 2)` for unit vectors.
#[inline]
pub fn l2_distance_to_cosine_similarity(l2: f64) -> f64 {
    1.0 - ((l2 * l2) / 2.0)
}

/// Normalize an embedding to unit length.
pub fn normalize_embedding(v: &[f32]) -> Vec<f32> {
    let norm = v
        .iter()
        .map(|x| (*x as f64) * (*x as f64))
        .sum::<f64>()
        .sqrt();
    if norm <= f64::EPSILON {
        return v.to_vec();
    }
    v.iter().map(|x| ((*x as f64) / norm) as f32).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l2_to_cosine_identity() {
        assert!((l2_distance_to_cosine_similarity(0.0) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn normalize_unit_length() {
        let n = normalize_embedding(&[3.0, 4.0]);
        let len = (n[0] as f64 * n[0] as f64 + n[1] as f64 * n[1] as f64).sqrt();
        assert!((len - 1.0).abs() < 1e-10);
    }
}
