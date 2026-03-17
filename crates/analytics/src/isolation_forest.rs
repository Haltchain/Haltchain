//! Wednesday: Isolation Forest — multivariate anomaly detection.
//!
//! Lightweight pure-Rust implementation; no BLAS dependency.
//! Works on the fixed-length FeatureVector from the features module.
//!
//! Reference: Liu, Fei Tony, et al. "Isolation Forest." ICDM 2008.

use std::fmt;

use serde::Serialize;

// Hyper-params

/// Number of trees in the forest.
const N_TREES: usize = 100;
/// Sub-sample size per tree.
const SUBSAMPLE: usize = 256;
/// Anomaly score threshold: scores > this are flagged.
pub const ANOMALY_THRESHOLD: f64 = 0.60;

// ─── Tree node ────────────────────────────────────────────────────────────────

enum Node {
    Internal {
        feature: usize,
        split_value: f64,
        left: Box<Node>,
        right: Box<Node>,
    },
    Leaf {
        size: usize,
    },
}

// ─── Tree builder ─────────────────────────────────────────────────────────────

fn average_path_length(n: usize) -> f64 {
    match n {
        0 | 1 => 0.0,
        2 => 1.0,
        _ => {
            let n = n as f64;
            2.0 * (n - 1.0).ln() + std::f64::consts::EULER_GAMMA - 2.0 * (n - 1.0) / n
        }
    }
}

/// Minimal deterministic PRNG (xorshift64) — no `rand` dep needed.
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn next_usize_below(&mut self, n: usize) -> usize {
        (self.next_u64() as usize) % n
    }
}

fn build_tree(data: &[Vec<f64>], depth: usize, limit: usize, rng: &mut Rng) -> Node {
    let n = data.len();
    if n <= 1 || depth >= limit {
        return Node::Leaf { size: n };
    }
    let n_features = data[0].len();
    let feature = rng.next_usize_below(n_features);

    let min = data
        .iter()
        .map(|r| r[feature])
        .fold(f64::INFINITY, f64::min);
    let max = data
        .iter()
        .map(|r| r[feature])
        .fold(f64::NEG_INFINITY, f64::max);

    if (max - min).abs() < 1e-12 {
        return Node::Leaf { size: n };
    }

    let split = min + rng.next_f64() * (max - min);
    let left_data: Vec<Vec<f64>> = data
        .iter()
        .filter(|r| r[feature] < split)
        .cloned()
        .collect();
    let right_data: Vec<Vec<f64>> = data
        .iter()
        .filter(|r| r[feature] >= split)
        .cloned()
        .collect();

    Node::Internal {
        feature,
        split_value: split,
        left: Box::new(build_tree(&left_data, depth + 1, limit, rng)),
        right: Box::new(build_tree(&right_data, depth + 1, limit, rng)),
    }
}

fn path_length(node: &Node, point: &[f64], current_depth: usize) -> f64 {
    match node {
        Node::Leaf { size } => current_depth as f64 + average_path_length(*size),
        Node::Internal {
            feature,
            split_value,
            left,
            right,
        } => {
            if point[*feature] < *split_value {
                path_length(left, point, current_depth + 1)
            } else {
                path_length(right, point, current_depth + 1)
            }
        }
    }
}

// ─── Forest ──────────────────────────────────────────────────────────────────

pub struct IsolationForest {
    trees: Vec<Node>,
    #[allow(dead_code)]
    tree_limit: usize,
    subsample_len: usize,
}

impl fmt::Debug for IsolationForest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IsolationForest {{ trees: {}, subsample: {} }}",
            self.trees.len(),
            self.subsample_len
        )
    }
}

impl IsolationForest {
    /// Train the forest on `data` (rows = samples, cols = features).
    pub fn fit(data: &[Vec<f64>]) -> Self {
        let subsample_len = SUBSAMPLE.min(data.len());
        let tree_limit = (subsample_len as f64).log2().ceil() as usize;
        let mut trees = Vec::with_capacity(N_TREES);

        for i in 0..N_TREES {
            let mut rng = Rng::new((i as u64).wrapping_add(1).wrapping_mul(6364136223846793005));
            let sample: Vec<Vec<f64>> = (0..subsample_len)
                .map(|_| data[rng.next_usize_below(data.len())].clone())
                .collect();
            trees.push(build_tree(&sample, 0, tree_limit, &mut rng));
        }

        Self {
            trees,
            tree_limit,
            subsample_len,
        }
    }

    /// Returns anomaly score in [0, 1].  Scores near 1 indicate anomalies.
    pub fn score(&self, point: &[f64]) -> f64 {
        let avg_path: f64 = self
            .trees
            .iter()
            .map(|t| path_length(t, point, 0))
            .sum::<f64>()
            / N_TREES as f64;

        let c = average_path_length(self.subsample_len);
        if c < 1e-12 {
            return 0.5;
        }
        2f64.powf(-avg_path / c)
    }

    /// `true` when the point's anomaly score exceeds [`ANOMALY_THRESHOLD`].
    pub fn is_anomaly(&self, point: &[f64]) -> bool {
        self.score(point) > ANOMALY_THRESHOLD
    }
}

/// Convenience result type surfaced back to the validator.
#[derive(Debug, Clone, Serialize)]
pub struct AnomalyResult {
    pub is_anomaly: bool,
    pub score: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_normal_data(n: usize) -> Vec<Vec<f64>> {
        let mut rng = Rng::new(42);
        (0..n)
            .map(|_| vec![rng.next_f64() * 10.0, rng.next_f64() * 10.0])
            .collect()
    }

    #[test]
    fn inlier_score_below_threshold() {
        let data = make_normal_data(300);
        let forest = IsolationForest::fit(&data);
        // A point smack in the middle of the distribution should not be anomalous.
        let score = forest.score(&[5.0, 5.0]);
        assert!(score < ANOMALY_THRESHOLD, "inlier score={score:.3}");
    }

    #[test]
    fn outlier_score_above_threshold() {
        let data = make_normal_data(300);
        let forest = IsolationForest::fit(&data);
        // Way outside the [0, 10] range.
        let score = forest.score(&[999.0, 999.0]);
        assert!(score > ANOMALY_THRESHOLD, "outlier score={score:.3}");
    }

    #[test]
    fn average_path_length_monotone() {
        // Should increase with n.
        let (a, b) = (average_path_length(10), average_path_length(100));
        assert!(b > a);
    }
}
