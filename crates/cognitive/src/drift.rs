//! Zero-Shot Embedding Drift Detection (ZEDD) Core-Distance implementation.
//!
//! Section 5.1.2: "K Core-Distance normalizes for local density"
//! Section 5.1.3: "Multi-scale paraphrase detection"

/// Core distance to k-th nearest neighbor in reference distribution
/// Section 5.1.2: "Distance to k-th nearest neighbor normalizes for local density"
pub fn core_distance(query: &[f64], references: &[Vec<f64>], k: usize) -> f64 {
    if references.len() < k {
        return 1.0;
    }

    let mut distances: Vec<f64> = references
        .iter()
        .map(|ref_emb| euclidean_distance(query, ref_emb))
        .collect();
    distances.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    distances.get(k.saturating_sub(1)).copied().unwrap_or(1.0)
}

/// Euclidean distance between two vectors
fn euclidean_distance(a: &[f64], b: &[f64]) -> f64 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x - y).powi(2))
        .sum::<f64>()
        .sqrt()
}

/// Cosine similarity (for comparison with core-distance)
pub fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let norm_b: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();

    if norm_a < 1e-10 || norm_b < 1e-10 {
        0.0
    } else {
        (dot / (norm_a * norm_b)).clamp(-1.0, 1.0)
    }
}

/// Multi-scale embedding analysis
/// Section 5.1.3: "Sentence-level + phrase-level dual embedding"
pub struct MultiScaleAnalyzer {
    window_sizes: Vec<usize>, // Phrase-level windows (in words)
}

impl MultiScaleAnalyzer {
    pub fn new() -> Self {
        Self {
            window_sizes: vec![3, 5, 7, 10], // 3-gram, 5-gram, etc.
        }
    }

    /// Extract sliding windows from text
    pub fn extract_windows(&self, text: &str) -> Vec<String> {
        let words: Vec<&str> = text.split_whitespace().collect();
        let mut windows = Vec::new();

        windows.push(text.to_string());

        for sentence in text.split(|c| c == '.' || c == '!' || c == '?') {
            let trimmed = sentence.trim();
            if !trimmed.is_empty() && trimmed.len() > 10 {
                windows.push(trimmed.to_string());
            }
        }

        for window_size in &self.window_sizes {
            if words.len() >= *window_size {
                for i in 0..=(words.len() - window_size) {
                    let window = words[i..i + window_size].join(" ");
                    if window.len() > 10 {
                        windows.push(window);
                    }
                }
            }
        }

        windows
    }

    /// Detect drift at any scale
    pub fn detect_drift_multi_scale(
        &self,
        text: &str,
        embed_fn: &dyn Fn(&str) -> Vec<f64>,
        baseline_refs: &[Vec<f64>],
        k: usize,
    ) -> DriftResult {
        let windows = self.extract_windows(text);
        let mut max_drift = 0.0;
        let mut suspicious_window = None;
        let mut all_scores = Vec::new();

        for window in &windows {
            let emb = embed_fn(window);
            let core_dist = core_distance(&emb, baseline_refs, k);

            all_scores.push((window.clone(), core_dist));

            if core_dist > max_drift {
                max_drift = core_dist;
                suspicious_window = Some(window.clone());
            }
        }

        DriftResult {
            max_drift_score: max_drift,
            suspicious_window,
            window_scores: all_scores,
        }
    }
}

/// Drift detection result
#[derive(Debug, Clone)]
pub struct DriftResult {
    pub max_drift_score: f64,
    pub suspicious_window: Option<String>,
    pub window_scores: Vec<(String, f64)>,
}

/// Percentile rank within historical distribution
pub fn percentile_rank(value: f64, historical: &[f64]) -> f64 {
    if historical.is_empty() {
        return 50.0;
    }

    let count_below = historical.iter().filter(|&&x| x <= value).count();
    (count_below as f64 / historical.len() as f64) * 100.0
}

/// ZEDD-style drift score combining core-distance and percentile
pub fn zedd_drift_score(
    query: &[f64],
    baseline_refs: &[Vec<f64>],
    historical_core_dists: &[f64],
    k: usize,
) -> f64 {
    let core_dist = core_distance(query, baseline_refs, k);
    let percentile = percentile_rank(core_dist, historical_core_dists);

    // Normalize to 0-1 scale
    percentile / 100.0
}

/// Adversarial augmentation: Generate embedding perturbations
/// Section 2.2.3: "Test-time synonym graphs for paraphrase expansion"
pub fn generate_perturbations(text: &str) -> Vec<String> {
    let mut perturbed = Vec::new();

    // Original
    perturbed.push(text.to_string());

    // Simple perturbations
    let lower = text.to_lowercase();
    perturbed.push(lower.clone());

    // Common synonym replacements
    let synonyms: Vec<(&str, &str)> = vec![
        ("bypass", "circumvent"),
        ("steal", "exfiltrate"),
        ("attack", "exploit"),
        ("hack", "compromise"),
        ("break", "breach"),
    ];

    for (orig, repl) in synonyms {
        if lower.contains(orig) {
            let replaced = lower.replace(orig, repl);
            perturbed.push(replaced);
        }
    }

    perturbed
}

/// Robust similarity using ensemble of perturbations
pub fn robust_similarity(text: &str, baseline: &[f64], embed_fn: &dyn Fn(&str) -> Vec<f64>) -> f64 {
    let perturbations = generate_perturbations(text);
    let mut max_sim = 0.0;

    for pert in &perturbations {
        let emb = embed_fn(pert);
        let sim = cosine_similarity(&emb, baseline);
        if sim > max_sim {
            max_sim = sim;
        }
    }

    max_sim
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_distance() {
        let refs = vec![
            vec![1.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0],
            vec![0.0, 0.0, 1.0],
            vec![0.5, 0.5, 0.0],
        ];

        let query = vec![1.0, 0.0, 0.0];
        let dist = core_distance(&query, &refs, 2);

        // Query matches first reference exactly, so k=2 distance should be small
        assert!(dist < 1.0);
    }

    #[test]
    fn test_multi_scale_windows() {
        let analyzer = MultiScaleAnalyzer::new();
        let text = "I will bypass security and steal data from the system";
        let windows = analyzer.extract_windows(text);

        // Should have whole text, sentences, and phrase windows
        assert!(windows.len() > 3);

        // Check that "bypass security" appears in some window
        let has_bypass = windows.iter().any(|w| w.contains("bypass"));
        assert!(has_bypass);
    }

    #[test]
    fn test_percentile_rank() {
        let historical = vec![0.1, 0.2, 0.3, 0.4, 0.5];

        assert_eq!(percentile_rank(0.3, &historical), 60.0);
        assert_eq!(percentile_rank(0.0, &historical), 0.0);
        assert_eq!(percentile_rank(1.0, &historical), 100.0);
    }

    #[test]
    fn test_perturbation_generation() {
        let text = "I will bypass security";
        let perms = generate_perturbations(text);

        // Should have original, lowercase, and synonym variant
        assert!(perms.len() >= 2);

        let has_circumvent = perms.iter().any(|p| p.contains("circumvent"));
        assert!(has_circumvent);
    }
}
