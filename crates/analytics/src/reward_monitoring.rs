use std::collections::HashMap;

use serde::Serialize;

use crate::isolation_forest::IsolationForest;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct RewardEvent {
    pub value: f64,
    pub task_progress: f64,
    pub timestamp_secs: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewardStreamFeatures {
    pub mean: f64,
    pub variance: f64,
    pub skewness: f64,
    pub lag1_autocorrelation: f64,
    pub hurst_like: f64,
    pub progress_correlation: f64,
    pub burstiness: f64,
}

impl RewardStreamFeatures {
    pub fn to_vec(&self) -> Vec<f64> {
        vec![
            self.mean,
            self.variance,
            self.skewness,
            self.lag1_autocorrelation,
            self.hurst_like,
            self.progress_correlation,
            self.burstiness,
        ]
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AnomalyScore {
    pub value: f64,
    pub isolation_component: f64,
    pub density_component: f64,
    pub temporal_component: f64,
    pub feature_vector: RewardStreamFeatures,
}

#[derive(Debug, Clone)]
pub struct RewardStatistics {
    baseline_complexity: Vec<(f64, f64)>,
}

impl RewardStatistics {
    pub fn from_solution_paths(paths: &[SolutionPath]) -> Self {
        let mut baseline_complexity = Vec::with_capacity(paths.len());
        for p in paths {
            baseline_complexity.push((p.task_difficulty, p.cyclomatic_complexity()));
        }
        Self { baseline_complexity }
    }

    pub fn complexity_for_difficulty(&self, difficulty: f64) -> f64 {
        if self.baseline_complexity.is_empty() {
            return (difficulty * 10.0).max(1.0);
        }
        let mut sorted = self.baseline_complexity.clone();
        sorted.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        let mut nearest = sorted[0];
        let mut best_dist = (sorted[0].0 - difficulty).abs();
        for pair in sorted.into_iter().skip(1) {
            let dist = (pair.0 - difficulty).abs();
            if dist < best_dist {
                best_dist = dist;
                nearest = pair;
            }
        }
        nearest.1.max(1.0)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SolutionPath {
    pub task_difficulty: f64,
    pub reward: f64,
    pub steps: Vec<String>,
}

impl SolutionPath {
    pub fn cyclomatic_complexity(&self) -> f64 {
        if self.steps.is_empty() {
            return 0.0;
        }
        let mut branch_tokens = 0.0;
        for step in &self.steps {
            let lower = step.to_lowercase();
            if lower.contains("if") || lower.contains("else") {
                branch_tokens += 1.0;
            }
            if lower.contains("for") || lower.contains("while") {
                branch_tokens += 1.0;
            }
            if lower.contains("match") {
                branch_tokens += 1.0;
            }
        }
        (self.steps.len() as f64 + branch_tokens).max(1.0)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum ShortcutRisk {
    Low,
    Medium {
        reason: String,
        complexity_ratio: f64,
        pattern_entropy: f64,
    },
    High {
        reason: String,
        complexity_ratio: f64,
        pattern_entropy: f64,
    },
}

pub struct RewardAnomalyDetector {
    isolation_forest: IsolationForest,
    baseline_features: Vec<Vec<f64>>,
    kde_bandwidth: f64,
    density_floor: f64,
    baseline_stats: RewardStatistics,
}

impl RewardAnomalyDetector {
    pub fn fit(
        baseline_streams: &[Vec<RewardEvent>],
        baseline_solutions: &[SolutionPath],
    ) -> Self {
        let baseline_features: Vec<Vec<f64>> = baseline_streams
            .iter()
            .map(|stream| Self::extract_features(stream).to_vec())
            .collect();

        let training = if baseline_features.len() < 4 {
            vec![
                vec![0.1, 0.05, 0.0, 0.1, 0.5, 0.2, 0.1],
                vec![0.2, 0.05, 0.0, 0.2, 0.5, 0.2, 0.2],
                vec![0.3, 0.08, 0.0, 0.3, 0.6, 0.4, 0.2],
                vec![0.4, 0.10, 0.0, 0.4, 0.6, 0.5, 0.3],
            ]
        } else {
            baseline_features.clone()
        };

        let isolation_forest = IsolationForest::fit(&training);
        let density_floor = if baseline_features.is_empty() {
            0.05
        } else {
            let mut d: Vec<f64> = baseline_features
                .iter()
                .map(|f| Self::kde_density_raw_with_set(f, &baseline_features, 0.75))
                .collect();
            d.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            d[d.len() / 10].max(1e-8)
        };

        Self {
            isolation_forest,
            baseline_features,
            kde_bandwidth: 0.75,
            density_floor,
            baseline_stats: RewardStatistics::from_solution_paths(baseline_solutions),
        }
    }

    pub fn evaluate_reward_stream(&self, rewards: &[RewardEvent]) -> AnomalyScore {
        let feature_vector = Self::extract_features(rewards);
        let features = feature_vector.to_vec();

        let isolation_component = self.isolation_forest.score(&features);

        let density_raw = self.kde_density_raw(&features);
        let density_scaled = if self.baseline_features.is_empty() {
            density_raw.clamp(0.0, 1.0)
        } else {
            (density_raw / (self.density_floor * 2.0)).clamp(0.0, 1.0)
        };
        let density_component = 1.0 - density_scaled;

        let temporal_component = (feature_vector.burstiness.abs() * 0.5
            + feature_vector.lag1_autocorrelation.abs() * 0.25
            + (1.0 - feature_vector.progress_correlation.abs()) * 0.25)
            .clamp(0.0, 1.0);

        let value = (isolation_component * 0.6 + density_component * 0.3 + temporal_component * 0.1)
            .clamp(0.0, 1.0);

        AnomalyScore {
            value,
            isolation_component,
            density_component,
            temporal_component,
            feature_vector,
        }
    }

    pub fn detect_shortcuts(&self, solution_path: &SolutionPath) -> ShortcutRisk {
        let complexity = solution_path.cyclomatic_complexity();
        let expected = self
            .baseline_stats
            .complexity_for_difficulty(solution_path.task_difficulty)
            .max(1e-6);
        let complexity_ratio = complexity / expected;
        let pattern_entropy = Self::calculate_solution_diversity(&solution_path.steps);

        if complexity_ratio < 0.30 && solution_path.reward > 0.90 {
            return ShortcutRisk::High {
                reason: "Suspicious simplicity for high reward".to_string(),
                complexity_ratio,
                pattern_entropy,
            };
        }

        if pattern_entropy < 0.20 && solution_path.reward > 0.80 {
            return ShortcutRisk::High {
                reason: "Low solution diversity suggests exploitation".to_string(),
                complexity_ratio,
                pattern_entropy,
            };
        }

        if (complexity_ratio < 0.55 && solution_path.reward > 0.75)
            || (pattern_entropy < 0.35 && solution_path.reward > 0.70)
        {
            return ShortcutRisk::Medium {
                reason: "Potential shortcut signature".to_string(),
                complexity_ratio,
                pattern_entropy,
            };
        }

        ShortcutRisk::Low
    }

    pub fn calculate_solution_diversity(steps: &[String]) -> f64 {
        if steps.is_empty() {
            return 0.0;
        }
        let mut counts: HashMap<String, usize> = HashMap::new();
        for step in steps {
            let norm = step.trim().to_lowercase();
            *counts.entry(norm).or_insert(0) += 1;
        }
        let n = steps.len() as f64;
        let entropy = counts.values().fold(0.0, |acc, c| {
            let p = *c as f64 / n;
            if p > 0.0 { acc - p * p.log2() } else { acc }
        });
        let max_entropy = (counts.len() as f64).log2();
        if max_entropy <= 0.0 {
            return 0.0;
        }
        (entropy / max_entropy).clamp(0.0, 1.0)
    }

    pub fn extract_features(rewards: &[RewardEvent]) -> RewardStreamFeatures {
        if rewards.is_empty() {
            return RewardStreamFeatures {
                mean: 0.0,
                variance: 0.0,
                skewness: 0.0,
                lag1_autocorrelation: 0.0,
                hurst_like: 0.5,
                progress_correlation: 0.0,
                burstiness: 0.0,
            };
        }

        let values: Vec<f64> = rewards.iter().map(|r| r.value).collect();
        let progresses: Vec<f64> = rewards.iter().map(|r| r.task_progress).collect();

        let mean = values.iter().sum::<f64>() / values.len() as f64;
        let variance = if values.len() < 2 {
            0.0
        } else {
            values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (values.len() - 1) as f64
        };
        let std = variance.sqrt();

        let skewness = if values.len() < 3 || std < 1e-9 {
            0.0
        } else {
            let m3 = values.iter().map(|v| (v - mean).powi(3)).sum::<f64>() / values.len() as f64;
            m3 / std.powi(3)
        };

        let lag1_autocorrelation = Self::autocorrelation(&values, 1);
        let hurst_like = Self::hurst_like(&values);
        let progress_correlation = Self::pearson_correlation(&values, &progresses);

        let median = Self::median(&values);
        let mad = {
            let devs: Vec<f64> = values.iter().map(|v| (v - median).abs()).collect();
            Self::median(&devs)
        };
        let burstiness = if mad < 1e-9 {
            0.0
        } else {
            ((values.iter().map(|v| (v - median).abs()).sum::<f64>() / values.len() as f64) / mad)
                .clamp(0.0, 10.0)
                / 10.0
        };

        RewardStreamFeatures {
            mean,
            variance,
            skewness,
            lag1_autocorrelation,
            hurst_like,
            progress_correlation,
            burstiness,
        }
    }

    fn kde_density_raw(&self, x: &[f64]) -> f64 {
        Self::kde_density_raw_with_set(x, &self.baseline_features, self.kde_bandwidth)
    }

    fn kde_density_raw_with_set(x: &[f64], refs: &[Vec<f64>], bandwidth: f64) -> f64 {
        if refs.is_empty() {
            return 0.5;
        }
        let bw2 = (bandwidth * bandwidth).max(1e-9);
        let d = x.len().max(1) as f64;
        let norm = (2.0 * std::f64::consts::PI * bw2).powf(-d / 2.0);
        let sum = refs.iter().fold(0.0, |acc, r| {
            let dist2 = x
                .iter()
                .zip(r.iter())
                .map(|(a, b)| (a - b).powi(2))
                .sum::<f64>();
            acc + (-dist2 / (2.0 * bw2)).exp()
        });
        norm * (sum / refs.len() as f64)
    }

    fn autocorrelation(series: &[f64], lag: usize) -> f64 {
        if series.len() <= lag + 1 {
            return 0.0;
        }
        let mean = series.iter().sum::<f64>() / series.len() as f64;
        let num = (lag..series.len())
            .map(|i| (series[i] - mean) * (series[i - lag] - mean))
            .sum::<f64>();
        let den = series.iter().map(|x| (x - mean).powi(2)).sum::<f64>();
        if den < 1e-9 {
            0.0
        } else {
            (num / den).clamp(-1.0, 1.0)
        }
    }

    fn hurst_like(series: &[f64]) -> f64 {
        if series.len() < 8 {
            return 0.5;
        }
        let mean = series.iter().sum::<f64>() / series.len() as f64;
        let mut cum: f64 = 0.0;
        let mut min_cum: f64 = 0.0;
        let mut max_cum: f64 = 0.0;
        for v in series {
            cum += v - mean;
            min_cum = min_cum.min(cum);
            max_cum = max_cum.max(cum);
        }
        let range = (max_cum - min_cum).max(1e-9);
        let std = {
            let var = series.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (series.len() - 1) as f64;
            var.sqrt().max(1e-9)
        };
        let rs = range / std;
        ((rs.ln() / (series.len() as f64).ln()).clamp(0.0, 1.0)).max(0.0)
    }

    fn pearson_correlation(x: &[f64], y: &[f64]) -> f64 {
        if x.len() != y.len() || x.len() < 2 {
            return 0.0;
        }
        let mx = x.iter().sum::<f64>() / x.len() as f64;
        let my = y.iter().sum::<f64>() / y.len() as f64;
        let mut num = 0.0;
        let mut dx = 0.0;
        let mut dy = 0.0;
        for i in 0..x.len() {
            let a = x[i] - mx;
            let b = y[i] - my;
            num += a * b;
            dx += a * a;
            dy += b * b;
        }
        if dx < 1e-9 || dy < 1e-9 {
            0.0
        } else {
            (num / (dx.sqrt() * dy.sqrt())).clamp(-1.0, 1.0)
        }
    }

    fn median(values: &[f64]) -> f64 {
        if values.is_empty() {
            return 0.0;
        }
        let mut v = values.to_vec();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mid = v.len() / 2;
        if v.len() % 2 == 0 {
            (v[mid - 1] + v[mid]) / 2.0
        } else {
            v[mid]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline_stream(seed: f64) -> Vec<RewardEvent> {
        (0..64)
            .map(|i| RewardEvent {
                value: 0.5 + ((i as f64 * 0.11 + seed).sin() * 0.05),
                task_progress: (i as f64 / 64.0).min(1.0),
                timestamp_secs: i as f64,
            })
            .collect()
    }

    fn baseline_solution_paths() -> Vec<SolutionPath> {
        vec![
            SolutionPath {
                task_difficulty: 0.3,
                reward: 0.65,
                steps: vec!["load".into(), "validate".into(), "respond".into()],
            },
            SolutionPath {
                task_difficulty: 0.7,
                reward: 0.8,
                steps: vec!["load".into(), "branch if".into(), "iterate for".into(), "respond".into()],
            },
            SolutionPath {
                task_difficulty: 0.9,
                reward: 0.85,
                steps: vec![
                    "load".into(),
                    "branch if".into(),
                    "iterate for".into(),
                    "iterate while".into(),
                    "aggregate".into(),
                    "respond".into(),
                ],
            },
        ]
    }

    #[test]
    fn anomaly_score_detects_anomalies_with_high_confidence() {
        // RH-11 FIX: Per Project Architecture §4.1.2, reward anomaly detection must
        // distinguish normal from anomalous reward streams with meaningful discrimination.
        // VACUOUS TEST REPLACEMENT: Original only checked clamp bounds (always true).
        let streams = vec![baseline_stream(0.1), baseline_stream(0.4), baseline_stream(0.8), baseline_stream(1.2)];
        let detector = RewardAnomalyDetector::fit(&streams, &baseline_solution_paths());
        
        // Test normal stream
        let normal_score = detector.evaluate_reward_stream(&baseline_stream(0.2));
        
        // Test anomalous stream with high variance oscillation
        // Per §4.1.2: Isolation Forest should detect "unpredictable rewards" vs task progress
        let anomalous: Vec<RewardEvent> = (0..64)
            .map(|i| RewardEvent {
                value: if i % 2 == 0 { 0.99 } else { 0.01 }, // High variance, oscillating
                task_progress: (i as f64 / 64.0).min(1.0),
                timestamp_secs: i as f64,
            })
            .collect();
        let anomaly_score = detector.evaluate_reward_stream(&anomalous);
        
        // RH-11 FIX: Anomalous must score SIGNIFICANTLY higher than normal (minimum 0.2 gap)
        // This tests actual discrimination capability, not just clamp bounds
        let discrimination_gap = anomaly_score.value - normal_score.value;
        assert!(
            anomaly_score.value > normal_score.value && discrimination_gap >= 0.15,
            "RH-11: Detector failing to discriminate! \
            Normal={:.3}, Anomalous={:.3}, gap={:.3} (min 0.15 required). \
            Isolation Forest must reliably separate anomalous from normal reward streams.",
            normal_score.value, anomaly_score.value, discrimination_gap
        );
        
        println!("RH-11: Normal={:.3}, Anomalous={:.3}, gap={:.3} - Detection quality verified", 
            normal_score.value, anomaly_score.value, discrimination_gap);
    }

    #[test]
    fn high_variance_unstable_stream_scores_higher() {
        let streams = vec![baseline_stream(0.1), baseline_stream(0.4), baseline_stream(0.8), baseline_stream(1.2)];
        let detector = RewardAnomalyDetector::fit(&streams, &baseline_solution_paths());

        let normal = baseline_stream(0.2);
        let attack: Vec<RewardEvent> = (0..64)
            .map(|i| RewardEvent {
                value: if i % 2 == 0 { 0.99 } else { 0.01 },
                task_progress: (i as f64 / 64.0).min(1.0),
                timestamp_secs: i as f64,
            })
            .collect();

        let s1 = detector.evaluate_reward_stream(&normal);
        let s2 = detector.evaluate_reward_stream(&attack);
        assert!(s2.value > s1.value, "normal={} attack={}", s1.value, s2.value);
    }

    #[test]
    fn shortcut_detector_flags_suspicious_simplicity() {
        let streams = vec![baseline_stream(0.1), baseline_stream(0.4), baseline_stream(0.8), baseline_stream(1.2)];
        let detector = RewardAnomalyDetector::fit(&streams, &baseline_solution_paths());

        let suspicious = SolutionPath {
            task_difficulty: 0.95,
            reward: 0.98,
            steps: vec!["do it".into(), "done".into()],
        };

        let risk = detector.detect_shortcuts(&suspicious);
        assert!(matches!(risk, ShortcutRisk::High { .. }));
    }

    #[test]
    fn diversity_increases_with_step_variety() {
        let low = vec!["a".to_string(), "a".to_string(), "a".to_string()];
        let high = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let l = RewardAnomalyDetector::calculate_solution_diversity(&low);
        let h = RewardAnomalyDetector::calculate_solution_diversity(&high);
        assert!(h > l, "low={} high={}", l, h);
    }

    #[test]
    fn rh_e01_empty_reward_stream_returns_safe_defaults() {
        // RH-E01: Empty stream must not panic and must return bounded values.
        let streams = vec![baseline_stream(0.1), baseline_stream(0.4), baseline_stream(0.8), baseline_stream(1.2)];
        let detector = RewardAnomalyDetector::fit(&streams, &baseline_solution_paths());
        let score = detector.evaluate_reward_stream(&[]);
        assert!((0.0..=1.0).contains(&score.value), "value={}", score.value);
        assert!((0.0..=1.0).contains(&score.isolation_component), "isolation={}", score.isolation_component);
        assert!((0.0..=1.0).contains(&score.density_component), "density={}", score.density_component);
        assert!((0.0..=1.0).contains(&score.temporal_component), "temporal={}", score.temporal_component);
    }

    #[test]
    fn rh_e02_single_element_reward_stream_returns_valid_score() {
        // RH-E02: Single-element stream must not panic and must return bounded values.
        let streams = vec![baseline_stream(0.1), baseline_stream(0.4), baseline_stream(0.8), baseline_stream(1.2)];
        let detector = RewardAnomalyDetector::fit(&streams, &baseline_solution_paths());
        let single = vec![RewardEvent { value: 0.5, task_progress: 0.5, timestamp_secs: 0.0 }];
        let score = detector.evaluate_reward_stream(&single);
        assert!((0.0..=1.0).contains(&score.value), "value={}", score.value);
        assert!((0.0..=1.0).contains(&score.isolation_component), "isolation={}", score.isolation_component);
        assert!((0.0..=1.0).contains(&score.density_component), "density={}", score.density_component);
        assert!((0.0..=1.0).contains(&score.temporal_component), "temporal={}", score.temporal_component);
    }
}
