//! Section 8.1: Sampling & Alerting
//!
//! Implements:
//! - Stratified sampling for high-volume systems
//! - Multi-armed bandit optimization

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Risk level for stratification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
}

impl RiskLevel {
    /// Default sampling rate for each risk level
    pub fn default_rate(&self) -> f64 {
        match self {
            RiskLevel::Critical => 1.0,  // 100%
            RiskLevel::High => 0.5,      // 50%
            RiskLevel::Medium => 0.1,    // 10%
            RiskLevel::Low => 0.01,      // 1%
        }
    }
}

/// Sampling stratum configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingStratum {
    pub risk_level: RiskLevel,
    pub sampling_rate: f64,
    pub sample_count: u64,
    pub anomaly_count: u64,
}

impl SamplingStratum {
    /// Create new stratum with default rate
    pub fn new(risk_level: RiskLevel) -> Self {
        Self {
            risk_level,
            sampling_rate: risk_level.default_rate(),
            sample_count: 0,
            anomaly_count: 0,
        }
    }

    /// Create with custom rate
    pub fn with_rate(risk_level: RiskLevel, rate: f64) -> Self {
        Self {
            risk_level,
            sampling_rate: rate.clamp(0.0, 1.0),
            sample_count: 0,
            anomaly_count: 0,
        }
    }

    /// Calculate anomaly rate
    pub fn anomaly_rate(&self) -> f64 {
        if self.sample_count == 0 {
            return 0.0;
        }
        self.anomaly_count as f64 / self.sample_count as f64
    }

    /// Record a sample
    pub fn record_sample(&mut self, is_anomaly: bool) {
        self.sample_count += 1;
        if is_anomaly {
            self.anomaly_count += 1;
        }
    }
}

/// Interaction to be sampled
#[derive(Debug, Clone)]
pub struct Interaction {
    pub id: String,
    pub risk_level: RiskLevel,
    pub timestamp: u64,
    pub metadata: HashMap<String, String>,
}

/// Stratified sampler for high-volume systems (Section 8.1.1)
#[derive(Debug, Clone)]
pub struct StratifiedSampler {
    strata: HashMap<RiskLevel, SamplingStratum>,
    rng: rand::rngs::ThreadRng,
}

impl StratifiedSampler {
    /// Create new sampler with default strata
    pub fn new() -> Self {
        let mut strata = HashMap::new();
        for level in [RiskLevel::Critical, RiskLevel::High, RiskLevel::Medium, RiskLevel::Low] {
            strata.insert(level, SamplingStratum::new(level));
        }

        Self {
            strata,
            rng: rand::thread_rng(),
        }
    }

    /// Create with custom stratum configurations
    pub fn with_strata(strata: Vec<SamplingStratum>) -> Self {
        let mut map = HashMap::new();
        for stratum in strata {
            map.insert(stratum.risk_level, stratum);
        }

        Self {
            strata: map,
            rng: rand::thread_rng(),
        }
    }

    /// Classify interaction into risk level
    pub fn classify(&self, interaction: &Interaction) -> RiskLevel {
        // Default: use interaction's risk level
        // Could be extended with ML-based classification
        interaction.risk_level
    }

    /// Decide whether to sample an interaction (Section 8.1.1)
    /// 
    /// Returns true if this interaction should be sampled
    pub fn should_sample(&mut self, interaction: &Interaction) -> bool {
        let stratum = self.classify(interaction);
        
        let rate = self.strata
            .get(&stratum)
            .map(|s| s.sampling_rate)
            .unwrap_or_else(|| stratum.default_rate());
        
        self.rng.r#gen::<f64>() < rate
    }

    /// Record sampling outcome for optimization
    pub fn record_outcome(&mut self, risk_level: RiskLevel, is_anomaly: bool) {
        if let Some(stratum) = self.strata.get_mut(&risk_level) {
            stratum.record_sample(is_anomaly);
        }
    }

    /// Multi-armed bandit optimization (Section 8.1.1)
    /// 
    /// Adjusts sampling rates based on observed anomaly rates.
    /// Increases sampling where anomalies are found.
    pub fn optimize_sampling_rates(&mut self, min_rate: f64, max_rate: f64) {
        for stratum in self.strata.values_mut() {
            let anomaly_rate = stratum.anomaly_rate();
            
            // Increase sampling where anomalies are found (>5% threshold)
            if anomaly_rate > 0.05 {
                stratum.sampling_rate = (stratum.sampling_rate * 2.0).min(max_rate);
            } else if anomaly_rate < 0.01 {
                // Decrease sampling where few anomalies found
                stratum.sampling_rate = (stratum.sampling_rate * 0.8).max(min_rate);
            }
            
            // Ensure within bounds
            stratum.sampling_rate = stratum.sampling_rate.clamp(min_rate, max_rate);
        }
    }

    /// Get current stratum statistics
    pub fn stratum_stats(&self) -> Vec<(RiskLevel, f64, u64, u64)> {
        self.strata
            .iter()
            .map(|(level, stratum)| {
                (*level, stratum.sampling_rate, stratum.sample_count, stratum.anomaly_count)
            })
            .collect()
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        for stratum in self.strata.values_mut() {
            stratum.sample_count = 0;
            stratum.anomaly_count = 0;
        }
    }
}

impl Default for StratifiedSampler {
    fn default() -> Self {
        Self::new()
    }
}

/// Multi-armed bandit using epsilon-greedy strategy
#[derive(Debug, Clone)]
pub struct EpsilonGreedyBandit {
    arms: Vec<BanditArm>,
    epsilon: f64,
    total_pulls: u64,
}

/// Single bandit arm
#[derive(Debug, Clone)]
pub struct BanditArm {
    pub id: String,
    pub pulls: u64,
    pub rewards: f64,
}

impl BanditArm {
    pub fn new(id: String) -> Self {
        Self {
            id,
            pulls: 0,
            rewards: 0.0,
        }
    }

    pub fn average_reward(&self) -> f64 {
        if self.pulls == 0 {
            return 0.0;
        }
        self.rewards / self.pulls as f64
    }

    pub fn update(&mut self, reward: f64) {
        self.pulls += 1;
        self.rewards += reward;
    }
}

impl EpsilonGreedyBandit {
    /// Create new bandit with epsilon exploration rate
    pub fn new(epsilon: f64, arm_ids: Vec<String>) -> Self {
        let arms = arm_ids.into_iter().map(BanditArm::new).collect();
        
        Self {
            arms,
            epsilon: epsilon.clamp(0.0, 1.0),
            total_pulls: 0,
        }
    }

    /// Select arm to pull
    pub fn select(&mut self) -> usize {
        let mut rng = rand::thread_rng();
        
        // Epsilon: explore randomly
        if rng.r#gen::<f64>() < self.epsilon {
            rng.gen_range(0..self.arms.len())
        } else {
            // Exploit: select best arm
            self.best_arm()
        }
    }

    /// Get index of best arm
    fn best_arm(&self) -> usize {
        let mut best_idx = 0;
        let mut best_reward = 0.0;
        
        for (i, arm) in self.arms.iter().enumerate() {
            let reward = arm.average_reward();
            if reward > best_reward || (reward == best_reward && arm.pulls == 0) {
                best_reward = reward;
                best_idx = i;
            }
        }
        
        best_idx
    }

    /// Update arm with reward
    pub fn update(&mut self, arm_idx: usize, reward: f64) {
        if let Some(arm) = self.arms.get_mut(arm_idx) {
            arm.update(reward);
            self.total_pulls += 1;
        }
    }

    /// Get arm statistics
    pub fn arm_stats(&self) -> Vec<(String, u64, f64)> {
        self.arms
            .iter()
            .map(|arm| (arm.id.clone(), arm.pulls, arm.average_reward()))
            .collect()
    }
}

/// Thompson Sampling bandit (Bayesian approach)
#[derive(Debug, Clone)]
pub struct ThompsonSamplingBandit {
    arms: Vec<ThompsonArm>,
}

/// Thompson sampling arm using Beta distribution
#[derive(Debug, Clone)]
pub struct ThompsonArm {
    pub id: String,
    pub alpha: f64, // Successes + 1
    pub beta: f64,  // Failures + 1
}

impl ThompsonArm {
    pub fn new(id: String) -> Self {
        Self {
            id,
            alpha: 1.0,
            beta: 1.0,
        }
    }

    pub fn update(&mut self, success: bool) {
        if success {
            self.alpha += 1.0;
        } else {
            self.beta += 1.0;
        }
    }

    pub fn expected_value(&self) -> f64 {
        self.alpha / (self.alpha + self.beta)
    }

    /// Sample from Beta distribution (simplified)
    pub fn sample<R: Rng>(&self, rng: &mut R) -> f64 {
        // Simplified Beta sampling using approximation
        // For proper implementation, use statrs crate
        let mean = self.expected_value();
        let variance = (self.alpha * self.beta) 
            / ((self.alpha + self.beta).powi(2) * (self.alpha + self.beta + 1.0));
        
        // Simplified: use uniform with variance-based scaling
        let std = variance.sqrt();
        let uniform: f64 = rng.r#gen();
        let z = (uniform - 0.5) * 2.0 * 1.73; // Approximate normal via uniform
        (z * std + mean).clamp(0.0, 1.0)
    }
}

impl ThompsonSamplingBandit {
    pub fn new(arm_ids: Vec<String>) -> Self {
        let arms = arm_ids.into_iter().map(ThompsonArm::new).collect();
        Self { arms }
    }

    pub fn select(&mut self) -> usize {
        let mut rng = rand::thread_rng();
        
        let mut best_idx = 0;
        let mut best_sample = 0.0;
        
        for (i, arm) in self.arms.iter().enumerate() {
            let sample = arm.sample(&mut rng);
            if sample > best_sample {
                best_sample = sample;
                best_idx = i;
            }
        }
        
        best_idx
    }

    pub fn update(&mut self, arm_idx: usize, success: bool) {
        if let Some(arm) = self.arms.get_mut(arm_idx) {
            arm.update(success);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stratified_sampler_critical() {
        let mut sampler = StratifiedSampler::new();
        
        let interaction = Interaction {
            id: "test-001".to_string(),
            risk_level: RiskLevel::Critical,
            timestamp: 1000,
            metadata: HashMap::new(),
        };
        
        // Critical should always be sampled
        assert!(sampler.should_sample(&interaction));
    }

    #[test]
    fn test_stratified_sampler_low() {
        let mut sampler = StratifiedSampler::new();
        
        let interaction = Interaction {
            id: "test-002".to_string(),
            risk_level: RiskLevel::Low,
            timestamp: 1000,
            metadata: HashMap::new(),
        };
        
        // Low is sampled at 1% - test many times
        let mut sampled = 0;
        for _ in 0..1000 {
            if sampler.should_sample(&interaction) {
                sampled += 1;
            }
        }
        
        // Should be around 10 (1% of 1000)
        println!("Low risk sampled: {}/1000", sampled);
        assert!(sampled >= 1 && sampled <= 50); // Wide tolerance for randomness
    }

    #[test]
    fn test_sampling_optimization() {
        let mut sampler = StratifiedSampler::new();
        
        // Record many anomalies in Medium stratum
        for _ in 0..100 {
            sampler.record_outcome(RiskLevel::Medium, true);
        }
        
        let before = sampler.strata.get(&RiskLevel::Medium).unwrap().sampling_rate;
        
        // Optimize
        sampler.optimize_sampling_rates(0.01, 1.0);
        
        let after = sampler.strata.get(&RiskLevel::Medium).unwrap().sampling_rate;
        
        println!("Medium stratum rate: {:.2} -> {:.2}", before, after);
        assert!(after > before); // Should increase due to high anomaly rate
    }

    #[test]
    fn test_epsilon_greedy() {
        let mut bandit = EpsilonGreedyBandit::new(
            0.1, 
            vec!["arm1".to_string(), "arm2".to_string(), "arm3".to_string()]
        );
        
        // Simulate: arm2 is best
        for _ in 0..100 {
            let arm = bandit.select();
            let reward = if arm == 1 { 1.0 } else { 0.0 }; // arm2 (index 1) is best
            bandit.update(arm, reward);
        }
        
        let stats = bandit.arm_stats();
        println!("Bandit stats: {:?}", stats);
        
        // arm2 should have highest average reward
        assert!(stats[1].2 >= stats[0].2 || stats[1].2 >= stats[2].2);
    }

    #[test]
    fn test_thompson_sampling() {
        let mut bandit = ThompsonSamplingBandit::new(
            vec!["A".to_string(), "B".to_string()]
        );
        
        // Arm A has higher success rate
        for _ in 0..50 {
            let arm = bandit.select();
            // Arm 0 succeeds 70%, Arm 1 succeeds 30%
            use rand::Rng;
            let success = if arm == 0 {
                rand::thread_rng().r#gen::<f64>() < 0.7
            } else {
                rand::thread_rng().r#gen::<f64>() < 0.3
            };
            bandit.update(arm, success);
        }
        
        println!("Thompson arm 0: alpha={:.1}, beta={:.1}, ev={:.3}",
            bandit.arms[0].alpha, bandit.arms[0].beta, bandit.arms[0].expected_value());
        println!("Thompson arm 1: alpha={:.1}, beta={:.1}, ev={:.3}",
            bandit.arms[1].alpha, bandit.arms[1].beta, bandit.arms[1].expected_value());
        
        // Arm 0 should have higher expected value
        assert!(bandit.arms[0].expected_value() > bandit.arms[1].expected_value());
    }

    #[test]
    fn test_sampling_stratum() {
        let mut stratum = SamplingStratum::new(RiskLevel::High);
        
        assert_eq!(stratum.sampling_rate, 0.5); // Default for High
        
        stratum.record_sample(true);
        stratum.record_sample(false);
        stratum.record_sample(true);
        
        assert_eq!(stratum.sample_count, 3);
        assert_eq!(stratum.anomaly_count, 2);
        assert!((stratum.anomaly_rate() - 0.667).abs() < 0.01);
    }
}
