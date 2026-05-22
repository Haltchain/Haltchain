//! Statistical Process Control (SPC)
//!
//! Implements:
//! - Population Stability Index (PSI)
//! - EWMA with dynamic thresholds (reuses existing Ewma from lib.rs)
//! - Kolmogorov-Smirnov test for distribution comparison

use serde::{Deserialize, Serialize};

/// Statistical Process Control monitor (Section 7.2)
///
/// Combines PSI, EWMA, and KS test for comprehensive stability monitoring
#[derive(Debug, Clone)]
pub struct SpcMonitor {
    /// PSI calculator state
    psi_threshold: f32,
    /// EWMA tracker (reuses existing Ewma from crate root)
    ewma_alpha: f64,
    /// KS test significance level
    ks_significance: f64,
}

/// Population Stability Index result
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PsiResult {
    pub psi: f32,
    pub stability: Stability,
    pub drift_detected: bool,
}

/// Stability classification based on PSI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stability {
    /// PSI < 0.1: No significant change
    Stable,
    /// 0.1 <= PSI < 0.25: Investigate
    Investigate,
    /// PSI >= 0.25: Action required
    ActionRequired,
}

/// EWMA alert status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertStatus {
    InControl,
    Warning,
    OutOfControl,
}

/// Distribution for PSI calculation
#[derive(Debug, Clone)]
pub struct Distribution {
    bins: Vec<f32>,
    bin_edges: Vec<f32>,
}

/// EWMA tracker with control limits (Section 7.2)
///
/// Extends the base Ewma from crate root with control limit functionality
#[derive(Debug, Clone)]
pub struct EwmaTracker {
    ewma: crate::Ewma,
    alpha: f64,
    target: f64,
    sigma: f64,
    sample_count: usize,
    sum_squares: f64,
}

/// Kolmogorov-Smirnov test result
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct KsResult {
    pub statistic: f64,
    pub critical_value: f64,
    pub significant: bool,
    pub p_value: f64,
}

impl SpcMonitor {
    /// Create new SPC monitor with default thresholds
    pub fn new() -> Self {
        Self {
            psi_threshold: 0.25,
            ewma_alpha: 0.3,
            ks_significance: 0.05,
        }
    }

    /// Create with custom parameters
    pub fn with_params(psi_threshold: f32, ewma_alpha: f64, ks_significance: f64) -> Self {
        Self {
            psi_threshold,
            ewma_alpha,
            ks_significance,
        }
    }

    /// Population Stability Index
    ///
    /// Measures distribution shift between current and expected distributions.
    /// PSI < 0.1: Stable, 0.1-0.25: Investigate, >0.25: Action Required
    pub fn calculate_psi(&self, current: &Distribution, expected: &Distribution) -> PsiResult {
        let mut psi = 0.0f32;

        for (_i, (curr, exp)) in current
            .bins()
            .iter()
            .zip(expected.bins().iter())
            .enumerate()
        {
            // Avoid division by zero and log(0)
            let exp_safe = exp.max(1e-10);
            let curr_safe = curr.max(1e-10);

            if *exp > 0.0 && *curr > 0.0 {
                // PSI formula: sum((Actual - Expected) * ln(Actual / Expected))
                let contribution = (curr_safe - exp_safe) * (curr_safe / exp_safe).ln();
                psi += contribution as f32;
            }
        }

        psi = psi.abs(); // PSI is typically reported as positive

        let stability = self.interpret_psi(psi);
        let drift_detected = stability != Stability::Stable;

        PsiResult {
            psi,
            stability,
            drift_detected,
        }
    }

    /// Interpret PSI value into stability category
    pub fn interpret_psi(&self, psi: f32) -> Stability {
        let investigate_threshold = self.psi_threshold * 0.4;
        match psi {
            p if p < investigate_threshold => Stability::Stable,
            p if p < self.psi_threshold => Stability::Investigate,
            _ => Stability::ActionRequired,
        }
    }

    /// Create new EWMA tracker with control limits
    pub fn create_ewma_tracker(&self, target: f64, sigma: f64) -> EwmaTracker {
        EwmaTracker::new(self.ewma_alpha, target, sigma)
    }

    /// Kolmogorov-Smirnov two-sample test
    ///
    /// Tests whether two samples come from the same distribution.
    /// Returns true if distributions are significantly different.
    pub fn ks_test(&self, sample1: &[f64], sample2: &[f64]) -> KsResult {
        let n1 = sample1.len() as f64;
        let n2 = sample2.len() as f64;

        if n1 == 0.0 || n2 == 0.0 {
            return KsResult {
                statistic: 0.0,
                critical_value: 1.0,
                significant: false,
                p_value: 1.0,
            };
        }

        // Sort samples for ECDF calculation
        let mut s1: Vec<f64> = sample1.to_vec();
        let mut s2: Vec<f64> = sample2.to_vec();
        s1.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        s2.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        // Find all unique values for ECDF comparison
        let mut all_values: Vec<f64> = s1.iter().chain(s2.iter()).copied().collect();
        all_values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        all_values.dedup_by(|a, b| (*a - *b).abs() < 1e-10);

        // Calculate KS statistic: max |ECDF1(x) - ECDF2(x)|
        let mut max_diff: f64 = 0.0;
        for &x in &all_values {
            let cdf1 = Self::empirical_cdf(&s1, x);
            let cdf2 = Self::empirical_cdf(&s2, x);
            let diff = (cdf1 - cdf2).abs();
            max_diff = max_diff.max(diff);
        }

        // Critical value for two-tailed test at significance level alpha
        // D_crit = c(alpha) * sqrt((n1 + n2) / (n1 * n2))
        // c(0.05) ≈ 1.358, c(0.01) ≈ 1.628
        let c_alpha = if self.ks_significance <= 0.01 {
            1.628
        } else {
            1.358 // 0.05 significance
        };
        let critical_value = c_alpha * ((n1 + n2) / (n1 * n2)).sqrt();

        // Approximate p-value using Kolmogorov distribution
        let p_value = Self::kolmogorov_p_value(max_diff, n1, n2);

        KsResult {
            statistic: max_diff,
            critical_value,
            significant: max_diff > critical_value,
            p_value,
        }
    }

    /// Empirical CDF at point x
    fn empirical_cdf(sorted_sample: &[f64], x: f64) -> f64 {
        let count = sorted_sample.iter().filter(|&&v| v <= x).count();
        count as f64 / sorted_sample.len() as f64
    }

    /// Approximate p-value for KS statistic
    fn kolmogorov_p_value(d: f64, n1: f64, n2: f64) -> f64 {
        let n = (n1 * n2) / (n1 + n2);
        let lambda = (n.sqrt() + 0.12 + 0.11 / n.sqrt()) * d;

        // Smirnov approximation for two-tailed test
        let mut sum = 0.0;
        for i in 1..=100 {
            let term = (-2.0 * lambda * lambda * i as f64 * i as f64).exp();
            if i % 2 == 1 {
                sum += term;
            } else {
                sum -= term;
            }
            if term < 1e-10 {
                break;
            }
        }

        (2.0 * sum).min(1.0).max(0.0)
    }
}

impl Default for SpcMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Distribution {
    /// Create distribution from histogram bins
    pub fn from_bins(bins: Vec<f32>, bin_edges: Vec<f32>) -> Self {
        // Normalize to sum to 1.0
        let sum: f32 = bins.iter().sum();
        let normalized: Vec<f32> = bins.iter().map(|b| b / sum).collect();

        Self {
            bins: normalized,
            bin_edges,
        }
    }

    /// Create from raw samples using percentile-based binning
    ///
    /// Uses decile-based bins to ensure proper distribution separation
    pub fn from_samples(samples: &[f64], num_bins: usize) -> Self {
        if samples.is_empty() {
            return Self {
                bins: vec![1.0 / num_bins as f32; num_bins],
                bin_edges: (0..=num_bins).map(|i| i as f32).collect(),
            };
        }

        let mut sorted = samples.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let min = sorted[0];
        let max = sorted[sorted.len() - 1];
        let range = max - min;

        if range < 1e-10 {
            // All values are the same
            return Self {
                bins: vec![1.0; 1], // Single bin with all mass
                bin_edges: vec![min as f32, max as f32 + 1.0],
            };
        }

        // Use percentile-based bin edges to ensure even distribution
        let mut bin_edges = Vec::with_capacity(num_bins + 1);
        bin_edges.push(min as f32);

        for i in 1..num_bins {
            let percentile = i as f64 / num_bins as f64;
            let idx = (percentile * (sorted.len() - 1) as f64) as usize;
            bin_edges.push(sorted[idx.clamp(0, sorted.len() - 1)] as f32);
        }
        bin_edges.push((max + 1e-6) as f32); // Slightly extend max to include it

        Self::from_samples_with_edges(samples, &bin_edges)
    }

    /// Create distribution using pre-defined bin edges (for shared binning)
    pub fn from_samples_with_edges(samples: &[f64], bin_edges: &[f32]) -> Self {
        let num_bins = bin_edges.len().saturating_sub(1);
        if num_bins == 0 || samples.is_empty() {
            return Self {
                bins: vec![1.0],
                bin_edges: bin_edges.to_vec(),
            };
        }

        let mut bins = vec![0.0f32; num_bins];

        for &sample in samples {
            // Find bin by checking edges
            let mut bin_idx = 0;
            for (i, edge) in bin_edges.iter().enumerate().skip(1) {
                if sample <= *edge as f64 {
                    bin_idx = i - 1;
                    break;
                }
            }
            bin_idx = bin_idx.min(num_bins - 1);
            bins[bin_idx] += 1.0;
        }

        // Normalize to probabilities
        let total = bins.iter().sum::<f32>();
        if total > 0.0 {
            for bin in &mut bins {
                *bin /= total;
            }
        }

        Self {
            bins,
            bin_edges: bin_edges.to_vec(),
        }
    }

    pub fn bins(&self) -> &[f32] {
        &self.bins
    }

    pub fn bin_edges(&self) -> &[f32] {
        &self.bin_edges
    }
}

impl EwmaTracker {
    /// Create new EWMA tracker with control limits
    ///
    /// * `alpha` - Smoothing parameter (0, 1]
    /// * `target` - Target/process mean
    /// * `sigma` - Process standard deviation
    pub fn new(alpha: f64, target: f64, sigma: f64) -> Self {
        Self {
            ewma: crate::Ewma::new(alpha),
            alpha,
            target,
            sigma,
            sample_count: 0,
            sum_squares: 0.0,
        }
    }

    /// Update with new sample
    pub fn update(&mut self, sample: f64) {
        self.ewma.update(sample);
        self.sample_count += 1;
        let deviation = sample - self.target;
        self.sum_squares += deviation * deviation;
    }

    /// Get current EWMA value
    pub fn value(&self) -> f64 {
        self.ewma.get()
    }

    /// Calculate control limits
    ///
    /// Returns (upper_limit, lower_limit) for given sigma multiplier
    pub fn control_limits(&self, sigma_multiplier: f64) -> (f64, f64) {
        // Alpha is stored in self.alpha

        // Variance of EWMA: sigma^2 * alpha / (2 - alpha)
        let var_ewma = self.sigma * self.sigma * self.alpha / (2.0 - self.alpha);
        let std_ewma = var_ewma.sqrt();

        let margin = sigma_multiplier * std_ewma;
        let upper = self.target + margin;
        let lower = self.target - margin;

        (upper, lower)
    }

    /// Check alert status (3-sigma default)
    pub fn alert_status(&self) -> AlertStatus {
        self.alert_status_with_sigma(3.0)
    }

    /// Check alert status with custom sigma
    pub fn alert_status_with_sigma(&self, sigma_multiplier: f64) -> AlertStatus {
        let ewma_val = self.value();
        let (upper, lower) = self.control_limits(sigma_multiplier);

        if ewma_val > upper || ewma_val < lower {
            AlertStatus::OutOfControl
        } else {
            // Check warning level (2-sigma)
            let (warn_upper, warn_lower) = self.control_limits(2.0);
            if ewma_val > warn_upper || ewma_val < warn_lower {
                AlertStatus::Warning
            } else {
                AlertStatus::InControl
            }
        }
    }

    /// Get estimated process standard deviation
    pub fn estimated_sigma(&self) -> f64 {
        if self.sample_count < 2 {
            return self.sigma;
        }
        (self.sum_squares / self.sample_count as f64).sqrt()
    }

    /// Get sample count
    pub fn sample_count(&self) -> usize {
        self.sample_count
    }
}

/// Convenience function for one-off PSI calculation
pub fn calculate_psi(current: &[f64], expected: &[f64], num_bins: usize) -> f32 {
    let dist_current = Distribution::from_samples(current, num_bins);
    let dist_expected = Distribution::from_samples(expected, num_bins);

    let monitor = SpcMonitor::new();
    monitor.calculate_psi(&dist_current, &dist_expected).psi
}

/// Convenience function for one-off KS test
pub fn ks_test(sample1: &[f64], sample2: &[f64]) -> KsResult {
    let monitor = SpcMonitor::new();
    monitor.ks_test(sample1, sample2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psi_calculation_stable() {
        // Two identical distributions should have PSI = 0
        let dist1 = Distribution::from_samples(&[1.0, 2.0, 3.0, 4.0, 5.0], 5);
        let dist2 = Distribution::from_samples(&[1.0, 2.0, 3.0, 4.0, 5.0], 5);

        let monitor = SpcMonitor::new();
        let result = monitor.calculate_psi(&dist1, &dist2);

        println!("PSI for identical distributions: {:.4}", result.psi);
        assert_eq!(result.stability, Stability::Stable);
        assert!(!result.drift_detected);
    }

    #[test]
    fn test_psi_calculation_drift() {
        // Significantly different distributions
        // Create larger samples for more reliable PSI calculation
        let samples1: Vec<f64> = (0..100).map(|i| i as f64 * 0.1).collect(); // 0.0 to 9.9
        let samples2: Vec<f64> = (0..100).map(|i| 50.0 + i as f64 * 0.1).collect(); // 50.0 to 59.9

        // Use shared binning: combine all samples to create common bins
        let all_samples: Vec<f64> = samples1.iter().chain(&samples2).copied().collect();
        let combined_dist = Distribution::from_samples(&all_samples, 10);
        let shared_edges = combined_dist.bin_edges();

        // Now create both distributions using shared bin edges
        let dist1 = Distribution::from_samples_with_edges(&samples1, shared_edges);
        let dist2 = Distribution::from_samples_with_edges(&samples2, shared_edges);

        let monitor = SpcMonitor::new();
        let result = monitor.calculate_psi(&dist1, &dist2);

        println!("PSI for different distributions: {:.4}", result.psi);
        println!("Dist1 bins: {:?}", dist1.bins());
        println!("Dist2 bins: {:?}", dist2.bins());
        println!("Shared edges: {:?}", shared_edges);

        // These distributions are completely separated - PSI should be high
        assert!(
            result.psi > 0.1,
            "PSI should detect distribution drift (>0.1), got {:.4}",
            result.psi
        );
        assert!(result.drift_detected, "Should flag as drift detected");
        assert_eq!(
            result.stability,
            Stability::ActionRequired,
            "Should require action for such different distributions"
        );
    }

    #[test]
    fn test_ewma_tracker() {
        let mut tracker = EwmaTracker::new(0.3, 10.0, 1.0);

        // Feed values around target
        for _ in 0..20 {
            tracker.update(10.0);
            tracker.update(10.1);
            tracker.update(9.9);
        }

        assert_eq!(tracker.alert_status(), AlertStatus::InControl);

        // Feed extreme value
        tracker.update(20.0);

        let status = tracker.alert_status();
        println!("Alert status after outlier: {:?}", status);
        assert!(
            !matches!(status, AlertStatus::InControl),
            "EWMA tracker must detect a 10-sigma outlier (20.0 vs target 10.0)"
        );
    }

    #[test]
    fn test_ks_test_identical() {
        let sample1 = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let sample2 = vec![1.0, 2.0, 3.0, 4.0, 5.0];

        let result = ks_test(&sample1, &sample2);

        println!("KS statistic (identical): {:.4}", result.statistic);
        println!("P-value: {:.4}", result.p_value);

        assert!(!result.significant); // Should not be significantly different
    }

    #[test]
    fn test_ks_test_different() {
        let sample1: Vec<f64> = (0..100).map(|i| i as f64).collect();
        let sample2: Vec<f64> = (50..150).map(|i| i as f64).collect();

        let result = ks_test(&sample1, &sample2);

        println!("KS statistic (different): {:.4}", result.statistic);
        println!("P-value: {:.4}", result.p_value);
        println!("Significant: {}", result.significant);

        assert!(result.significant); // Should be significantly different
    }

    #[test]
    fn test_distribution_from_samples() {
        let samples = vec![1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0];
        let dist = Distribution::from_samples(&samples, 5);

        println!("Bins: {:?}", dist.bins());
        println!("Bin edges: {:?}", dist.bin_edges());

        // Bins should sum to 1.0
        let sum: f32 = dist.bins().iter().sum();
        assert!((sum - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_interpret_psi() {
        let monitor = SpcMonitor::new();

        assert_eq!(monitor.interpret_psi(0.05), Stability::Stable);
        assert_eq!(monitor.interpret_psi(0.15), Stability::Investigate);
        assert_eq!(monitor.interpret_psi(0.30), Stability::ActionRequired);
    }

    #[test]
    fn test_ks_p_value() {
        // Test with known values
        let p = SpcMonitor::kolmogorov_p_value(0.5, 100.0, 100.0);
        println!("P-value for D=0.5, n=100: {:.6}", p);

        // Larger D should give smaller p-value
        let p2 = SpcMonitor::kolmogorov_p_value(0.8, 100.0, 100.0);
        println!("P-value for D=0.8, n=100: {:.6}", p2);

        assert!(
            p2 < p,
            "KS p-value must decrease for larger D statistic (p2={p2:.6} should be < p={p:.6})"
        );
    }
}
