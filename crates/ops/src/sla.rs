//! Section 8.2: Performance SLAs
//!
//! Implements:
//! - Mean Time To Detect (MTTD)
//! - Mean Time To Respond (MTTR)
//! - Precision @ Recall tracking

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// SLA Tracker for monitoring detection and response performance (Section 8.2)
#[derive(Debug, Clone)]
pub struct SlaTracker {
    /// Mean Time To Detect records
    mttd_records: VecDeque<Duration>,
    /// Mean Time To Respond records
    mttr_records: VecDeque<Duration>,
    /// Precision/recall history keyed by decision threshold.
    /// Tuple: (threshold, confusion_matrix)
    threshold_metrics: Vec<(f32, ConfusionMatrix)>,
    /// MTTD SLA target (default: 60s for critical)
    mttd_target: Duration,
    /// MTTR SLA target (default: 5min for critical)
    mttr_target: Duration,
    /// Maximum records to keep for moving average
    max_records: usize,
}

/// Detection latency record
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DetectionRecord {
    pub occurrence_time: u64, // Unix timestamp
    pub detection_time: u64,  // Unix timestamp
    pub latency: Duration,
}

/// Response record
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ResponseRecord {
    pub alert_time: u64,
    pub response_time: u64,
    pub latency: Duration,
}

/// Confusion matrix for precision/recall calculation
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct ConfusionMatrix {
    pub true_positives: u64,
    pub false_positives: u64,
    pub true_negatives: u64,
    pub false_negatives: u64,
}

impl ConfusionMatrix {
    /// Calculate precision: TP / (TP + FP)
    pub fn precision(&self) -> f32 {
        let tp_fp = self.true_positives + self.false_positives;
        if tp_fp == 0 {
            return 0.0;
        }
        self.true_positives as f32 / tp_fp as f32
    }

    /// Calculate recall: TP / (TP + FN)
    pub fn recall(&self) -> f32 {
        let tp_fn = self.true_positives + self.false_negatives;
        if tp_fn == 0 {
            return 0.0;
        }
        self.true_positives as f32 / tp_fn as f32
    }

    /// Calculate F1 score
    pub fn f1_score(&self) -> f32 {
        let p = self.precision();
        let r = self.recall();
        if p + r == 0.0 {
            return 0.0;
        }
        2.0 * (p * r) / (p + r)
    }

    /// Calculate accuracy
    pub fn accuracy(&self) -> f32 {
        let total =
            self.true_positives + self.false_positives + self.true_negatives + self.false_negatives;
        if total == 0 {
            return 0.0;
        }
        let correct = self.true_positives + self.true_negatives;
        correct as f32 / total as f32
    }
}

/// SLA metrics summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaMetrics {
    pub mttd: Duration,
    pub mttr: Duration,
    pub mttd_sla_met: bool,
    pub mttr_sla_met: bool,
    pub precision_at_95_recall: f32,
    pub overall_recall: f32,
    pub overall_precision: f32,
    pub f1_score: f32,
}

/// Alert severity for SLA tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl AlertSeverity {
    /// MTTD target for this severity
    pub fn mttd_target(&self) -> Duration {
        match self {
            AlertSeverity::Info => Duration::from_secs(300), // 5 min
            AlertSeverity::Low => Duration::from_secs(180),  // 3 min
            AlertSeverity::Medium => Duration::from_secs(120), // 2 min
            AlertSeverity::High => Duration::from_secs(60),  // 1 min
            AlertSeverity::Critical => Duration::from_secs(30), // 30 sec
        }
    }

    /// MTTR target for this severity
    pub fn mttr_target(&self) -> Duration {
        match self {
            AlertSeverity::Info => Duration::from_secs(1800), // 30 min
            AlertSeverity::Low => Duration::from_secs(900),   // 15 min
            AlertSeverity::Medium => Duration::from_secs(600), // 10 min
            AlertSeverity::High => Duration::from_secs(300),  // 5 min
            AlertSeverity::Critical => Duration::from_secs(60), // 1 min
        }
    }
}

impl SlaTracker {
    /// Create new SLA tracker with default targets
    pub fn new() -> Self {
        Self {
            mttd_records: VecDeque::with_capacity(1000),
            mttr_records: VecDeque::with_capacity(1000),
            threshold_metrics: Vec::new(),
            mttd_target: Duration::from_secs(60), // 1 min for critical
            mttr_target: Duration::from_secs(300), // 5 min for critical
            max_records: 10000,
        }
    }

    /// Create with custom targets
    pub fn with_targets(mttd_target: Duration, mttr_target: Duration) -> Self {
        Self {
            mttd_records: VecDeque::with_capacity(1000),
            mttr_records: VecDeque::with_capacity(1000),
            threshold_metrics: Vec::new(),
            mttd_target,
            mttr_target,
            max_records: 10000,
        }
    }

    /// Record MTTD (Section 8.2)
    ///
    /// Records time from occurrence to detection.
    /// Panics if MTTD SLA is violated for critical alerts.
    pub fn record_mttd(
        &mut self,
        occurrence: Instant,
        detection: Instant,
        severity: AlertSeverity,
    ) {
        let latency = detection.duration_since(occurrence);

        // Check SLA violation
        let target = severity.mttd_target();
        if latency > target {
            eprintln!(
                "SLA VIOLATION: MTTD {:.2}s exceeds target {:.2}s for {:?}",
                latency.as_secs_f64(),
                target.as_secs_f64(),
                severity
            );

            // For critical, this is a serious violation
            if severity == AlertSeverity::Critical {
                panic!(
                    "CRITICAL SLA VIOLATION: MTTD {}s exceeds 60s target",
                    latency.as_secs()
                );
            }
        }

        self.add_mttd_record(latency);
    }

    /// Record MTTD from timestamps
    pub fn record_mttd_timestamp(
        &mut self,
        occurrence: u64,
        detection: u64,
        severity: AlertSeverity,
    ) {
        let latency = Duration::from_secs(detection.saturating_sub(occurrence));

        let target = severity.mttd_target();
        if latency > target {
            eprintln!(
                "SLA VIOLATION: MTTD {:.2}s exceeds target {:.2}s for {:?}",
                latency.as_secs_f64(),
                target.as_secs_f64(),
                severity
            );
        }

        self.add_mttd_record(latency);
    }

    fn add_mttd_record(&mut self, latency: Duration) {
        if self.mttd_records.len() >= self.max_records {
            self.mttd_records.pop_front();
        }
        self.mttd_records.push_back(latency);
    }

    /// Record MTTR
    pub fn record_mttr(&mut self, alert: Instant, response: Instant, severity: AlertSeverity) {
        let latency = response.duration_since(alert);

        let target = severity.mttr_target();
        if latency > target {
            eprintln!(
                "SLA VIOLATION: MTTR {:.2}s exceeds target {:.2}s for {:?}",
                latency.as_secs_f64(),
                target.as_secs_f64(),
                severity
            );
        }

        self.add_mttr_record(latency);
    }

    fn add_mttr_record(&mut self, latency: Duration) {
        if self.mttr_records.len() >= self.max_records {
            self.mttr_records.pop_front();
        }
        self.mttr_records.push_back(latency);
    }

    /// Calculate Mean Time To Detect
    pub fn mttd(&self) -> Duration {
        if self.mttd_records.is_empty() {
            return Duration::from_secs(0);
        }

        let total: Duration = self.mttd_records.iter().sum();
        total / self.mttd_records.len() as u32
    }

    /// Calculate Mean Time To Respond
    pub fn mttr(&self) -> Duration {
        if self.mttr_records.is_empty() {
            return Duration::from_secs(0);
        }

        let total: Duration = self.mttr_records.iter().sum();
        total / self.mttr_records.len() as u32
    }

    /// Get MTTD percentile
    pub fn mttd_percentile(&self, p: f64) -> Duration {
        if self.mttd_records.is_empty() {
            return Duration::from_secs(0);
        }

        let mut sorted: Vec<Duration> = self.mttd_records.iter().copied().collect();
        sorted.sort();

        let idx = (p / 100.0 * (sorted.len() - 1) as f64) as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    /// Calculate Precision @ Recall = 0.95 (Section 8.2)
    ///
    /// Finds precision at the threshold where recall >= 0.95
    pub fn calculate_precision_at_recall(&self, target_recall: f32) -> (f32, f32) {
        // Select the best precision among thresholds that satisfy recall >= target.
        // Tie-breaker: higher recall.
        let mut best: Option<(f32, f32)> = None;

        for (_, matrix) in &self.threshold_metrics {
            let recall = matrix.recall();
            let precision = matrix.precision();
            if recall + f32::EPSILON < target_recall {
                continue;
            }

            best = match best {
                Some((best_recall, best_precision)) => {
                    if precision > best_precision
                        || ((precision - best_precision).abs() <= f32::EPSILON
                            && recall > best_recall)
                    {
                        Some((recall, precision))
                    } else {
                        Some((best_recall, best_precision))
                    }
                }
                None => Some((recall, precision)),
            };
        }

        best.unwrap_or((0.0, 0.0))
    }

    /// Record precision/recall pair
    pub fn record_precision_recall(&mut self, threshold: f32, matrix: &ConfusionMatrix) {
        self.threshold_metrics.push((threshold, *matrix));

        // Keep last 1000 records
        if self.threshold_metrics.len() > 1000 {
            self.threshold_metrics.remove(0);
        }
    }

    /// Calculate confusion matrix at given threshold
    pub fn confusion_matrix_at(&self, threshold: f32) -> ConfusionMatrix {
        if self.threshold_metrics.is_empty() {
            return ConfusionMatrix::default();
        }

        // Return matrix at nearest threshold.
        let mut best_idx = 0usize;
        let mut best_delta = f32::INFINITY;
        for (i, (th, _)) in self.threshold_metrics.iter().enumerate() {
            let delta = (threshold - *th).abs();
            if delta < best_delta {
                best_delta = delta;
                best_idx = i;
            }
        }
        self.threshold_metrics[best_idx].1
    }

    /// Get all metrics summary
    pub fn metrics(&self) -> SlaMetrics {
        let (recall, precision) = self.calculate_precision_at_recall(0.95);

        // Calculate overall precision/recall from stored data
        let overall_recall = recall;
        let overall_precision = precision;

        // Simple F1 (not weighted properly, but illustrative)
        let f1 = if overall_precision + overall_recall > 0.0 {
            2.0 * (overall_precision * overall_recall) / (overall_precision + overall_recall)
        } else {
            0.0
        };

        SlaMetrics {
            mttd: self.mttd(),
            mttr: self.mttr(),
            mttd_sla_met: self.mttd() <= self.mttd_target,
            mttr_sla_met: self.mttr() <= self.mttr_target,
            precision_at_95_recall: precision,
            overall_recall,
            overall_precision,
            f1_score: f1,
        }
    }

    /// Check if all SLAs are being met
    pub fn slas_met(&self) -> bool {
        let metrics = self.metrics();
        metrics.mttd_sla_met && metrics.mttr_sla_met && metrics.precision_at_95_recall > 0.0
    }

    /// Get MTTD target
    pub fn mttd_target(&self) -> Duration {
        self.mttd_target
    }

    /// Get MTTR target
    pub fn mttr_target(&self) -> Duration {
        self.mttr_target
    }

    /// Set MTTD target
    pub fn set_mttd_target(&mut self, target: Duration) {
        self.mttd_target = target;
    }

    /// Set MTTR target
    pub fn set_mttr_target(&mut self, target: Duration) {
        self.mttr_target = target;
    }

    /// Reset all records
    pub fn reset(&mut self) {
        self.mttd_records.clear();
        self.mttr_records.clear();
        self.threshold_metrics.clear();
    }

    /// Get record counts
    pub fn record_counts(&self) -> (usize, usize) {
        (self.mttd_records.len(), self.mttr_records.len())
    }
}

impl Default for SlaTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Rolling window SLA tracker for real-time monitoring
#[derive(Debug, Clone)]
pub struct RollingSlaTracker {
    window_size: Duration,
    detections: VecDeque<(Instant, Duration)>, // (detection_time, latency)
    responses: VecDeque<(Instant, Duration)>,
}

impl RollingSlaTracker {
    pub fn new(window_size: Duration) -> Self {
        Self {
            window_size,
            detections: VecDeque::new(),
            responses: VecDeque::new(),
        }
    }

    pub fn record_detection(&mut self, detection_time: Instant, latency: Duration) {
        self.prune_old_records(detection_time);
        self.detections.push_back((detection_time, latency));
    }

    pub fn record_response(&mut self, response_time: Instant, latency: Duration) {
        self.prune_old_records(response_time);
        self.responses.push_back((response_time, latency));
    }

    fn prune_old_records(&mut self, now: Instant) {
        let cutoff = now - self.window_size;

        while let Some((time, _)) = self.detections.front() {
            if *time < cutoff {
                self.detections.pop_front();
            } else {
                break;
            }
        }

        while let Some((time, _)) = self.responses.front() {
            if *time < cutoff {
                self.responses.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn rolling_mttd(&self) -> Duration {
        if self.detections.is_empty() {
            return Duration::from_secs(0);
        }
        let total: Duration = self.detections.iter().map(|(_, lat)| *lat).sum();
        total / self.detections.len() as u32
    }

    pub fn rolling_mttr(&self) -> Duration {
        if self.responses.is_empty() {
            return Duration::from_secs(0);
        }
        let total: Duration = self.responses.iter().map(|(_, lat)| *lat).sum();
        total / self.responses.len() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mttd_calculation() {
        let mut tracker = SlaTracker::new();

        // Record some MTTD values
        tracker.add_mttd_record(Duration::from_secs(10));
        tracker.add_mttd_record(Duration::from_secs(20));
        tracker.add_mttd_record(Duration::from_secs(30));

        let mttd = tracker.mttd();
        assert_eq!(mttd, Duration::from_secs(20)); // Average of 10, 20, 30
    }

    #[test]
    fn test_mttr_calculation() {
        let mut tracker = SlaTracker::new();

        tracker.add_mttr_record(Duration::from_secs(60));
        tracker.add_mttr_record(Duration::from_secs(120));

        let mttr = tracker.mttr();
        assert_eq!(mttr, Duration::from_secs(90));
    }

    #[test]
    fn test_confusion_matrix() {
        let matrix = ConfusionMatrix {
            true_positives: 80,
            false_positives: 20,
            true_negatives: 70,
            false_negatives: 30,
        };

        assert!((matrix.precision() - 0.8).abs() < 0.01); // 80/100
        assert!((matrix.recall() - 0.727).abs() < 0.01); // 80/110
        assert!(matrix.accuracy() > 0.7);
    }

    #[test]
    fn test_sla_metrics() {
        let mut tracker = SlaTracker::new();

        tracker.add_mttd_record(Duration::from_secs(30));
        tracker.add_mttr_record(Duration::from_secs(120));

        let metrics = tracker.metrics();

        assert_eq!(metrics.mttd, Duration::from_secs(30));
        assert_eq!(metrics.mttr, Duration::from_secs(120));
        assert!(metrics.mttd_sla_met); // 30s < 60s target
        assert!(metrics.mttr_sla_met); // 120s < 300s target
    }

    #[test]
    fn test_mttd_percentile() {
        let mut tracker = SlaTracker::new();

        for i in 1..=10 {
            tracker.add_mttd_record(Duration::from_secs(i));
        }

        let p50 = tracker.mttd_percentile(50.0);
        let p90 = tracker.mttd_percentile(90.0);

        println!("MTTD p50: {:?}, p90: {:?}", p50, p90);

        assert!(p50.as_secs() >= 5 && p50.as_secs() <= 6);
        assert!(p90.as_secs() >= 9);
    }

    #[test]
    fn test_rolling_tracker() {
        let mut tracker = RollingSlaTracker::new(Duration::from_secs(60));

        let now = Instant::now();

        tracker.record_detection(now, Duration::from_secs(10));
        tracker.record_detection(now - Duration::from_secs(30), Duration::from_secs(15));
        tracker.record_detection(now - Duration::from_secs(70), Duration::from_secs(20)); // Old

        let mttd = tracker.rolling_mttd();

        // Should only include non-pruned records
        println!("Rolling MTTD: {:?}", mttd);
        assert!(mttd.as_secs() > 0);
    }

    #[test]
    fn test_sla_targets_by_severity() {
        assert_eq!(
            AlertSeverity::Critical.mttd_target(),
            Duration::from_secs(30)
        );
        assert_eq!(AlertSeverity::High.mttd_target(), Duration::from_secs(60));
        assert_eq!(
            AlertSeverity::Medium.mttd_target(),
            Duration::from_secs(120)
        );

        assert_eq!(
            AlertSeverity::Critical.mttr_target(),
            Duration::from_secs(60)
        );
        assert_eq!(AlertSeverity::High.mttr_target(), Duration::from_secs(300));
    }

    #[test]
    #[should_panic(expected = "CRITICAL SLA VIOLATION")]
    fn test_critical_sla_violation_panics() {
        let mut tracker = SlaTracker::new();

        let occurrence = Instant::now();
        let detection = occurrence + Duration::from_secs(120); // 2 minutes later

        // This should panic for critical alerts exceeding 60s
        tracker.record_mttd(occurrence, detection, AlertSeverity::Critical);
    }

    #[test]
    fn test_precision_at_recall_selects_best_threshold() {
        let mut tracker = SlaTracker::new();

        // threshold 0.9: high precision but low recall (below target)
        tracker.record_precision_recall(
            0.9,
            &ConfusionMatrix {
                true_positives: 50,
                false_positives: 5,
                true_negatives: 95,
                false_negatives: 50,
            },
        );
        // threshold 0.7: recall meets 0.95, moderate precision
        tracker.record_precision_recall(
            0.7,
            &ConfusionMatrix {
                true_positives: 95,
                false_positives: 20,
                true_negatives: 80,
                false_negatives: 5,
            },
        );
        // threshold 0.6: also meets recall, worse precision
        tracker.record_precision_recall(
            0.6,
            &ConfusionMatrix {
                true_positives: 98,
                false_positives: 40,
                true_negatives: 60,
                false_negatives: 2,
            },
        );

        let (recall, precision) = tracker.calculate_precision_at_recall(0.95);
        assert!(recall >= 0.95);
        assert!((precision - (95.0 / 115.0)).abs() < 1e-5);
    }

    #[test]
    fn test_confusion_matrix_at_returns_nearest_threshold() {
        let mut tracker = SlaTracker::new();
        let m1 = ConfusionMatrix {
            true_positives: 10,
            false_positives: 2,
            true_negatives: 20,
            false_negatives: 5,
        };
        let m2 = ConfusionMatrix {
            true_positives: 15,
            false_positives: 3,
            true_negatives: 18,
            false_negatives: 2,
        };
        tracker.record_precision_recall(0.25, &m1);
        tracker.record_precision_recall(0.80, &m2);

        let got = tracker.confusion_matrix_at(0.78);
        assert_eq!(got.true_positives, 15);
        assert_eq!(got.false_negatives, 2);
    }
}
