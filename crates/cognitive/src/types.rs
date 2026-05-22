//! Shared types for cognitive safety detection system
//!
//! This module provides canonical type definitions used across multiple
//! detection modules to ensure consistency and prevent type mismatches.

use serde::{Deserialize, Serialize};

/// Canonical alert tier classification (AC-05 FIX)
///
/// Unified enum replacing three separate AlertTier definitions:
/// - ensemble_divergence.rs: None, Low, Medium, High, Critical
/// - guardian.rs: None, Low, Medium, High, Critical
/// - robust_detector.rs: Normal, Review, Critical
///
/// This unified version provides a common vocabulary for all detection modules
/// with clear percentile-based thresholds per Project Architecture §1.1.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertTier {
    /// No anomaly detected (0-80th percentile)
    None,
    /// Low confidence anomaly (80-95th percentile)
    Low,
    /// Medium confidence anomaly (95-99.5th percentile)
    Medium,
    /// High confidence anomaly (99.5-99.9th percentile)
    High,
    /// Critical anomaly requiring immediate action (>99.9th percentile)
    Critical,
}

impl AlertTier {
    /// Convert from percentile to tier (per §1.1.3)
    pub fn from_percentile(percentile: f64) -> Self {
        match percentile {
            p if p > 99.9 => AlertTier::Critical,
            p if p > 99.5 => AlertTier::High,
            p if p > 95.0 => AlertTier::Medium,
            p if p > 80.0 => AlertTier::Low,
            _ => AlertTier::None,
        }
    }

    /// Check if this tier meets or exceeds the given tier
    pub fn at_least(&self, other: AlertTier) -> bool {
        let self_ord = self.ordinal();
        let other_ord = other.ordinal();
        self_ord >= other_ord
    }

    /// Get ordinal value for comparison
    fn ordinal(&self) -> u8 {
        match self {
            AlertTier::None => 0,
            AlertTier::Low => 1,
            AlertTier::Medium => 2,
            AlertTier::High => 3,
            AlertTier::Critical => 4,
        }
    }

    /// Returns true if tier is Critical (highest)
    pub fn is_critical(&self) -> bool {
        matches!(self, AlertTier::Critical)
    }

    /// Returns true if tier requires some action (Medium or higher)
    pub fn requires_action(&self) -> bool {
        matches!(
            self,
            AlertTier::Medium | AlertTier::High | AlertTier::Critical
        )
    }
}

impl Default for AlertTier {
    fn default() -> Self {
        AlertTier::None
    }
}

/// Three-way decision regions (Section 2.1.3)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionRegion {
    /// Definitely normal (below alpha threshold)
    Negative,
    /// Ambiguous - requires escalation (between alpha and beta)
    Boundary,
    /// Definitely anomalous (above beta threshold)
    Positive,
}

impl DecisionRegion {
    /// Create decision region from percentile with given thresholds
    pub fn from_percentile(percentile: f64, alpha: f64, beta: f64) -> Self {
        if percentile > beta * 100.0 {
            DecisionRegion::Positive
        } else if percentile < alpha * 100.0 {
            DecisionRegion::Negative
        } else {
            DecisionRegion::Boundary
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_tier_from_percentile() {
        assert!(matches!(AlertTier::from_percentile(50.0), AlertTier::None));
        assert!(matches!(AlertTier::from_percentile(85.0), AlertTier::Low));
        assert!(matches!(
            AlertTier::from_percentile(97.0),
            AlertTier::Medium
        ));
        assert!(matches!(AlertTier::from_percentile(99.7), AlertTier::High));
        assert!(matches!(
            AlertTier::from_percentile(99.95),
            AlertTier::Critical
        ));
    }

    #[test]
    fn alert_tier_at_least() {
        assert!(AlertTier::High.at_least(AlertTier::Medium));
        assert!(AlertTier::Medium.at_least(AlertTier::Medium));
        assert!(!AlertTier::Low.at_least(AlertTier::Medium));
    }

    #[test]
    fn decision_region_from_percentile() {
        assert!(matches!(
            DecisionRegion::from_percentile(50.0, 0.95, 0.99),
            DecisionRegion::Negative
        ));
        assert!(matches!(
            DecisionRegion::from_percentile(97.0, 0.95, 0.99),
            DecisionRegion::Boundary
        ));
        assert!(matches!(
            DecisionRegion::from_percentile(99.5, 0.95, 0.99),
            DecisionRegion::Positive
        ));
    }
}
