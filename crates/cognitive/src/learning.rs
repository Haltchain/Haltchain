//! FP/TP counters for calibration drift (Roadmap D). Wire from review outcomes or SIEM.

use std::sync::atomic::{AtomicU64, Ordering};

static FP: AtomicU64 = AtomicU64::new(0);
static TP: AtomicU64 = AtomicU64::new(0);

pub fn record_false_positive() {
    FP.fetch_add(1, Ordering::Relaxed);
}

pub fn record_true_positive() {
    TP.fetch_add(1, Ordering::Relaxed);
}

pub fn fp_count() -> u64 {
    FP.load(Ordering::Relaxed)
}

pub fn tp_count() -> u64 {
    TP.load(Ordering::Relaxed)
}

/// Suggested extra benign samples to add per calibration cycle when FPs dominate.
pub fn suggested_benign_refresh_count() -> u32 {
    let fp = fp_count();
    let tp = tp_count().max(1);
    if fp == 0 {
        return 0;
    }
    let ratio = fp as f64 / tp as f64;
    if ratio < 0.05 {
        return 0;
    }
    (ratio * 10.0).min(500.0) as u32
}
