//! EWMA velocity tracker + sliding-window statistics.
//!
//! Uses exponential weighted moving average (EWMA) for velocity — more
//! sensitive to recent spikes than a simple rolling window.

pub mod auth;
pub mod features;
pub mod isolation_forest;
pub mod spc;

use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::Serialize;

//EWMA velocity tracker
/// Single-pass EWMA tracker.
/// α controls how fast old observations decay:  higher α = more reactive.
#[derive(Debug, Clone)]
pub struct Ewma {
    alpha: f64,
    value: f64,
    updated: bool,
}

impl Ewma {
    /// `alpha` in (0, 1]. Recommended: 0.3 for 1-min responsiveness.
    pub fn new(alpha: f64) -> Self {
        assert!((0.0..=1.0).contains(&alpha), "alpha must be in (0, 1]");
        Self {
            alpha,
            value: 0.0,
            updated: false,
        }
    }

    pub fn update(&mut self, sample: f64) {
        if self.updated {
            self.value = self.alpha * sample + (1.0 - self.alpha) * self.value;
        } else {
            self.value = sample;
            self.updated = true;
        }
    }

    pub fn get(&self) -> f64 {
        self.value
    }
}

//Sliding-window ring buffer

//Samples kept for the last `window` duration.
struct Window {
    samples: Vec<(Instant, f64)>,
    window: Duration,
}

impl Window {
    fn new(window: Duration) -> Self {
        Self {
            samples: Vec::new(),
            window,
        }
    }

    fn push(&mut self, value: f64) {
        let now = Instant::now();
        self.prune(now);
        self.samples.push((now, value));
    }

    fn prune(&mut self, now: Instant) {
        let cutoff = now - self.window;
        self.samples.retain(|(t, _)| *t > cutoff);
    }

    fn count(&mut self) -> usize {
        self.prune(Instant::now());
        self.samples.len()
    }

    fn mean(&mut self) -> f64 {
        self.prune(Instant::now());
        if self.samples.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.samples.iter().map(|(_, v)| v).sum();
        sum / self.samples.len() as f64
    }

    fn variance(&mut self) -> f64 {
        self.prune(Instant::now());
        let n = self.samples.len();
        if n < 2 {
            return 0.0;
        }
        let mean = self.mean();
        let var: f64 = self.samples.iter().map(|(_, v)| (v - mean).powi(2)).sum();
        var / (n - 1) as f64
    }
}

//Multi-Windows Stats****

/// Stats snapshot exported to the caller.
#[derive(Debug, Clone, Serialize)]
pub struct WindowStats {
    pub count: usize,
    pub mean: f64,
    pub variance: f64,
    pub std_dev: f64,
}

/// Tracks rolling statistics across 1-min, 5-min and 1-hr windows simultaneously.
pub struct SlidingWindowTracker {
    inner: Mutex<TrackerInner>,
}

struct TrackerInner {
    w1m: Window,
    w5m: Window,
    w1h: Window,
    ewma: Ewma,
}

impl SlidingWindowTracker {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(TrackerInner {
                w1m: Window::new(Duration::from_secs(60)),
                w5m: Window::new(Duration::from_secs(300)),
                w1h: Window::new(Duration::from_secs(3600)),
                ewma: Ewma::new(0.3),
            }),
        }
    }

    pub fn record(&self, value: f64) {
        let mut g = self.inner.lock();
        g.w1m.push(value);
        g.w5m.push(value);
        g.w1h.push(value);
        g.ewma.update(value);
    }

    pub fn stats_1m(&self) -> WindowStats {
        self.stats_for(|g| &mut g.w1m)
    }
    pub fn stats_5m(&self) -> WindowStats {
        self.stats_for(|g| &mut g.w5m)
    }
    pub fn stats_1h(&self) -> WindowStats {
        self.stats_for(|g| &mut g.w1h)
    }

    fn stats_for(&self, pick: impl Fn(&mut TrackerInner) -> &mut Window) -> WindowStats {
        let mut g = self.inner.lock();
        let w = pick(&mut g);
        let count = w.count();
        let mean = w.mean();
        let variance = w.variance();
        WindowStats {
            count,
            mean,
            variance,
            std_dev: variance.sqrt(),
        }
    }

    pub fn ewma_velocity(&self) -> f64 {
        self.inner.lock().ewma.get()
    }
}

impl Default for SlidingWindowTracker {
    fn default() -> Self {
        Self::new()
    }
}

//tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ewma_converges() {
        let mut e = Ewma::new(0.5);
        for _ in 0..20 {
            e.update(10.0);
        }
        assert!((e.get() - 10.0).abs() < 0.01);
    }

    #[test]
    fn ewma_reacts_to_spike() {
        let mut e = Ewma::new(0.5);
        for _ in 0..10 {
            e.update(1.0);
        }
        let baseline = e.get();
        e.update(100.0);
        assert!(e.get() > baseline * 2.0, "EWMA should react to spike");
    }

    #[test]
    fn sliding_window_counts_samples() {
        let t = SlidingWindowTracker::new();
        t.record(1.0);
        t.record(2.0);
        t.record(3.0);
        let s = t.stats_1m();
        assert_eq!(s.count, 3);
        assert!((s.mean - 2.0).abs() < 1e-10);
    }

    #[test]
    fn variance_correct() {
        let t = SlidingWindowTracker::new();
        t.record(2.0);
        t.record(4.0);
        t.record(4.0);
        t.record(4.0);
        t.record(5.0);
        t.record(5.0);
        t.record(7.0);
        t.record(9.0);
        let s = t.stats_1m();
        // sample variance of [2,4,4,4,5,5,7,9] = 4.571...
        assert!((s.variance - 4.571).abs() < 0.01, "variance={}", s.variance);
    }
}
