// Minimal Prometheus text (Roadmap E); expand with histograms when OTel lands.
use std::sync::atomic::{AtomicU64, Ordering};

use haltchain_validator::AppState;

static VALIDATE_TOTAL: AtomicU64 = AtomicU64::new(0);

pub fn record_validate() {
    VALIDATE_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn prometheus_text(state: &AppState) -> String {
    let n = VALIDATE_TOTAL.load(Ordering::Relaxed);
    let cache_stats = state.cache_stats();
    let mut text = format!(
        "# HELP haltchain_validate_requests_total POST /validate completions\n\
         # TYPE haltchain_validate_requests_total counter\n\
         haltchain_validate_requests_total {n}\n\
         # HELP haltchain_decision_cache_entries Current in-process validator cache size\n\
         # TYPE haltchain_decision_cache_entries gauge\n\
         haltchain_decision_cache_entries {}\n\
         # HELP haltchain_decision_cache_hits_total Total in-process validator cache hits\n\
         # TYPE haltchain_decision_cache_hits_total counter\n\
         haltchain_decision_cache_hits_total {}\n\
         # HELP haltchain_decision_cache_misses_total Total in-process validator cache misses\n\
         # TYPE haltchain_decision_cache_misses_total counter\n\
         haltchain_decision_cache_misses_total {}\n\
         # HELP haltchain_decision_cache_hit_rate Current in-process validator cache hit rate\n\
         # TYPE haltchain_decision_cache_hit_rate gauge\n\
         haltchain_decision_cache_hit_rate {:.4}\n",
        cache_stats.size, cache_stats.hits, cache_stats.misses, cache_stats.hit_rate,
    );

    if let Some(remote_cache_metrics) = state.remote_cache_metrics_text() {
        text.push_str(&remote_cache_metrics);
    }

    text
}
