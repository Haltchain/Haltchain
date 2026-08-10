//! DragonflyDB / Redis-compatible remote cache client.
//!
//! DragonflyDB implements the Redis protocol in full, so we use the `redis`
//! crate directly.  This module provides:
//!
//! * Async connection pool via `deadpool-redis`  
//! * SHA-256 keyed get/set with typed TTL policies  
//! * Prometheus hit/miss counters  
//! * Automatic in-memory LRU fallback when DragonflyDB is unreachable  
//!
//! # TTL Policy
//!
//! | Policy State | TTL |
//! |---|---|
//! | Static (immutable rule set) | 1 hour |
//! | Dynamic (actively calibrating) | 30 seconds |
//!
//! # Security
//!
//! * Connections use TLS when `DRAGONFLY_TLS=true` is set in the environment.
//! * `FLUSHALL`/`CONFIG SET` are never called by this client.
//! * Bind interface is enforced server-side (see `dragonflydb.conf`).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use deadpool_redis::{Config, Connection, Pool, Runtime};
use redis::AsyncCommands;

use crate::CachedDecision;

// ─── TTL matrix ──────────────────────────────────────────────────────────────

/// TTL for cache entries whose policy set is immutable / fully converged.
pub const TTL_STATIC: Duration = Duration::from_secs(3600); // 1 hour

/// TTL for cache entries under active adaptive calibration.
pub const TTL_DYNAMIC: Duration = Duration::from_secs(30);

/// Represents the policy drift state used to select the appropriate TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyState {
    /// Policy is static / fully converged — use [`TTL_STATIC`].
    Static,
    /// Policy is dynamically adapting — use [`TTL_DYNAMIC`].
    Dynamic,
}

impl PolicyState {
    pub fn ttl(self) -> Duration {
        match self {
            PolicyState::Static => TTL_STATIC,
            PolicyState::Dynamic => TTL_DYNAMIC,
        }
    }
}

// ─── Metrics ─────────────────────────────────────────────────────────────────

/// Lightweight atomic counters exported as Prometheus gauges.
#[derive(Debug, Default)]
pub struct CacheMetrics {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub fallback_activations: AtomicU64,
    pub errors: AtomicU64,
}

impl CacheMetrics {
    pub fn hit_rate(&self) -> f64 {
        let h = self.hits.load(Ordering::Relaxed) as f64;
        let m = self.misses.load(Ordering::Relaxed) as f64;
        if h + m == 0.0 { 0.0 } else { h / (h + m) }
    }

    /// Render metrics in Prometheus text exposition format.
    pub fn prometheus_text(&self) -> String {
        format!(
            "# HELP dragonfly_cache_hits_total Total DragonflyDB cache hits\n\
             # TYPE dragonfly_cache_hits_total counter\n\
             dragonfly_cache_hits_total {}\n\
             # HELP dragonfly_cache_misses_total Total DragonflyDB cache misses\n\
             # TYPE dragonfly_cache_misses_total counter\n\
             dragonfly_cache_misses_total {}\n\
             # HELP dragonfly_cache_fallback_activations_total Times in-memory fallback was activated\n\
             # TYPE dragonfly_cache_fallback_activations_total counter\n\
             dragonfly_cache_fallback_activations_total {}\n\
             # HELP dragonfly_cache_errors_total DragonflyDB client errors\n\
             # TYPE dragonfly_cache_errors_total counter\n\
             dragonfly_cache_errors_total {}\n\
             # HELP dragonfly_cache_hit_rate Current cache hit rate (0.0–1.0)\n\
             # TYPE dragonfly_cache_hit_rate gauge\n\
             dragonfly_cache_hit_rate {:.4}\n",
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
            self.fallback_activations.load(Ordering::Relaxed),
            self.errors.load(Ordering::Relaxed),
            self.hit_rate(),
        )
    }
}

// ─── Serialisation helpers ────────────────────────────────────────────────────

fn serialize_decision(d: &CachedDecision) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(d)
}

fn deserialize_decision(bytes: &[u8]) -> Result<CachedDecision, serde_json::Error> {
    serde_json::from_slice(bytes)
}

// ─── DragonflyClient ─────────────────────────────────────────────────────────

/// Result type used throughout this module.
pub type DragonflyResult<T> = Result<T, DragonflyError>;

/// Errors produced by the DragonflyDB client.
#[derive(Debug, thiserror::Error)]
pub enum DragonflyError {
    #[error("DragonflyDB connection error: {0}")]
    Connection(String),
    #[error("serialisation error: {0}")]
    Serialisation(#[from] serde_json::Error),
    #[error("DragonflyDB unreachable — operating in fallback mode")]
    Unreachable,
}

/// Async DragonflyDB client with connection pooling and in-memory fallback.
///
/// Uses the Redis protocol (DragonflyDB is Redis-compatible).
/// Falls back to the in-process [`crate::DecisionCache`] LRU when the remote
/// instance is unreachable, emitting a telemetry warning on each activation.
pub struct DragonflyClient {
    /// URL of the DragonflyDB instance, e.g. `redis://127.0.0.1:6379`
    pub url: String,
    pub metrics: Arc<CacheMetrics>,
    /// In-memory LRU used as fallback when DragonflyDB is unavailable.
    fallback: Arc<crate::DecisionCache>,
    /// Async Redis-compatible connection pool.
    pool: Option<Pool>,
    /// Whether the last connection attempt succeeded (used for logging).
    connected: AtomicBool,
}

impl DragonflyClient {
    /// Create a new client. Does not open a connection until the first operation.
    ///
    /// `url` should be `redis://127.0.0.1:6379` for local DragonflyDB, or
    /// `rediss://…` for TLS-enabled connections.
    pub fn new(url: impl Into<String>) -> Self {
        let url = url.into();
        let pool = Self::build_pool(&url);
        if pool.is_none() {
            tracing::warn!(url = %url, "failed to initialize DragonflyDB pool; remote cache will fall back to in-memory mode");
        }

        Self {
            url,
            metrics: Arc::new(CacheMetrics::default()),
            fallback: Arc::new(crate::DecisionCache::new()),
            pool,
            connected: AtomicBool::new(false),
        }
    }

    fn build_pool(url: &str) -> Option<Pool> {
        let cfg = Config::from_url(url);
        cfg.create_pool(Some(Runtime::Tokio1)).ok()
    }

    async fn pool_connection(&self) -> DragonflyResult<Connection> {
        let pool = self.pool.as_ref().ok_or_else(|| {
            DragonflyError::Connection("DragonflyDB pool is not configured".to_string())
        })?;

        pool.get()
            .await
            .map_err(|e| DragonflyError::Connection(e.to_string()))
    }

    #[cfg(test)]
    fn pool_is_configured(&self) -> bool {
        self.pool.is_some()
    }

    /// Attempt to get a decision from DragonflyDB.
    ///
    /// On failure (connection refused / timeout) activates in-memory fallback
    /// and records a `fallback_activations` metric increment.
    pub async fn get(&self, key: &str) -> Option<CachedDecision> {
        match self.remote_get(key).await {
            Ok(Some(v)) => {
                self.metrics.hits.fetch_add(1, Ordering::Relaxed);
                Some(v)
            }
            Ok(None) => {
                self.metrics.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
            Err(_) => {
                self.metrics.errors.fetch_add(1, Ordering::Relaxed);
                self.activate_fallback();
                // Try in-memory fallback.
                self.fallback.get(key)
            }
        }
    }

    /// Store a decision in DragonflyDB with the given TTL.
    ///
    /// If DragonflyDB is unavailable, stores in the in-memory fallback.
    pub async fn set(&self, key: &str, decision: &CachedDecision, policy: PolicyState) {
        let ttl = policy.ttl();
        if self.remote_set(key, decision, ttl).await.is_err() {
            self.activate_fallback();
            self.fallback.insert(key.to_string(), decision.clone());
        }
    }

    fn activate_fallback(&self) {
        let already = self.connected.swap(false, Ordering::Relaxed);
        if already {
            // Only warn once per transition connected→disconnected.
            tracing::warn!(
                url = %self.url,
                "DragonflyDB unreachable — activating in-memory LRU fallback"
            );
        }
        self.metrics
            .fallback_activations
            .fetch_add(1, Ordering::Relaxed);
    }

    // ─── Redis calls via connection pool ──────────────────────────────────

    async fn remote_get(&self, key: &str) -> DragonflyResult<Option<CachedDecision>> {
        let mut conn = self.pool_connection().await?;
        let payload: Option<Vec<u8>> = conn
            .get(key)
            .await
            .map_err(|e| DragonflyError::Connection(e.to_string()))?;

        self.connected.store(true, Ordering::Relaxed);

        match payload {
            Some(bytes) => Ok(Some(deserialize_decision(&bytes)?)),
            None => Ok(None),
        }
    }

    async fn remote_set(
        &self,
        key: &str,
        decision: &CachedDecision,
        ttl: Duration,
    ) -> DragonflyResult<()> {
        let mut conn = self.pool_connection().await?;
        let payload = serialize_decision(decision)?;
        let _: () = conn
            .set_ex(key, payload, ttl.as_secs())
            .await
            .map_err(|e| DragonflyError::Connection(e.to_string()))?;

        self.connected.store(true, Ordering::Relaxed);
        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_decision() -> CachedDecision {
        CachedDecision {
            decision: "allow".to_string(),
            circuit_breaker_active: false,
            reason: None,
            policy: Some("test".to_string()),
            rate_limit: 100,
        }
    }

    #[test]
    fn policy_state_ttl_matrix() {
        assert_eq!(PolicyState::Static.ttl(), TTL_STATIC);
        assert_eq!(PolicyState::Dynamic.ttl(), TTL_DYNAMIC);
        assert!(
            TTL_STATIC > TTL_DYNAMIC,
            "static TTL must exceed dynamic TTL"
        );
    }

    #[test]
    fn metrics_hit_rate_zero_when_no_ops() {
        let m = CacheMetrics::default();
        assert_eq!(m.hit_rate(), 0.0);
    }

    #[test]
    fn metrics_hit_rate_calculation() {
        let m = CacheMetrics::default();
        m.hits.store(80, Ordering::Relaxed);
        m.misses.store(20, Ordering::Relaxed);
        assert!((m.hit_rate() - 0.8).abs() < 1e-9);
    }

    #[test]
    fn metrics_prometheus_text_contains_expected_keys() {
        let m = CacheMetrics::default();
        m.hits.store(10, Ordering::Relaxed);
        let text = m.prometheus_text();
        assert!(text.contains("dragonfly_cache_hits_total 10"));
        assert!(text.contains("dragonfly_cache_hit_rate"));
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let d = sample_decision();
        let bytes = serialize_decision(&d).unwrap();
        let d2 = deserialize_decision(&bytes).unwrap();
        assert_eq!(d.decision, d2.decision);
        assert_eq!(d.circuit_breaker_active, d2.circuit_breaker_active);
    }

    #[test]
    fn client_initializes_connection_pool_for_valid_url() {
        let client = DragonflyClient::new("redis://127.0.0.1:6379");
        assert!(client.pool_is_configured());
    }

    #[tokio::test]
    async fn fallback_activates_on_connection_failure() {
        // Use an address guaranteed to be unreachable in CI.
        let client = DragonflyClient::new("redis://127.0.0.1:16399");
        // First get → will fail → fallback activated.
        let result = client.get("nonexistent-key").await;
        assert!(result.is_none(), "key not in fallback cache");
        assert!(
            client.metrics.errors.load(Ordering::Relaxed) > 0,
            "error counter must increment on connection failure"
        );
        assert!(
            client.metrics.fallback_activations.load(Ordering::Relaxed) > 0,
            "fallback activation counter must increment"
        );
    }

    #[tokio::test]
    async fn fallback_stores_and_retrieves_decision() {
        let client = DragonflyClient::new("redis://127.0.0.1:16399");
        let d = sample_decision();
        // set → goes to fallback (DragonflyDB unreachable)
        client.set("key1", &d, PolicyState::Static).await;
        // get → retrieves from fallback
        let result = client.get("key1").await;
        assert!(result.is_some());
        let got = result.unwrap();
        assert_eq!(got.decision, "allow");
    }
}
