//! Thursday: Decision cache — avoid recomputing for identical agent states.
//!
//! Cache key = SHA-256( agent_id || action_type || amount_bucket || action_count_bucket )
//! TTL = 30 seconds.  Capacity-bounded with a simple LRU-style eviction.

pub mod dragonfly_client;

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// Config.
#[cfg(not(test))]
const MAX_ENTRIES: usize = 10_000;
#[cfg(test)]
const MAX_ENTRIES: usize = 64;

#[cfg(not(test))]
const TTL: Duration = Duration::from_secs(30);
#[cfg(test)]
const TTL: Duration = Duration::from_millis(25);

//cached decision

//slice of bytes from validation response to avoid pull all from crates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedDecision {
    pub decision: String,
    pub circuit_breaker_active: bool,
    pub reason: Option<String>,
    pub policy: Option<String>,
    pub rate_limit: usize,
}
struct Entry {
    decision: CachedDecision,
    inserted: Instant,
    last_accessed: Instant,
    agent_id: Option<String>,
}

impl Entry {
    fn is_valid(&self) -> bool {
        self.inserted.elapsed() < TTL
    }
}

//cache
pub struct DecisionCache {
    inner: Mutex<Inner>,
}
struct Inner {
    map: HashMap<String, Entry>,
    hits: u64,
    misses: u64,
}
//cache stats
#[derive(Debug, Clone, Serialize)]
pub struct CacheStats {
    pub size: usize,
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f64,
}
impl DecisionCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                map: HashMap::with_capacity(MAX_ENTRIES),
                hits: 0,
                misses: 0,
            }),
        }
    }

    /// Derive a stable cache key from request fields that fully determine the decision.
    ///
    /// `action_count_bucket` quantises the sliding-window count into bands of 2
    /// so that e.g. 3 and 4 actions map to the same key (avoids over-invalidation).
    pub fn make_key(
        agent_id: &str,
        action_type: &str,
        amount_bucket: i64,         // floor(amount / 100)
        action_count_bucket: usize, // floor(count / 2)
    ) -> String {
        let mut h = Sha256::new();
        h.update(agent_id.as_bytes());
        h.update(b"|");
        h.update(action_type.as_bytes());
        h.update(b"|");
        h.update(amount_bucket.to_le_bytes());
        h.update(b"|");
        h.update(action_count_bucket.to_le_bytes());
        hex::encode(h.finalize())
    }

    /// Returns the cached decision if it exists and has not expired.
    pub fn get(&self, key: &str) -> Option<CachedDecision> {
        let mut g = self.inner.lock();
        let mut hit: Option<CachedDecision> = None;
        let mut expired = false;

        if let Some(entry) = g.map.get_mut(key) {
            if entry.is_valid() {
                entry.last_accessed = Instant::now();
                hit = Some(entry.decision.clone());
            } else {
                expired = true;
            }
        }

        if let Some(decision) = hit {
            g.hits += 1;
            return Some(decision);
        }

        if expired {
            // Expired entries are removed eagerly on read.
            g.map.remove(key);
        }

        g.misses += 1;
        None
    }

    /// Insert a decision. Evicts expired entries (and least-recently-used
    /// entries if at capacity) before inserting.
    pub fn insert(&self, key: String, decision: CachedDecision) {
        self.insert_for(key, decision, None)
    }

    /// Insert a decision tagged with the originating agent_id for targeted
    /// invalidation.
    pub fn insert_for(&self, key: String, decision: CachedDecision, agent_id: Option<&str>) {
        let mut g = self.inner.lock();
        Self::evict(&mut g);
        g.map.insert(
            key,
            Entry {
                decision,
                inserted: Instant::now(),
                last_accessed: Instant::now(),
                agent_id: agent_id.map(String::from),
            },
        );
    }

    /// Invalidate all entries for a specific agent (called when the circuit-
    /// breaker trips so stale ALLOW decisions can never leak through).
    pub fn invalidate_agent(&self, agent_id: &str) {
        let mut g = self.inner.lock();
        if agent_id.is_empty() {
            g.map.clear();
            return;
        }
        g.map
            .retain(|_key, entry| entry.agent_id.as_deref() != Some(agent_id));
    }

    pub fn stats(&self) -> CacheStats {
        let g = self.inner.lock();
        let total = g.hits + g.misses;
        CacheStats {
            size: g.map.len(),
            hits: g.hits,
            misses: g.misses,
            hit_rate: if total == 0 {
                0.0
            } else {
                g.hits as f64 / total as f64
            },
        }
    }

    fn evict(g: &mut Inner) {
        // Remove expired entries first.
        g.map.retain(|_, e| e.is_valid());

        // If still at capacity, remove true LRU entries by last access tick.
        if g.map.len() >= MAX_ENTRIES {
            let remove_count = (MAX_ENTRIES / 10).max(1);
            let mut by_age: Vec<(String, Instant)> = g
                .map
                .iter()
                .map(|(k, e)| (k.clone(), e.last_accessed))
                .collect();
            by_age.sort_by_key(|(_, accessed)| *accessed);
            for (key, _) in by_age.into_iter().take(remove_count) {
                g.map.remove(&key);
            }
        }
    }
}

impl Default for DecisionCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow() -> CachedDecision {
        CachedDecision {
            decision: "ALLOW".into(),
            rate_limit: 60,
            circuit_breaker_active: false,
            reason: None,
            policy: None,
        }
    }

    #[test]
    fn basic_hit_miss() {
        let c = DecisionCache::new();
        let key = DecisionCache::make_key("agent1", "transfer", 5, 0);
        assert!(c.get(&key).is_none());
        c.insert(key.clone(), allow());
        assert!(c.get(&key).is_some());
        let s = c.stats();
        assert_eq!(s.hits, 1);
        assert_eq!(s.misses, 1);
    }

    #[test]
    fn different_buckets_different_keys() {
        let k1 = DecisionCache::make_key("a1", "transfer", 5, 0);
        let k2 = DecisionCache::make_key("a1", "transfer", 6, 0);
        assert_ne!(k1, k2);
    }

    #[test]
    fn different_action_types_different_keys() {
        let k1 = DecisionCache::make_key("a1", "transfer", 5, 0);
        let k2 = DecisionCache::make_key("a1", "withdraw", 5, 0);
        assert_ne!(k1, k2);
    }

    #[test]
    fn different_agents_different_keys() {
        let k1 = DecisionCache::make_key("agent-1", "transfer", 5, 0);
        let k2 = DecisionCache::make_key("agent-2", "transfer", 5, 0);
        assert_ne!(k1, k2);
    }

    #[test]
    fn key_stable() {
        let k1 = DecisionCache::make_key("bot", "transfer", 10, 2);
        let k2 = DecisionCache::make_key("bot", "transfer", 10, 2);
        assert_eq!(k1, k2);
    }

    #[test]
    fn overwrite_existing_key_returns_latest_value() {
        let c = DecisionCache::new();
        let key = DecisionCache::make_key("agent-ow", "transfer", 5, 0);
        c.insert(key.clone(), allow());
        let deny = CachedDecision {
            decision: "DENY".into(),
            rate_limit: 0,
            circuit_breaker_active: true,
            reason: Some("overwritten".into()),
            policy: None,
        };
        c.insert(key.clone(), deny);
        let got = c.get(&key).expect("must hit");
        assert_eq!(got.decision, "DENY");
        assert!(got.circuit_breaker_active);
    }

    #[test]
    fn empty_cache_stats_are_zero() {
        let c = DecisionCache::new();
        let s = c.stats();
        assert_eq!(s.size, 0);
        assert_eq!(s.hits, 0);
        assert_eq!(s.misses, 0);
        assert!((s.hit_rate - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn hit_rate_calculation_accuracy() {
        let c = DecisionCache::new();
        let key = DecisionCache::make_key("hr", "transfer", 1, 0);
        c.insert(key.clone(), allow());
        // 3 hits
        for _ in 0..3 {
            assert!(c.get(&key).is_some());
        }
        // 1 miss
        assert!(c.get("nonexistent").is_none());
        let s = c.stats();
        assert_eq!(s.hits, 3);
        assert_eq!(s.misses, 1);
        assert!((s.hit_rate - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn insert_for_tags_agent_and_invalidation_clears_only_that_agent() {
        let c = DecisionCache::new();
        let k1 = DecisionCache::make_key("a", "x", 0, 0);
        let k2 = DecisionCache::make_key("b", "x", 0, 0);
        let k3 = DecisionCache::make_key("a", "y", 1, 0);
        c.insert_for(k1.clone(), allow(), Some("a"));
        c.insert_for(k2.clone(), allow(), Some("b"));
        c.insert_for(k3.clone(), allow(), Some("a"));

        c.invalidate_agent("a");
        assert!(c.get(&k1).is_none(), "agent-a entry should be gone");
        assert!(c.get(&k3).is_none(), "agent-a second entry should be gone");
        assert!(c.get(&k2).is_some(), "agent-b entry should survive");
    }

    #[test]
    fn invalidate_empty_agent_id_clears_all() {
        let c = DecisionCache::new();
        for i in 0..5 {
            let k = DecisionCache::make_key("agent", "t", i, 0);
            c.insert_for(k, allow(), Some("agent"));
        }
        assert_eq!(c.stats().size, 5);
        c.invalidate_agent("");
        assert_eq!(c.stats().size, 0);
    }

    #[test]
    fn concurrent_insert_and_get() {
        use std::sync::Arc;
        let c = Arc::new(DecisionCache::new());
        let mut handles = Vec::new();
        for t in 0..4 {
            let cache = Arc::clone(&c);
            handles.push(std::thread::spawn(move || {
                for i in 0..16 {
                    let key = DecisionCache::make_key(&format!("t{t}"), "transfer", i, 0);
                    cache.insert(
                        key.clone(),
                        CachedDecision {
                            decision: "ALLOW".into(),
                            rate_limit: 60,
                            circuit_breaker_active: false,
                            reason: None,
                            policy: None,
                        },
                    );
                    let _ = cache.get(&key);
                }
            }));
        }
        for h in handles {
            h.join().expect("thread should not panic");
        }
        // All threads completed without deadlock or panic
        assert!(c.stats().size <= MAX_ENTRIES);
    }

    #[test]
    fn ttl_expiry_is_cleaned_on_read() {
        let c = DecisionCache::new();
        let key = DecisionCache::make_key("agent-ttl", "transfer", 5, 0);
        c.insert(key.clone(), allow());

        std::thread::sleep(TTL + Duration::from_millis(10));

        assert!(c.get(&key).is_none());
        let s = c.stats();
        assert_eq!(s.size, 0);
    }

    #[test]
    fn invalidate_agent_removes_only_target_agent_entries() {
        let c = DecisionCache::new();
        let k1 = DecisionCache::make_key("agent-a", "transfer", 1, 0);
        let k2 = DecisionCache::make_key("agent-b", "transfer", 1, 0);

        c.insert_for(k1.clone(), allow(), Some("agent-a"));
        c.insert_for(k2.clone(), allow(), Some("agent-b"));

        c.invalidate_agent("agent-a");

        assert!(c.get(&k1).is_none());
        assert!(c.get(&k2).is_some());
    }

    #[test]
    fn evicts_least_recently_used_entry_when_over_capacity() {
        let c = DecisionCache::new();

        let protected_key = DecisionCache::make_key("agent-hot", "transfer", 0, 0);
        c.insert(protected_key.clone(), allow());

        for i in 1..MAX_ENTRIES {
            let k = DecisionCache::make_key("agent-cold", "transfer", i as i64, 0);
            c.insert(k, allow());
        }

        // Refresh recency right before the overflow insert triggers eviction.
        assert!(c.get(&protected_key).is_some());

        let overflow_key = DecisionCache::make_key("agent-overflow", "transfer", 9_999, 0);
        c.insert(overflow_key, allow());

        // The recently accessed key should survive an LRU eviction pass.
        assert!(c.get(&protected_key).is_some());
    }
}
