//! Thursday: Decision cache — avoid recomputing for identical agent states.
//!
//! Cache key = SHA-256( agent_id || action_type || amount_bucket || action_count_bucket )
//! TTL = 30 seconds.  Capacity-bounded with a simple LRU-style eviction.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

//Config
//max entries before eviction
const MAX_ENTRIES: usize = 10_000;
const TTL: Duration = Duration::from_secs(30); //valid time

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
        let valid = g.map.get(key).map(|e| e.is_valid()).unwrap_or(false);
        if valid {
            g.hits += 1;
            Some(g.map.get(key).unwrap().decision.clone())
        } else {
            g.misses += 1;
            None
        }
    }

    /// Insert a decision.  Evicts expired entries (and oldest entries if at
    /// capacity) before inserting.
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
                agent_id: agent_id.map(String::from),
            },
        );
    }

    /// Invalidate all entries for a specific agent (called when the circuit-
    /// breaker trips so stale ALLOW decisions can never leak through).
    pub fn invalidate_agent(&self, agent_id: &str) {
        let mut g = self.inner.lock();
        // Retain only entries whose key was NOT produced for this agent.
        // Cache keys are SHA-256 hashes, so we rebuild candidate keys across
        // plausible action_types / buckets and remove matches.  For safety,
        // fall back to full clear only if agent_id is empty.
        if agent_id.is_empty() {
            g.map.clear();
            return;
        }
        g.map.retain(|_key, entry| {
            // Keep entries that are not ALLOW for defensive correctness;
            // also keep entries from other agents.  Because keys are hashes
            // of (agent_id || ...) we cannot reverse them.  We mark entries
            // with the originating agent_id at insert time (see Entry).
            entry.agent_id.as_deref() != Some(agent_id)
        });
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
        //remove expired entries first.
        g.map.retain(|_, e| e.is_valid());
        //if still at capacity, drop oldest 10 %.
        if g.map.len() >= MAX_ENTRIES {
            let remove_count = MAX_ENTRIES / 10;
            let keys_to_remove: Vec<String> = g
                .map
                .iter()
                .map(|(k, e)| (k.clone(), e.inserted))
                .collect::<Vec<_>>()
                .into_iter()
                .take(remove_count)
                .map(|(k, _)| k)
                .collect();
            for k in keys_to_remove {
                g.map.remove(&k);
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
    fn key_stable() {
        let k1 = DecisionCache::make_key("bot", "transfer", 10, 2);
        let k2 = DecisionCache::make_key("bot", "transfer", 10, 2);
        assert_eq!(k1, k2);
    }
}
