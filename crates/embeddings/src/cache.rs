//! Embedding cache with LRU eviction (Weekend: perf optimisation).
//!
//! Uses SHA-256 of the input text as the map key so the raw text is
//! never stored, reducing memory footprint.

use std::collections::{HashMap, VecDeque};

use parking_lot::Mutex;
use sha2::{Digest, Sha256};

pub const DEFAULT_CACHE_CAP: usize = 1_000;

struct CacheInner {
    map: HashMap<String, Vec<f64>>,
    order: VecDeque<String>,
    capacity: usize,
    hits: u64,
    misses: u64,
}

impl CacheInner {
    fn new(capacity: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            capacity,
            hits: 0,
            misses: 0,
        }
    }

    fn get(&mut self, key: &str) -> Option<Vec<f64>> {
        if let Some(v) = self.map.get(key) {
            self.hits += 1;
            Some(v.clone())
        } else {
            self.misses += 1;
            None
        }
    }

    fn insert(&mut self, key: String, vec: Vec<f64>) {
        if self.map.contains_key(&key) {
            return;
        }
        if self.map.len() >= self.capacity {
            // Evict oldest
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
            }
        }
        self.order.push_back(key.clone());
        self.map.insert(key, vec);
    }
}

pub struct EmbeddingCache(Mutex<CacheInner>);

#[derive(Debug)]
pub struct CacheStats {
    pub size: usize,
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f64,
}

impl EmbeddingCache {
    pub fn new(capacity: usize) -> Self {
        Self(Mutex::new(CacheInner::new(capacity)))
    }

    pub fn get(&self, text: &str) -> Option<Vec<f64>> {
        let key = Self::key(text);
        self.0.lock().get(&key)
    }

    pub fn insert(&self, text: &str, vec: Vec<f64>) {
        let key = Self::key(text);
        self.0.lock().insert(key, vec);
    }

    pub fn stats(&self) -> CacheStats {
        let g = self.0.lock();
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

    fn key(text: &str) -> String {
        hex::encode(Sha256::digest(text.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_miss_basic() {
        let c = EmbeddingCache::new(100);
        assert!(c.get("hello world").is_none());
        c.insert("hello world", vec![0.1, 0.2]);
        assert_eq!(c.get("hello world"), Some(vec![0.1, 0.2]));
        let s = c.stats();
        assert_eq!(s.hits, 1);
        assert_eq!(s.misses, 1);
    }

    #[test]
    fn lru_eviction_at_capacity() {
        let c = EmbeddingCache::new(2);
        c.insert("a", vec![1.0]);
        c.insert("b", vec![2.0]);
        c.insert("c", vec![3.0]); // evicts "a"
        assert!(c.get("a").is_none());
        assert!(c.get("b").is_some());
        assert!(c.get("c").is_some());
    }

    #[test]
    fn duplicate_inserts_do_not_grow() {
        let c = EmbeddingCache::new(100);
        c.insert("x", vec![1.0]);
        c.insert("x", vec![2.0]);
        assert_eq!(c.stats().size, 1);
    }
}
