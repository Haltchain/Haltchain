//! Redis-backed L2 embedding cache for cross-instance sharing.
//!
//! Architecture:
//!   L1 = In-process LRU (in OnnxModel, ~0μs)
//!   L2 = Redis (this module, ~1ms LAN)
//!   L3 = ONNX inference (~7ms/trace)
//!
//! Embeddings are deterministic for a given model+text, so they can be
//! cached aggressively. The key includes a version prefix so that model
//! upgrades automatically invalidate stale entries.
//!
//! Feature-gated behind `redis-cache`. Gracefully degrades if Redis is
//! unreachable — never blocks or panics the safety pipeline.

use redis::{Client, Commands, Connection};
use tracing::warn;

/// Key prefix — bump version when the model changes (e.g., INT8 vs FP32,
/// or model architecture upgrade) to avoid returning stale embeddings.
const KEY_PREFIX: &str = "haltchain:emb:v1";

/// TTL for cached embeddings. 24 hours — embeddings are deterministic for
/// the same model, but TTL prevents unbounded growth on Redis.
const TTL_SECS: u64 = 86_400;

/// Embedding dimension for Snowflake Arctic Embed 2.0 Large.
const EMBED_DIMS: usize = 1024;

pub struct RedisEmbeddingCache {
    conn: Connection,
}

impl RedisEmbeddingCache {
    /// Try to connect to Redis. Returns `None` if unreachable (graceful degradation).
    ///
    /// Reads `HALTCHAIN_REDIS_URL` env var, falling back to `redis://127.0.0.1:6379`.
    pub fn connect() -> Option<Self> {
        let url = std::env::var("HALTCHAIN_REDIS_URL")
            .or_else(|_| std::env::var("REDIS_URL"))
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

        Self::connect_to(&url)
    }

    /// Connect to a specific Redis URL.
    pub fn connect_to(url: &str) -> Option<Self> {
        let client = Client::open(url).ok()?;
        let conn = client.get_connection().ok()?;
        Some(Self { conn })
    }

    /// Look up a single embedding by text hash.
    pub fn get(&mut self, text_hash: u64) -> Option<Vec<f64>> {
        let key = format!("{KEY_PREFIX}:{text_hash:016x}");
        let bytes: Vec<u8> = self.conn.get(&key).ok()?;
        deserialize_embedding(&bytes)
    }

    /// Store a single embedding.
    pub fn put(&mut self, text_hash: u64, embedding: &[f64]) {
        let key = format!("{KEY_PREFIX}:{text_hash:016x}");
        let bytes = serialize_embedding(embedding);
        if let Err(e) = self.conn.set_ex::<_, _, ()>(&key, &bytes[..], TTL_SECS) {
            warn!("Redis embedding cache PUT failed: {e}");
        }
    }

    /// Batch lookup: returns found embeddings keyed by hash.
    /// Missing hashes are simply absent from the result.
    pub fn get_batch(&mut self, hashes: &[u64]) -> Vec<(usize, Vec<f64>)> {
        if hashes.is_empty() {
            return Vec::new();
        }

        let keys: Vec<String> = hashes
            .iter()
            .map(|h| format!("{KEY_PREFIX}:{h:016x}"))
            .collect();

        // MGET returns Vec<Option<Vec<u8>>>
        let results: Vec<Option<Vec<u8>>> =
            match redis::cmd("MGET").arg(&keys).query(&mut self.conn) {
                Ok(r) => r,
                Err(e) => {
                    warn!("Redis embedding cache MGET failed: {e}");
                    return Vec::new();
                }
            };

        results
            .into_iter()
            .enumerate()
            .filter_map(|(i, opt)| {
                opt.and_then(|bytes| deserialize_embedding(&bytes).map(|emb| (i, emb)))
            })
            .collect()
    }

    /// Batch store embeddings. Uses a pipeline for efficiency.
    pub fn put_batch(&mut self, entries: &[(u64, &[f64])]) {
        if entries.is_empty() {
            return;
        }

        let mut pipe = redis::pipe();
        for (hash, embedding) in entries {
            let key = format!("{KEY_PREFIX}:{hash:016x}");
            let bytes = serialize_embedding(embedding);
            pipe.cmd("SETEX")
                .arg(&key)
                .arg(TTL_SECS)
                .arg(bytes)
                .ignore();
        }

        if let Err(e) = pipe.query::<()>(&mut self.conn) {
            warn!("Redis embedding cache pipeline PUT failed: {e}");
        }
    }
}

/// Serialize embedding as raw little-endian f64 bytes (1024 × 8 = 8192 bytes).
/// Compact and zero-copy on decode.
fn serialize_embedding(embedding: &[f64]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(embedding.len() * 8);
    for &val in embedding {
        buf.extend_from_slice(&val.to_le_bytes());
    }
    buf
}

/// Deserialize raw bytes back to f64 vector.
fn deserialize_embedding(bytes: &[u8]) -> Option<Vec<f64>> {
    if bytes.len() != EMBED_DIMS * 8 {
        return None;
    }
    let mut embedding = Vec::with_capacity(EMBED_DIMS);
    for chunk in bytes.chunks_exact(8) {
        embedding.push(f64::from_le_bytes(chunk.try_into().ok()?));
    }
    Some(embedding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_roundtrip() {
        let original: Vec<f64> = (0..EMBED_DIMS).map(|i| i as f64 * 0.001).collect();
        let bytes = serialize_embedding(&original);
        assert_eq!(bytes.len(), EMBED_DIMS * 8);
        let decoded = deserialize_embedding(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn deserialize_rejects_wrong_size() {
        assert!(deserialize_embedding(&[0u8; 100]).is_none());
        assert!(deserialize_embedding(&[]).is_none());
    }
}
