//! Embedding model abstraction.
//!
//! Three backends:
//!   * [`LocalModel`]  — ONNX transformer-based, fully offline, privacy-preserving.
//!   * [`HashModel`]   — Legacy hash-projection (fallback, NOT semantic).
//!   * [`RemoteModel`] — OpenAI-compatible `/v1/embeddings` HTTP endpoint.
//!
//! Use [`ModelKind`] as the concrete type to avoid `dyn` indirection.

use async_trait::async_trait;
use parking_lot::Mutex;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;

// Import ONNX model
pub use crate::onnx_model::{OnnxError, OnnxModel, DEFAULT_ONNX_DIMS};

#[cfg(feature = "redis-cache")]
use crate::redis_cache::RedisEmbeddingCache;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum EmbedError {
    #[error("HTTP request failed: {0}")]
    Http(String),
    #[error("response parse error: {0}")]
    Parse(String),
    #[error("empty response from model")]
    Empty,
    #[error("ONNX error: {0}")]
    Onnx(#[from] OnnxError),
}

// ─── Trait ────────────────────────────────────────────────────────────────────

#[async_trait]
pub trait EmbeddingModel: Send + Sync {
    /// Embed a batch of texts.  Implementations should preserve input order.
    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f64>>, EmbedError>;

    fn dims(&self) -> usize;

    async fn embed_one(&self, text: &str) -> Result<Vec<f64>, EmbedError> {
        self.embed_batch(&[text])
            .await?
            .into_iter()
            .next()
            .ok_or(EmbedError::Empty)
    }
}

// ─── Local model (ONNX transformer-based) ─────────────────────────────────────

pub const LOCAL_DIMS: usize = DEFAULT_ONNX_DIMS;

/// Semantic embedding model using ONNX Runtime.
/// 
/// Uses all-MiniLM-L6-v2 (22MB, 384-dim) for high-quality semantic embeddings.
/// This is the PRIMARY model for production use against rogue AGI.
/// 
/// Internally caches the ONNX model as a singleton to avoid repeated disk loads
/// when multiple instances are created (e.g., in test helpers).
pub struct LocalModel {
    onnx: Arc<Mutex<OnnxModel>>,
    #[cfg(feature = "redis-cache")]
    redis: Option<Arc<Mutex<RedisEmbeddingCache>>>,
}

/// Global cache for the ONNX model to avoid repeated disk loads.
static ONNX_SINGLETON: std::sync::OnceLock<Arc<Mutex<OnnxModel>>> = std::sync::OnceLock::new();

/// Global cache for Redis connection (shared across LocalModel instances).
#[cfg(feature = "redis-cache")]
static REDIS_SINGLETON: std::sync::OnceLock<Option<Arc<Mutex<RedisEmbeddingCache>>>> =
    std::sync::OnceLock::new();

impl LocalModel {
    /// Load from cache directory.
    /// 
    /// Uses a process-wide singleton to avoid repeated disk loads when
    /// multiple LocalModel instances are created (common in test helpers).
    /// 
    /// When compiled with `redis-cache`, automatically connects to Redis
    /// for L2 embedding cache (env: `HALTCHAIN_REDIS_URL` or `REDIS_URL`,
    /// defaults to `redis://127.0.0.1:6379`). Gracefully degrades if
    /// Redis is unavailable.
    pub fn new() -> Result<Self, EmbedError> {
        // Fast path: reuse cached model
        if let Some(cached) = ONNX_SINGLETON.get() {
            return Ok(Self {
                onnx: cached.clone(),
                #[cfg(feature = "redis-cache")]
                redis: Self::get_redis(),
            });
        }
        
        // Slow path: load from disk and cache
        let onnx = Self::load_from_disk()?;
        let shared = Arc::new(Mutex::new(onnx));
        // If another thread raced us, use theirs instead
        let shared = ONNX_SINGLETON.get_or_init(|| shared.clone()).clone();
        Ok(Self {
            onnx: shared,
            #[cfg(feature = "redis-cache")]
            redis: Self::get_redis(),
        })
    }
    
    fn load_from_disk() -> Result<OnnxModel, EmbedError> {
        let mut cache_dirs: Vec<Option<PathBuf>> = vec![
            // Prefer INT8 quantized models for lower latency
            dirs::home_dir().map(|d| d.join(".cache").join("haltchain").join("models_int8")),
            dirs::cache_dir().map(|d| d.join("haltchain").join("models_int8")),
            // Fall back to FP32 models
            dirs::home_dir().map(|d| d.join(".cache").join("haltchain").join("models")),
            dirs::cache_dir().map(|d| d.join("haltchain").join("models")),
            Some(PathBuf::from("./models")),
            Some(PathBuf::from("../models")),
            Some(PathBuf::from("../../models")),
        ];

        if let Ok(env_dir) = std::env::var("HALTCHAIN_MODEL_DIR") {
            cache_dirs.insert(0, Some(PathBuf::from(env_dir)));
        }

        for dir in &cache_dirs {
            if let Some(dir) = dir {
                if dir.exists() {
                    if let Ok(onnx) = OnnxModel::from_dir(dir) {
                        return Ok(onnx);
                    }
                }
            }
        }

        eprintln!("ONNX model not found. Searched in:");
        for dir in &cache_dirs {
            if let Some(d) = dir {
                eprintln!("  - {}", d.display());
            }
        }
        eprintln!("\nDownload with: ./download_model.sh");
        eprintln!("Or set HALTCHAIN_MODEL_DIR environment variable.");

        Err(EmbedError::Onnx(OnnxError::ModelNotFound(
            "Could not find ONNX model in any cache directory".to_string()
        )))
    }

    #[cfg(feature = "redis-cache")]
    fn get_redis() -> Option<Arc<Mutex<RedisEmbeddingCache>>> {
        REDIS_SINGLETON
            .get_or_init(|| {
                RedisEmbeddingCache::connect().map(|r| Arc::new(Mutex::new(r)))
            })
            .clone()
    }

    /// Load from specific directory.
    pub fn from_dir(path: impl Into<PathBuf>) -> Result<Self, EmbedError> {
        let onnx = OnnxModel::from_dir(path.into())?;
        Ok(Self {
            onnx: Arc::new(Mutex::new(onnx)),
            #[cfg(feature = "redis-cache")]
            redis: Self::get_redis(),
        })
    }

    /// Download model from HuggingFace if not present.
    pub async fn download(cache_dir: impl AsRef<std::path::Path>) -> Result<PathBuf, EmbedError> {
        OnnxModel::download(cache_dir).await.map_err(EmbedError::Onnx)
    }

    /// Embed a single text (synchronous for convenience).
    ///
    /// Cache hierarchy: L1 (in-process) → L2 (Redis, if enabled) → ONNX inference.
    pub fn embed_text(&self, text: &str) -> Vec<f64> {
        #[cfg(feature = "redis-cache")]
        {
            let hash = OnnxModel::hash_text(text);
            // Check Redis L2 before taking the ONNX lock
            if let Some(redis) = &self.redis {
                if let Some(cached) = redis.lock().get(hash) {
                    return cached;
                }
            }
            let embedding = self.onnx.lock().embed_text(text);
            // Write-through to Redis
            if let Some(redis) = &self.redis {
                redis.lock().put(hash, &embedding);
            }
            return embedding;
        }
        #[cfg(not(feature = "redis-cache"))]
        self.onnx.lock().embed_text(text)
    }

    /// Embed multiple texts synchronously in a single batch.
    ///
    /// Much more efficient than calling `embed_text` in a loop because
    /// ONNX Runtime can parallelise across the batch dimension.
    /// When Redis L2 is enabled, batch-checks Redis for misses before inference.
    pub fn embed_batch_sync(&self, texts: &[&str]) -> Vec<Vec<f64>> {
        #[cfg(feature = "redis-cache")]
        {
            if let Some(redis) = &self.redis {
                let hashes: Vec<u64> = texts.iter().map(|t| OnnxModel::hash_text(t)).collect();
                let redis_hits = redis.lock().get_batch(&hashes);

                // If all found in Redis, skip ONNX entirely
                if redis_hits.len() == texts.len() {
                    let mut results = vec![Vec::new(); texts.len()];
                    for (idx, emb) in redis_hits {
                        results[idx] = emb;
                    }
                    return results;
                }

                // Partial hits — compute misses via ONNX
                let hit_set: std::collections::HashSet<usize> =
                    redis_hits.iter().map(|(i, _)| *i).collect();
                let miss_texts: Vec<&str> = texts
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| !hit_set.contains(i))
                    .map(|(_, t)| *t)
                    .collect();
                let miss_indices: Vec<usize> = (0..texts.len())
                    .filter(|i| !hit_set.contains(i))
                    .collect();

                let computed = self.onnx.lock().embed_batch(&miss_texts);

                // Assemble results
                let mut results = vec![Vec::new(); texts.len()];
                for (idx, emb) in redis_hits {
                    results[idx] = emb;
                }
                for (j, emb) in computed.into_iter().enumerate() {
                    let idx = miss_indices[j];
                    results[idx] = emb;
                }
                // Write-through misses to Redis
                let puts: Vec<(u64, &[f64])> = miss_indices
                    .iter()
                    .map(|&idx| (hashes[idx], results[idx].as_slice()))
                    .collect();
                if !puts.is_empty() {
                    redis.lock().put_batch(&puts);
                }
                return results;
            }
        }
        self.onnx.lock().embed_batch(texts)
    }

    /// Compute semantic similarity.
    pub fn similarity(&self, text1: &str, text2: &str) -> f64 {
        self.onnx.lock().similarity(text1, text2)
    }
}

#[async_trait]
impl EmbeddingModel for LocalModel {
    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f64>>, EmbedError> {
        Ok(self.onnx.lock().embed_batch(texts))
    }

    fn dims(&self) -> usize {
        LOCAL_DIMS
    }
}

impl Default for LocalModel {
    fn default() -> Self {
        // Fallback to hash model if ONNX not available
        Self::new().expect("Failed to load LocalModel. Run model download or check paths.")
    }
}

// ─── Hash model (legacy, non-semantic fallback) ───────────────────────────────

/// Hash-projection model - NOT semantic, used only as emergency fallback.
/// 
/// ⚠️ WARNING: This model does NOT understand meaning. It only matches
/// exact or near-exact keyword overlaps. Do not use for security-critical
/// applications against sophisticated adversaries.
pub struct HashModel {
    dims: usize,
}

impl HashModel {
    pub fn new(dims: usize) -> Self {
        Self { dims }
    }

    pub fn embed_text(&self, text: &str) -> Vec<f64> {
        let tokens = tokenize_with_hints(text);
        let mut agg = vec![0.0f64; self.dims];
        for token in &tokens {
            let proj = token_projection(token, self.dims);
            for (a, p) in agg.iter_mut().zip(proj.iter()) {
                *a += p;
            }
            for ngram in token_ngrams(token, 3) {
                let proj = token_projection(&format!("ng:{ngram}"), self.dims);
                for (a, p) in agg.iter_mut().zip(proj.iter()) {
                    *a += 0.35 * p;
                }
            }
        }
        l2_normalize(&mut agg);
        agg
    }
}

#[async_trait]
impl EmbeddingModel for HashModel {
    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f64>>, EmbedError> {
        Ok(texts.iter().map(|t| self.embed_text(t)).collect())
    }

    fn dims(&self) -> usize {
        self.dims
    }
}

impl Default for HashModel {
    fn default() -> Self {
        Self::new(64)
    }
}

// ─── Remote model (OpenAI-compatible) ─────────────────────────────────────────

pub struct RemoteModel {
    /// Base URL, e.g. `https://api.openai.com/v1`.
    pub url: String,
    pub model_name: String,
    pub api_key: Option<String>,
    pub dims: usize,
    client: reqwest::Client,
}

impl RemoteModel {
    pub fn new(
        url: impl Into<String>,
        model_name: impl Into<String>,
        api_key: Option<String>,
        dims: usize,
    ) -> Self {
        Self {
            url: url.into(),
            model_name: model_name.into(),
            api_key,
            dims,
            client: reqwest::Client::new(),
        }
    }
}

#[derive(serde::Deserialize)]
struct RemoteEmbedData {
    index: usize,
    embedding: Vec<f64>,
}

#[derive(serde::Deserialize)]
struct RemoteEmbedResponse {
    data: Vec<RemoteEmbedData>,
}

#[async_trait]
impl EmbeddingModel for RemoteModel {
    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f64>>, EmbedError> {
        let body = serde_json::json!({ "model": self.model_name, "input": texts });
        let mut req = self
            .client
            .post(format!("{}/embeddings", self.url))
            .json(&body);
        if let Some(key) = &self.api_key {
            req = req.bearer_auth(key);
        }
        let resp: RemoteEmbedResponse = req
            .send()
            .await
            .map_err(|e| EmbedError::Http(e.to_string()))?
            .json()
            .await
            .map_err(|e| EmbedError::Parse(e.to_string()))?;

        let mut pairs: Vec<(usize, Vec<f64>)> = resp
            .data
            .into_iter()
            .map(|d| (d.index, d.embedding))
            .collect();
        pairs.sort_by_key(|(i, _)| *i);
        Ok(pairs.into_iter().map(|(_, v)| v).collect())
    }

    fn dims(&self) -> usize {
        self.dims
    }
}

// ─── Enum wrapper (avoids dyn overhead) ──────────────────────────────────────

pub enum ModelKind {
    Local(LocalModel),
    Hash(HashModel),
    Remote(RemoteModel),
}

impl ModelKind {
    pub fn local() -> Result<Self, EmbedError> {
        Ok(Self::Local(LocalModel::new()?))
    }

    /// Fallback to hash model if ONNX unavailable.
    pub fn local_or_hash() -> Self {
        match LocalModel::new() {
            Ok(m) => Self::Local(m),
            Err(_) => {
                eprintln!("Warning: ONNX model not available, falling back to hash-projection. \
                          Download model for semantic security.");
                Self::Hash(HashModel::default())
            }
        }
    }

    pub fn hash(dims: usize) -> Self {
        Self::Hash(HashModel::new(dims))
    }

    pub fn remote(
        url: impl Into<String>,
        model: impl Into<String>,
        api_key: Option<String>,
        dims: usize,
    ) -> Self {
        Self::Remote(RemoteModel::new(url, model, api_key, dims))
    }

    /// Synchronous embed for local models (LocalModel and HashModel).
    /// Returns zero vector with error log if called on RemoteModel.
    pub fn embed_text(&self, text: &str) -> Vec<f64> {
        match self {
            ModelKind::Local(m) => m.embed_text(text),
            ModelKind::Hash(m) => m.embed_text(text),
            ModelKind::Remote(m) => {
                tracing::error!("embed_text is synchronous and cannot be used with RemoteModel; returning zero vector");
                vec![0.0; m.dims()]
            }
        }
    }
}

#[async_trait]
impl EmbeddingModel for ModelKind {
    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f64>>, EmbedError> {
        match self {
            ModelKind::Local(m) => m.embed_batch(texts).await,
            ModelKind::Hash(m) => m.embed_batch(texts).await,
            ModelKind::Remote(m) => m.embed_batch(texts).await,
        }
    }

    fn dims(&self) -> usize {
        match self {
            ModelKind::Local(m) => m.dims(),
            ModelKind::Hash(m) => m.dims(),
            ModelKind::Remote(m) => m.dims(),
        }
    }
}

// ─── Utility functions ────────────────────────────────────────────────────────

/// Cosine similarity.  Assumes unit-norm vectors; equivalent to dot product.
pub fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

// Hash-projection utilities (for fallback only)

fn tokenize(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| s.len() > 1)
        .map(String::from)
        .collect()
}

fn canonical_token(token: &str) -> &str {
    match token {
        "transfer" | "send" | "wire" | "payment" | "payout" | "remit" => "money_transfer",
        "recipient" | "beneficiary" | "payee" => "recipient",
        "rm" | "delete" | "erase" | "wipe" | "truncate" => "destructive_delete",
        "reboot" | "restart" | "shutdown" | "halt" => "system_control",
        "invoice" | "billing" | "bill" => "billing",
        _ => token,
    }
}

fn tokenize_with_hints(text: &str) -> Vec<String> {
    tokenize(text)
        .into_iter()
        .map(|t| canonical_token(&t).to_string())
        .collect()
}

fn token_ngrams(token: &str, n: usize) -> Vec<String> {
    let chars: Vec<char> = token.chars().collect();
    if chars.len() < n {
        return vec![token.to_string()];
    }
    let mut out = Vec::with_capacity(chars.len() - n + 1);
    for i in 0..=(chars.len() - n) {
        out.push(chars[i..i + n].iter().collect());
    }
    out
}

fn fnv1a(token: &str) -> u64 {
    let mut h: u64 = 14695981039346656037;
    for b in token.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}

fn token_projection(token: &str, dims: usize) -> Vec<f64> {
    let mut s = fnv1a(token);
    if s == 0 {
        s = 1;
    }
    let mut v = vec![0.0f64; dims];
    for x in v.iter_mut() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        *x = (s as i64) as f64 / i64::MAX as f64;
    }
    l2_normalize(&mut v);
    v
}

pub fn l2_normalize(v: &mut [f64]) {
    let norm: f64 = v.iter().map(|x| x * x).sum::<f64>().sqrt();
    if norm > 1e-10 {
        for x in v.iter_mut() {
            *x /= norm;
        }
    }
}

// ─── Model checksum verification ──────────────────────────────────────────────

pub async fn model_output_hash(model: &ModelKind, probe: &str) -> Result<String, EmbedError> {
    use sha2::{Digest, Sha256};
    let vec = model.embed_one(probe).await?;
    let rounded: Vec<f64> = vec
        .iter()
        .map(|x| (x * 1_000_000.0).round() / 1_000_000.0)
        .collect();
    let json = serde_json::to_string(&rounded).expect("vec serialization is infallible");
    let hash = Sha256::digest(json.as_bytes());
    Ok(hex::encode(hash))
}

pub async fn verify_model_checksum(
    model: &ModelKind,
    probe: &str,
    expected_hex: &str,
) -> Result<(), String> {
    let actual = model_output_hash(model, probe)
        .await
        .map_err(|e| format!("probe embed failed: {e}"))?;
    let actual_b = actual.as_bytes();
    let expected_b = expected_hex.trim().as_bytes();
    if actual_b.len() != expected_b.len() {
        return Err(format!(
            "checksum length mismatch: expected {} chars, got {}",
            expected_b.len(),
            actual_b.len()
        ));
    }
    let mut diff = 0u8;
    for (a, b) in actual_b.iter().zip(expected_b.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(format!(
            "model checksum FAILED – model output has changed or was tampered with. \
             expected={expected_hex} actual={actual}"
        ));
    }
    Ok(())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hash_model_same_text_stable() {
        let m = HashModel::new(64);
        let a = m.embed_text("transfer USD to alice");
        let b = m.embed_text("transfer USD to alice");
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn hash_model_unit_norm() {
        let m = HashModel::new(64);
        let v = m.embed_text("transfer 500 USD to alice");
        let norm: f64 = v.iter().map(|x| x * x).sum::<f64>().sqrt();
        assert!(
            (norm - 1.0).abs() < 1e-9,
            "vector must be unit norm, got {norm}"
        );
    }

    #[test]
    fn semantic_similarity_ordering() {
        // This test documents the limitation of hash-projection
        let m = HashModel::new(64);
        let goal = m.embed_text("transfer payment wire");
        let similar = m.embed_text("transfer payment wire usd");
        let diff = m.embed_text("reboot system shutdown command");
        let sim_s = cosine_similarity(&goal, &similar);
        let sim_d = cosine_similarity(&goal, &diff);
        // Hash-projection: exact match tokens matter more than semantics
        assert!(
            sim_s > sim_d,
            "similar sim {sim_s:.4} should exceed unrelated {sim_d:.4}"
        );
    }
}
