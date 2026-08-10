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

fn emit_security_downgrade_cef(reason: &str, hash_dims: usize) {
    // CEF sig HC010 matches the API siem module's emit_embedding_downgrade
    let ts = chrono::Utc::now().to_rfc3339();
    let escaped_reason = reason
        .replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace('\n', "\\n");
    let line = format!(
        "CEF:0|HaltChain|Validator|{}|HC010|Embedding Security Downgrade|6|\
         rt={ts} act=hash_fallback cs3={hash_dims} cs3Label=hashDims msg={escaped_reason}",
        env!("CARGO_PKG_VERSION"),
    );
    tracing::warn!(
        cef_line = %line,
        hash_dims,
        "SIEM CEF"
    );
    tracing::warn!(
        hash_dims,
        reason,
        "SECURITY_DOWNGRADE: ONNX embedding unavailable; detection confidence near-zero"
    );
    // Also write to CEF log file if configured
    if let Ok(path) = std::env::var("HALTCHAIN_SIEM_CEF_LOG_PATH")
        && !path.is_empty()
    {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = writeln!(f, "{line}");
        }
    }
}

// Import ONNX model
pub use crate::onnx_model::{DEFAULT_ONNX_DIMS, OnnxError, OnnxModel};

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

/// Hash fallback width: default 1024, clamped to 64..=4096 via `HALTCHAIN_HASH_DIMS`.
pub fn hash_dims_from_env() -> usize {
    const DEF: usize = 1024;
    const MAX: usize = 4096;
    const MIN: usize = 64;
    std::env::var("HALTCHAIN_HASH_DIMS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .map(|n| n.clamp(MIN, MAX))
        .unwrap_or(DEF)
}

/// Semantic embedding model using ONNX Runtime.
///
/// Uses Snowflake Arctic Embed 2.0 Large (~350MB Q4_K_M, 1024-dim) for high-quality semantic embeddings.
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

        for dir in cache_dirs.iter().flatten() {
            if dir.exists()
                && let Ok(onnx) = OnnxModel::from_dir(dir)
            {
                return Ok(onnx);
            }
        }

        eprintln!("ONNX model not found. Searched in:");
        for d in cache_dirs.iter().flatten() {
            eprintln!("  - {}", d.display());
        }
        eprintln!("\nDownload with: ./scripts/download_arctic_onnx.sh");
        eprintln!("Or set HALTCHAIN_MODEL_DIR environment variable.");

        Err(EmbedError::Onnx(OnnxError::ModelNotFound(
            "Could not find ONNX model in any cache directory".to_string(),
        )))
    }

    #[cfg(feature = "redis-cache")]
    fn get_redis() -> Option<Arc<Mutex<RedisEmbeddingCache>>> {
        REDIS_SINGLETON
            .get_or_init(|| RedisEmbeddingCache::connect().map(|r| Arc::new(Mutex::new(r))))
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
        OnnxModel::download(cache_dir)
            .await
            .map_err(EmbedError::Onnx)
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
                let miss_indices: Vec<usize> =
                    (0..texts.len()).filter(|i| !hit_set.contains(i)).collect();

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

    pub fn embedding_width(&self) -> usize {
        self.onnx.lock().dims()
    }
}

#[async_trait]
impl EmbeddingModel for LocalModel {
    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f64>>, EmbedError> {
        Ok(self.onnx.lock().embed_batch(texts))
    }

    fn dims(&self) -> usize {
        self.embedding_width()
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EmbeddingTier {
    Developer,
    Growth,
    Enterprise,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmbeddingMode {
    Local,
    Hybrid,
    ApiOnly,
}

fn embedding_mode_from_env() -> EmbeddingMode {
    match std::env::var("HALTCHAIN_EMBEDDING_MODE")
        .unwrap_or_default()
        .to_lowercase()
        .as_str()
    {
        "local" | "airgap" | "air_gapped" => EmbeddingMode::Local,
        "api_only" | "apionly" => EmbeddingMode::ApiOnly,
        _ => EmbeddingMode::Hybrid,
    }
}

fn embedding_tier_from_env() -> EmbeddingTier {
    match std::env::var("HALTCHAIN_EMBEDDING_TIER")
        .unwrap_or_default()
        .to_lowercase()
        .as_str()
    {
        "individual" | "developer" | "dev" => EmbeddingTier::Developer,
        "enterprise" => EmbeddingTier::Enterprise,
        // startup | smb | growth | midmarket | unset → ONNX+hash fallback
        _ => EmbeddingTier::Growth,
    }
}

/// Sync path for cognitive / ONNX detector (no blocking remote HTTP here).
///
/// * `HALTCHAIN_EMBEDDING_TIER=developer` → hash-only at [`hash_dims_from_env`] (overrides mode for cheap dev).
/// * `HALTCHAIN_EMBEDDING_MODE`: `local` = ONNX required (panic if missing); `hybrid` = ONNX or hash;
///   `api_only` = hash sync path; warm L1 via [`crate::hybrid::RemoteHydrator`] + shared [`EmbeddingCache`].
pub fn select_local_embedding_kind() -> ModelKind {
    if matches!(embedding_tier_from_env(), EmbeddingTier::Developer) {
        let d = hash_dims_from_env();
        tracing::info!(
            tier = "developer",
            dims = d,
            "embedding: hash-only (no ONNX). OK for dev; not for adversarial semantic evasion."
        );
        return ModelKind::Hash(HashModel::new(d));
    }
    match embedding_mode_from_env() {
        EmbeddingMode::Local => ModelKind::local_required(),
        EmbeddingMode::Hybrid => ModelKind::local_or_hash(),
        EmbeddingMode::ApiOnly => {
            let d = hash_dims_from_env();
            tracing::info!(
                mode = "api_only",
                dims = d,
                "embedding: sync hash; hydrate cache async (RemoteHydrator), align EMBEDDING_DIMS with hash width"
            );
            ModelKind::Hash(HashModel::new(d))
        }
    }
}

impl ModelKind {
    pub fn local() -> Result<Self, EmbedError> {
        Ok(Self::Local(LocalModel::new()?))
    }

    /// Air-gapped / strict local: ONNX only. Panics if the model cannot be loaded.
    pub fn local_required() -> Self {
        match LocalModel::new() {
            Ok(m) => {
                tracing::info!(
                    dims = m.embedding_width(),
                    "ONNX semantic model loaded (local mode)"
                );
                Self::Local(m)
            }
            Err(e) => panic!(
                "HALTCHAIN_EMBEDDING_MODE=local requires ONNX. Set HALTCHAIN_MODEL_DIR or run download script. Error: {e}"
            ),
        }
    }

    /// Fallback to hash model if ONNX unavailable.
    ///
    /// In production (`HALTCHAIN_ENV=production`), this will **panic** instead
    /// of silently degrading to the non-semantic hash model.  The hash model
    /// cannot perform real semantic similarity and will produce near-zero
    /// confidence on even obvious malicious text.
    ///
    /// Use [`ModelKind::standalone_or_hash`] for the standalone `--profile`
    /// mode, which must never panic even in production environments.
    pub fn local_or_hash() -> Self {
        let hd = hash_dims_from_env();
        match LocalModel::new() {
            Ok(m) => {
                tracing::info!(dims = m.embedding_width(), "ONNX semantic model loaded");
                Self::Local(m)
            }
            Err(e) => {
                let env = std::env::var("HALTCHAIN_ENV").unwrap_or_default();
                // Always emit HC010 so SIEM consumers see the downgrade event
                // regardless of whether the process is about to panic.
                let reason = format!("ONNX model unavailable: {e}");
                emit_security_downgrade_cef(&reason, hd);
                if env.eq_ignore_ascii_case("production") {
                    panic!(
                        "FATAL: ONNX model not available in production mode. \
                         Hash fallback is NOT safe for security-critical use. \
                         Run ./Documents/download_model.sh or set HALTCHAIN_MODEL_DIR. \
                         Error: {e}"
                    );
                }
                Self::Hash(HashModel::new(hd))
            }
        }
    }

    /// Standalone-safe variant: always falls back to the hash model without
    /// panicking, regardless of `HALTCHAIN_ENV`.  Used by `--profile standalone`
    /// which is designed for zero-external-dependency deployments.
    ///
    /// The semantic ONNX model is attempted first for best quality, but the
    /// hash fallback is explicitly sanctioned for this profile.
    pub fn standalone_or_hash() -> Self {
        let hd = hash_dims_from_env();
        match LocalModel::new() {
            Ok(m) => {
                tracing::info!(
                    "standalone: ONNX semantic model loaded ({}d)",
                    m.embedding_width()
                );
                Self::Local(m)
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    dims = hd,
                    "standalone: ONNX unavailable, using hash-projection embeddings (non-semantic)"
                );
                Self::Hash(HashModel::new(hd))
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
                tracing::error!(
                    "embed_text is synchronous and cannot be used with RemoteModel; returning zero vector"
                );
                vec![0.0; m.dims()]
            }
        }
    }

    /// Returns `true` when backed by a real semantic model (ONNX or Remote).
    /// Hash-projection is NOT semantic — it only matches keyword overlaps.
    pub fn is_semantic(&self) -> bool {
        matches!(self, ModelKind::Local(_) | ModelKind::Remote(_))
    }

    /// Human-readable label (default ONNX = Snowflake Arctic Embed L v2.0; override with HALTCHAIN_MODEL_LABEL).
    pub fn model_name(&self) -> String {
        match self {
            ModelKind::Local(_) => std::env::var("HALTCHAIN_MODEL_LABEL")
                .unwrap_or_else(|_| "onnx/snowflake-arctic-embed-l-v2.0".to_string()),
            ModelKind::Hash(_) => format!("hash-projection:{}d (non-semantic)", self.dims()),
            ModelKind::Remote(_) => "remote/openai-compatible".to_string(),
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
    use std::sync::{Mutex, OnceLock};

    static ENV_TEST_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

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

    #[test]
    fn hash_fallback_width_follows_hash_dims_env() {
        let d = hash_dims_from_env();
        let m = HashModel::new(d);
        assert_eq!(m.embed_text("x").len(), d);
    }

    #[test]
    fn hash_dims_env_clamped() {
        let _g = ENV_TEST_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap();
        unsafe {
            std::env::set_var("HALTCHAIN_HASH_DIMS", "999999");
            assert_eq!(hash_dims_from_env(), 4096);
            std::env::set_var("HALTCHAIN_HASH_DIMS", "10");
            assert_eq!(hash_dims_from_env(), 64);
            std::env::remove_var("HALTCHAIN_HASH_DIMS");
        }
    }

    #[test]
    fn tier_developer_select_is_full_dim_hash() {
        let _g = ENV_TEST_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap();
        // Rust 2024: env mutation is unsafe (no concurrent readers in this test process).
        unsafe {
            std::env::remove_var("HALTCHAIN_EMBEDDING_TIER");
            std::env::remove_var("HALTCHAIN_HASH_DIMS");
            std::env::set_var("HALTCHAIN_EMBEDDING_TIER", "developer");
        }
        let k = select_local_embedding_kind();
        unsafe {
            std::env::remove_var("HALTCHAIN_EMBEDDING_TIER");
        }
        assert!(matches!(k, ModelKind::Hash(_)));
        assert_eq!(k.dims(), hash_dims_from_env());
    }
}
