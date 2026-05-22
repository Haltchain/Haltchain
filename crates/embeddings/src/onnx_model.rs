//! ONNX-based semantic embedding model.
//!
//! Uses Snowflake Arctic Embed 2.0 Large for high-quality semantic embeddings.
//! Replaces the hash-projection LocalModel with real neural network-based embeddings.
//!
//! Model: Snowflake Arctic Embed 2.0 Large (~350MB Q4_K_M, 1024-dim, state-of-the-art retrieval)
//! - Mean pooling over token embeddings
//! - L2 normalized output
//! - Semantic similarity correlates with human judgment
//! - Supports up to 8192 tokens (vs 256 for MiniLM)

use ndarray::{Array1, Array2, IxDyn};
use ort::session::Session;
use ort::session::builder::{GraphOptimizationLevel, SessionBuilder};
use ort::value::Value;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokenizers::{PaddingDirection, PaddingParams, PaddingStrategy, Tokenizer, TruncationParams};

use crate::model::cosine_similarity;

// Re-export ep module for execution provider configuration
#[cfg(feature = "cuda")]
use ort::ep::CUDA;
#[cfg(feature = "coreml")]
use ort::ep::CoreML;
#[cfg(feature = "tensorrt")]
use ort::ep::TensorRT;

/// Default model dimension for Snowflake Arctic Embed 2.0 Large.
pub const DEFAULT_ONNX_DIMS: usize = 1024;

/// Model files needed for ONNX inference.
const MODEL_URL_BASE: &str =
    "https://huggingface.co/Snowflake/snowflake-arctic-embed-l-v2.0/resolve/main";
const ONNX_FILENAME: &str = "onnx/model.onnx";
const TOKENIZER_FILENAME: &str = "tokenizer.json";

/// Embedding cache capacity (number of unique texts to cache).
const EMBED_CACHE_CAPACITY: usize = 4096;

/// Semantic embedding model using ONNX Runtime.
///
/// Includes an embedding cache to avoid redundant inference for identical
/// text inputs (common in detection pipelines and throughput scenarios).
pub struct OnnxModel {
    session: Arc<Mutex<Session>>,
    tokenizer: Arc<Mutex<Tokenizer>>,
    dims: usize,
    /// Maximum tokenization length for truncation
    max_length: usize,
    /// Embedding cache: text hash → embedding vector
    cache: HashMap<u64, Vec<f64>>,
    /// Insertion order for LRU eviction
    cache_order: std::collections::VecDeque<u64>,
}

/// Compute SHA-256 of a file and return it as a lowercase hex string.
fn sha256_of_file(path: &Path) -> Result<String, OnnxError> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| OnnxError::ChecksumIo(format!("{}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| OnnxError::ChecksumIo(format!("{}: {e}", path.display())))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Verify a file's SHA-256 against an expected hex digest.
/// Env vars: HALTCHAIN_MODEL_ONNX_SHA256 (model), HALTCHAIN_MODEL_TOKENIZER_SHA256 (tokenizer).
/// Returns Ok(()) if env var not set (opt-in) or digest matches.
/// Returns Err(ChecksumMismatch) if env var is set and digest differs (fail-closed).
fn verify_checksum(path: &Path, env_var: &str) -> Result<(), OnnxError> {
    let expected = match std::env::var(env_var) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_lowercase(),
        _ => return Ok(()),
    };
    let actual = sha256_of_file(path)?;
    if actual != expected {
        return Err(OnnxError::ChecksumMismatch {
            file: path.display().to_string(),
            expected,
            actual,
        });
    }
    tracing::debug!(file = %path.display(), "model file integrity check passed");
    Ok(())
}

impl OnnxModel {
    /// Load model from directory containing model.onnx and tokenizer.json.
    ///
    /// # Arguments
    /// * `model_dir` - Directory containing `model.onnx` and `tokenizer.json`
    ///
    /// # Errors
    /// Returns error if model files not found or invalid.
    pub fn from_dir(model_dir: impl AsRef<Path>) -> Result<Self, OnnxError> {
        let model_dir = model_dir.as_ref();
        // Prefer quantized model if available (INT8 dynamic quantization)
        let model_path = {
            let quantized = model_dir.join("model_quantized.onnx");
            if quantized.exists() {
                quantized
            } else {
                model_dir.join("model.onnx")
            }
        };
        let tokenizer_path = model_dir.join("tokenizer.json");

        if !model_path.exists() {
            return Err(OnnxError::ModelNotFound(model_path.display().to_string()));
        }
        if !tokenizer_path.exists() {
            return Err(OnnxError::TokenizerNotFound(
                tokenizer_path.display().to_string(),
            ));
        }

        Self::load(&model_path, &tokenizer_path)
    }

    /// Load with explicit paths.
    ///
    /// Automatically registers GPU execution providers when compiled with
    /// the corresponding feature flags (`coreml`, `cuda`, `tensorrt`).
    /// Falls back to CPU if no GPU provider is available.
    pub fn load(model_path: &Path, tokenizer_path: &Path) -> Result<Self, OnnxError> {
        // Scale intra-op threads to available cores (capped at 8 to avoid overhead)
        let num_threads = std::thread::available_parallelism()
            .map(|n| n.get().min(8))
            .unwrap_or(4);

        // Integrity verification (fail-closed when env vars are set).
        verify_checksum(model_path, "HALTCHAIN_MODEL_ONNX_SHA256")?;
        verify_checksum(tokenizer_path, "HALTCHAIN_MODEL_TOKENIZER_SHA256")?;

        let mut builder = SessionBuilder::new()
            .map_err(|e| OnnxError::SessionBuild(e.to_string()))?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(|e| OnnxError::SessionBuild(e.to_string()))?
            .with_intra_threads(num_threads)
            .map_err(|e| OnnxError::SessionBuild(e.to_string()))?;

        // Register GPU execution providers (graceful fallback to CPU).
        // Priority: TensorRT > CUDA > CoreML > CPU
        #[allow(unused_mut)]
        let mut eps = Vec::new();

        #[cfg(feature = "tensorrt")]
        eps.push(TensorRT::default().build());

        #[cfg(feature = "cuda")]
        eps.push(CUDA::default().build());

        #[cfg(feature = "coreml")]
        eps.push(CoreML::default().build());

        if !eps.is_empty() {
            builder = builder
                .with_execution_providers(eps)
                .map_err(|e| OnnxError::SessionBuild(e.to_string()))?;
        }

        let session = builder
            .commit_from_file(model_path)
            .map_err(|e| OnnxError::ModelLoad(e.to_string()))?;

        // Load tokenizer
        let mut tokenizer = Tokenizer::from_file(tokenizer_path)
            .map_err(|e| OnnxError::TokenizerLoad(e.to_string()))?;

        // Configure padding/truncation
        let pad_id = tokenizer
            .get_padding()
            .map(|p| p.pad_id)
            .or_else(|| tokenizer.token_to_id("[PAD]"))
            .unwrap_or(0);

        tokenizer.with_padding(Some(PaddingParams {
            strategy: PaddingStrategy::BatchLongest,
            pad_id,
            pad_type_id: 0,
            pad_token: "[PAD]".to_string(),
            direction: PaddingDirection::Right,
            pad_to_multiple_of: None,
        }));

        // Snowflake Arctic Embed 2.0 supports up to 8192 tokens
        let max_length = 8192;
        tokenizer
            .with_truncation(Some(TruncationParams {
                max_length,
                ..Default::default()
            }))
            .map_err(|e| OnnxError::TokenizerLoad(e.to_string()))?;

        Ok(Self {
            session: Arc::new(Mutex::new(session)),
            tokenizer: Arc::new(Mutex::new(tokenizer)),
            dims: DEFAULT_ONNX_DIMS,
            max_length,
            cache: HashMap::with_capacity(EMBED_CACHE_CAPACITY),
            cache_order: std::collections::VecDeque::with_capacity(EMBED_CACHE_CAPACITY),
        })
    }

    /// Download model files from HuggingFace if not present.
    ///
    /// # Arguments
    /// * `cache_dir` - Directory to cache downloaded files
    ///
    /// # Errors
    /// Returns error if download fails.
    #[allow(unused)]
    pub async fn download(cache_dir: impl AsRef<Path>) -> Result<PathBuf, OnnxError> {
        let cache_dir = cache_dir.as_ref();
        tokio::fs::create_dir_all(cache_dir)
            .await
            .map_err(|e| OnnxError::Download(e.to_string()))?;

        let model_path = cache_dir.join("model.onnx");
        let tokenizer_path = cache_dir.join("tokenizer.json");

        // Download model if not exists
        if !model_path.exists() {
            let url = format!("{}/{}", MODEL_URL_BASE, ONNX_FILENAME);
            Self::download_file(&url, &model_path).await?;
        }

        // Download tokenizer if not exists
        if !tokenizer_path.exists() {
            let url = format!("{}/{}", MODEL_URL_BASE, TOKENIZER_FILENAME);
            Self::download_file(&url, &tokenizer_path).await?;
        }

        Ok(cache_dir.to_path_buf())
    }

    async fn download_file(url: &str, dest: &Path) -> Result<(), OnnxError> {
        let response = reqwest::get(url)
            .await
            .map_err(|e| OnnxError::Download(e.to_string()))?;

        if !response.status().is_success() {
            return Err(OnnxError::Download(format!(
                "HTTP {} for {}",
                response.status(),
                url
            )));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| OnnxError::Download(e.to_string()))?;

        tokio::fs::write(dest, bytes)
            .await
            .map_err(|e| OnnxError::Download(e.to_string()))?;

        Ok(())
    }

    /// Embed a single text string with caching.
    ///
    /// Checks the embedding cache first to avoid redundant ONNX inference.
    /// Cache is bounded to [`EMBED_CACHE_CAPACITY`] entries with LRU eviction.
    pub fn embed_text(&mut self, text: &str) -> Vec<f64> {
        let key = Self::hash_text(text);

        // Cache hit — return clone
        if let Some(cached) = self.cache.get(&key) {
            return cached.clone();
        }

        // Cache miss — compute embedding
        let embedding = self
            .embed_batch_uncached(&[text])
            .into_iter()
            .next()
            .unwrap_or_default();

        // Insert into cache with LRU eviction
        if self.cache_order.len() >= EMBED_CACHE_CAPACITY {
            if let Some(old_key) = self.cache_order.pop_front() {
                self.cache.remove(&old_key);
            }
        }
        self.cache.insert(key, embedding.clone());
        self.cache_order.push_back(key);

        embedding
    }

    pub fn hash_text(text: &str) -> u64 {
        let mut hasher = std::hash::DefaultHasher::new();
        text.hash(&mut hasher);
        hasher.finish()
    }

    /// Embed multiple texts in a batch (more efficient, no caching).
    pub fn embed_batch(&mut self, texts: &[&str]) -> Vec<Vec<f64>> {
        // For batch, check cache per-text and only run inference on misses
        if texts.is_empty() {
            return Vec::new();
        }

        let mut results = vec![None; texts.len()];
        let mut miss_indices = Vec::new();
        let mut miss_texts = Vec::new();

        for (i, text) in texts.iter().enumerate() {
            let key = Self::hash_text(text);
            if let Some(cached) = self.cache.get(&key) {
                results[i] = Some(cached.clone());
            } else {
                miss_indices.push(i);
                miss_texts.push(*text);
            }
        }

        // Run inference only on cache misses
        if !miss_texts.is_empty() {
            let miss_refs: Vec<&str> = miss_texts.iter().map(|s| *s).collect();
            let computed = self.embed_batch_uncached(&miss_refs);
            for (j, embedding) in computed.into_iter().enumerate() {
                let idx = miss_indices[j];
                let key = Self::hash_text(texts[idx]);
                // Cache the result
                if self.cache_order.len() >= EMBED_CACHE_CAPACITY {
                    if let Some(old_key) = self.cache_order.pop_front() {
                        self.cache.remove(&old_key);
                    }
                }
                self.cache.insert(key, embedding.clone());
                self.cache_order.push_back(key);
                results[idx] = Some(embedding);
            }
        }

        results
            .into_iter()
            .map(|r| {
                r.unwrap_or_else(|| {
                    tracing::warn!(
                        "embedding cache miss produced no result; returning zero vector"
                    );
                    vec![0.0; self.dims]
                })
            })
            .collect()
    }

    /// Raw ONNX inference without cache. Used internally.
    ///
    /// Automatically sub-batches large inputs into chunks for optimal
    /// throughput (avoids creating oversized tensors).
    fn embed_batch_uncached(&self, texts: &[&str]) -> Vec<Vec<f64>> {
        if texts.is_empty() {
            return Vec::new();
        }

        // Sub-batch for better throughput — moderate batch sizes
        // balance padding overhead vs call overhead. 128 provides
        // good parallelism without excessive padding waste.
        const SUB_BATCH: usize = 128;
        if texts.len() > SUB_BATCH {
            let mut all_embeddings = Vec::with_capacity(texts.len());
            for chunk in texts.chunks(SUB_BATCH) {
                all_embeddings.extend(self.embed_batch_single(chunk));
            }
            return all_embeddings;
        }

        self.embed_batch_single(texts)
    }

    /// Single-batch ONNX inference (no chunking).
    fn embed_batch_single(&self, texts: &[&str]) -> Vec<Vec<f64>> {
        if texts.is_empty() {
            return Vec::new();
        }

        // Tokenize
        let encoding = self.tokenizer.lock().encode_batch(texts.to_vec(), true);
        let encoding = match encoding {
            Ok(e) => e,
            Err(_) => return texts.iter().map(|_| vec![0.0; self.dims]).collect(),
        };

        // Convert to tensors
        let batch_size = encoding.len();
        let seq_length = encoding[0].get_ids().len();

        let mut input_ids = Array2::<i64>::zeros((batch_size, seq_length));
        let mut attention_mask = Array2::<i64>::zeros((batch_size, seq_length));
        let token_type_ids = Array2::<i64>::zeros((batch_size, seq_length)); // All zeros for single-sequence

        for (i, enc) in encoding.iter().enumerate() {
            for (j, &id) in enc.get_ids().iter().enumerate() {
                input_ids[[i, j]] = id as i64;
            }
            for (j, &mask) in enc.get_attention_mask().iter().enumerate() {
                attention_mask[[i, j]] = mask as i64;
            }
            // token_type_ids stays all zeros (single sequence classification)
        }

        // Run inference
        let mut session = self.session.lock();

        // Create input values - from_array takes the ndarray directly
        let input_ids_value = match ndarray::Array::from_shape_vec(
            IxDyn(&[batch_size, seq_length]),
            input_ids.iter().cloned().collect(),
        )
        .and_then(|a| {
            Value::from_array(a)
                .map_err(|_| ndarray::ShapeError::from_kind(ndarray::ErrorKind::Unsupported).into())
        }) {
            Ok(v) => v,
            Err(_) => {
                tracing::error!("failed to create input_ids tensor");
                return texts.iter().map(|_| vec![0.0; self.dims]).collect();
            }
        };

        let attention_mask_value = match ndarray::Array::from_shape_vec(
            IxDyn(&[batch_size, seq_length]),
            attention_mask.iter().cloned().collect(),
        )
        .and_then(|a| {
            Value::from_array(a)
                .map_err(|_| ndarray::ShapeError::from_kind(ndarray::ErrorKind::Unsupported).into())
        }) {
            Ok(v) => v,
            Err(_) => {
                tracing::error!("failed to create attention_mask tensor");
                return texts.iter().map(|_| vec![0.0; self.dims]).collect();
            }
        };

        let token_type_ids_value = match ndarray::Array::from_shape_vec(
            IxDyn(&[batch_size, seq_length]),
            token_type_ids.iter().cloned().collect(),
        )
        .and_then(|a| {
            Value::from_array(a)
                .map_err(|_| ndarray::ShapeError::from_kind(ndarray::ErrorKind::Unsupported).into())
        }) {
            Ok(v) => v,
            Err(_) => {
                tracing::error!("failed to create token_type_ids tensor");
                return texts.iter().map(|_| vec![0.0; self.dims]).collect();
            }
        };

        // Run inference - SessionInputs needs named inputs
        let inputs = vec![
            ("input_ids", input_ids_value.into_dyn()),
            ("attention_mask", attention_mask_value.into_dyn()),
            ("token_type_ids", token_type_ids_value.into_dyn()),
        ];
        let mut outputs = match session.run(inputs) {
            Ok(o) => o,
            Err(_) => return texts.iter().map(|_| vec![0.0; self.dims]).collect(),
        };

        let first_key = match outputs.keys().next() {
            Some(k) => k.to_string(),
            None => {
                tracing::error!("ONNX model returned no output keys");
                return texts.iter().map(|_| vec![0.0; self.dims]).collect();
            }
        };
        let output_value = match outputs.remove(&first_key) {
            Some(v) => v,
            None => {
                tracing::error!("ONNX output key vanished after iteration");
                return texts.iter().map(|_| vec![0.0; self.dims]).collect();
            }
        };
        let output_tensor = match output_value.downcast::<ort::value::TensorValueType<f32>>() {
            Ok(t) => t,
            Err(_) => {
                tracing::error!("ONNX output is not a float32 tensor");
                return texts.iter().map(|_| vec![0.0; self.dims]).collect();
            }
        };
        let (shape, output_data) = match output_tensor.try_extract_tensor::<f32>() {
            Ok(pair) => pair,
            Err(_) => {
                tracing::error!("failed to extract tensor data from ONNX output");
                return texts.iter().map(|_| vec![0.0; self.dims]).collect();
            }
        };

        // Convert to ndarray for processing
        let shape_vec: Vec<usize> = shape.iter().map(|&x| x as usize).collect();
        let batch = shape_vec[0];
        let seq_len = shape_vec[1];
        let hidden = shape_vec[2];

        let token_embeddings = match Array2::from_shape_vec(
            (batch * seq_len, hidden),
            output_data.iter().cloned().collect(),
        ) {
            Ok(t) => t,
            Err(_) => {
                tracing::error!(batch, seq_len, hidden, "ONNX output shape mismatch");
                return texts.iter().map(|_| vec![0.0; self.dims]).collect();
            }
        };

        // Mean pooling with attention mask
        let mut embeddings = Vec::with_capacity(batch_size);
        for b in 0..batch_size {
            let mask = attention_mask.slice(ndarray::s![b, ..]);
            let start_idx = b * seq_len;

            // Compute mean of non-padding tokens
            let mut sum = Array1::<f32>::zeros(self.dims);
            let mut count = 0i64;

            for (t, &m) in mask.iter().enumerate() {
                if m > 0 {
                    let idx = start_idx + t;
                    for (i, val) in token_embeddings
                        .slice(ndarray::s![idx, ..])
                        .iter()
                        .enumerate()
                    {
                        sum[i] += val;
                    }
                    count += 1;
                }
            }

            let mut embedding = if count > 0 {
                (&sum / count as f32).to_vec()
            } else {
                vec![0.0f32; self.dims]
            };

            // Normalize
            let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
            if norm > 1e-12 {
                embedding.iter_mut().for_each(|x| *x /= norm);
            }

            embeddings.push(embedding.into_iter().map(|x| x as f64).collect());
        }

        embeddings
    }

    /// Get maximum tokenization length
    pub fn max_length(&self) -> usize {
        self.max_length
    }

    /// Compute semantic similarity between two texts.
    pub fn similarity(&mut self, text1: &str, text2: &str) -> f64 {
        let emb1 = self.embed_text(text1);
        let emb2 = self.embed_text(text2);
        cosine_similarity(&emb1, &emb2)
    }

    pub fn dims(&self) -> usize {
        self.dims
    }
}

/// Errors that can occur with ONNX model operations.
#[derive(Debug, thiserror::Error)]
pub enum OnnxError {
    #[error("model file not found: {0}")]
    ModelNotFound(String),
    #[error("tokenizer file not found: {0}")]
    TokenizerNotFound(String),
    #[error("failed to build ONNX session: {0}")]
    SessionBuild(String),
    #[error("failed to load model: {0}")]
    ModelLoad(String),
    #[error("failed to load tokenizer: {0}")]
    TokenizerLoad(String),
    #[error("download failed: {0}")]
    Download(String),
    #[error("model integrity check failed for {file}: expected {expected}, got {actual}")]
    ChecksumMismatch {
        file: String,
        expected: String,
        actual: String,
    },
    #[error("failed to read file for checksum verification: {0}")]
    ChecksumIo(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_test_model() -> Option<OnnxModel> {
        // Try to load from cache or env
        let cache_dir = dirs::cache_dir()
            .map(|d| d.join("haltchain").join("models"))
            .or_else(|| Some(PathBuf::from("./models")))?;

        OnnxModel::from_dir(&cache_dir).ok()
    }

    #[test]
    fn semantic_similarity_paraphrases() {
        let Some(mut model) = get_test_model() else {
            eprintln!("Skipping test: ONNX model not available");
            return;
        };

        // Paraphrases should have high similarity
        let sim = model.similarity(
            "Transfer money to the account",
            "Send funds to the bank account",
        );
        assert!(
            sim > 0.7,
            "Paraphrases should have high similarity, got {:.3}",
            sim
        );
    }

    #[test]
    fn semantic_dissimilarity_unrelated() {
        let Some(mut model) = get_test_model() else {
            eprintln!("Skipping test: ONNX model not available");
            return;
        };

        // Unrelated texts should have low similarity
        let sim = model.similarity(
            "Transfer money between accounts",
            "Delete all system files immediately",
        );
        assert!(
            sim < 0.5,
            "Unrelated texts should have low similarity, got {:.3}",
            sim
        );
    }

    #[test]
    fn embedding_stable() {
        let Some(mut model) = get_test_model() else {
            eprintln!("Skipping test: ONNX model not available");
            return;
        };

        // Same text should produce same embedding
        let emb1 = model.embed_text("Process the payment request");
        let emb2 = model.embed_text("Process the payment request");
        assert_eq!(emb1.len(), DEFAULT_ONNX_DIMS);
        assert_eq!(emb1, emb2);
    }

    #[test]
    fn embedding_normalized() {
        let Some(mut model) = get_test_model() else {
            eprintln!("Skipping test: ONNX model not available");
            return;
        };

        let emb = model.embed_text("Test normalization");
        let norm: f64 = emb.iter().map(|x| x * x).sum::<f64>().sqrt();
        assert!(
            (norm - 1.0).abs() < 1e-6,
            "Embedding should be unit normalized, got norm={}",
            norm
        );
    }
}
