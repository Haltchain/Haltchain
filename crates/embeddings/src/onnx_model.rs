//! ONNX-based semantic embedding model.
//!
//! Uses pre-trained transformer models (e.g., all-MiniLM-L6-v2) for
//! high-quality semantic embeddings. Replaces the hash-projection
//! LocalModel with real neural network-based embeddings.
//!
//! Model: all-MiniLM-L6-v2 (22MB, 384-dim, fast inference)
//! - Mean pooling over token embeddings
//! - L2 normalized output
//! - Semantic similarity correlates with human judgment

use ndarray::{Array1, Array2, IxDyn};
use ort::session::Session;
use ort::session::builder::{GraphOptimizationLevel, SessionBuilder};
use ort::value::Value;
use parking_lot::Mutex;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokenizers::{PaddingDirection, PaddingParams, PaddingStrategy, Tokenizer, TruncationParams};

use crate::model::cosine_similarity;

/// Default model dimension for all-MiniLM-L6-v2.
pub const DEFAULT_ONNX_DIMS: usize = 384;

/// Model files needed for ONNX inference.
const MODEL_URL_BASE: &str = "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main";
const ONNX_FILENAME: &str = "onnx/model.onnx";
const TOKENIZER_FILENAME: &str = "tokenizer.json";

/// Semantic embedding model using ONNX Runtime.
pub struct OnnxModel {
    session: Arc<Mutex<Session>>,
    tokenizer: Arc<Mutex<Tokenizer>>,
    dims: usize,
    /// Maximum tokenization length for truncation
    max_length: usize,
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
        let model_path = model_dir.join("model.onnx");
        let tokenizer_path = model_dir.join("tokenizer.json");

        if !model_path.exists() {
            return Err(OnnxError::ModelNotFound(model_path.display().to_string()));
        }
        if !tokenizer_path.exists() {
            return Err(OnnxError::TokenizerNotFound(tokenizer_path.display().to_string()));
        }

        Self::load(&model_path, &tokenizer_path)
    }

    /// Load with explicit paths.
    pub fn load(model_path: &Path, tokenizer_path: &Path) -> Result<Self, OnnxError> {
        // Build ONNX session - uses global environment
        let session = SessionBuilder::new()
            .map_err(|e| OnnxError::SessionBuild(e.to_string()))?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(|e| OnnxError::SessionBuild(e.to_string()))?
            .with_intra_threads(4)
            .map_err(|e| OnnxError::SessionBuild(e.to_string()))?
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

        let max_length = 256;
        tokenizer.with_truncation(Some(TruncationParams {
            max_length,
            ..Default::default()
        })).map_err(|e| OnnxError::TokenizerLoad(e.to_string()))?;

        Ok(Self {
            session: Arc::new(Mutex::new(session)),
            tokenizer: Arc::new(Mutex::new(tokenizer)),
            dims: DEFAULT_ONNX_DIMS,
            max_length,
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

    /// Embed a single text string.
    pub fn embed_text(&self, text: &str) -> Vec<f64> {
        self.embed_batch(&[text]).into_iter().next().unwrap_or_default()
    }

    /// Embed multiple texts in a batch (more efficient).
    pub fn embed_batch(&self, texts: &[&str]) -> Vec<Vec<f64>> {
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
        let input_ids_value = Value::from_array(
            ndarray::Array::from_shape_vec(
                IxDyn(&[batch_size, seq_length]),
                input_ids.iter().cloned().collect()
            ).unwrap()
        ).unwrap();
        
        let attention_mask_value = Value::from_array(
            ndarray::Array::from_shape_vec(
                IxDyn(&[batch_size, seq_length]),
                attention_mask.iter().cloned().collect()
            ).unwrap()
        ).unwrap();
        
        let token_type_ids_value = Value::from_array(
            ndarray::Array::from_shape_vec(
                IxDyn(&[batch_size, seq_length]),
                token_type_ids.iter().cloned().collect()
            ).unwrap()
        ).unwrap();

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

        // Extract token embeddings from first output
        // Get the first output key and remove it
        let first_key = outputs.keys().next().unwrap().to_string();
        let output_value = outputs.remove(&first_key)
            .unwrap_or_else(|| panic!("No outputs from model"));
        let output_tensor = output_value.downcast::<ort::value::TensorValueType<f32>>().unwrap();
        let (shape, output_data) = output_tensor.try_extract_tensor::<f32>().unwrap();
        
        // Convert to ndarray for processing
        let shape_vec: Vec<usize> = shape.iter().map(|&x| x as usize).collect();
        let batch = shape_vec[0];
        let seq_len = shape_vec[1];
        let hidden = shape_vec[2];
        
        let token_embeddings = Array2::from_shape_vec(
            (batch * seq_len, hidden),
            output_data.iter().cloned().collect()
        ).unwrap();

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
                    for (i, val) in token_embeddings.slice(ndarray::s![idx, ..]).iter().enumerate() {
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
    pub fn similarity(&self, text1: &str, text2: &str) -> f64 {
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
        let Some(model) = get_test_model() else {
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
        let Some(model) = get_test_model() else {
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
        let Some(model) = get_test_model() else {
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
        let Some(model) = get_test_model() else {
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
