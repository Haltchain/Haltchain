//! Wednesday: Action-to-embedding pipeline.
//!
//! Serialises `ActionMeta` to a human-readable text string, then embeds it.
//! Weekend: batch embedding with per-text caching (deduplicated model calls).

use std::sync::Arc;

use crate::{
    cache::{DEFAULT_CACHE_CAP, EmbeddingCache},
    model::{EmbedError, EmbeddingModel, ModelKind, verify_model_checksum},
};

//Action metadata (mirrors validator::ActionPayload for decoupling)

pub struct ActionMeta<'a> {
    pub action_type: &'a str,
    pub amount: Option<f64>,
    pub currency: Option<&'a str>,
    pub recipient: Option<&'a str>,
    pub endpoint: Option<&'a str>,
    pub method: Option<&'a str>,
    pub command: Option<&'a str>,
}

/// Serialise action metadata to a concise natural-language string for embedding.
pub fn action_to_text(m: &ActionMeta<'_>) -> String {
    let mut parts = vec![m.action_type.to_string()];
    match (m.amount, m.currency) {
        (Some(amt), Some(cur)) => parts.push(format!("{amt:.2} {cur}")),
        (Some(amt), None) => parts.push(format!("{amt:.2}")),
        _ => {}
    }
    if let Some(r) = m.recipient {
        parts.push(format!("to {r}"));
    }
    if let (Some(mth), Some(ep)) = (m.method, m.endpoint) {
        parts.push(format!("{mth} {ep}"));
    }
    if let Some(cmd) = m.command {
        parts.push(format!("command {cmd}"));
    }
    parts.join(" ")
}

// ─── Pipeline ────────────────────────────────────────────────────────────────

pub struct EmbedPipeline {
    model: Arc<ModelKind>,
    cache: EmbeddingCache,
}

impl EmbedPipeline {
    pub fn new(model: ModelKind) -> Self {
        Self::with_cache_cap(model, DEFAULT_CACHE_CAP)
    }

    pub fn with_cache_cap(model: ModelKind, cap: usize) -> Self {
        Self {
            model: Arc::new(model),
            cache: EmbeddingCache::new(cap),
        }
    }

    /// Build the pipeline and verify the model against a pinned probe hash.
    ///
    /// Env vars:
    ///   `HALTCHAIN_EMBED_PROBE`      — probe text to embed
    ///   `HALTCHAIN_EMBED_PROBE_HASH` — expected SHA-256 hex of the rounded JSON vector
    ///
    /// If the vars are unset, verification is skipped.  If the hash mismatches
    /// the process is killed rather than silently serving poisoned embeddings.
    pub async fn new_verified(model: ModelKind) -> Self {
        let pipeline = Self::new(model);
        if let (Ok(probe), Ok(expected_hash)) = (
            std::env::var("HALTCHAIN_EMBED_PROBE"),
            std::env::var("HALTCHAIN_EMBED_PROBE_HASH"),
        ) {
            tracing::info!("Verifying embedding model checksum…");
            match verify_model_checksum(&pipeline.model, &probe, &expected_hash).await {
                Ok(()) => tracing::info!("Embedding model checksum OK"),
                Err(e) => {
                    tracing::error!("{e}");
                    std::process::exit(1);
                }
            }
        }
        pipeline
    }

    /// Embed a single text, using cache when available.
    pub async fn embed_cached(&self, text: &str) -> Result<Vec<f64>, EmbedError> {
        if let Some(v) = self.cache.get(text) {
            return Ok(v);
        }
        let v: Vec<f64> = self.model.embed_one(text).await?;
        self.cache.insert(text, v.clone());
        Ok(v)
    }

    /// Embed an action struct directly.
    pub async fn embed_action(&self, meta: &ActionMeta<'_>) -> Result<Vec<f64>, EmbedError> {
        self.embed_cached(&action_to_text(meta)).await
    }

    /// Weekend: batch embed with deduplication — only uncached texts hit the model.
    pub async fn embed_batch_cached(&self, texts: &[&str]) -> Result<Vec<Vec<f64>>, EmbedError> {
        let mut result = vec![vec![]; texts.len()];
        let mut misses: Vec<(usize, &str)> = Vec::new();

        for (i, &text) in texts.iter().enumerate() {
            if let Some(v) = self.cache.get(text) {
                result[i] = v;
            } else {
                misses.push((i, text));
            }
        }

        if !misses.is_empty() {
            let miss_texts: Vec<&str> = misses.iter().map(|(_, t)| *t).collect();
            let vecs: Vec<Vec<f64>> = self.model.embed_batch(&miss_texts).await?;
            for ((i, text), vec) in misses.iter().zip(vecs.into_iter()) {
                self.cache.insert(text, vec.clone());
                result[*i] = vec;
            }
        }

        Ok(result)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ModelKind;

    fn meta_transfer() -> ActionMeta<'static> {
        ActionMeta {
            action_type: "transfer",
            amount: Some(500.0),
            currency: Some("USD"),
            recipient: Some("alice"),
            endpoint: None,
            method: None,
            command: None,
        }
    }

    #[test]
    fn action_to_text_transfer() {
        let t = action_to_text(&meta_transfer());
        assert_eq!(t, "transfer 500.00 USD to alice");
    }

    #[test]
    fn action_to_text_api_call() {
        let m = ActionMeta {
            action_type: "api_call",
            amount: None,
            currency: None,
            recipient: None,
            endpoint: Some("/users"),
            method: Some("GET"),
            command: None,
        };
        assert_eq!(action_to_text(&m), "api_call GET /users");
    }

    #[test]
    fn action_to_text_command() {
        let m = ActionMeta {
            action_type: "execute",
            amount: None,
            currency: None,
            recipient: None,
            endpoint: None,
            method: None,
            command: Some("restart"),
        };
        assert_eq!(action_to_text(&m), "execute command restart");
    }

    #[tokio::test]
    async fn embed_action_returns_vector() {
        let p = EmbedPipeline::new(ModelKind::local_or_hash());
        let v = p.embed_action(&meta_transfer()).await.unwrap();
        assert!(!v.is_empty());
    }

    #[tokio::test]
    async fn second_embed_hits_cache() {
        let p = EmbedPipeline::new(ModelKind::local_or_hash());
        let t = "transfer 100 USD to bob";
        p.embed_cached(t).await.unwrap();
        p.embed_cached(t).await.unwrap();
        assert!(p.cache.stats().hits >= 1);
    }

    #[tokio::test]
    async fn batch_cached_deduplicates_model_calls() {
        let p = EmbedPipeline::new(ModelKind::local_or_hash());
        let texts = ["foo bar baz", "alpha beta gamma", "foo bar baz"];
        let vecs = p.embed_batch_cached(&texts).await.unwrap();
        assert_eq!(vecs.len(), 3);
        // "foo bar baz" appears twice — result must be identical.
        assert_eq!(vecs[0], vecs[2]);
        // Cache should have 2 unique entries.
        assert_eq!(p.cache.stats().size, 2);
    }
}
