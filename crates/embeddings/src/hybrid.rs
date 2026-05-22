// Async remote → L1 EmbeddingCache. Cognitive stays sync: no blocking HTTP on hot path.

use std::sync::Arc;

use crate::cache::EmbeddingCache;
use crate::model::{EmbedError, EmbeddingModel, ModelKind, RemoteModel};

pub struct RemoteHydrator {
    remote: RemoteModel,
    cache: Arc<EmbeddingCache>,
}

impl RemoteHydrator {
    pub fn new(remote: RemoteModel, cache: Arc<EmbeddingCache>) -> Self {
        Self { remote, cache }
    }

    pub async fn hydrate_texts(&self, texts: &[String]) -> Result<(), EmbedError> {
        if texts.is_empty() {
            return Ok(());
        }
        let refs: Vec<&str> = texts.iter().map(|s| s.as_str()).collect();
        let vecs = self.remote.embed_batch(&refs).await?;
        for (t, v) in texts.iter().zip(vecs) {
            self.cache.insert(t, v);
        }
        Ok(())
    }
}

pub fn sync_embed_with_l1_cache(model: &ModelKind, cache: &EmbeddingCache, text: &str) -> Vec<f64> {
    if let Some(v) = cache.get(text) {
        return v;
    }
    let v = model.embed_text(text);
    cache.insert(text, v.clone());
    v
}
