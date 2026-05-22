// Fails if embed width != centroid row width (zip-sum would truncate silently).

use haltchain_cognitive::CognitiveMonitor;

#[test]
fn monitor_embed_trace_matches_centroid_row_width() {
    let mon = CognitiveMonitor::new();
    let v = mon.embed_trace("contract probe: centroid row must match embed width");
    assert_eq!(
        v.len(),
        mon.embedding_dims(),
        "embed_trace and centroids must share model.dims() (incl. HALTCHAIN_HASH_DIMS)"
    );
}
