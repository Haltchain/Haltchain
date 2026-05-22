use criterion::{Criterion, black_box, criterion_group, criterion_main};
use haltchain_mcp_guard::types::{Decision, McpToolCall};
use serde_json::json;
use std::time::Duration;
use uuid::Uuid;

fn cache_hit_path_baseline(c: &mut Criterion) {
    let call = McpToolCall {
        agent_id: Uuid::new_v4(),
        org_id: Uuid::new_v4(),
        tool_name: "list_files".to_string(),
        tool_args: json!({"path": "/tmp"}),
        context_hash: "ctx-hash".to_string(),
        timestamp: chrono::Utc::now().timestamp(),
    };

    let mut group = c.benchmark_group("mcp_guard_latency");
    group.measurement_time(Duration::from_secs(10));
    group.bench_function("decision_match_overhead", |b| {
        b.iter(|| {
            let d = Decision::Allow;
            let allow = matches!(d, Decision::Allow);
            black_box((allow, &call.tool_name));
        });
    });
    group.finish();
}

criterion_group!(benches, cache_hit_path_baseline);
criterion_main!(benches);
