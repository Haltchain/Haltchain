//! MCP Guard competitive benchmark — HaltChain vs "scanner" approach.
//!
//! Measures the latency of HaltChain's runtime MCP enforcement pipeline
//! vs a simulated static scanner (regex-only, like Aira's mcp-checkpoint).
//!
//! Run with:
//!   cargo run -p haltchain-bench --bin mcp_enforcement_gate --release
//!
//! CI gate: mcp_enforcement_p99_us < HALTCHAIN_MCP_BENCH_TARGET_US (default 2000 = 2ms)

use std::sync::Arc;
use std::time::Instant;

use haltchain_cognitive::monitor::CognitiveMonitor;
use haltchain_cognitive::monitor::ReasoningMetadata;
use haltchain_mcp_guard::types::{Decision, McpToolCall};
use serde_json::json;
use uuid::Uuid;

const N_ITERATIONS: usize = 5_000;

#[tokio::main]
async fn main() {
    let mut dry_run = false;
    let args: Vec<String> = std::env::args().skip(1).collect();
    for arg in &args {
        if arg == "--dry-run" {
            dry_run = true;
        }
    }

    if dry_run {
        println!("dry-run: iterations={N_ITERATIONS}");
        return;
    }

    let monitor = Arc::new(CognitiveMonitor::new());

    // ── Benchmark 1: Static scanner (regex-only, like Aira) ──
    println!("Benchmark 1 — Static scanner (regex-only, like Aira mcp-checkpoint) …");
    let static_latencies = bench_static_scanner();
    print_stats("Static scanner (regex)", &static_latencies);

    // ── Benchmark 2: HaltChain MCP enforcement pipeline ──
    println!("\nBenchmark 2 — HaltChain MCP enforcement pipeline …");
    let haltchain_latencies = bench_haltchain_pipeline(Arc::clone(&monitor)).await;
    print_stats("HaltChain enforcement", &haltchain_latencies);

    // ── Benchmark 3: Pattern firewall only (Aho-Corasick) ──
    println!("\nBenchmark 3 — Pattern firewall only (Aho-Corasick) …");
    let pattern_latencies = bench_pattern_firewall();
    print_stats("Pattern firewall (Aho-Corasick)", &pattern_latencies);

    // ── Comparison ──
    let static_p99 = percentile(&static_latencies, 0.99);
    let haltchain_p99 = percentile(&haltchain_latencies, 0.99);
    let pattern_p99 = percentile(&pattern_latencies, 0.99);

    println!("\n═══════════════════════════════════════════════════");
    println!("  Competitive Comparison (p99 latency)");
    println!("═══════════════════════════════════════════════════");
    println!("  Static scanner (Aira-style):  {static_p99:>8} µs");
    println!("  Pattern firewall only:        {pattern_p99:>8} µs");
    println!("  HaltChain full pipeline:      {haltchain_p99:>8} µs");
    println!("═══════════════════════════════════════════════════");

    if static_p99 > 0 {
        let ratio = static_p99 as f64 / haltchain_p99.max(1) as f64;
        if ratio > 1.0 {
            println!("  HaltChain is {ratio:.0}x faster than static scanner");
        } else {
            println!(
                "  Static scanner is {:.0}x faster (HaltChain does more work)",
                1.0 / ratio
            );
        }
    }

    // CI gate
    let target_us: u64 = std::env::var("HALTCHAIN_MCP_BENCH_TARGET_US")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2_000);

    if haltchain_p99 <= target_us {
        println!("\n✓ HaltChain enforcement p99 {haltchain_p99} µs ≤ target {target_us} µs");
    } else {
        println!("\n✗ HaltChain enforcement p99 {haltchain_p99} µs exceeds target {target_us} µs");
        std::process::exit(1);
    }
}

/// Simulated static scanner: regex matching only (like Aira's mcp-checkpoint).
/// No behavioral analysis, no drift detection, no cryptographic audit.
fn bench_static_scanner() -> Vec<u64> {
    let mut latencies = Vec::with_capacity(N_ITERATIONS);

    let blocked = ["exec", "shell", "sudo", "curl", "bash", "rm -rf"];

    let tool_calls: Vec<McpToolCall> = (0..100)
        .map(|i| McpToolCall {
            agent_id: Uuid::new_v4(),
            org_id: Uuid::new_v4(),
            tool_name: if i % 10 == 0 {
                "exec_malicious".to_string()
            } else {
                format!("tool_{}", i % 20)
            },
            tool_args: json!({"path": "/tmp/test", "recursive": true}),
            context_hash: format!("ctx_{i}"),
            timestamp: chrono::Utc::now().timestamp(),
        })
        .collect();

    for i in 0..N_ITERATIONS {
        let call = &tool_calls[i % tool_calls.len()];
        let t0 = Instant::now();

        // Simulate Aira's approach: regex scan tool name + args
        let mut found = false;
        for pattern in &blocked {
            if call.tool_name.to_lowercase().contains(pattern) {
                found = true;
                break;
            }
            if call.tool_args.to_string().to_lowercase().contains(pattern) {
                found = true;
                break;
            }
        }

        let _decision = if found {
            Decision::Block {
                reason: "static pattern match".to_string(),
                intent: None,
            }
        } else {
            Decision::Allow
        };

        latencies.push(t0.elapsed().as_micros() as u64);
    }

    latencies.sort_unstable();
    latencies
}

/// HaltChain's full MCP enforcement pipeline:
/// 1. Aho-Corasick pattern firewall
/// 2. Intent classification
/// 3. Cognitive triage
/// 4. Decision with intent annotation
async fn bench_haltchain_pipeline(monitor: Arc<CognitiveMonitor>) -> Vec<u64> {
    let mut latencies = Vec::with_capacity(N_ITERATIONS);

    let tool_calls: Vec<McpToolCall> = (0..100)
        .map(|i| McpToolCall {
            agent_id: Uuid::new_v4(),
            org_id: Uuid::new_v4(),
            tool_name: if i % 10 == 0 {
                "exec_malicious".to_string()
            } else {
                format!("tool_{}", i % 20)
            },
            tool_args: json!({"path": "/tmp/test", "recursive": true}),
            context_hash: format!("ctx_{i}"),
            timestamp: chrono::Utc::now().timestamp(),
        })
        .collect();

    for i in 0..N_ITERATIONS {
        let call = &tool_calls[i % tool_calls.len()];
        let t0 = Instant::now();

        // Step 1: Pattern firewall (Aho-Corasick — O(n) guaranteed)
        let pattern_match = {
            let ac = aho_corasick::AhoCorasick::new([
                "exec",
                "shell",
                "sudo",
                "curl",
                "bash",
                "rm -rf",
                "drop database",
                "token_exfiltration",
                "credential_dump",
            ])
            .unwrap();
            let text = format!("{} {}", call.tool_name, call.tool_args);
            ac.find(&text).is_some()
        };

        // Step 2: Intent classification
        let _intent = haltchain_cognitive::classify_intent(
            0.0, // drift_score
            &[], // behavioral markers
            &format!("{} {}", call.tool_name, call.tool_args),
        );

        // Step 3: Cognitive triage (200+ patterns, keyword analysis)
        let trace = format!(
            "Agent calls tool {} with args {}",
            call.tool_name, call.tool_args
        );
        let meta = ReasoningMetadata::from_trace(&trace);
        let _assessment = monitor.triage(&meta, &trace);

        // Step 4: Make decision
        let _decision = if pattern_match {
            Decision::Block {
                reason: "pattern firewall match".to_string(),
                intent: Some(format!("{:?}", _intent)),
            }
        } else {
            Decision::Allow
        };

        latencies.push(t0.elapsed().as_micros() as u64);
    }

    latencies.sort_unstable();
    latencies
}

/// Pattern firewall only — Aho-Corasick with 200+ patterns.
fn bench_pattern_firewall() -> Vec<u64> {
    let mut latencies = Vec::with_capacity(N_ITERATIONS);

    // Build a realistic pattern set (200+ patterns like the production firewall)
    let mut all_patterns: Vec<String> = vec![
        "exec",
        "shell",
        "sudo",
        "curl",
        "bash",
        "rm -rf",
        "drop database",
        "token_exfiltration",
        "credential_dump",
        "wget",
        "nc",
        "ncat",
        "netcat",
        "eval(",
        "system(",
        "os.system",
        "subprocess",
        "__import__",
        "pickle",
        "marshal",
        "base64_decode",
        "reverse_shell",
        "bind_shell",
        "meterpreter",
        "mimikatz",
        "bloodhound",
        "lazagne",
        "crackmapexec",
        "evil-winrm",
        "psexec",
        "wmiexec",
        "smbexec",
        "dcomexec",
        "atexec",
        "registry",
        "service",
        "task",
        "scheduled",
        "persist",
        "exfil",
        "c2",
        "beacon",
    ]
    .into_iter()
    .map(String::from)
    .collect();

    // Pad to 200+ patterns
    for i in 0..200 {
        all_patterns.push(format!("pattern_{i:04}"));
    }

    let ac = aho_corasick::AhoCorasick::new(&all_patterns).unwrap();

    let texts: Vec<String> = (0..100)
        .map(|i| {
            if i % 10 == 0 {
                "exec --shell --sudo --bash".to_string()
            } else {
                format!("tool_{i} with some normal arguments and context")
            }
        })
        .collect();

    for i in 0..N_ITERATIONS {
        let text = &texts[i % texts.len()];
        let t0 = Instant::now();

        let _matches: Vec<_> = ac.find_iter(text).collect();

        latencies.push(t0.elapsed().as_micros() as u64);
    }

    latencies.sort_unstable();
    latencies
}

fn print_stats(label: &str, sorted: &[u64]) {
    let total = sorted.len();
    let p50 = percentile(sorted, 0.50);
    let p95 = percentile(sorted, 0.95);
    let p99 = percentile(sorted, 0.99);
    let max = sorted.last().copied().unwrap_or(0);
    println!("\n── {label} latency (µs) — {total} samples ─────────────────");
    println!("  p50 : {p50} µs");
    println!("  p95 : {p95} µs");
    println!("  p99 : {p99} µs");
    println!("  max : {max} µs");
    println!("──────────────────────────────────────────────────────────");
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((p * sorted.len() as f64).ceil() as usize).saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)]
}
