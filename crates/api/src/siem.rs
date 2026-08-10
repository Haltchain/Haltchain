/// SIEM Integration — Section C: Cryptographic Audit Layer
///
/// Provides:
/// 1. CEF (Common Event Format) log lines for Splunk, Datadog, Google Chronicle.
/// 2. Fire-and-forget HTTP webhooks for critical decisions (DENY / CIRCUIT_BREAK).
///
/// CEF format (v0):
///   `CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions`
///
/// Extensions are space-separated `key=value` pairs.  Values containing `|` or `\`
/// must be escaped; we escape only what the spec requires.
///
/// Configuration (environment variables):
/// - `HALTCHAIN_SIEM_WEBHOOK_URL` — HTTP(S) endpoint to POST critical-alert JSON.
/// - `HALTCHAIN_SIEM_WEBHOOK_SECRET` — Shared secret added as `X-Webhook-Secret` header.
/// - `HALTCHAIN_SIEM_CEF_LOG_PATH` — File path for CEF log lines (default: stderr only).
use chrono::Utc;
use std::fs::OpenOptions;
use std::io::Write;

/// Severity mapping for CEF (0–10, where 10 is the most severe).
fn cef_severity(decision: &str) -> u8 {
    match decision.to_ascii_uppercase().as_str() {
        "DENY" => 8,
        "CIRCUIT_BREAK" => 9,
        "GOAL_CLARIFICATION_REQUIRED" => 5,
        _ => 2, // ALLOW
    }
}

/// Escape a CEF extension value: `\` → `\\`, `=` → `\=`, newline → `\n`.
fn cef_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// Build a single CEF log line for an agent validation decision.
///
/// Signature IDs map to decision outcomes:
/// - `HC001` — ALLOW
/// - `HC002` — DENY
/// - `HC003` — CIRCUIT_BREAK
/// - `HC004` — GOAL_CLARIFICATION_REQUIRED
pub fn format_cef_line(
    transaction_id: &str,
    agent_id: &str,
    decision: &str,
    policy_code: Option<&str>,
    timestamp: &str,
    merkle_root: Option<&str>,
    intent_label: Option<&str>,
) -> String {
    let sig_id = match decision.to_ascii_uppercase().as_str() {
        "DENY" => "HC002",
        "CIRCUIT_BREAK" => "HC003",
        "GOAL_CLARIFICATION_REQUIRED" => "HC004",
        _ => "HC001",
    };
    let name = match decision.to_ascii_uppercase().as_str() {
        "DENY" => "Agent Action Denied",
        "CIRCUIT_BREAK" => "Agent Circuit Breaker Tripped",
        "GOAL_CLARIFICATION_REQUIRED" => "Goal Clarification Required",
        _ => "Agent Action Allowed",
    };
    let severity = cef_severity(decision);

    // Build extension key=value pairs.
    let mut ext = format!(
        "rt={rt} src={agent} act={decision} externalId={txn}",
        rt = cef_escape(timestamp),
        agent = cef_escape(agent_id),
        decision = cef_escape(decision),
        txn = cef_escape(transaction_id),
    );
    if let Some(pc) = policy_code {
        ext.push_str(&format!(" reason={}", cef_escape(pc)));
    }
    if let Some(root) = merkle_root {
        ext.push_str(&format!(" cs1={} cs1Label=merkleRoot", cef_escape(root)));
    }
    if let Some(intent) = intent_label.filter(|s| !s.trim().is_empty()) {
        ext.push_str(&format!(" cs2={} cs2Label=intentLabel", cef_escape(intent)));
    }

    format!(
        "CEF:0|HaltChain|Validator|{}|{sig_id}|{name}|{severity}|{ext}",
        env!("CARGO_PKG_VERSION"),
    )
}

/// Append a CEF log line to the configured file (if set) and to tracing.
pub fn emit_cef(line: &str) {
    // Always emit to tracing so it appears in structured log outputs.
    tracing::info!(cef_line = %line, "SIEM CEF");

    if let Ok(path) = std::env::var("HALTCHAIN_SIEM_CEF_LOG_PATH")
        && !path.is_empty()
        && let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path)
    {
        let _ = writeln!(f, "{line}");
    }
}

/// Fire a webhook for critical decisions (DENY or CIRCUIT_BREAK).
///
/// The POST body is a JSON object.  The call is fire-and-forget using
/// `tokio::spawn`; failures are logged but not returned to the caller.
pub fn fire_webhook_if_critical(
    transaction_id: &str,
    agent_id: &str,
    decision: &str,
    policy_code: Option<&str>,
    timestamp: &str,
) {
    let decision_upper = decision.to_ascii_uppercase();
    if decision_upper != "DENY" && decision_upper != "CIRCUIT_BREAK" {
        return;
    }

    let Ok(url) = std::env::var("HALTCHAIN_SIEM_WEBHOOK_URL") else {
        return;
    };
    if url.is_empty() {
        return;
    }

    let secret = std::env::var("HALTCHAIN_SIEM_WEBHOOK_SECRET").unwrap_or_default();
    let payload = serde_json::json!({
        "event":          "critical_decision",
        "transaction_id": transaction_id,
        "agent_id":       agent_id,
        "decision":       decision,
        "policy_code":    policy_code,
        "timestamp":      timestamp,
        "alert_at":       Utc::now().to_rfc3339(),
    });

    // Clone to move into the spawned task.
    let url = url.clone();
    let secret = secret.clone();
    let body = payload.to_string();

    tokio::spawn(async move {
        let client = reqwest::Client::new();
        let mut req = client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body);
        if !secret.is_empty() {
            req = req.header("X-Webhook-Secret", &secret);
        }
        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!(url = %url, "SIEM webhook delivered");
            }
            Ok(resp) => {
                tracing::warn!(
                    url = %url,
                    status = %resp.status(),
                    "SIEM webhook non-success response"
                );
            }
            Err(e) => {
                tracing::warn!(url = %url, error = %e, "SIEM webhook delivery failed");
            }
        }
    });
}

/// Emit a CEF security-downgrade event when the embedding layer falls back from
/// ONNX semantic model to the hash-projection fallback.
///
/// Signature: `HC010` — Embedding Security Downgrade
/// Severity: 6 — Medium. Detection confidence significantly reduced.
pub fn emit_embedding_downgrade(reason: &str, hash_dims: usize) {
    let ts = Utc::now().to_rfc3339();
    let line = format!(
        "CEF:0|HaltChain|Validator|{}|HC010|Embedding Security Downgrade|6|\
         rt={rt} act=hash_fallback cs3={dims} cs3Label=hashDims msg={msg}",
        env!("CARGO_PKG_VERSION"),
        rt = cef_escape(&ts),
        dims = hash_dims,
        msg = cef_escape(reason),
    );
    emit_cef(&line);
    tracing::warn!(
        hash_dims,
        reason,
        cef_sig = "HC010",
        "SECURITY_DOWNGRADE: ONNX embedding unavailable; using hash-projection. \
         Semantic evasion attacks may bypass detection."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cef_escape_special_chars() {
        assert_eq!(cef_escape("a=b\\c"), "a\\=b\\\\c");
    }

    #[test]
    fn format_deny_cef_line() {
        let line = format_cef_line(
            "txn-001",
            "agent-01",
            "DENY",
            Some("RATE_LIMIT"),
            "2026-01-01T00:00:00Z",
            None,
            None,
        );
        assert!(line.starts_with("CEF:0|HaltChain|Validator|"));
        assert!(line.contains("HC002"));
        assert!(line.contains("Agent Action Denied"));
        assert!(line.contains("|8|"));
        assert!(line.contains("reason=RATE_LIMIT"));
    }

    #[test]
    fn format_allow_cef_line() {
        let line = format_cef_line(
            "txn-002",
            "agent-02",
            "ALLOW",
            None,
            "2026-01-01T00:00:00Z",
            Some("abc123"),
            Some("benign"),
        );
        assert!(line.contains("HC001"));
        assert!(line.contains("|2|"));
        assert!(line.contains("cs1=abc123"));
        assert!(line.contains("cs1Label=merkleRoot"));
        assert!(line.contains("cs2=benign"));
        assert!(line.contains("cs2Label=intentLabel"));
    }

    #[test]
    fn cef_severity_values() {
        assert_eq!(cef_severity("DENY"), 8);
        assert_eq!(cef_severity("CIRCUIT_BREAK"), 9);
        assert_eq!(cef_severity("ALLOW"), 2);
        assert_eq!(cef_severity("GOAL_CLARIFICATION_REQUIRED"), 5);
    }
}
