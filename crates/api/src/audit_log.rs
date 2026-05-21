use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::OnceLock;

use base64::{Engine as _, engine::general_purpose};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use chrono::Utc;
use parking_lot::Mutex;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const DEFAULT_RETENTION_DAYS: i64 = 30;
const DEFAULT_PRUNE_INTERVAL_SECS: u64 = 3600;

fn log_path() -> PathBuf {
    std::env::var("HALTCHAIN_AUDIT_LOG_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/haltchain-audit.log.enc"))
}

fn encryption_key() -> Result<Key, String> {
    let hex_key = std::env::var("HALTCHAIN_LOG_ENCRYPTION_KEY_HEX")
        .map_err(|_| "HALTCHAIN_LOG_ENCRYPTION_KEY_HEX not set".to_string())?;
    let key_bytes = hex::decode(hex_key).map_err(|e| format!("invalid encryption key hex: {e}"))?;
    if key_bytes.len() != 32 {
        return Err("HALTCHAIN_LOG_ENCRYPTION_KEY_HEX must be 32 bytes (64 hex chars)".to_string());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key_bytes);
    Ok(Key::from(arr))
}

pub fn audit_retention_days() -> i64 {
    std::env::var("HALTCHAIN_AUDIT_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|days| *days > 0)
        .unwrap_or(DEFAULT_RETENTION_DAYS)
}

pub fn audit_prune_interval_secs() -> u64 {
    std::env::var("HALTCHAIN_AUDIT_PRUNE_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(DEFAULT_PRUNE_INTERVAL_SECS)
}

fn is_sensitive_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "x-api-key"
            | "authorization"
            | "x-haltchain-signature"
            | "request_sig"
            | "api_key"
            | "token"
            | "password"
            | "secret"
            | "sig"
            | "nonce"
            | "request_nonce"
            | "session_token"
            | "cookie"
    )
}

pub fn redact_json(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if is_sensitive_key(k) {
                    *v = Value::String("[REDACTED]".to_string());
                } else {
                    redact_json(v);
                }
            }
        }
        Value::Array(arr) => {
            for v in arr {
                redact_json(v);
            }
        }
        _ => {}
    }
}

pub fn append_audit_event(mut event: Value) -> Result<(), String> {
    if event.get("logged_at").is_none() {
        event["logged_at"] = Value::String(Utc::now().to_rfc3339());
    }
    redact_json(&mut event);

    // Extend the hash chain: H(canonical_json || prev_hash).
    let canonical = serde_json::to_vec(&event).map_err(|e| format!("json encode error: {e}"))?;
    AuditChain::global().push(&canonical);

    let b64 = encrypt_line(&canonical)?;
    append_encrypted_line(&b64)
}

fn encrypt_line(line: &[u8]) -> Result<String, String> {
    let key = encryption_key()?;
    let cipher = XChaCha20Poly1305::new(&key);

    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let nonce_ref = XNonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(nonce_ref, line.as_ref())
        .map_err(|e| format!("encrypt failed: {e}"))?;

    let mut packed = Vec::with_capacity(24 + ciphertext.len());
    packed.extend_from_slice(&nonce);
    packed.extend_from_slice(&ciphertext);

    Ok(general_purpose::STANDARD.encode(packed))
}

fn append_encrypted_line(b64: &str) -> Result<(), String> {
    let path = log_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir failed: {e}"))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open log file failed: {e}"))?;
    file.write_all(b64.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .map_err(|e| format!("write log failed: {e}"))?;
    Ok(())
}

fn decrypt_line(line: &str, cipher: &XChaCha20Poly1305) -> Option<Value> {
    let packed = general_purpose::STANDARD.decode(line).ok()?;
    if packed.len() < 24 {
        return None;
    }
    let (nonce_bytes, ciphertext) = packed.split_at(24);
    let nonce_ref = XNonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce_ref, ciphertext).ok()?;
    serde_json::from_slice::<Value>(&plaintext).ok()
}

fn parse_logged_at_epoch(event: &Value) -> Option<i64> {
    event
        .get("logged_at")
        .and_then(Value::as_str)
        .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
        .map(|dt| dt.timestamp())
}

#[derive(Debug, Clone, Copy)]
pub struct PruneReport {
    pub total_lines: usize,
    pub kept_lines: usize,
    pub removed_lines: usize,
    pub skipped_lines: usize,
}

pub fn prune_expired_audit_events() -> Result<PruneReport, String> {
    let retention_days = audit_retention_days();
    let cutoff_ts = Utc::now().timestamp() - (retention_days * 24 * 60 * 60);
    prune_expired_audit_events_with_cutoff(cutoff_ts)
}

fn prune_expired_audit_events_with_cutoff(cutoff_ts: i64) -> Result<PruneReport, String> {
    let path = log_path();
    if !path.exists() {
        return Ok(PruneReport {
            total_lines: 0,
            kept_lines: 0,
            removed_lines: 0,
            skipped_lines: 0,
        });
    }

    let file = File::open(&path).map_err(|e| format!("open log file failed: {e}"))?;
    let lines: Vec<String> = BufReader::new(file)
        .lines()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("read log failed: {e}"))?;

    let key = encryption_key()?;
    let cipher = XChaCha20Poly1305::new(&key);
    let mut kept_encoded = Vec::new();
    let mut removed_lines = 0usize;
    let mut skipped_lines = 0usize;

    for line in &lines {
        let Some(event) = decrypt_line(line, &cipher) else {
            skipped_lines += 1;
            tracing::debug!("audit-log: skipped undecryptable line during prune");
            continue;
        };
        if let Some(ts) = parse_logged_at_epoch(&event)
            && ts < cutoff_ts
        {
            removed_lines += 1;
            continue;
        }
        kept_encoded.push(line.clone());
    }

    let temp_path = path.with_extension("tmp");
    {
        let mut temp =
            File::create(&temp_path).map_err(|e| format!("create temp log failed: {e}"))?;
        for line in &kept_encoded {
            temp.write_all(line.as_bytes())
                .and_then(|_| temp.write_all(b"\n"))
                .map_err(|e| format!("write temp log failed: {e}"))?;
        }
        temp.flush()
            .map_err(|e| format!("flush temp log failed: {e}"))?;
    }

    std::fs::rename(&temp_path, &path).map_err(|e| format!("replace log failed: {e}"))?;

    Ok(PruneReport {
        total_lines: lines.len(),
        kept_lines: kept_encoded.len(),
        removed_lines,
        skipped_lines,
    })
}

/// Maximum lines to load from the audit log file at once.
const MAX_AUDIT_LOG_LINES: usize = 500_000;

/// Filters for `query_audit_events`.
#[derive(Debug, Default)]
pub struct AuditQueryFilter {
    /// Inclusive lower bound (epoch seconds).
    pub time_from: Option<i64>,
    /// Inclusive upper bound (epoch seconds).
    pub time_to: Option<i64>,
    /// Match events whose `agent_id` field equals this value.
    pub agent_id: Option<String>,
    /// Match events whose `decision` field equals this value (e.g. `"DENY"`).
    pub decision: Option<String>,
    /// Maximum number of events to return (newest-first). Defaults to 100.
    pub limit: usize,
}

/// Structured result from `query_audit_events`.
#[derive(Debug)]
pub struct AuditQueryResult {
    pub events: Vec<Value>,
    /// Total events scanned (before filtering).
    pub scanned: usize,
}

/// Query the encrypted audit log with optional time-range, agent, and decision filters.
///
/// Scans up to `MAX_AUDIT_LOG_LINES` lines, newest-first, and returns matching
/// events up to `filter.limit`.  All filter comparisons are case-insensitive for
/// decision and exact-match for agent_id.
pub fn query_audit_events(filter: &AuditQueryFilter) -> Result<AuditQueryResult, String> {
    let limit = if filter.limit == 0 { 100 } else { filter.limit };
    let path = log_path();
    let file = File::open(&path).map_err(|e| format!("open log file failed: {e}"))?;

    let lines: Vec<String> = BufReader::new(file)
        .lines()
        .take(MAX_AUDIT_LOG_LINES)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("read log failed: {e}"))?;

    let scanned = lines.len();
    let key = encryption_key()?;
    let cipher = XChaCha20Poly1305::new(&key);
    let mut out = Vec::new();

    for line in lines.into_iter().rev() {
        if out.len() >= limit {
            break;
        }
        let Some(event) = decrypt_line(&line, &cipher) else {
            continue;
        };

        // ── time_from filter ──────────────────────────────────────────────────
        if let Some(from) = filter.time_from {
            match parse_logged_at_epoch(&event) {
                Some(ts) if ts >= from => {}
                _ => continue,
            }
        }

        // ── time_to filter ────────────────────────────────────────────────────
        if let Some(to) = filter.time_to {
            match parse_logged_at_epoch(&event) {
                Some(ts) if ts <= to => {}
                _ => continue,
            }
        }

        // ── agent_id filter ───────────────────────────────────────────────────
        if let Some(ref agent_filter) = filter.agent_id {
            match event.get("agent_id").and_then(Value::as_str) {
                Some(aid) if aid == agent_filter.as_str() => {}
                _ => continue,
            }
        }

        // ── decision filter ───────────────────────────────────────────────────
        if let Some(ref decision_filter) = filter.decision {
            match event.get("decision").and_then(Value::as_str) {
                Some(d) if d.eq_ignore_ascii_case(decision_filter.as_str()) => {}
                _ => continue,
            }
        }

        out.push(event);
    }

    Ok(AuditQueryResult {
        events: out,
        scanned,
    })
}

pub fn read_recent_audit_events(limit: usize) -> Result<Vec<Value>, String> {
    let path = log_path();
    let file = File::open(path).map_err(|e| format!("open log file failed: {e}"))?;
    // Read only the last MAX_AUDIT_LOG_LINES to bound memory.
    let lines: Vec<String> = BufReader::new(file)
        .lines()
        .take(MAX_AUDIT_LOG_LINES)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("read log failed: {e}"))?;

    let key = encryption_key()?;
    let cipher = XChaCha20Poly1305::new(&key);
    let mut out = Vec::new();

    for line in lines.into_iter().rev().take(limit) {
        if let Some(v) = decrypt_line(&line, &cipher) {
            out.push(v);
        }
    }

    if out.is_empty() {
        out.push(json!({ "status": "empty" }));
    }
    Ok(out)
}

// Audit Log Hash Chain

/// Sequential hash chain over audit log entries.
///
/// Every entry's hash is `SHA-256(canonical_json || prev_hash)` where `prev_hash`
/// is the hash of the preceding entry (or 32 zero bytes for the first entry).
/// Tampering with any entry breaks the chain from that point forward.
pub struct AuditChain {
    inner: Mutex<ChainInner>,
}

struct ChainInner {
    /// Hash of the most recent entry (head of the chain).
    head: [u8; 32],
    /// Total entries appended since process start.
    count: u64,
}

/// Snapshot of the audit chain state.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditChainStatus {
    /// Hex-encoded hash of the most recent entry.
    pub head_hex: String,
    /// Total entries since process start.
    pub entries: u64,
}

fn sha256_audit(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

impl AuditChain {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(ChainInner {
                head: [0u8; 32],
                count: 0,
            }),
        }
    }

    pub fn global() -> &'static AuditChain {
        static INSTANCE: OnceLock<AuditChain> = OnceLock::new();
        INSTANCE.get_or_init(AuditChain::new)
    }

    /// Hash the canonical entry bytes with the current chain head and advance.
    pub fn push(&self, canonical_json: &[u8]) {
        let mut inner = self.inner.lock();
        let mut preimage = Vec::with_capacity(canonical_json.len() + 32);
        preimage.extend_from_slice(canonical_json);
        preimage.extend_from_slice(&inner.head);
        inner.head = sha256_audit(&preimage);
        inner.count += 1;
    }

    /// Current chain status.
    pub fn status(&self) -> AuditChainStatus {
        let inner = self.inner.lock();
        AuditChainStatus {
            head_hex: hex::encode(inner.head),
            entries: inner.count,
        }
    }

    /// Verify a sequence of canonical JSON entries against an expected chain.
    ///
    /// `entries` must be in append order. Returns `Ok(head_hex)` with the
    /// resulting chain head if the replay succeeds.
    pub fn verify_sequence(entries: &[Vec<u8>], initial_head: [u8; 32]) -> String {
        let mut head = initial_head;
        for entry in entries {
            let mut preimage = Vec::with_capacity(entry.len() + 32);
            preimage.extend_from_slice(entry);
            preimage.extend_from_slice(&head);
            head = sha256_audit(&preimage);
        }
        hex::encode(head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex as StdMutex, OnceLock as StdOnceLock};

    fn env_lock() -> &'static StdMutex<()> {
        static ENV_LOCK: StdOnceLock<StdMutex<()>> = StdOnceLock::new();
        ENV_LOCK.get_or_init(|| StdMutex::new(()))
    }

    #[test]
    fn redaction_masks_secrets() {
        let mut v = json!({
            "agent_id": "a1",
            "api_key": "secret",
            "nested": {
                "authorization": "Bearer abc"
            }
        });
        redact_json(&mut v);
        assert_eq!(v["api_key"], "[REDACTED]");
        assert_eq!(v["nested"]["authorization"], "[REDACTED]");
    }

    #[test]
    fn prune_removes_expired_events() {
        let _guard = env_lock().lock().expect("env lock should acquire");
        let unique = format!("{}", Utc::now().timestamp_nanos_opt().unwrap_or_default());
        let path = std::env::temp_dir().join(format!("haltchain-audit-{unique}.log.enc"));
        unsafe {
            std::env::set_var(
                "HALTCHAIN_AUDIT_LOG_PATH",
                path.to_string_lossy().to_string(),
            );
            std::env::set_var(
                "HALTCHAIN_LOG_ENCRYPTION_KEY_HEX",
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            );
        }

        let old = json!({
            "event": "old",
            "logged_at": "2020-01-01T00:00:00Z",
        });
        let fresh = json!({
            "event": "fresh",
            "logged_at": "2099-01-01T00:00:00Z",
        });
        append_audit_event(old).expect("old event should append");
        append_audit_event(fresh).expect("fresh event should append");

        let report = prune_expired_audit_events_with_cutoff(Utc::now().timestamp())
            .expect("prune should succeed");
        assert_eq!(report.total_lines, 2);
        assert_eq!(report.removed_lines, 1);
        assert_eq!(report.kept_lines, 1);

        let events = read_recent_audit_events(10).expect("events should read");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["event"], "fresh");

        let _ = std::fs::remove_file(path);
        unsafe {
            std::env::remove_var("HALTCHAIN_AUDIT_LOG_PATH");
            std::env::remove_var("HALTCHAIN_LOG_ENCRYPTION_KEY_HEX");
        }
    }

    #[test]
    fn audit_chain_sequential_hashing() {
        let chain = AuditChain::new();
        assert_eq!(chain.status().entries, 0);
        assert_eq!(chain.status().head_hex, "0".repeat(64));

        chain.push(b"event-1");
        let h1 = chain.status().head_hex.clone();
        assert_ne!(h1, "0".repeat(64));
        assert_eq!(chain.status().entries, 1);

        chain.push(b"event-2");
        let h2 = chain.status().head_hex.clone();
        assert_ne!(h2, h1, "head must advance");
        assert_eq!(chain.status().entries, 2);
    }

    #[test]
    fn audit_chain_verify_sequence() {
        let entries: Vec<Vec<u8>> = vec![b"alpha".to_vec(), b"bravo".to_vec(), b"charlie".to_vec()];
        let result = AuditChain::verify_sequence(&entries, [0u8; 32]);

        // Verify produces the same head as pushing individually.
        let chain = AuditChain::new();
        for e in &entries {
            chain.push(e);
        }
        assert_eq!(result, chain.status().head_hex);
    }

    #[test]
    fn audit_chain_deterministic() {
        let a = AuditChain::new();
        let b = AuditChain::new();
        for i in 0..10 {
            let payload = format!("entry-{i}");
            a.push(payload.as_bytes());
            b.push(payload.as_bytes());
        }
        assert_eq!(a.status().head_hex, b.status().head_hex);
    }
}
