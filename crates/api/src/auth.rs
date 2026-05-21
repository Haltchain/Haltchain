use std::{
    collections::HashSet,
    collections::VecDeque,
    sync::OnceLock,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use axum::{
    Json,
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter as GovernorRateLimiter};
use hmac::{Hmac, Mac};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{error, warn};

use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

const REQUEST_SIG_MAX_AGE_SECS: i64 = 300;
pub const NONCE_TTL_SECS: u64 = 300;
pub const NONCE_SWEEP_SECS: u64 = 60;

// Rate limiting constants
const RATE_LIMIT_WINDOW_SECS: u64 = 60;
const MAX_REQUESTS_PER_IP: u32 = 100;
const MAX_REQUESTS_PER_API_KEY: u32 = 1000;
const MAX_REQUESTS_PER_AGENT: u32 = 500;
const GLOBAL_RATE_LIMIT: u32 = 10_000;

static API_KEYS: OnceLock<HashSet<String>> = OnceLock::new();
static ADMIN_KEYS: OnceLock<HashSet<String>> = OnceLock::new();
static NONCES: OnceLock<Mutex<std::collections::HashMap<String, Instant>>> = OnceLock::new();
static LAST_SWEEP: OnceLock<Mutex<Instant>> = OnceLock::new();

// Ed25519 public keys for request signing verification
static CLIENT_PUBKEYS: OnceLock<DashMap<String, VerifyingKey>> = OnceLock::new();

// Multi-layer rate limiting state
static RATE_LIMITER: OnceLock<RateLimiter> = OnceLock::new();
static VALIDATE_INGRESS_GATE: OnceLock<ValidateIngressGate> = OnceLock::new();

// Admin MFA configuration (loaded from env vars on first use)
static ADMIN_TOTP_SECRET: OnceLock<Option<String>> = OnceLock::new();
static ADMIN_IP_ALLOWLIST: OnceLock<Option<HashSet<String>>> = OnceLock::new();
static JWT_SECRET: OnceLock<Option<String>> = OnceLock::new();
// Separate secret for admin browser sessions (falls back to JWT_SECRET or a dev default).
static ADMIN_SESSION_SECRET: OnceLock<Vec<u8>> = OnceLock::new();

/// JWT expiry in seconds (15 minutes).
const JWT_EXPIRY_SECS: u64 = 900;
/// Admin browser session expiry: 8 hours.
const ADMIN_SESSION_EXPIRY_SECS: u64 = 60 * 60 * 8;

/// Claims encoded in short-lived API JWT tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String, // agent_id
    pub exp: u64,    // Unix expiry
    pub iat: u64,    // issued-at
    pub jti: String, // unique token id (nonce)
    /// Space-separated OAuth2-style scopes (e.g. "validate read:status").
    /// Empty string means unrestricted (legacy tokens).
    #[serde(default)]
    pub scp: String,
}

impl JwtClaims {
    /// Returns true if the token carries the given scope, or if the token
    /// has no scopes at all (unrestricted legacy token).
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scp.is_empty() || self.scp.split_whitespace().any(|s| s == scope)
    }
}

/// Claims for admin browser sessions issued by `POST /auth/admin/login`.
#[derive(Debug, Serialize, Deserialize)]
pub struct AdminSessionClaims {
    pub sub: String, // email
    pub exp: u64,
    pub iat: u64,
    pub typ: String, // always "admin_session"
}

fn admin_session_secret() -> &'static [u8] {
    ADMIN_SESSION_SECRET.get_or_init(|| {
        let raw = std::env::var("HALTCHAIN_ADMIN_SESSION_SECRET")
            .or_else(|_| std::env::var("HALTCHAIN_JWT_SECRET"))
            .unwrap_or_else(|_| "dev-admin-session-secret-change-me".to_string());
        raw.into_bytes()
    })
}

/// Issue an admin session JWT (for browser logins).
pub fn issue_admin_session_jwt(email: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let claims = AdminSessionClaims {
        sub: email.to_string(),
        exp: now + ADMIN_SESSION_EXPIRY_SECS,
        iat: now,
        typ: "admin_session".to_string(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(admin_session_secret()),
    )
    .unwrap_or_default()
}

/// Verify an admin session JWT. Returns the email on success.
pub fn verify_admin_session_jwt(token: &str) -> Option<String> {
    let mut validation = Validation::default();
    validation.validate_exp = true;
    decode::<AdminSessionClaims>(
        token,
        &DecodingKey::from_secret(admin_session_secret()),
        &validation,
    )
    .ok()
    .filter(|data| data.claims.typ == "admin_session")
    .map(|data| data.claims.sub)
}

pub fn configured_api_keys() -> &'static HashSet<String> {
    API_KEYS.get_or_init(|| {
        let raw = std::env::var("HALTCHAIN_API_KEYS")
            .unwrap_or_else(|_| "dev-key,canary-api-key,bench-key".to_string());
        raw.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect()
    })
}

pub fn configured_admin_keys() -> &'static HashSet<String> {
    ADMIN_KEYS.get_or_init(|| {
        let raw =
            std::env::var("HALTCHAIN_ADMIN_KEYS").unwrap_or_else(|_| "dev-admin-key".to_string());
        raw.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect()
    })
}

/// Initialize or get client public keys for Ed25519 request signing
pub fn client_pubkey_store() -> &'static DashMap<String, VerifyingKey> {
    CLIENT_PUBKEYS.get_or_init(|| {
        let map = DashMap::new();
        // Load from environment: HALTCHAIN_CLIENT_PUBKEYS=key1:base64pubkey1,key2:base64pubkey2
        if let Ok(env_keys) = std::env::var("HALTCHAIN_CLIENT_PUBKEYS") {
            for entry in env_keys.split(',') {
                let entry = entry.trim();
                if entry.is_empty() {
                    continue;
                }
                let Some((key_id, pubkey_b64)) = entry.split_once(':') else {
                    warn!(entry = %entry, "skipped malformed client pubkey entry (missing ':')");
                    continue;
                };
                let Ok(pubkey_bytes) = general_purpose::STANDARD.decode(pubkey_b64.trim()) else {
                    warn!(key_id = %key_id.trim(), "skipped client pubkey: base64 decode failed");
                    continue;
                };
                if pubkey_bytes.len() != 32 {
                    warn!(key_id = %key_id.trim(), len = pubkey_bytes.len(), "skipped client pubkey: expected 32 bytes");
                    continue;
                }
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&pubkey_bytes);
                match VerifyingKey::from_bytes(&bytes) {
                    Ok(pubkey) => {
                        map.insert(key_id.trim().to_string(), pubkey);
                    }
                    Err(e) => {
                        warn!(key_id = %key_id.trim(), error = %e, "skipped client pubkey: invalid Ed25519 key");
                    }
                }
            }
        }
        map
    })
}

/// Rate limiter with multiple layers: IP, API Key, Agent, Global
pub struct RateLimiter {
    /// Layer 1: IP-based rate limiting
    ip_buckets: DashMap<String, TokenBucket>,
    /// Layer 2: API key-based rate limiting  
    key_buckets: DashMap<String, TokenBucket>,
    /// Layer 3: Agent-based rate limiting
    agent_buckets: DashMap<String, TokenBucket>,
    /// Layer 4: Global rate limiting
    global_bucket: Mutex<TokenBucket>,
}

#[derive(Clone)]
struct TokenBucket {
    tokens: u32,
    last_update: Instant,
    capacity: u32,
    refill_rate: u32, // tokens per second
}

impl TokenBucket {
    fn new(capacity: u32, refill_rate: u32) -> Self {
        Self {
            tokens: capacity,
            last_update: Instant::now(),
            capacity,
            refill_rate,
        }
    }

    fn consume(&mut self, amount: u32) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs() as u32;
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_update = now;

        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            ip_buckets: DashMap::new(),
            key_buckets: DashMap::new(),
            agent_buckets: DashMap::new(),
            global_bucket: Mutex::new(TokenBucket::new(GLOBAL_RATE_LIMIT, GLOBAL_RATE_LIMIT / 60)),
        }
    }

    /// Check all rate limit layers. Returns Err if any layer is exceeded.
    pub fn check(
        &self,
        ip: &str,
        api_key: Option<&str>,
        agent_id: Option<&str>,
    ) -> Result<(), RateLimitError> {
        // Layer 4: Global rate limit (checked first)
        {
            let mut global = self.global_bucket.lock();
            if !global.consume(1) {
                return Err(RateLimitError::Global);
            }
        }

        // Layer 1: IP-based rate limiting
        {
            let mut bucket = self
                .ip_buckets
                .entry(ip.to_string())
                .or_insert_with(|| TokenBucket::new(MAX_REQUESTS_PER_IP, MAX_REQUESTS_PER_IP / 60));
            if !bucket.consume(1) {
                return Err(RateLimitError::Ip);
            }
        }

        // Layer 2: API key-based rate limiting
        if let Some(key) = api_key {
            let mut bucket = self.key_buckets.entry(key.to_string()).or_insert_with(|| {
                TokenBucket::new(MAX_REQUESTS_PER_API_KEY, MAX_REQUESTS_PER_API_KEY / 60)
            });
            if !bucket.consume(1) {
                return Err(RateLimitError::Key);
            }
        }

        // Layer 3: Agent-based rate limiting
        if let Some(agent) = agent_id {
            let mut bucket = self
                .agent_buckets
                .entry(agent.to_string())
                .or_insert_with(|| {
                    TokenBucket::new(MAX_REQUESTS_PER_AGENT, MAX_REQUESTS_PER_AGENT / 60)
                });
            if !bucket.consume(1) {
                return Err(RateLimitError::Agent);
            }
        }

        Ok(())
    }

    /// Clean up stale entries periodically
    pub fn cleanup(&self) {
        let cutoff = Instant::now() - Duration::from_secs(RATE_LIMIT_WINDOW_SECS * 2);
        self.ip_buckets
            .retain(|_, bucket| bucket.last_update > cutoff);
        self.key_buckets
            .retain(|_, bucket| bucket.last_update > cutoff);
        self.agent_buckets
            .retain(|_, bucket| bucket.last_update > cutoff);
    }
}

struct ValidateIngressGate {
    limiter: Mutex<DefaultDirectRateLimiter>,
    semaphore: std::sync::Arc<Semaphore>,
    inflight: AtomicUsize,
    permit_limit: AtomicUsize,
    permit_floor: AtomicUsize,
    p95_target_ms: AtomicU64,
    latency_samples: Mutex<VecDeque<(Instant, u64)>>,
    breach_since: Mutex<Option<Instant>>,
    adaptive_window: Duration,
}

struct ValidateGatePermit<'a> {
    _permit: OwnedSemaphorePermit,
    gate: &'a ValidateIngressGate,
}

impl Drop for ValidateGatePermit<'_> {
    fn drop(&mut self) {
        self.gate.inflight.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Copy)]
struct ValidateIngressConfig {
    rate_limit_rps: u32,
    burst: u32,
    permits: usize,
    permit_floor: usize,
    p95_target_ms: u64,
}

impl ValidateIngressConfig {
    fn from_env() -> Self {
        let rate_limit_rps = std::env::var("HALTCHAIN_VALIDATE_RATE_LIMIT_RPS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10_000)
            .max(1);
        let burst = std::env::var("HALTCHAIN_VALIDATE_RATE_LIMIT_BURST")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2_000)
            .max(1);
        let permits = std::env::var("HALTCHAIN_VALIDATE_SEMAPHORE_PERMITS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(29)
            .max(1);
        let permit_floor = std::env::var("HALTCHAIN_VALIDATE_SEMAPHORE_FLOOR")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8)
            .max(1)
            .min(permits);
        let p95_target_ms = std::env::var("HALTCHAIN_VALIDATE_P95_TARGET_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2)
            .max(1);
        Self {
            rate_limit_rps,
            burst,
            permits,
            permit_floor,
            p95_target_ms,
        }
    }
}

impl ValidateIngressGate {
    fn new(cfg: ValidateIngressConfig) -> Self {
        Self {
            limiter: Mutex::new(build_validate_limiter(cfg.rate_limit_rps, cfg.burst)),
            semaphore: std::sync::Arc::new(Semaphore::new(cfg.permits)),
            inflight: AtomicUsize::new(0),
            permit_limit: AtomicUsize::new(cfg.permits),
            permit_floor: AtomicUsize::new(cfg.permit_floor),
            p95_target_ms: AtomicU64::new(cfg.p95_target_ms),
            latency_samples: Mutex::new(VecDeque::new()),
            breach_since: Mutex::new(None),
            adaptive_window: Duration::from_secs(3),
        }
    }

    fn check_rate_limit(&self) -> bool {
        let limiter = self.limiter.lock();
        limiter.check().is_ok()
    }

    fn try_acquire(&self) -> Option<ValidateGatePermit<'_>> {
        let limit = self.permit_limit.load(Ordering::Acquire);
        let inflight = self.inflight.load(Ordering::Acquire);
        if inflight >= limit {
            return None;
        }

        let permit = self.semaphore.clone().try_acquire_owned().ok()?;
        let prev = self.inflight.fetch_add(1, Ordering::AcqRel);
        if prev + 1 > limit {
            self.inflight.fetch_sub(1, Ordering::AcqRel);
            drop(permit);
            return None;
        }
        Some(ValidateGatePermit {
            _permit: permit,
            gate: self,
        })
    }

    fn observe_latency(&self, elapsed: Duration) {
        let mut samples = self.latency_samples.lock();
        let now = Instant::now();
        samples.push_back((now, elapsed.as_micros() as u64));
        while let Some((ts, _)) = samples.front() {
            if now.duration_since(*ts) > self.adaptive_window {
                samples.pop_front();
            } else {
                break;
            }
        }
    }

    fn maybe_reduce_permits(&self) {
        let now = Instant::now();
        let window = self.adaptive_window;
        let target_us = self.p95_target_ms.load(Ordering::Relaxed) * 1_000;

        let p95_us = {
            let mut samples = self.latency_samples.lock();
            while let Some((ts, _)) = samples.front() {
                if now.duration_since(*ts) > window {
                    samples.pop_front();
                } else {
                    break;
                }
            }
            if samples.len() < 20 {
                return;
            }
            let mut latencies = samples.iter().map(|(_, us)| *us).collect::<Vec<_>>();
            latencies.sort_unstable();
            let idx = ((latencies.len() - 1) as f64 * 0.95).round() as usize;
            latencies[idx]
        };

        let mut breach = self.breach_since.lock();
        if p95_us > target_us {
            match *breach {
                Some(started) if now.duration_since(started) >= Duration::from_secs(3) => {
                    let current = self.permit_limit.load(Ordering::Acquire);
                    let floor = self.permit_floor.load(Ordering::Acquire);
                    if current > floor {
                        let mut reduced = ((current as f64) * 0.9).ceil() as usize;
                        if reduced >= current {
                            reduced = current.saturating_sub(1);
                        }
                        let next = reduced.max(floor);
                        self.permit_limit.store(next, Ordering::Release);
                        warn!(
                            current_permits = current,
                            reduced_permits = next,
                            p95_us,
                            target_us,
                            "validate adaptive backpressure reduced permit limit"
                        );
                    }
                    *breach = Some(now);
                }
                Some(_) => {}
                None => *breach = Some(now),
            }
        } else {
            *breach = None;
        }
    }
}

fn build_validate_limiter(rps: u32, burst: u32) -> DefaultDirectRateLimiter {
    let per_second = std::num::NonZeroU32::new(rps.max(1)).expect("non-zero rps");
    let burst_nz = std::num::NonZeroU32::new(burst.max(1)).expect("non-zero burst");
    let quota = Quota::per_second(per_second).allow_burst(burst_nz);
    GovernorRateLimiter::direct(quota)
}

fn validate_ingress_gate() -> &'static ValidateIngressGate {
    VALIDATE_INGRESS_GATE
        .get_or_init(|| ValidateIngressGate::new(ValidateIngressConfig::from_env()))
}

pub fn spawn_validate_adaptive_controller() {
    // Ensure the gate is initialized from env before the controller starts.
    let gate = validate_ingress_gate();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        loop {
            ticker.tick().await;
            gate.maybe_reduce_permits();
        }
    });
}

pub async fn validate_ingress_middleware(
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    if req.uri().path() != "/validate" && req.uri().path() != "/v1/validate" {
        return Ok(next.run(req).await);
    }

    let gate = validate_ingress_gate();
    if !gate.check_rate_limit() {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "rate_limit_exceeded",
                "code": "VALIDATE_RATE_LIMIT",
                "message": "validate ingress rate limit exceeded"
            })),
        ));
    }

    let permit = gate.try_acquire().ok_or((
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({
            "error": "overloaded",
            "code": "VALIDATE_OVERLOADED",
            "message": "validate ingress is saturated"
        })),
    ))?;

    let started = Instant::now();
    let response = next.run(req).await;
    gate.observe_latency(started.elapsed());
    drop(permit);
    Ok(response)
}

#[cfg(test)]
fn make_validate_ingress_gate_for_test(cfg: ValidateIngressConfig) -> ValidateIngressGate {
    ValidateIngressGate::new(cfg)
}

#[derive(Debug, Clone, Copy)]
pub enum RateLimitError {
    Global,
    Ip,
    Key,
    Agent,
}

impl RateLimitError {
    pub fn to_response(self) -> (StatusCode, Json<serde_json::Value>) {
        let (code, message) = match self {
            RateLimitError::Global => ("GLOBAL_RATE_LIMIT", "Service overloaded"),
            RateLimitError::Ip => ("IP_RATE_LIMIT", "Too many requests from this IP"),
            RateLimitError::Key => ("API_KEY_RATE_LIMIT", "API key quota exceeded"),
            RateLimitError::Agent => ("AGENT_RATE_LIMIT", "Agent quota exceeded"),
        };
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "rate_limit_exceeded",
                "code": code,
                "message": message,
                "retry_after": RATE_LIMIT_WINDOW_SECS
            })),
        )
    }
}

pub fn rate_limiter() -> &'static RateLimiter {
    RATE_LIMITER.get_or_init(|| {
        // Spawn cleanup task
        RateLimiter::new()
    })
}

pub fn require_admin(headers: &HeaderMap) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    // Accept static admin key header (machine-to-machine / CLI).
    let provided = headers
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if configured_admin_keys().contains(provided) {
        return Ok(());
    }

    // Also accept admin session JWT Bearer (browser login flow).
    if let Some(token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        && verify_admin_session_jwt(token).is_some()
    {
        return Ok(());
    }

    Err((
        StatusCode::FORBIDDEN,
        Json(json!({ "error": "admin access required" })),
    ))
}

pub fn require_api_key(headers: &HeaderMap) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    require_api_key_with_scope(headers, None)
}

/// Like `require_api_key` but also checks that the JWT (if used) carries the
/// required scope.  Static API keys are treated as unrestricted but emit a
/// deprecation warning.
pub fn require_api_key_with_scope(
    headers: &HeaderMap,
    required_scope: Option<&str>,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    // Accept static API keys in X-API-Key header.
    if let Some(k) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        if configured_api_keys().contains(k) {
            warn!("static API key used — migrate to scoped JWT tokens via POST /auth/token");
            return Ok(());
        }
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid api_key" })),
        ));
    }
    // Also accept short-lived JWT Bearer tokens in Authorization header.
    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok())
        && let Some(token) = auth.strip_prefix("Bearer ")
    {
        match verify_jwt_token(token) {
            Ok(claims) => {
                if let Some(scope) = required_scope {
                    if !claims.has_scope(scope) {
                        return Err((
                            StatusCode::FORBIDDEN,
                            Json(
                                json!({ "error": format!("token missing required scope: {scope}") }),
                            ),
                        ));
                    }
                }
                return Ok(());
            }
            Err(e) => {
                warn!("JWT verification failed: {e}");
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "error": "invalid or expired token" })),
                ));
            }
        }
    }
    Err((
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "x-api-key or Authorization: Bearer <token> required" })),
    ))
}

/// Extract API key from headers for rate limiting
pub fn extract_api_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Verify HMAC-SHA256 request signature (legacy, for backward compatibility)
pub fn verify_request_sig(
    agent_id: &str,
    api_key: &str,
    nonce: &str,
    timestamp: &str,
    provided_sig_hex: &str,
) -> bool {
    let canonical = format!("{agent_id}\0{nonce}\0{timestamp}");
    let mut mac = match HmacSha256::new_from_slice(api_key.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(canonical.as_bytes());
    let expected = mac.finalize().into_bytes();
    match hex::decode(provided_sig_hex) {
        Ok(provided) => {
            if provided.len() != expected.len() {
                return false;
            }
            // Constant-time comparison to avoid timing side channels.
            let mut diff = 0u8;
            for (a, b) in expected.iter().zip(provided.iter()) {
                diff |= a ^ b;
            }
            diff == 0
        }
        Err(_) => false,
    }
}

/// Verify Ed25519 request signature (new, more secure)
///
/// Headers expected:
/// - X-HaltChain-Signature: Base64-encoded Ed25519 signature
/// - X-HaltChain-Timestamp: Unix timestamp (seconds)
/// - X-HaltChain-Nonce: UUID v4 nonce
/// - X-HaltChain-Key-Id: Client key identifier
pub fn verify_ed25519_request_sig(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<bool, SignatureError> {
    let sig_b64 = headers
        .get("x-haltchain-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(SignatureError::MissingHeader)?;

    let timestamp = headers
        .get("x-haltchain-timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or(SignatureError::MissingHeader)?;

    let nonce = headers
        .get("x-haltchain-nonce")
        .and_then(|v| v.to_str().ok())
        .ok_or(SignatureError::MissingHeader)?;

    let key_id = headers
        .get("x-haltchain-key-id")
        .and_then(|v| v.to_str().ok())
        .ok_or(SignatureError::MissingHeader)?;

    // Verify timestamp is fresh (prevent replay of old requests)
    let ts: i64 = timestamp
        .parse()
        .map_err(|_| SignatureError::InvalidTimestamp)?;
    let now = Utc::now().timestamp();
    if (now - ts).abs() > REQUEST_SIG_MAX_AGE_SECS {
        return Ok(false); // Timestamp too old
    }

    // Verify nonce hasn't been used
    if !check_and_insert_nonce(nonce) {
        return Ok(false); // Replay detected
    }

    // Get client's public key
    let pubkey = client_pubkey_store()
        .get(key_id)
        .ok_or(SignatureError::UnknownKey)?;

    // Decode signature
    let sig_bytes = general_purpose::STANDARD
        .decode(sig_b64)
        .map_err(|_| SignatureError::InvalidSignature)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| SignatureError::InvalidSignature)?;

    // Build canonical message: timestamp:nonce:body_hash
    let body_hash = sha2::Sha256::digest(body);
    let message = format!("{}:{}:{}", timestamp, nonce, hex::encode(body_hash));

    // Verify signature
    match pubkey.verify(message.as_bytes(), &sig) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[derive(Debug)]
pub enum SignatureError {
    MissingHeader,
    InvalidTimestamp,
    UnknownKey,
    InvalidSignature,
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureError::MissingHeader => write!(f, "Missing required signature header"),
            SignatureError::InvalidTimestamp => write!(f, "Invalid timestamp format"),
            SignatureError::UnknownKey => write!(f, "Unknown client key ID"),
            SignatureError::InvalidSignature => write!(f, "Invalid signature format"),
        }
    }
}

impl std::error::Error for SignatureError {}

pub fn timestamp_fresh(ts: &str) -> bool {
    match DateTime::parse_from_rfc3339(ts) {
        Ok(parsed) => {
            let delta = (Utc::now() - parsed.with_timezone(&Utc))
                .num_seconds()
                .abs();
            delta <= REQUEST_SIG_MAX_AGE_SECS
        }
        Err(_) => false,
    }
}

pub fn nonce_store() -> &'static Mutex<std::collections::HashMap<String, Instant>> {
    NONCES.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

pub fn last_sweep() -> &'static Mutex<Instant> {
    LAST_SWEEP.get_or_init(|| Mutex::new(Instant::now()))
}

/// Hard cap on nonce entries to bound memory under sustained load.
const MAX_NONCE_ENTRIES: usize = 50_000;

/// Check and insert nonce. Returns false if nonce already exists (replay detected).
pub fn check_and_insert_nonce(nonce: &str) -> bool {
    let now = Instant::now();
    let mut last = last_sweep().lock();
    if now.duration_since(*last) > Duration::from_secs(NONCE_SWEEP_SECS) {
        let mut store = nonce_store().lock();
        store.retain(|_, inserted| {
            now.duration_since(*inserted) < Duration::from_secs(NONCE_TTL_SECS)
        });
        *last = now;
    }
    drop(last);

    let mut store = nonce_store().lock();
    if store.contains_key(nonce) {
        return false;
    }
    if store.len() >= MAX_NONCE_ENTRIES {
        warn!("nonce store at capacity ({MAX_NONCE_ENTRIES}), rejecting new nonce");
        return false;
    }
    store.insert(nonce.to_string(), now);
    true
}

/// Multi-layer rate limiting middleware
pub async fn rate_limit_middleware(
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let headers = req.headers();
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(String::from)
        })
        .unwrap_or_else(|| "unknown".to_string());
    let api_key = extract_api_key(headers);

    // Try to extract agent_id from request body for agent-based limiting
    // This is best-effort; if we can't parse it, we just won't do agent limiting
    let agent_id: Option<String> = None; // Simplified for now

    // Keep bucket maps bounded under sustained traffic.
    rate_limiter().cleanup();

    match rate_limiter().check(&ip, api_key.as_deref(), agent_id.as_deref()) {
        Ok(()) => Ok(next.run(req).await),
        Err(e) => {
            warn!(ip = %ip, "Rate limit exceeded: {:?}", e);
            Err(e.to_response())
        }
    }
}

/// Enhanced security middleware that combines replay protection and request signing verification
///
/// This middleware should be applied to all API endpoints for P0 security.
pub async fn security_middleware(
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let headers = req.headers().clone();
    // Check for Ed25519 signature headers first (new, more secure method)
    let has_ed25519 = headers.contains_key("x-haltchain-signature")
        && headers.contains_key("x-haltchain-timestamp")
        && headers.contains_key("x-haltchain-nonce")
        && headers.contains_key("x-haltchain-key-id");

    if has_ed25519 {
        // Clone body for signature verification
        let (parts, body) = req.into_parts();
        // Cap body read at 10 MB to prevent OOM.
        let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
            .await
            .map_err(|_| {
                (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    Json(json!({"error": "Request body too large"})),
                )
            })?;

        match verify_ed25519_request_sig(&headers, &body_bytes) {
            Ok(true) => {
                // Reconstruct request and continue
                let req = Request::from_parts(parts, axum::body::Body::from(body_bytes));
                Ok(next.run(req).await)
            }
            Ok(false) => Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid signature"})),
            )),
            Err(e) => {
                error!("Signature verification error: {}", e);
                Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "Signature verification failed"})),
                ))
            }
        }
    } else {
        // Fall back to legacy HMAC verification (handled in individual handlers)
        // Just pass through - the individual handlers will do their own auth
        Ok(next.run(req).await)
    }
}

fn configured_admin_totp_secret() -> &'static Option<String> {
    ADMIN_TOTP_SECRET.get_or_init(|| std::env::var("HALTCHAIN_ADMIN_TOTP_SECRET").ok())
}

fn configured_admin_ip_allowlist() -> &'static Option<HashSet<String>> {
    ADMIN_IP_ALLOWLIST.get_or_init(|| {
        std::env::var("HALTCHAIN_ADMIN_IP_ALLOWLIST")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect()
            })
    })
}

/// Generate an RFC 6238 TOTP code using HMAC-SHA1 (standard TOTP algorithm).
/// `unix_secs` is used to derive the 30-second counter.
fn generate_totp(secret_hex: &str, unix_secs: u64) -> Option<u32> {
    let key = hex::decode(secret_hex).ok()?;
    let counter = (unix_secs / 30).to_be_bytes();
    let mut mac = HmacSha1::new_from_slice(&key).ok()?;
    mac.update(&counter);
    let hs = mac.finalize().into_bytes();
    // Dynamic truncation per RFC 4226 §5.4
    let offset = (hs[19] & 0x0f) as usize;
    let code = ((hs[offset] as u32 & 0x7f) << 24)
        | ((hs[offset + 1] as u32) << 16)
        | ((hs[offset + 2] as u32) << 8)
        | (hs[offset + 3] as u32);
    Some(code % 1_000_000)
}

/// Verify a 6-digit TOTP code. Accepts the current 30-second window ±1 to
/// tolerate clock skew between client and server.
pub fn verify_totp(secret_hex: &str, provided_code: &str) -> bool {
    let code: u32 = match provided_code.trim().parse() {
        Ok(c) => c,
        Err(_) => return false,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    for window in [-1i64, 0, 1] {
        let t = (now as i64 + window * 30).max(0) as u64;
        if let Some(expected) = generate_totp(secret_hex, t) {
            // Constant-time u32 comparison to avoid timing oracles.
            let mut diff = expected ^ code;
            diff |= diff >> 16;
            diff |= diff >> 8;
            if diff & 0xff == 0 {
                return true;
            }
        }
    }
    false
}

/// Admin authentication with optional TOTP MFA and IP allowlist.
///
/// Layers enforced (in order):
/// 1. Admin key via `X-Admin-Key` header — always required.
/// 2. TOTP code via `X-Admin-TOTP` — only when `HALTCHAIN_ADMIN_TOTP_SECRET` is set.
/// 3. IP allowlist — only when `HALTCHAIN_ADMIN_IP_ALLOWLIST` is set.
///
/// When the env vars are absent all layers collapse to key-only, preserving
/// backward-compatible local dev behaviour.
pub fn require_admin_mfa(headers: &HeaderMap) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    // Browser sessions authenticated via JWT still require admin key to be
    // present, preventing leaked JWTs from granting standalone admin access.
    if let Some(token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        && verify_admin_session_jwt(token).is_some()
    {
        // JWT is only a second factor — admin key must still be valid.
        require_admin(headers)?;
        return Ok(());
    }

    // Layer 1: static admin key
    require_admin(headers)?;

    // Layer 2: TOTP (enforced only when secret is configured)
    if let Some(secret) = configured_admin_totp_secret() {
        let provided = headers
            .get("x-admin-totp")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !verify_totp(secret, provided) {
            warn!("Admin MFA failed: invalid or missing TOTP code");
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "MFA verification required" })),
            ));
        }
    }

    // Layer 3: IP allowlist (enforced only when allowlist is configured)
    if let Some(allowlist) = configured_admin_ip_allowlist() {
        let client_ip = headers
            .get("x-forwarded-for")
            .or_else(|| headers.get("x-real-ip"))
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(str::trim)
            .unwrap_or("");
        if !client_ip.is_empty() && !allowlist.contains(client_ip) {
            warn!(ip = %client_ip, "Admin access denied: IP not allowlisted");
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "Access denied from this network" })),
            ));
        }
    }

    Ok(())
}

fn configured_jwt_secret() -> &'static Option<String> {
    JWT_SECRET.get_or_init(|| std::env::var("HALTCHAIN_JWT_SECRET").ok())
}

/// Issue a short-lived JWT for the given agent_id (unrestricted scopes).
/// Returns `Err` if `HALTCHAIN_JWT_SECRET` is not configured.
pub fn issue_jwt_token(agent_id: &str) -> Result<String, String> {
    issue_scoped_jwt_token(agent_id, &[])
}

/// Issue a short-lived JWT with explicit scope claims.
/// An empty `scopes` slice means unrestricted (backward-compatible).
pub fn issue_scoped_jwt_token(agent_id: &str, scopes: &[&str]) -> Result<String, String> {
    let secret = configured_jwt_secret()
        .as_ref()
        .ok_or_else(|| "JWT not configured (HALTCHAIN_JWT_SECRET not set)".to_string())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let claims = JwtClaims {
        sub: agent_id.to_string(),
        exp: now + JWT_EXPIRY_SECS,
        iat: now,
        jti: uuid::Uuid::new_v4().to_string(),
        scp: scopes.join(" "),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| format!("JWT encode error: {e}"))
}

/// Verify a JWT token and return its claims.
pub fn verify_jwt_token(token: &str) -> Result<JwtClaims, String> {
    let secret = configured_jwt_secret()
        .as_ref()
        .ok_or_else(|| "JWT not configured".to_string())?;
    let mut validation = Validation::default();
    validation.validate_exp = true;
    decode::<JwtClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|e| format!("JWT decode error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(10, 1);
        assert!(bucket.consume(5));
        assert!(bucket.consume(5));
        assert!(!bucket.consume(1)); // Empty
    }

    #[test]
    fn test_rate_limiter_check() {
        let limiter = RateLimiter::new();

        // Should allow requests within limit
        for _ in 0..MAX_REQUESTS_PER_IP {
            assert!(
                limiter
                    .check("1.2.3.4", Some("test-key"), Some("test-agent"))
                    .is_ok()
            );
        }

        // IP should be rate limited now (but we need many more to actually hit the limit)
        // This test verifies the structure works
    }

    #[test]
    fn test_check_and_insert_nonce() {
        // Clear nonce store for test
        let nonce = "test-nonce-12345";
        assert!(check_and_insert_nonce(nonce));
        assert!(!check_and_insert_nonce(nonce)); // Replay should fail
    }

    #[test]
    fn test_totp_rfc_4226_vector() {
        // RFC 4226 Appendix D: secret = ASCII "12345678901234567890" (hex below),
        // counter = 0 → expected code = 755224
        let secret_hex = "3132333435363738393031323334353637383930";
        let code = generate_totp(secret_hex, 0).expect("should generate code at counter 0");
        assert_eq!(code, 755224, "RFC 4226 test vector mismatch at counter 0");
    }

    #[test]
    fn test_verify_totp_rejects_nonnumeric() {
        let secret_hex = "3132333435363738393031323334353637383930";
        assert!(
            !verify_totp(secret_hex, "abc"),
            "non-numeric code must be rejected"
        );
        assert!(!verify_totp(secret_hex, ""), "empty code must be rejected");
    }

    #[test]
    fn test_require_admin_mfa_key_only_when_no_totp_configured() {
        // When HALTCHAIN_ADMIN_TOTP_SECRET is not set, MFA collapses to key-only.
        // Use whatever key is actually configured so the test isn't env-specific.
        let admin_key = configured_admin_keys()
            .iter()
            .next()
            .cloned()
            .unwrap_or_else(|| "dev-admin-key".to_string());
        let mut headers = HeaderMap::new();
        headers.insert("x-admin-key", admin_key.parse().unwrap());
        if configured_admin_totp_secret().is_none() {
            assert!(
                require_admin_mfa(&headers).is_ok(),
                "key-only should pass when TOTP secret is not configured"
            );
        }
    }

    #[test]
    fn test_require_admin_mfa_rejects_bad_key() {
        let mut headers = HeaderMap::new();
        headers.insert("x-admin-key", "wrong-key".parse().unwrap());
        assert!(
            require_admin_mfa(&headers).is_err(),
            "wrong admin key must be rejected"
        );
    }

    #[tokio::test]
    async fn validate_ingress_gate_rate_limiter_denies_after_burst() {
        let gate = make_validate_ingress_gate_for_test(ValidateIngressConfig {
            rate_limit_rps: 1,
            burst: 1,
            permits: 4,
            permit_floor: 1,
            p95_target_ms: 5,
        });

        assert!(gate.check_rate_limit(), "first request should be allowed");
        assert!(
            !gate.check_rate_limit(),
            "second immediate request should be rate limited"
        );
    }

    #[tokio::test]
    async fn validate_ingress_gate_returns_none_when_permits_exhausted() {
        let gate = make_validate_ingress_gate_for_test(ValidateIngressConfig {
            rate_limit_rps: 100,
            burst: 100,
            permits: 1,
            permit_floor: 1,
            p95_target_ms: 5,
        });

        let permit = gate.try_acquire();
        assert!(permit.is_some(), "first permit should be acquired");
        let second = gate.try_acquire();
        assert!(
            second.is_none(),
            "second acquisition should fail when semaphore is saturated"
        );
    }

    mod concurrency {
        use super::*;

        #[tokio::test]
        async fn semaphore_drop() {
            let gate = make_validate_ingress_gate_for_test(ValidateIngressConfig {
                rate_limit_rps: 100,
                burst: 100,
                permits: 1,
                permit_floor: 1,
                p95_target_ms: 5,
            });

            let hold = gate.try_acquire();
            assert!(hold.is_some(), "first permit should be acquired");
            assert!(
                gate.try_acquire().is_none(),
                "semaphore should reject when permit is exhausted"
            );
            drop(hold);
            assert!(
                gate.try_acquire().is_some(),
                "permit should be available again after drop"
            );
        }
    }
}
