pub mod a2a_auth;
pub mod hsm;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chrono::Utc;
use dashmap::DashMap;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use parking_lot::RwLock;
use std::time::{Duration, Instant};
use uuid::Uuid;

use hsm::{KeyBackend, SoftwareBackend};

/// Ed25519 signing service backed by a pluggable [`KeyBackend`].
///
/// The default backend is [`SoftwareBackend`] (in-memory).  Pass an HSM or
/// cloud-KMS implementation via [`SigningService::with_backend`] for
/// production deployments that require hardware-backed keys.
pub struct SigningService {
    inner: RwLock<ServiceInner>,
    nonces: NonceStore,
}

struct ServiceInner {
    /// Stable identifier for the active key — changes on rotation.
    key_id: String,
    /// Pre-encoded protected header bytes for COSE Sign1.
    protected_header: Vec<u8>,
    /// Pluggable key backend: software (default), YubiHSM, AWS KMS, etc.
    backend: Box<dyn KeyBackend>,
}

/// Attached to every validator decision for client-side verification.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedEnvelope {
    /// Random UUID — binds this signature to a single response (replay prevention).
    pub nonce: String,
    /// ISO-8601 UTC timestamp of when the signature was created.
    pub signed_at: String,
    /// Identifies which keypair signed — changes on rotation.
    pub key_id: String,
    /// Base64-encoded Ed25519 signature over canonical_message(payload, nonce, signed_at).
    pub signature: String,
}

impl SigningService {
    /// Create a service backed by the given [`KeyBackend`] implementation.
    pub fn with_backend(backend: Box<dyn KeyBackend>) -> Self {
        let key_id = Uuid::new_v4().to_string();
        Self {
            inner: RwLock::new(ServiceInner {
                protected_header: cose_protected_header(&key_id),
                key_id,
                backend,
            }),
            nonces: NonceStore::new(Duration::from_secs(300)),
        }
    }

    /// Generate a fresh in-memory Ed25519 keypair on startup (default backend).
    pub fn generate() -> Self {
        Self::with_backend(Box::new(SoftwareBackend::generate()))
    }

    /// Canonical message format — null-byte separated to prevent field injection.
    pub fn canonical_decision_payload(
        transaction_id: &str,
        decision: &str,
        agent_id: &str,
        timestamp: &str,
    ) -> String {
        format!("{transaction_id}\0{decision}\0{agent_id}\0{timestamp}")
    }

    fn canonical_message(payload: &str, nonce: &str, signed_at: &str) -> String {
        format!("{payload}\0{nonce}\0{signed_at}")
    }

    /// Signs `payload` and returns an envelope with a unique nonce + timestamp.
    pub fn sign(&self, payload: &str) -> SignedEnvelope {
        let nonce = Uuid::new_v4().to_string();
        let signed_at = Utc::now().to_rfc3339();
        let message = Self::canonical_message(payload, &nonce, &signed_at);
        let inner = self.inner.read();
        let sig_bytes = inner
            .backend
            .sign(message.as_bytes())
            .expect("signing backend must not fail for hardware-backed or software keys");
        SignedEnvelope {
            nonce,
            signed_at,
            key_id: inner.key_id.clone(),
            signature: B64.encode(sig_bytes),
        }
    }

    /// Verifies an envelope against the current public key.
    /// Returns `false` on invalid signature or if the nonce was already consumed (replay).
    pub fn verify_and_consume(&self, payload: &str, envelope: &SignedEnvelope) -> bool {
        if !self.nonces.check_and_insert(&envelope.nonce) {
            return false; // replay detected
        }
        let message = Self::canonical_message(payload, &envelope.nonce, &envelope.signed_at);
        let inner = self.inner.read();
        let Ok(sig_bytes) = B64.decode(&envelope.signature) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&sig_bytes) else {
            return false;
        };
        let Ok(pub_bytes) = inner.backend.public_key() else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pub_bytes) else {
            return false;
        };
        vk.verify(message.as_bytes(), &sig).is_ok()
    }

    /// Returns the Base64-encoded 32-byte public key for client distribution.
    pub fn public_key_b64(&self) -> String {
        let inner = self.inner.read();
        inner
            .backend
            .public_key()
            .map(|b| B64.encode(b))
            .unwrap_or_default()
    }

    /// Returns the active key identifier.
    pub fn key_id(&self) -> String {
        self.inner.read().key_id.clone()
    }

    /// Atomically rotates the keypair via the backend's `generate_key`.
    /// Returns `(new_key_id, new_public_key_b64)`.
    pub fn rotate(&self) -> (String, String) {
        let mut inner = self.inner.write();
        let (new_id, new_pub_bytes) = inner
            .backend
            .generate_key()
            .expect("backend key generation must not fail");
        inner.key_id = new_id.clone();
        inner.protected_header = cose_protected_header(&new_id);
        let pub_b64 = B64.encode(new_pub_bytes);
        (new_id, pub_b64)
    }
}

/// Replay-attack prevention via time-bounded nonce tracking.
/// Uses DashMap for lock-free concurrent access.
struct NonceStore {
    seen: DashMap<String, Instant>,
    ttl: Duration,
}

impl NonceStore {
    fn new(ttl: Duration) -> Self {
        Self {
            seen: DashMap::new(),
            ttl,
        }
    }

    /// Returns `true` and records the nonce if it has not been seen before.
    /// Returns `false` (replay) if the nonce is already in the store.
    fn check_and_insert(&self, nonce: &str) -> bool {
        self.evict_stale();
        if self.seen.contains_key(nonce) {
            return false;
        }
        self.seen.insert(nonce.to_string(), Instant::now());
        true
    }

    fn evict_stale(&self) {
        let ttl = self.ttl;
        self.seen
            .retain(|_, inserted_at| inserted_at.elapsed() < ttl);
    }
}

// ── COSE Sign1 Decision Envelope ─────────────────────────────────────────────

/// Minimal CBOR encoder for the COSE Sign1 structure required by [`DecisionEnvelope`].
///
/// We implement only the subset of CBOR needed for COSE_Sign1 to avoid an
/// external CBOR dependency:
///   • Byte strings (major type 2)
///   • Text strings (major type 3)
///   • Arrays (major type 4)
///   • Maps (major type 5)
///   • Unsigned integers (major type 0)
///   • Negative integers (major type 1)
mod cbor {
    fn encode_head(major: u8, value: usize, out: &mut Vec<u8>) {
        let m = major << 5;
        match value {
            0..=23 => out.push(m | value as u8),
            24..=0xff => {
                out.push(m | 24);
                out.push(value as u8);
            }
            0x100..=0xffff => {
                out.push(m | 25);
                out.extend_from_slice(&(value as u16).to_be_bytes());
            }
            _ => {
                out.push(m | 26);
                out.extend_from_slice(&(value as u32).to_be_bytes());
            }
        }
    }

    pub fn encode_bstr(data: &[u8], out: &mut Vec<u8>) {
        encode_head(2, data.len(), out);
        out.extend_from_slice(data);
    }

    pub fn encode_tstr(s: &str, out: &mut Vec<u8>) {
        let b = s.as_bytes();
        encode_head(3, b.len(), out);
        out.extend_from_slice(b);
    }

    pub fn encode_array_head(len: usize, out: &mut Vec<u8>) {
        encode_head(4, len, out);
    }

    pub fn encode_map_head(pairs: usize, out: &mut Vec<u8>) {
        encode_head(5, pairs, out);
    }

    /// Encode an unsigned integer.
    pub fn encode_uint(v: u64, out: &mut Vec<u8>) {
        encode_head(0, v as usize, out);
    }

    /// Encode a negative integer (CBOR value = -n-1; pass n as a positive u64).
    pub fn encode_nint(n: u64, out: &mut Vec<u8>) {
        encode_head(1, n as usize, out);
    }
}

/// COSE Sign1 protected header bytes: `{1: -8, 4: kid_utf8_bytes}`.
/// Algorithm 1 = alg, -8 = EdDSA; 4 = kid.
fn cose_protected_header(kid: &str) -> Vec<u8> {
    let mut hdr = Vec::new();
    cbor::encode_map_head(2, &mut hdr);
    cbor::encode_uint(1, &mut hdr); // key: alg
    cbor::encode_nint(7, &mut hdr); // value: EdDSA = -8 (encoded as n=7)
    cbor::encode_uint(4, &mut hdr); // key: kid
    cbor::encode_bstr(kid.as_bytes(), &mut hdr); // value: key ID bytes
    hdr
}

/// Build the COSE `Sig_Structure` for Sign1.
///
/// ```text
/// Sig_Structure = [
///     context:    "Signature1",
///     protected:  bstr .cbor protected_header,
///     external_aad: h'',            ; empty in our use case
///     payload:    bstr              ; the decision payload bytes
/// ]
/// ```
fn cose_sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut s = Vec::new();
    cbor::encode_array_head(4, &mut s);
    cbor::encode_tstr("Signature1", &mut s);
    cbor::encode_bstr(protected, &mut s);
    cbor::encode_bstr(b"", &mut s); // external_aad = empty
    cbor::encode_bstr(payload, &mut s);
    s
}

/// Encode the complete COSE_Sign1 object as a CBOR byte array.
///
/// ```text
/// COSE_Sign1 = [
///     protected:   bstr .cbor protected_header,
///     unprotected: {},
///     payload:     bstr,
///     signature:   bstr
/// ]
/// ```
fn cose_sign1_bytes(protected: &[u8], payload: &[u8], sig: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::encode_array_head(4, &mut out);
    cbor::encode_bstr(protected, &mut out);
    cbor::encode_map_head(0, &mut out); // unprotected = {}
    cbor::encode_bstr(payload, &mut out);
    cbor::encode_bstr(sig, &mut out);
    out
}

/// COSE Sign1 envelope covering an agent decision.
///
/// Every `/validate` response carries one of these.  Verifiers can decode
/// [`cose_token`] (base64url-encoded COSE_Sign1 binary) or use the decoded
/// fields directly.
///
/// Algorithm: EdDSA (Ed25519), COSE algorithm ID −8 (RFC 8152 §8.2).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DecisionEnvelope {
    /// Base64url-encoded COSE_Sign1 binary — the canonical artifact for auditors.
    pub cose_token: String,
    // ── Decoded fields for API consumers ─────────────────────────────────────
    /// Agent whose action was validated.
    pub agent_id: String,
    /// One of: ALLOW, DENY, CIRCUIT_BREAK, GOAL_CLARIFICATION_REQUIRED.
    pub decision: String,
    /// ISO-8601 UTC timestamp of the decision.
    pub timestamp: String,
    /// Policy version active at decision time (semver string from PolicyFile).
    pub policy_version: String,
    /// Validates the transaction uniquely.
    pub transaction_id: String,
    /// SHA-256 hex digest of the canonical payload bytes.
    pub content_hash: String,
    /// Identifies which keypair produced the signature.
    pub key_id: String,
}

impl SigningService {
    /// Create a COSE Sign1 [`DecisionEnvelope`] for an agent decision.
    ///
    /// The payload bytes are the JSON-serialized canonical form:
    /// `{"txn":…,"decision":…,"agent_id":…,"timestamp":…,"policy_version":…}`.
    /// The `Sig_Structure` follows RFC 8152 §4.4.
    pub fn sign_decision(
        &self,
        transaction_id: &str,
        decision: &str,
        agent_id: &str,
        timestamp: &str,
        policy_version: &str,
    ) -> DecisionEnvelope {
        use sha2::{Digest, Sha256};

        #[derive(serde::Serialize)]
        struct DecisionPayload<'a> {
            txn: &'a str,
            decision: &'a str,
            agent_id: &'a str,
            timestamp: &'a str,
            policy_version: &'a str,
        }

        let payload_bytes = serde_json::to_vec(&DecisionPayload {
            txn: transaction_id,
            decision,
            agent_id,
            timestamp,
            policy_version,
        })
        .expect("decision payload JSON serialization must not fail");

        // SHA-256 of payload for content integrity
        let content_hash = hex::encode(Sha256::digest(&payload_bytes));

        let inner = self.inner.read();
        let protected = inner.protected_header.as_slice();
        let sig_structure = cose_sig_structure(protected, &payload_bytes);

        let sig_bytes = inner
            .backend
            .sign(&sig_structure)
            .expect("backend signing must not fail");

        let cose_bytes = cose_sign1_bytes(protected, &payload_bytes, &sig_bytes);
        // RFC 4648 §5 base64url (no padding) for compact token form
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let cose_token = URL_SAFE_NO_PAD.encode(&cose_bytes);

        DecisionEnvelope {
            cose_token,
            agent_id: agent_id.to_string(),
            decision: decision.to_string(),
            timestamp: timestamp.to_string(),
            policy_version: policy_version.to_string(),
            transaction_id: transaction_id.to_string(),
            content_hash,
            key_id: inner.key_id.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_service() -> SigningService {
        SigningService::generate()
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let svc = make_service();
        let payload = SigningService::canonical_decision_payload(
            "txn-001",
            "ALLOW",
            "agent-01",
            "2026-01-01T00:00:00Z",
        );
        let env = svc.sign(&payload);
        assert!(svc.verify_and_consume(&payload, &env));
    }

    #[test]
    fn replay_is_rejected() {
        let svc = make_service();
        let payload = "txn-002\0DENY\0agent-02\x002026-01-01T00:00:00Z".to_string();
        let env = svc.sign(&payload);
        assert!(svc.verify_and_consume(&payload, &env));
        // Second consumption of the same nonce must fail.
        assert!(!svc.verify_and_consume(&payload, &env));
    }

    #[test]
    fn tampered_payload_rejected() {
        let svc = make_service();
        let payload = "txn-003\0ALLOW\0agent-03\x002026-01-01T00:00:00Z".to_string();
        let env = svc.sign(&payload);
        let tampered = "txn-003\0CIRCUIT_BREAK\0agent-03\x002026-01-01T00:00:00Z";
        assert!(!svc.verify_and_consume(tampered, &env));
    }

    #[test]
    fn rotate_invalidates_old_public_key() {
        let svc = make_service();
        let old_pub = svc.public_key_b64();
        svc.rotate();
        assert_ne!(old_pub, svc.public_key_b64());
    }

    #[test]
    fn rotate_returns_new_key_id() {
        let svc = make_service();
        let old_id = svc.key_id();
        let (new_id, _) = svc.rotate();
        assert_ne!(old_id, new_id);
        assert_eq!(new_id, svc.key_id());
    }

    #[test]
    fn decision_envelope_cose_token_is_valid_base64url() {
        let svc = make_service();
        let env = svc.sign_decision(
            "txn-100",
            "ALLOW",
            "agent-cose-01",
            "2026-06-01T00:00:00Z",
            "1.0.0",
        );
        // cose_token must be non-empty base64url
        assert!(!env.cose_token.is_empty());
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let bytes = URL_SAFE_NO_PAD
            .decode(&env.cose_token)
            .expect("must be valid base64url");
        // COSE_Sign1 is a CBOR array (major type 4, length 4) → first byte 0x84
        assert_eq!(
            bytes[0], 0x84,
            "COSE_Sign1 outer array must start with 0x84"
        );
    }

    #[test]
    fn decision_envelope_fields_match_inputs() {
        let svc = make_service();
        let env = svc.sign_decision(
            "txn-200",
            "DENY",
            "agent-02",
            "2026-06-01T12:00:00Z",
            "2.3.1",
        );
        assert_eq!(env.decision, "DENY");
        assert_eq!(env.agent_id, "agent-02");
        assert_eq!(env.policy_version, "2.3.1");
        assert_eq!(env.transaction_id, "txn-200");
        assert_eq!(env.key_id, svc.key_id());
        assert!(!env.content_hash.is_empty());
    }

    #[test]
    fn decision_envelope_content_hash_is_sha256_hex() {
        let svc = make_service();
        let env = svc.sign_decision("txn-300", "ALLOW", "a", "t", "0.1.0");
        // SHA-256 hex is always 64 lowercase hex chars
        assert_eq!(env.content_hash.len(), 64);
        assert!(env.content_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn decision_envelope_content_hash_uses_escaped_json_payload() {
        use sha2::{Digest, Sha256};

        #[derive(serde::Serialize)]
        struct DecisionPayload<'a> {
            txn: &'a str,
            decision: &'a str,
            agent_id: &'a str,
            timestamp: &'a str,
            policy_version: &'a str,
        }

        let svc = make_service();
        let txn = "txn-400";
        let decision = "ALLOW";
        let agent = "agent-\"quoted\"\\path";
        let ts = "2026-06-01T12:34:56Z";
        let policy = "3.0.0";

        let env = svc.sign_decision(txn, decision, agent, ts, policy);

        let payload = serde_json::to_vec(&DecisionPayload {
            txn,
            decision,
            agent_id: agent,
            timestamp: ts,
            policy_version: policy,
        })
        .expect("payload serialization must succeed");
        let expected_hash = hex::encode(Sha256::digest(payload));

        assert_eq!(env.content_hash, expected_hash);
    }
}
