use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chrono::Utc;
use dashmap::DashMap;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use parking_lot::RwLock;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Ed25519 signing service with atomic key rotation and replay-nonce tracking.
pub struct SigningService {
    inner: RwLock<KeyPairInner>,
    nonces: NonceStore,
}

struct KeyPairInner {
    key_id: String,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

/// Attached to every validator decision for client-side verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Generates a fresh Ed25519 keypair on startup.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            inner: RwLock::new(KeyPairInner {
                key_id: Uuid::new_v4().to_string(),
                signing_key,
                verifying_key,
            }),
            nonces: NonceStore::new(Duration::from_secs(300)),
        }
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
        let sig: Signature = inner.signing_key.sign(message.as_bytes());
        SignedEnvelope {
            nonce,
            signed_at,
            key_id: inner.key_id.clone(),
            signature: B64.encode(sig.to_bytes()),
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
        inner.verifying_key.verify(message.as_bytes(), &sig).is_ok()
    }

    /// Returns the Base64-encoded 32-byte public key for client distribution.
    pub fn public_key_b64(&self) -> String {
        B64.encode(self.inner.read().verifying_key.as_bytes())
    }

    /// Returns the active key identifier.
    pub fn key_id(&self) -> String {
        self.inner.read().key_id.clone()
    }

    /// Atomically rotates the keypair with zero downtime.
    /// Returns `(new_key_id, new_public_key_b64)`.
    pub fn rotate(&self) -> (String, String) {
        let new_sk = SigningKey::generate(&mut OsRng);
        let new_vk = new_sk.verifying_key();
        let new_id = Uuid::new_v4().to_string();
        let pub_b64 = B64.encode(new_vk.as_bytes());
        let mut inner = self.inner.write();
        inner.key_id = new_id.clone();
        inner.signing_key = new_sk;
        inner.verifying_key = new_vk;
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
}
