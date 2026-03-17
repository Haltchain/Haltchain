use base64::{Engine as _, engine::general_purpose};
use chrono::{Datelike, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Standard binary Merkle tree root over a leaf set.
/// Odd-length layers duplicate the last leaf before hashing pairs.
fn merkle_root(leaves: &[[u8; 32]]) -> Option<[u8; 32]> {
    if leaves.is_empty() {
        return None;
    }
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        let mut i = 0;
        while i < layer.len() {
            let left = layer[i];
            let right = if i + 1 < layer.len() {
                layer[i + 1]
            } else {
                layer[i]
            };
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&left);
            combined[32..].copy_from_slice(&right);
            next.push(sha256(&combined));
            i += 2;
        }
        layer = next;
    }
    Some(layer[0])
}

/// Collects signed decision hashes across the day; rolls over at UTC midnight.
pub struct MerkleAccumulator {
    inner: Mutex<AccumulatorInner>,
}

struct AccumulatorInner {
    /// SHA-256 leaf hashes — one per validator decision.
    leaves: Vec<[u8; 32]>,
    /// Day-of-year (1-366) when these leaves were collected.
    day: u32,
}

/// Snapshot returned by `GET /merkle/root`.
#[derive(Debug, Serialize)]
pub struct MerkleStatus {
    /// Hex-encoded Merkle root, or null if no decisions yet today.
    pub root_hex: Option<String>,
    /// Number of decisions accumulated today.
    pub leaf_count: usize,
    /// UTC day-of-year (1-366).
    pub day_of_year: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RootAttestation {
    pub witness_id: String,
    pub signature_b64: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WitnessVerification {
    pub witness_id: String,
    pub verified: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DistributedVerificationStatus {
    pub verified: bool,
    pub threshold: usize,
    pub valid_attestations: usize,
    pub results: Vec<WitnessVerification>,
}

pub struct DistributedMerkleVerifier {
    witnesses: HashMap<String, VerifyingKey>,
    threshold: usize,
}

impl MerkleAccumulator {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(AccumulatorInner {
                leaves: Vec::new(),
                day: Utc::now().ordinal(),
            }),
        }
    }

    /// Appends a leaf derived from the signed decision fields.
    /// Automatically rolls over to a fresh tree at UTC midnight.
    pub fn push(&self, transaction_id: &str, timestamp: &str, decision: &str, signature: &str) {
        let leaf_data = format!("{transaction_id}\0{timestamp}\0{decision}\0{signature}");
        let leaf = sha256(leaf_data.as_bytes());
        let mut inner = self.inner.lock();
        let today = Utc::now().ordinal();
        if inner.day != today {
            inner.leaves.clear();
            inner.day = today;
        }
        inner.leaves.push(leaf);
    }

    /// Returns the current Merkle root and accumulator stats.
    pub fn status(&self) -> MerkleStatus {
        let inner = self.inner.lock();
        let root = merkle_root(&inner.leaves);
        MerkleStatus {
            root_hex: root.map(hex::encode),
            leaf_count: inner.leaves.len(),
            day_of_year: inner.day,
        }
    }
}

impl DistributedMerkleVerifier {
    /// Build verifier from env.
    ///
    /// `HALTCHAIN_MERKLE_WITNESS_KEYS` format:
    /// `w1:base64ed25519pubkey,w2:base64ed25519pubkey`
    ///
    /// `HALTCHAIN_MERKLE_WITNESS_THRESHOLD` defaults to 2.
    pub fn from_env() -> Self {
        let mut witnesses = HashMap::new();
        if let Ok(raw) = std::env::var("HALTCHAIN_MERKLE_WITNESS_KEYS") {
            for entry in raw.split(',') {
                let Some((id, key_b64)) = entry.split_once(':') else {
                    continue;
                };
                let Ok(bytes) = general_purpose::STANDARD.decode(key_b64.trim()) else {
                    continue;
                };
                if bytes.len() != 32 {
                    continue;
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                if let Ok(key) = VerifyingKey::from_bytes(&arr) {
                    witnesses.insert(id.trim().to_string(), key);
                }
            }
        }
        let threshold = std::env::var("HALTCHAIN_MERKLE_WITNESS_THRESHOLD")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(2);
        Self {
            witnesses,
            threshold,
        }
    }

    pub fn with_witnesses(witnesses: HashMap<String, VerifyingKey>, threshold: usize) -> Self {
        Self {
            witnesses,
            threshold,
        }
    }

    /// Verify witness attestations for a root and day.
    ///
    /// Witnesses sign the canonical message:
    /// `"{root_hex}:{day_of_year}"`
    pub fn verify(
        &self,
        root_hex: &str,
        day_of_year: u32,
        attestations: &[RootAttestation],
    ) -> DistributedVerificationStatus {
        let message = format!("{root_hex}:{day_of_year}");
        let mut valid_attestations = 0usize;
        let mut results = Vec::with_capacity(attestations.len());

        for a in attestations {
            let Some(key) = self.witnesses.get(&a.witness_id) else {
                results.push(WitnessVerification {
                    witness_id: a.witness_id.clone(),
                    verified: false,
                    reason: Some("unknown witness".to_string()),
                });
                continue;
            };

            let Ok(sig_bytes) = general_purpose::STANDARD.decode(&a.signature_b64) else {
                results.push(WitnessVerification {
                    witness_id: a.witness_id.clone(),
                    verified: false,
                    reason: Some("invalid base64 signature".to_string()),
                });
                continue;
            };
            let Ok(sig) = Signature::from_slice(&sig_bytes) else {
                results.push(WitnessVerification {
                    witness_id: a.witness_id.clone(),
                    verified: false,
                    reason: Some("invalid signature bytes".to_string()),
                });
                continue;
            };
            match key.verify(message.as_bytes(), &sig) {
                Ok(_) => {
                    valid_attestations += 1;
                    results.push(WitnessVerification {
                        witness_id: a.witness_id.clone(),
                        verified: true,
                        reason: None,
                    });
                }
                Err(_) => results.push(WitnessVerification {
                    witness_id: a.witness_id.clone(),
                    verified: false,
                    reason: Some("signature mismatch".to_string()),
                }),
            }
        }

        DistributedVerificationStatus {
            verified: valid_attestations >= self.threshold,
            threshold: self.threshold,
            valid_attestations,
            results,
        }
    }
}

impl Default for MerkleAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn distributed_verification_requires_threshold() {
        let k1 = SigningKey::from_bytes(&[1u8; 32]);
        let k2 = SigningKey::from_bytes(&[2u8; 32]);
        let mut witnesses = HashMap::new();
        witnesses.insert("w1".to_string(), k1.verifying_key());
        witnesses.insert("w2".to_string(), k2.verifying_key());
        let verifier = DistributedMerkleVerifier::with_witnesses(witnesses, 2);

        let root_hex = "ab".repeat(32);
        let day = 42;
        let msg = format!("{root_hex}:{day}");
        let s1 = k1.sign(msg.as_bytes());

        let attestations = vec![RootAttestation {
            witness_id: "w1".to_string(),
            signature_b64: general_purpose::STANDARD.encode(s1.to_bytes()),
        }];
        let status = verifier.verify(&root_hex, day, &attestations);
        assert!(!status.verified);
        assert_eq!(status.valid_attestations, 1);
    }

    #[test]
    fn distributed_verification_succeeds_with_two_valid_signatures() {
        let k1 = SigningKey::from_bytes(&[11u8; 32]);
        let k2 = SigningKey::from_bytes(&[22u8; 32]);
        let mut witnesses = HashMap::new();
        witnesses.insert("w1".to_string(), k1.verifying_key());
        witnesses.insert("w2".to_string(), k2.verifying_key());
        let verifier = DistributedMerkleVerifier::with_witnesses(witnesses, 2);

        let root_hex = "cd".repeat(32);
        let day = 87;
        let msg = format!("{root_hex}:{day}");
        let s1 = k1.sign(msg.as_bytes());
        let s2 = k2.sign(msg.as_bytes());

        let attestations = vec![
            RootAttestation {
                witness_id: "w1".to_string(),
                signature_b64: general_purpose::STANDARD.encode(s1.to_bytes()),
            },
            RootAttestation {
                witness_id: "w2".to_string(),
                signature_b64: general_purpose::STANDARD.encode(s2.to_bytes()),
            },
        ];
        let status = verifier.verify(&root_hex, day, &attestations);
        assert!(status.verified);
        assert_eq!(status.valid_attestations, 2);
    }
}
