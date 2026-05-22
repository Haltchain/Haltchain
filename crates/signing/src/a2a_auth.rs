//! Agent-to-Agent (A2A) mutual authentication via Ed25519 delegation tokens.
//!
//! When agent A delegates a task to agent B through haltchain, both agents
//! present signed delegation tokens.  Each hop in the chain is independently
//! signed by the delegating agent, forming a verifiable delegation chain.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// A single hop in a delegation chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationToken {
    /// Agent that issued this delegation.
    pub delegator: String,
    /// Agent being delegated to.
    pub delegatee: String,
    /// RFC 3339 timestamp of when the delegation was created.
    pub issued_at: String,
    /// RFC 3339 timestamp of when the delegation expires.
    pub expires_at: String,
    /// Scope restriction for this delegation (space-separated).
    pub scope: String,
    /// Base64-encoded Ed25519 signature over the canonical token payload.
    pub signature: String,
    /// Base64-encoded 32-byte Ed25519 public key of the delegator.
    pub delegator_pubkey: String,
}

/// A complete chain of delegation tokens from original caller to current agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationChain {
    pub tokens: Vec<DelegationToken>,
}

impl DelegationToken {
    /// Canonical message that is signed.  Null-byte separated to prevent
    /// field injection attacks.
    fn canonical(
        delegator: &str,
        delegatee: &str,
        issued_at: &str,
        expires_at: &str,
        scope: &str,
    ) -> String {
        format!("A2A\0{delegator}\0{delegatee}\0{issued_at}\0{expires_at}\0{scope}")
    }

    /// Create a signed delegation token from `delegator` to `delegatee`.
    pub fn sign(
        delegator: &str,
        delegatee: &str,
        scope: &str,
        ttl_secs: u64,
        signing_key: &SigningKey,
    ) -> Self {
        let now = Utc::now();
        let issued_at = now.to_rfc3339();
        let expires_at = (now + chrono::Duration::seconds(ttl_secs as i64)).to_rfc3339();
        let message = Self::canonical(delegator, delegatee, &issued_at, &expires_at, scope);
        let sig: Signature = signing_key.sign(message.as_bytes());
        Self {
            delegator: delegator.to_string(),
            delegatee: delegatee.to_string(),
            issued_at,
            expires_at,
            scope: scope.to_string(),
            signature: B64.encode(sig.to_bytes()),
            delegator_pubkey: B64.encode(signing_key.verifying_key().as_bytes()),
        }
    }

    /// Verify this token's cryptographic signature and check expiry.
    pub fn verify(&self) -> Result<(), DelegationError> {
        // Decode the public key.
        let pubkey_bytes = B64
            .decode(&self.delegator_pubkey)
            .map_err(|_| DelegationError::InvalidKey)?;
        if pubkey_bytes.len() != 32 {
            return Err(DelegationError::InvalidKey);
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&pubkey_bytes);
        let verifying_key =
            VerifyingKey::from_bytes(&key_arr).map_err(|_| DelegationError::InvalidKey)?;

        // Decode and verify signature.
        let sig_bytes = B64
            .decode(&self.signature)
            .map_err(|_| DelegationError::InvalidSignature)?;
        let sig =
            Signature::from_slice(&sig_bytes).map_err(|_| DelegationError::InvalidSignature)?;
        let message = Self::canonical(
            &self.delegator,
            &self.delegatee,
            &self.issued_at,
            &self.expires_at,
            &self.scope,
        );
        verifying_key
            .verify(message.as_bytes(), &sig)
            .map_err(|_| DelegationError::InvalidSignature)?;

        // Check expiry.
        let expires = chrono::DateTime::parse_from_rfc3339(&self.expires_at)
            .map_err(|_| DelegationError::Expired)?;
        if Utc::now() > expires {
            return Err(DelegationError::Expired);
        }
        Ok(())
    }
}

impl DelegationChain {
    /// Validate the entire delegation chain:
    /// 1. Each token has a valid signature and is not expired.
    /// 2. Chain is contiguous: token[i].delegatee == token[i+1].delegator.
    /// 3. Chain depth does not exceed `max_depth`.
    pub fn validate(&self, max_depth: u32) -> Result<(), DelegationError> {
        if self.tokens.is_empty() {
            return Err(DelegationError::EmptyChain);
        }
        if self.tokens.len() as u32 > max_depth {
            return Err(DelegationError::DepthExceeded {
                depth: self.tokens.len() as u32,
                max: max_depth,
            });
        }
        for (i, token) in self.tokens.iter().enumerate() {
            token.verify()?;
            // Verify contiguity.
            if i > 0 && self.tokens[i - 1].delegatee != token.delegator {
                return Err(DelegationError::BrokenChain {
                    expected: self.tokens[i - 1].delegatee.clone(),
                    got: token.delegator.clone(),
                });
            }
        }
        Ok(())
    }

    /// The final agent in the chain (the one executing the action).
    pub fn terminal_agent(&self) -> Option<&str> {
        self.tokens.last().map(|t| t.delegatee.as_str())
    }

    /// Depth of the chain (number of hops).
    pub fn depth(&self) -> u32 {
        self.tokens.len() as u32
    }
}

/// Errors that can occur during delegation chain validation.
#[derive(Debug, Clone, PartialEq)]
pub enum DelegationError {
    EmptyChain,
    InvalidKey,
    InvalidSignature,
    Expired,
    DepthExceeded { depth: u32, max: u32 },
    BrokenChain { expected: String, got: String },
}

impl std::fmt::Display for DelegationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyChain => write!(f, "delegation chain is empty"),
            Self::InvalidKey => write!(f, "invalid delegator public key"),
            Self::InvalidSignature => write!(f, "delegation token signature verification failed"),
            Self::Expired => write!(f, "delegation token has expired"),
            Self::DepthExceeded { depth, max } => {
                write!(f, "delegation chain depth {depth} exceeds max {max}")
            }
            Self::BrokenChain { expected, got } => {
                write!(
                    f,
                    "broken chain: expected delegator '{expected}', got '{got}'"
                )
            }
        }
    }
}

impl std::error::Error for DelegationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    #[test]
    fn single_hop_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let token = DelegationToken::sign("agent-a", "agent-b", "validate", 300, &sk);
        assert!(token.verify().is_ok());
    }

    #[test]
    fn chain_validation_passes() {
        let sk_a = SigningKey::generate(&mut OsRng);
        let sk_b = SigningKey::generate(&mut OsRng);
        let t1 = DelegationToken::sign("agent-a", "agent-b", "validate", 300, &sk_a);
        let t2 = DelegationToken::sign("agent-b", "agent-c", "validate", 300, &sk_b);
        let chain = DelegationChain {
            tokens: vec![t1, t2],
        };
        assert!(chain.validate(3).is_ok());
        assert_eq!(chain.terminal_agent(), Some("agent-c"));
        assert_eq!(chain.depth(), 2);
    }

    #[test]
    fn chain_depth_exceeded() {
        let sk = SigningKey::generate(&mut OsRng);
        let t1 = DelegationToken::sign("a", "b", "", 300, &sk);
        let chain = DelegationChain { tokens: vec![t1] };
        assert_eq!(
            chain.validate(0),
            Err(DelegationError::DepthExceeded { depth: 1, max: 0 })
        );
    }

    #[test]
    fn broken_chain_detected() {
        let sk_a = SigningKey::generate(&mut OsRng);
        let sk_c = SigningKey::generate(&mut OsRng);
        let t1 = DelegationToken::sign("agent-a", "agent-b", "", 300, &sk_a);
        // Wrong delegator — should be agent-b but is agent-c.
        let t2 = DelegationToken::sign("agent-c", "agent-d", "", 300, &sk_c);
        let chain = DelegationChain {
            tokens: vec![t1, t2],
        };
        assert!(matches!(
            chain.validate(5),
            Err(DelegationError::BrokenChain { .. })
        ));
    }

    #[test]
    fn tampered_token_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut token = DelegationToken::sign("agent-a", "agent-b", "validate", 300, &sk);
        token.delegatee = "agent-evil".to_string(); // tamper
        assert_eq!(token.verify(), Err(DelegationError::InvalidSignature));
    }
}
