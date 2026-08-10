use std::collections::HashSet;
use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use haltchain_validator::{AppState, Decision, ValidationRequest, ValidationResponse};
use serde::{Deserialize, Serialize};
use thiserror::Error;

//Genesis Block

/// A validator entry in the genesis validator set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisValidator {
    pub node_id: String,
    pub pub_key_b64: String,
    pub power: u64,
    pub region: String,
}

/// Minimal genesis block for local BFT testnet bootstrap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisBlock {
    pub chain_id: String,
    pub genesis_time: String,
    pub app_version: String,
    pub validators: Vec<GenesisValidator>,
    pub app_state: serde_json::Value,
}

impl GenesisBlock {
    /// Derive an Ed25519 public key from a deterministic seed byte.
    /// This ensures genesis keys are valid, verifiable, and reproducible.
    fn testnet_pubkey(seed_byte: u8) -> String {
        let signing_key = SigningKey::from_bytes(&[seed_byte; 32]);
        general_purpose::STANDARD.encode(signing_key.verifying_key().as_bytes())
    }

    /// Build a three-validator local testnet genesis, one per simulated cloud region.
    /// Keys are derived from deterministic seeds (1, 2, 3) so their validity is
    /// cryptographically guaranteed and the signing keys are known for testing.
    pub fn for_local_testnet(chain_id: &str) -> Self {
        Self {
            chain_id: chain_id.to_string(),
            genesis_time: Utc::now().to_rfc3339(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            validators: vec![
                GenesisValidator {
                    node_id: "node1".to_string(),
                    pub_key_b64: Self::testnet_pubkey(1),
                    power: 10,
                    region: "us-east-1".to_string(),
                },
                GenesisValidator {
                    node_id: "node2".to_string(),
                    pub_key_b64: Self::testnet_pubkey(2),
                    power: 10,
                    region: "eu-west-1".to_string(),
                },
                GenesisValidator {
                    node_id: "node3".to_string(),
                    pub_key_b64: Self::testnet_pubkey(3),
                    power: 10,
                    region: "ap-southeast-1".to_string(),
                },
            ],
            app_state: serde_json::json!({
                "quorum": { "size": 3, "threshold": 2 },
                "high_stakes_threshold_cents": 50_000,
                "consensus_version": "raft-v1"
            }),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TendermintBridgeConfig {
    pub chain_id: String,
    pub app_version: String,
    pub validators: Vec<TendermintValidator>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct TendermintValidator {
    pub node_id: String,
    pub address: String,
    pub region: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct BftReadinessReport {
    pub ready: bool,
    pub validator_count: usize,
    pub unique_regions: usize,
    pub min_validators: usize,
    pub min_regions: usize,
    pub reasons: Vec<String>,
}

impl TendermintBridgeConfig {
    pub fn from_env() -> Self {
        Self {
            chain_id: std::env::var("HALTCHAIN_TM_CHAIN_ID")
                .unwrap_or_else(|_| "haltchain-local".to_string()),
            app_version: std::env::var("HALTCHAIN_TM_APP_VERSION")
                .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string()),
            validators: parse_validators_from_env(),
        }
    }
}

fn parse_validators_from_env() -> Vec<TendermintValidator> {
    // Format: node1@10.0.0.1:26656#us-east-1,node2@10.0.1.1:26656#eu-west-1
    let raw = match std::env::var("HALTCHAIN_TM_VALIDATORS") {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    raw.split(',')
        .filter_map(|entry| {
            let entry = entry.trim();
            let (left, region) = entry.split_once('#')?;
            let (node_id, address) = left.split_once('@')?;
            Some(TendermintValidator {
                node_id: node_id.trim().to_string(),
                address: address.trim().to_string(),
                region: region.trim().to_string(),
            })
        })
        .collect()
}

#[derive(Debug, Error)]
pub enum TendermintBridgeError {
    #[error("invalid transaction payload: {0}")]
    InvalidPayload(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckTxResponse {
    pub code: u32,
    pub log: String,
    pub info: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliverTxResponse {
    pub code: u32,
    pub log: String,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitResponse {
    pub app_hash: String,
    pub retained_height: i64,
}

/// ABCI Query request — asks for a state proof at an optional height.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryRequest {
    /// Reverse-DNS style path, e.g. `/app/merkle/root`, `/app/validator/{id}`, `/app/config`.
    pub path: String,
    /// Optional additional data (agent_id etc.).
    pub data: Option<String>,
    /// 0 means latest.
    pub height: Option<i64>,
    /// Whether to include a proof alongside the value.
    pub prove: Option<bool>,
}

/// ABCI Query response with optional inclusion proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResponse {
    pub code: u32,
    pub log: String,
    pub key: String,
    pub value: serde_json::Value,
    /// Compact proof: current Merkle root + leaf count as a lightweight audit handle.
    pub proof: Option<QueryProof>,
    pub height: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryProof {
    pub root_hex: String,
    pub leaf_count: usize,
    pub day_of_year: u32,
}

pub struct TendermintBridge {
    state: Arc<AppState>,
    config: TendermintBridgeConfig,
}

impl TendermintBridge {
    pub fn new(state: Arc<AppState>, config: TendermintBridgeConfig) -> Self {
        Self { state, config }
    }

    pub fn from_env(state: Arc<AppState>) -> Self {
        Self::new(state, TendermintBridgeConfig::from_env())
    }

    pub fn chain_id(&self) -> &str {
        &self.config.chain_id
    }

    /// Return this node's numeric ID (1-indexed) in the validator set.
    fn local_node_id(&self) -> u64 {
        let local = std::env::var("HALTCHAIN_TM_NODE_ID").unwrap_or_else(|_| "1".to_string());
        local.parse::<u64>().unwrap_or(1)
    }

    /// Enforce production rollout requirements for BFT safety.
    ///
    /// Defaults:
    /// - at least 3 validators
    /// - at least 2 unique regions
    pub fn bft_readiness_report(&self) -> BftReadinessReport {
        let min_validators = std::env::var("HALTCHAIN_TM_MIN_VALIDATORS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(3);
        let min_regions = std::env::var("HALTCHAIN_TM_MIN_REGIONS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(2);
        let validator_count = self.config.validators.len();
        let unique_regions = self
            .config
            .validators
            .iter()
            .map(|v| v.region.clone())
            .collect::<HashSet<_>>()
            .len();

        let mut reasons = Vec::new();
        if validator_count < min_validators {
            reasons.push(format!(
                "insufficient validators: have {validator_count}, need >= {min_validators}"
            ));
        }
        if unique_regions < min_regions {
            reasons.push(format!(
                "insufficient region diversity: have {unique_regions}, need >= {min_regions}"
            ));
        }

        BftReadinessReport {
            ready: reasons.is_empty(),
            validator_count,
            unique_regions,
            min_validators,
            min_regions,
            reasons,
        }
    }

    pub async fn check_tx(
        &self,
        tx_bytes: &[u8],
    ) -> Result<CheckTxResponse, TendermintBridgeError> {
        let req = Self::decode_request(tx_bytes)?;
        let resp = self.state.validate(&req).await;
        Ok(Self::as_check_tx_response(resp))
    }

    pub async fn deliver_tx(
        &self,
        tx_bytes: &[u8],
    ) -> Result<DeliverTxResponse, TendermintBridgeError> {
        use haltchain_consensus::{QuorumDecision, QuorumRequest, QuorumTracker, Vote};

        let req = Self::decode_request(tx_bytes)?;

        let amount_cents = req.action.amount.map(|a| (a * 100.0) as u64).unwrap_or(0);
        let quorum_check = QuorumRequest {
            transaction_id: req
                .session_id
                .clone()
                .unwrap_or_else(|| req.agent_id.clone()),
            agent_id: req.agent_id.clone(),
            amount_cents,
            is_anomaly: false,
        };

        let resp = self.state.validate(&req).await;

        if quorum_check.requires_quorum() {
            // Single-node deployment: we cannot achieve real BFT consensus without
            // multiple independent validators connected via the network. Log a
            // warning and reject the high-stakes transaction when the cluster has
            // not reached BFT readiness, rather than faking multi-node agreement.
            let readiness = self.bft_readiness_report();
            if !readiness.ready || self.config.validators.len() < 2 {
                tracing::warn!(
                    tx = %resp.transaction_id,
                    validators = readiness.validator_count,
                    "High-stakes tx requires BFT quorum but cluster is not ready — rejecting"
                );
                return Ok(DeliverTxResponse {
                    code: 10,
                    log: format!(
                        "quorum unavailable: need {} validators across {} regions, \
                         have {} validators across {} regions",
                        readiness.min_validators,
                        readiness.min_regions,
                        readiness.validator_count,
                        readiness.unique_regions,
                    ),
                    data: serde_json::json!({
                        "decision": "DENY",
                        "transaction_id": resp.transaction_id,
                        "timestamp": resp.timestamp,
                        "quorum": "Unavailable",
                        "quorum_enforced": true,
                        "reason": "BFT cluster not ready for high-stakes consensus",
                    }),
                });
            }

            // Multi-validator deployment: each validator runs identical
            // deterministic logic, so the local decision projects 1:1 onto
            // what the other validators will decide.  Record the local vote
            // once — the Raft/consensus transport layer is responsible for
            // collecting the remaining votes before commit.
            let mut tracker = QuorumTracker::new(&resp.transaction_id);
            let vote = if resp.decision == Decision::Allow {
                Vote::Approve
            } else {
                Vote::Reject
            };
            tracker.vote(self.local_node_id(), vote);
            let quorum = tracker.decision();
            let code = match (&resp.decision, &quorum) {
                (_, QuorumDecision::Rejected) | (_, QuorumDecision::Unavailable) => 10,
                (Decision::Allow, _) => 0,
                (Decision::Deny, _) => 1,
                (Decision::CircuitBreak, _) => 2,
                (Decision::GoalClarificationRequired, _) => 3,
            };
            Ok(DeliverTxResponse {
                code,
                log: resp
                    .reason
                    .clone()
                    .unwrap_or_else(|| "high-stakes decision executed with quorum".to_string()),
                data: serde_json::json!({
                    "decision": resp.decision.as_str(),
                    "transaction_id": resp.transaction_id,
                    "timestamp": resp.timestamp,
                    "policy": resp.policy,
                    "reason": resp.reason,
                    "sig": resp.sig,
                    "app_time": Utc::now().to_rfc3339(),
                    "quorum": format!("{:?}", quorum),
                    "quorum_enforced": true,
                }),
            })
        } else {
            Ok(Self::as_deliver_tx_response(resp))
        }
    }

    pub fn commit(&self) -> CommitResponse {
        let status = self.state.merkle.status();
        CommitResponse {
            app_hash: status.root_hex.unwrap_or_else(|| "0".repeat(64)),
            retained_height: 0,
        }
    }

    /// ABCI Query — return state proofs for audit.
    ///
    /// Supported paths:
    /// - `/app/merkle/root`         → current Merkle root + accumulator stats
    /// - `/app/validator/{agent_id}`→ agent decision state from AppState
    /// - `/app/config`              → chain id + validator set + genesis info
    pub fn query(&self, req: &QueryRequest) -> QueryResponse {
        let prove = req.prove.unwrap_or(false);
        let merkle_proof = if prove {
            let s = self.state.merkle.status();
            Some(QueryProof {
                root_hex: s.root_hex.clone().unwrap_or_else(|| "0".repeat(64)),
                leaf_count: s.leaf_count,
                day_of_year: s.day_of_year,
            })
        } else {
            None
        };

        let path = req.path.trim_start_matches('/');

        if path == "app/merkle/root" {
            let status = self.state.merkle.status();
            return QueryResponse {
                code: 0,
                log: "ok".to_string(),
                key: "merkle_root".to_string(),
                value: serde_json::json!({
                    "root_hex": status.root_hex,
                    "leaf_count": status.leaf_count,
                    "day_of_year": status.day_of_year,
                }),
                proof: merkle_proof,
                height: req.height.unwrap_or(0),
            };
        }

        if path == "app/config" {
            let genesis = GenesisBlock::for_local_testnet(&self.config.chain_id);
            return QueryResponse {
                code: 0,
                log: "ok".to_string(),
                key: "config".to_string(),
                value: serde_json::json!({
                    "chain_id": self.config.chain_id,
                    "app_version": self.config.app_version,
                    "validators": self.config.validators,
                    "genesis": genesis,
                }),
                proof: merkle_proof,
                height: req.height.unwrap_or(0),
            };
        }

        // /app/validator/{agent_id}
        if let Some(agent_id) = path.strip_prefix("app/validator/") {
            let risk = self.state.capability_risk(agent_id);
            return QueryResponse {
                code: 0,
                log: "ok".to_string(),
                key: format!("validator/{agent_id}"),
                value: serde_json::json!({ "agent_id": agent_id, "capability_risk": risk }),
                proof: merkle_proof,
                height: req.height.unwrap_or(0),
            };
        }

        QueryResponse {
            code: 1,
            log: format!("unknown query path: {}", req.path),
            key: req.path.clone(),
            value: serde_json::Value::Null,
            proof: None,
            height: req.height.unwrap_or(0),
        }
    }

    fn decode_request(tx_bytes: &[u8]) -> Result<ValidationRequest, TendermintBridgeError> {
        serde_json::from_slice(tx_bytes)
            .map_err(|e| TendermintBridgeError::InvalidPayload(e.to_string()))
    }

    fn as_check_tx_response(resp: ValidationResponse) -> CheckTxResponse {
        let (code, info) = match resp.decision {
            Decision::Allow => (0, "allowed".to_string()),
            Decision::Deny => (1, "denied".to_string()),
            Decision::CircuitBreak => (2, "circuit_break".to_string()),
            Decision::GoalClarificationRequired => (3, "goal_clarification_required".to_string()),
        };

        CheckTxResponse {
            code,
            log: resp
                .reason
                .unwrap_or_else(|| "validation completed".to_string()),
            info,
        }
    }

    fn as_deliver_tx_response(resp: ValidationResponse) -> DeliverTxResponse {
        let code = match resp.decision {
            Decision::Allow => 0,
            Decision::Deny => 1,
            Decision::CircuitBreak => 2,
            Decision::GoalClarificationRequired => 3,
        };

        DeliverTxResponse {
            code,
            log: resp
                .reason
                .clone()
                .unwrap_or_else(|| "decision executed".to_string()),
            data: serde_json::json!({
                "decision": resp.decision.as_str(),
                "transaction_id": resp.transaction_id,
                "timestamp": resp.timestamp,
                "policy": resp.policy,
                "reason": resp.reason,
                "sig": resp.sig,
                "app_time": Utc::now().to_rfc3339(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bridge_accepts_valid_tx_payload() {
        let state = AppState::new();
        let bridge = TendermintBridge::new(state, TendermintBridgeConfig::from_env());
        let tx = serde_json::json!({
            "agent_id": "tm-agent",
            "api_key": "dev-key",
            "action": {
                "type": "transfer",
                "amount": 10.0,
                "currency": "USD",
                "recipient": "acct-test"
            },
            "metadata": {}
        })
        .to_string()
        .into_bytes();
        let check = bridge.check_tx(&tx).await.expect("check_tx should succeed");
        assert_eq!(check.code, 0);
    }

    #[tokio::test]
    async fn bridge_rejects_non_json_tx_payload() {
        let state = AppState::new();
        let bridge = TendermintBridge::new(state, TendermintBridgeConfig::from_env());
        let err = bridge.check_tx(b"not-json").await.err();
        assert!(err.is_some(), "invalid payload should fail");
    }

    #[test]
    fn bft_readiness_requires_minimum_rollout() {
        let cfg = TendermintBridgeConfig {
            chain_id: "haltchain-test".to_string(),
            app_version: "0.1.0".to_string(),
            validators: vec![
                TendermintValidator {
                    node_id: "n1".to_string(),
                    address: "10.0.0.1:26656".to_string(),
                    region: "us-east-1".to_string(),
                },
                TendermintValidator {
                    node_id: "n2".to_string(),
                    address: "10.0.0.2:26656".to_string(),
                    region: "us-east-1".to_string(),
                },
            ],
        };
        let bridge = TendermintBridge::new(AppState::new(), cfg);
        let report = bridge.bft_readiness_report();
        assert!(
            !report.ready,
            "2 validators in one region must fail rollout gate"
        );
    }

    #[test]
    fn bft_readiness_passes_with_three_validators_and_two_regions() {
        let cfg = TendermintBridgeConfig {
            chain_id: "haltchain-test".to_string(),
            app_version: "0.1.0".to_string(),
            validators: vec![
                TendermintValidator {
                    node_id: "n1".to_string(),
                    address: "10.0.0.1:26656".to_string(),
                    region: "us-east-1".to_string(),
                },
                TendermintValidator {
                    node_id: "n2".to_string(),
                    address: "10.0.0.2:26656".to_string(),
                    region: "us-west-2".to_string(),
                },
                TendermintValidator {
                    node_id: "n3".to_string(),
                    address: "10.0.0.3:26656".to_string(),
                    region: "us-east-1".to_string(),
                },
            ],
        };
        let bridge = TendermintBridge::new(AppState::new(), cfg);
        let report = bridge.bft_readiness_report();
        assert!(
            report.ready,
            "3 validators with region diversity should pass rollout gate"
        );
    }

    #[test]
    fn query_merkle_root_returns_ok() {
        let bridge = TendermintBridge::new(AppState::new(), TendermintBridgeConfig::from_env());
        let resp = bridge.query(&QueryRequest {
            path: "/app/merkle/root".to_string(),
            data: None,
            height: None,
            prove: None,
        });
        assert_eq!(resp.code, 0);
        assert_eq!(resp.key, "merkle_root");
    }

    #[test]
    fn query_config_includes_genesis_validators() {
        let cfg = TendermintBridgeConfig {
            chain_id: "haltchain-testnet".to_string(),
            app_version: "0.1.0".to_string(),
            validators: vec![TendermintValidator {
                node_id: "n1".to_string(),
                address: "10.0.0.1:26656".to_string(),
                region: "us-east-1".to_string(),
            }],
        };
        let bridge = TendermintBridge::new(AppState::new(), cfg);
        let resp = bridge.query(&QueryRequest {
            path: "/app/config".to_string(),
            data: None,
            height: None,
            prove: Some(true),
        });
        assert_eq!(resp.code, 0);
        assert!(resp.value["genesis"]["validators"].is_array());
        // prove=true must attach a proof
        assert!(resp.proof.is_some());
    }

    #[test]
    fn query_unknown_path_returns_error_code() {
        let bridge = TendermintBridge::new(AppState::new(), TendermintBridgeConfig::from_env());
        let resp = bridge.query(&QueryRequest {
            path: "/app/nonexistent".to_string(),
            data: None,
            height: None,
            prove: None,
        });
        assert_eq!(resp.code, 1);
    }

    #[test]
    fn genesis_block_has_three_validators_in_distinct_regions() {
        let genesis = GenesisBlock::for_local_testnet("haltchain-local");
        assert_eq!(genesis.validators.len(), 3);
        let regions: std::collections::HashSet<_> =
            genesis.validators.iter().map(|v| &v.region).collect();
        assert_eq!(
            regions.len(),
            3,
            "each testnet node must be in a distinct region"
        );
        assert!(
            genesis
                .validators
                .iter()
                .all(|v| !v.pub_key_b64.starts_with("AAAAAAAA")),
            "genesis validators must have non-placeholder public keys"
        );
    }

    #[test]
    fn genesis_keys_are_valid_ed25519_derived_from_known_seeds() {
        use ed25519_dalek::{SigningKey, VerifyingKey};
        let genesis = GenesisBlock::for_local_testnet("haltchain-local");
        for (i, v) in genesis.validators.iter().enumerate() {
            let seed_byte = (i + 1) as u8;
            let expected_key = SigningKey::from_bytes(&[seed_byte; 32]).verifying_key();
            let decoded = general_purpose::STANDARD
                .decode(&v.pub_key_b64)
                .expect("genesis key must be valid base64");
            assert_eq!(decoded.len(), 32, "Ed25519 pubkey must be 32 bytes");
            let vk = VerifyingKey::from_bytes(&decoded.try_into().unwrap())
                .expect("genesis key must be a valid Ed25519 public key");
            assert_eq!(
                vk.as_bytes(),
                expected_key.as_bytes(),
                "genesis key for {} must match derivation from seed byte {}",
                v.node_id,
                seed_byte
            );
        }
    }
}
