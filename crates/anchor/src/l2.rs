//! BaseL2Anchor — feature-gated stub for Base (OP-stack) L2 anchoring.
//!
//! ## Status: STUB — does NOT submit transactions to Base L2.
//!
//! The commitment is computed and logged locally.  Production use requires:
//!   - The `alloy` crate: `cargo add alloy --features "provider-http,signers"`
//!   - A deployed `HaltChainAnchor` contract with a `commitRoot(bytes32)` entry
//!   - `BASE_RPC_URL` and `ANCHOR_PRIVATE_KEY` env vars
//!
//! Replace `_stub_submit` below with a real `alloy` provider transaction.

use async_trait::async_trait;
use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::{Anchor, AnchorDecision, AnchorError, AnchorProof};

pub struct BaseL2AnchorConfig {
    /// Base (or OP-stack) JSON-RPC endpoint, e.g. `https://mainnet.base.org`
    pub rpc_url: String,
    /// Hex-encoded 32-byte private key (without `0x` prefix).
    pub private_key_hex: String,
    /// Deployed `HaltChainAnchor` contract address.
    pub contract_address: String,
}

pub struct BaseL2Anchor {
    config: BaseL2AnchorConfig,
}

impl BaseL2Anchor {
    pub fn new(config: BaseL2AnchorConfig) -> Self {
        Self { config }
    }

    fn compute_commitment(&self, d: &AnchorDecision<'_>) -> [u8; 32] {
        let input = format!(
            "{}\0{}\0{}\0{}",
            d.transaction_id, d.agent_id, d.decision, d.timestamp
        );
        let hash = Sha256::digest(input.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash);
        out
    }
}

#[async_trait]
impl Anchor for BaseL2Anchor {
    async fn commit(&self, d: &AnchorDecision<'_>) -> Result<AnchorProof, AnchorError> {
        let commitment = self.compute_commitment(d);
        let commitment_hex = hex::encode(commitment);

        // TODO: replace with real alloy transaction:
        //
        //   use alloy::{providers::ProviderBuilder, signers::local::PrivateKeySigner};
        //   let signer   = PrivateKeySigner::from_hex(&self.config.private_key_hex)?;
        //   let provider = ProviderBuilder::new()
        //       .with_signer(signer)
        //       .on_http(self.config.rpc_url.parse()?);
        //   let receipt  = provider
        //       .send_transaction(encode_commit_root_calldata(&commitment))
        //       .await?
        //       .get_receipt()
        //       .await?;
        //   return Ok(AnchorProof { proof_id: receipt.transaction_hash.to_string(), ... });

        let fake_tx_hash = format!("0x{commitment_hex}");
        tracing::warn!(
            rpc_url   = %self.config.rpc_url,
            contract  = %self.config.contract_address,
            commitment = %commitment_hex,
            "BaseL2Anchor STUB — not submitted to Base L2"
        );

        Ok(AnchorProof {
            anchor_type: "base_l2",
            proof_id: fake_tx_hash.clone(),
            location: format!("https://basescan.org/tx/{fake_tx_hash}"),
            committed_at: Utc::now(),
        })
    }
}
