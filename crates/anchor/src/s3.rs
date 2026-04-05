use async_trait::async_trait;
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::{Anchor, AnchorDecision, AnchorError, AnchorProof};

type HmacSha256 = Hmac<Sha256>;

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn hmac_sha256_bytes(key: &[u8], data: &[u8]) -> Vec<u8> {
    // HMAC-SHA256 accepts any key size (RFC 2104 §2: keys shorter than block
    // size are zero-padded, longer keys are hashed).  new_from_slice only
    // fails for algorithm-level InvalidLength which cannot happen for SHA-256.
    let mut mac = HmacSha256::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC-SHA256 accepts any key length"));
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn aws4_signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256_bytes(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256_bytes(&k_date, region.as_bytes());
    let k_service = hmac_sha256_bytes(&k_region, service.as_bytes());
    hmac_sha256_bytes(&k_service, b"aws4_request")
}

/// Config for S3-compatible storage (AWS S3, Cloudflare R2, MinIO, …).
pub struct S3AnchorConfig {
    pub access_key: String,
    pub secret_key: String,
    pub region: String,
    /// Base bucket URL, e.g. `https://my-bucket.s3.us-east-1.amazonaws.com`
    pub endpoint: String,
    /// Key prefix for every object, e.g. `audit/`
    pub prefix: String,
}

pub struct S3Anchor {
    config: S3AnchorConfig,
    client: reqwest::Client,
}

impl S3Anchor {
    pub fn new(config: S3AnchorConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl Anchor for S3Anchor {
    async fn commit(&self, d: &AnchorDecision<'_>) -> Result<AnchorProof, AnchorError> {
        let body_bytes = serde_json::to_vec(&serde_json::json!({
            "transaction_id": d.transaction_id,
            "agent_id":       d.agent_id,
            "decision":       d.decision,
            "timestamp":      d.timestamp,
            "policy_code":    d.policy_code,
            "merkle_root":    d.merkle_root,
        }))
        .unwrap();

        let key = format!("{}{}.json", self.config.prefix, d.transaction_id);
        let object_url = format!("{}/{}", self.config.endpoint.trim_end_matches('/'), key);
        let now = Utc::now();
        let datetime = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date = now.format("%Y%m%d").to_string();
        let payload_hash = sha256_hex(&body_bytes);

        let host = reqwest::Url::parse(&self.config.endpoint)
            .map(|u| u.host_str().unwrap_or("s3.amazonaws.com").to_string())
            .unwrap_or_else(|_| "s3.amazonaws.com".to_string());

        let canonical_headers = format!(
            "content-type:application/json\nhost:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{datetime}\n"
        );
        let signed_headers = "content-type;host;x-amz-content-sha256;x-amz-date";
        let canonical_request =
            format!("PUT\n/{key}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
        let credential_scope = format!("{date}/{}/s3/aws4_request", self.config.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{datetime}\n{credential_scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );
        let signing_key =
            aws4_signing_key(&self.config.secret_key, &date, &self.config.region, "s3");
        let signature = hex::encode(hmac_sha256_bytes(&signing_key, string_to_sign.as_bytes()));
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.config.access_key
        );

        self.client
            .put(&object_url)
            .header("Content-Type", "application/json")
            .header("x-amz-date", &datetime)
            .header("x-amz-content-sha256", &payload_hash)
            .header("Authorization", &authorization)
            .body(body_bytes)
            .send()
            .await
            .map_err(|e| AnchorError::Network(e.to_string()))?
            .error_for_status()
            .map_err(|e| AnchorError::Storage(e.to_string()))?;

        Ok(AnchorProof {
            anchor_type: "s3",
            proof_id: key,
            location: object_url,
            committed_at: now,
        })
    }
}
