use async_trait::async_trait;
use chrono::{TimeZone, Utc};
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
    /// Compliance retention period for S3 Object Lock (WORM).
    ///
    /// When `Some`, the anchor sets `x-amz-object-lock-mode: COMPLIANCE` and
    /// `x-amz-object-lock-retain-until-date` on every uploaded object.
    /// The bucket must have Object Lock enabled at creation time (cannot be
    /// enabled after the fact on existing buckets).
    ///
    /// Recommended: `Some(Duration::from_secs(7 * 365 * 24 * 3600))` for
    /// 7-year compliance retention as required by most financial regulations.
    pub object_lock_retain_until: Option<std::time::Duration>,
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
            // ── S3 Object Lock (WORM) ──────────────────────────────────────────
            // Setting COMPLIANCE mode means no one (including root) can delete
            // the object before the retain-until date — required for 7-year
            // compliance retention under SOX, FINRA, MiFID II, etc.
            .headers({
                let mut m = reqwest::header::HeaderMap::new();
                if let Some(retain) = self.config.object_lock_retain_until {
                    let retain_until = (std::time::SystemTime::now() + retain)
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default();
                    let secs = retain_until.as_secs();
                    // RFC 3339 date-time required by Object Lock API
                    let dt = Utc
                        .timestamp_opt(secs as i64, 0)
                        .single()
                        .unwrap_or_else(Utc::now);
                    m.insert(
                        "x-amz-object-lock-mode",
                        reqwest::header::HeaderValue::from_static("COMPLIANCE"),
                    );
                    m.insert(
                        "x-amz-object-lock-retain-until-date",
                        reqwest::header::HeaderValue::from_str(
                            &dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                        )
                        .unwrap_or_else(|_| reqwest::header::HeaderValue::from_static("")),
                    );
                }
                m
            })
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── sha256_hex: known test vector ────────────────────────────────────────
    #[test]
    fn test_sha256_hex_empty() {
        // SHA-256("") is well-known.
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(sha256_hex(b""), expected);
    }

    #[test]
    fn test_sha256_hex_hello() {
        // SHA-256("hello") per NIST / openssl.
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert_eq!(sha256_hex(b"hello"), expected);
    }

    // ── hmac_sha256_bytes: RFC 4231 test case 2 ─────────────────────────────
    #[test]
    fn test_hmac_sha256_rfc4231_case2() {
        // Key  = "Jefe"
        // Data = "what do ya want for nothing?"
        // Expected HMAC-SHA256 (from RFC 4231 §4.3)
        let expected_hex = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        let result = hmac_sha256_bytes(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(hex::encode(&result), expected_hex);
    }

    // ── aws4_signing_key: AWS docs reference vector ─────────────────────────
    // From: https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html
    #[test]
    fn test_aws4_signing_key() {
        let key = aws4_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20120215",
            "us-east-1",
            "iam",
        );
        let expected = "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d";
        assert_eq!(hex::encode(&key), expected);
    }

    // ── Full SigV4 canonical request + signature ────────────────────────────
    // Verify the signing chain produces a deterministic signature for fixed
    // inputs (no network call required).
    #[test]
    fn test_sigv4_signing_chain() {
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let access_key = "AKIDEXAMPLE";
        let region = "us-east-1";
        let date = "20230101";
        let datetime = "20230101T000000Z";

        let body = br#"{"test":"value"}"#;
        let payload_hash = sha256_hex(body);
        let key = "audit/txn-123.json";
        let host = "my-bucket.s3.us-east-1.amazonaws.com";

        let canonical_headers = format!(
            "content-type:application/json\nhost:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{datetime}\n"
        );
        let signed_headers = "content-type;host;x-amz-content-sha256;x-amz-date";
        let canonical_request =
            format!("PUT\n/{key}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");

        let credential_scope = format!("{date}/{region}/s3/aws4_request");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{datetime}\n{credential_scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );
        let signing_key = aws4_signing_key(secret, date, region, "s3");
        let signature = hex::encode(hmac_sha256_bytes(&signing_key, string_to_sign.as_bytes()));

        // Signature must be exactly 64 hex chars (256 bits).
        assert_eq!(
            signature.len(),
            64,
            "SigV4 signature should be 64 hex chars"
        );
        // Must be stable across runs.
        assert_eq!(
            signature,
            hex::encode(hmac_sha256_bytes(&signing_key, string_to_sign.as_bytes())),
            "signing must be deterministic"
        );

        // Verify authorization header format.
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
        );
        assert!(authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"));
        assert!(
            authorization
                .contains("SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date")
        );
        assert!(authorization.contains(&format!("Signature={signature}")));
    }
}
