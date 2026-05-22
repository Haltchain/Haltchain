//! HSM (Hardware Security Module) backend abstraction.
//!
//! Defines the [`KeyBackend`] trait that signing operations delegate to.
//! Provides a default in-memory implementation ([`SoftwareBackend`]) and
//! stub trait implementations for external HSMs (YubiHSM 2, AWS KMS,
//! Azure Key Vault).
//!
//! # Design
//!
//! All backends must produce Ed25519-compatible signatures. External HSMs
//! that support Ed25519 natively (YubiHSM 2) call the hardware directly.
//! Cloud KMS backends (AWS, Azure) use asymmetric Ed25519 key operations.
//!
//! Key rotation is handled by the [`SigningService`] via `RwLock`-based
//! atomic swap — the backend just needs to generate or import new keys.

use std::fmt;

/// Errors from HSM / key backend operations.
#[derive(Debug)]
pub enum BackendError {
    /// The HSM hardware or service is unreachable.
    Unavailable(String),
    /// The requested key ID does not exist.
    KeyNotFound(String),
    /// Signing operation failed.
    SigningFailed(String),
    /// Key generation or import failed.
    KeyGenFailed(String),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(msg) => write!(f, "HSM unavailable: {msg}"),
            Self::KeyNotFound(msg) => write!(f, "key not found: {msg}"),
            Self::SigningFailed(msg) => write!(f, "signing failed: {msg}"),
            Self::KeyGenFailed(msg) => write!(f, "key generation failed: {msg}"),
        }
    }
}

impl std::error::Error for BackendError {}

/// Trait for pluggable key backends (in-memory, HSM, cloud KMS).
///
/// Implementations must be `Send + Sync` for use behind `RwLock`.
pub trait KeyBackend: Send + Sync {
    /// Human-readable backend name (e.g. "software", "yubihsm", "aws-kms").
    fn name(&self) -> &'static str;

    /// Sign `message` bytes and return the raw 64-byte Ed25519 signature.
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], BackendError>;

    /// Return the 32-byte Ed25519 public key.
    fn public_key(&self) -> Result<[u8; 32], BackendError>;

    /// Generate a new keypair, returning `(key_id, public_key_bytes)`.
    /// The backend stores the private key internally.
    fn generate_key(&mut self) -> Result<(String, [u8; 32]), BackendError>;

    /// Whether this backend provides FIPS 140-2 Level 2+ compliance.
    fn is_fips_compliant(&self) -> bool {
        false
    }
}

// ── Software (in-memory) backend ─────────────────────────────────────────────

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use uuid::Uuid;

/// Default in-memory Ed25519 backend. Not FIPS compliant but zero-dependency.
pub struct SoftwareBackend {
    key_id: String,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl SoftwareBackend {
    /// Generate a fresh random Ed25519 keypair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            key_id: Uuid::new_v4().to_string(),
            signing_key,
            verifying_key,
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl KeyBackend for SoftwareBackend {
    fn name(&self) -> &'static str {
        "software"
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], BackendError> {
        let sig = self.signing_key.sign(message);
        Ok(sig.to_bytes())
    }

    fn public_key(&self) -> Result<[u8; 32], BackendError> {
        Ok(self.verifying_key.to_bytes())
    }

    fn generate_key(&mut self) -> Result<(String, [u8; 32]), BackendError> {
        self.signing_key = SigningKey::generate(&mut OsRng);
        self.verifying_key = self.signing_key.verifying_key();
        self.key_id = Uuid::new_v4().to_string();
        Ok((self.key_id.clone(), self.verifying_key.to_bytes()))
    }
}

// ── YubiHSM 2 backend (stub — requires yubihsm crate at runtime) ────────────

/// YubiHSM 2 backend placeholder.
///
/// To enable: add `yubihsm` crate dependency and implement the trait methods
/// using the PKCS#11 or HTTP connector.
///
/// ```ignore
/// let connector = yubihsm::Connector::usb(&Default::default())?;
/// let session = connector.create_session_from_password(1, b"password")?;
/// ```
pub struct YubiHsmBackend {
    _private: (),
}

impl YubiHsmBackend {
    /// Create a YubiHSM backend. Returns error until the `yubihsm` crate is wired in.
    pub fn connect(
        _connector_url: &str,
        _auth_key_id: u16,
        _password: &str,
    ) -> Result<Self, BackendError> {
        Err(BackendError::Unavailable(
            "YubiHSM support requires the 'yubihsm' feature flag".into(),
        ))
    }
}

// ── AWS KMS backend (stub — requires aws-sdk-kms at runtime) ─────────────────

/// AWS KMS Ed25519 backend placeholder.
///
/// Uses asymmetric Ed25519 signing keys in AWS KMS.
/// Requires: `aws-sdk-kms` crate + valid AWS credentials.
pub struct AwsKmsBackend {
    _key_arn: String,
}

impl AwsKmsBackend {
    /// Create an AWS KMS backend for the given key ARN.
    pub fn new(_key_arn: String, _region: &str) -> Result<Self, BackendError> {
        Err(BackendError::Unavailable(
            "AWS KMS support requires the 'aws-kms' feature flag".into(),
        ))
    }
}

// ── Azure Key Vault backend (stub — requires azure_security_keyvault) ────────

/// Azure Key Vault Ed25519 backend placeholder.
///
/// Requires: `azure_security_keyvault` crate + valid Azure credentials.
pub struct AzureKeyVaultBackend {
    _vault_url: String,
    _key_name: String,
}

impl AzureKeyVaultBackend {
    /// Create an Azure Key Vault backend.
    pub fn new(_vault_url: String, _key_name: String) -> Result<Self, BackendError> {
        Err(BackendError::Unavailable(
            "Azure Key Vault support requires the 'azure-kv' feature flag".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_backend_sign_and_verify() {
        let backend = SoftwareBackend::generate();
        let message = b"test message";
        let sig_bytes = backend.sign(message).unwrap();
        let pubkey_bytes = backend.public_key().unwrap();

        // Verify with ed25519-dalek directly
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        use ed25519_dalek::Verifier;
        assert!(verifying_key.verify(message, &sig).is_ok());
    }

    #[test]
    fn software_backend_key_rotation() {
        let mut backend = SoftwareBackend::generate();
        let old_pub = backend.public_key().unwrap();
        let old_id = backend.key_id().to_string();

        let (new_id, new_pub) = backend.generate_key().unwrap();
        assert_ne!(old_pub, new_pub);
        assert_ne!(old_id, new_id);
    }

    #[test]
    fn software_backend_name() {
        let backend = SoftwareBackend::generate();
        assert_eq!(backend.name(), "software");
        assert!(!backend.is_fips_compliant());
    }

    #[test]
    fn yubihsm_stub_returns_unavailable() {
        let result = YubiHsmBackend::connect("http://localhost:12345", 1, "password");
        assert!(result.is_err());
    }

    #[test]
    fn aws_kms_stub_returns_unavailable() {
        let result = AwsKmsBackend::new("arn:aws:kms:us-east-1:123:key/abc".into(), "us-east-1");
        assert!(result.is_err());
    }

    #[test]
    fn azure_kv_stub_returns_unavailable() {
        let result = AzureKeyVaultBackend::new(
            "https://myvault.vault.azure.net".into(),
            "signing-key".into(),
        );
        assert!(result.is_err());
    }
}
