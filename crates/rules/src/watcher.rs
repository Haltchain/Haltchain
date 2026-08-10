//! Thursday: Policy hot-reload using the `notify` crate.
//!
//! Spawns a background OS-level watcher on a YAML file.  When the file changes,
//! it re-parses the policy and atomically swaps the shared handle.  Callers hold
//! a `PolicyHandle` and call `.load()` to get the current policy at any time.
//!
//! P1 Security: Rules are now cryptographically signed. The signature file
//! (rules.yaml.sig) must contain a valid Ed25519 signature over the rules file.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use notify::{RecommendedWatcher, RecursiveMode, Watcher, event::EventKind};
use parking_lot::RwLock;
use semver::Version;
use tracing::{error, info, warn};

use crate::schema::PolicyFile;

// ─── Policy handle ────────────────────────────────────────────────────────────

/// Thread-safe, cheaply-cloneable handle to the current policy.
///
/// Call `.load()` to get the latest version.  The background watcher
/// replaces the inner value on every successful reload.
/// Call `.generation()` to cheaply check if the policy changed (no clone).
#[derive(Clone)]
pub struct PolicyHandle(Arc<(RwLock<PolicyFile>, AtomicU64)>);

impl PolicyHandle {
    fn new(pf: PolicyFile) -> Self {
        Self(Arc::new((RwLock::new(pf), AtomicU64::new(0))))
    }

    pub fn load(&self) -> PolicyFile {
        self.0.0.read().clone()
    }

    /// Returns a monotonically increasing counter; incremented on every reload.
    /// Callers can compare this to a cached value to avoid redundant `load()` clones.
    pub fn generation(&self) -> u64 {
        self.0.1.load(Ordering::Acquire)
    }

    pub fn store(&self, pf: PolicyFile) {
        *self.0.0.write() = pf;
        self.0.1.fetch_add(1, Ordering::Release);
    }
}

// ─── Policy version store (rollback-capable) ─────────────────────────────────

/// A versioned snapshot of a policy, kept for rollback purposes.
#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    pub policy: PolicyFile,
    pub loaded_at: std::time::SystemTime,
    pub generation: u64,
}

/// Deployment environment tier for ordered policy promotion.
///
/// Policies must be promoted in ascending order: Dev → Staging → Prod.
/// A `push` that would skip a tier (e.g. Dev → Prod without going through
/// Staging first) is rejected by [`PolicyStore::promote`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PolicyEnvironment {
    Dev,
    Staging,
    Prod,
}

impl PolicyEnvironment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Staging => "staging",
            Self::Prod => "prod",
        }
    }
}

/// Thread-safe policy version store with fixed-capacity history ring buffer.
///
/// Wraps a [`PolicyHandle`] and additionally keeps the last N policy versions
/// so operators can roll back to a known-good state via `rollback()`.
/// Version strings are validated as [semver](https://semver.org/) on every
/// `push` and `promote` call.
#[derive(Clone)]
pub struct PolicyStore {
    handle: PolicyHandle,
    history: Arc<RwLock<Vec<PolicySnapshot>>>,
    max_history: usize,
    /// Per-environment active policy (dev / staging / prod).  The `handle`
    /// always reflects the current *promoted* policy; the env map tracks each
    /// tier independently for promotion-gating.
    env_policies: Arc<RwLock<std::collections::HashMap<PolicyEnvironment, PolicyFile>>>,
}

impl PolicyStore {
    /// Create a new store seeded with `initial` and retaining up to `max_history` versions.
    pub fn new(initial: PolicyFile, max_history: usize) -> Self {
        let generation = 0u64;
        let snapshot = PolicySnapshot {
            policy: initial.clone(),
            loaded_at: std::time::SystemTime::now(),
            generation,
        };
        let handle = PolicyHandle::new(initial.clone());
        let mut env_map = std::collections::HashMap::new();
        env_map.insert(PolicyEnvironment::Dev, initial);
        Self {
            handle,
            history: Arc::new(RwLock::new(vec![snapshot])),
            max_history: max_history.max(1),
            env_policies: Arc::new(RwLock::new(env_map)),
        }
    }

    /// Get the underlying handle (compatible with existing hot-reload watcher).
    pub fn handle(&self) -> &PolicyHandle {
        &self.handle
    }

    /// Load the current active policy.
    pub fn load(&self) -> PolicyFile {
        self.handle.load()
    }

    /// Current generation counter.
    pub fn generation(&self) -> u64 {
        self.handle.generation()
    }

    /// Parse and return the active policy's semver version string.
    /// Returns an error if the version field is not valid semver.
    pub fn semver_version(&self) -> Result<Version, semver::Error> {
        Version::parse(&self.handle.load().version)
    }

    /// Push a new policy version into the *dev* environment and activate it.
    ///
    /// The policy's `version` field must be a valid semver string.
    /// Returns `Err` with a descriptive message if validation fails.
    pub fn push(&self, pf: PolicyFile) -> Result<(), String> {
        // Validate semver before accepting
        Version::parse(&pf.version).map_err(|e| {
            format!(
                "policy version {:?} is not valid semver (e.g. \"1.2.3\"): {e}",
                pf.version
            )
        })?;
        self.env_policies
            .write()
            .insert(PolicyEnvironment::Dev, pf.clone());
        self.handle.store(pf.clone());
        let generation = self.handle.generation();
        let snapshot = PolicySnapshot {
            policy: pf,
            loaded_at: std::time::SystemTime::now(),
            generation,
        };
        let mut history = self.history.write();
        history.push(snapshot);
        // Trim to max_history (keep most recent)
        if history.len() > self.max_history {
            let excess = history.len() - self.max_history;
            history.drain(..excess);
        }
        Ok(())
    }

    /// Promote the policy currently in `from` to `to`.
    ///
    /// Enforces the ordered promotion path Dev → Staging → Prod; skipping a
    /// tier returns `Err`.  The `to` environment must not already have a
    /// policy at a *higher* semver than `from` — a downgrade (lower version)
    /// is also rejected to preserve immutability guarantees.
    pub fn promote(&self, from: PolicyEnvironment, to: PolicyEnvironment) -> Result<(), String> {
        // Enforce ordered promotion (cannot skip tiers)
        if to as i32 != from as i32 + 1 {
            return Err(format!(
                "invalid promotion path: {:?} → {:?}; must advance exactly one tier",
                from.as_str(),
                to.as_str(),
            ));
        }

        let env_map = self.env_policies.read();
        let source = env_map
            .get(&from)
            .ok_or_else(|| format!("no policy loaded for {:?} environment", from.as_str()))?
            .clone();
        let source_ver = Version::parse(&source.version).map_err(|e| {
            format!(
                "source policy version {:?} is not valid semver: {e}",
                source.version
            )
        })?;

        // Reject downgrade in the target environment
        if let Some(existing) = env_map.get(&to)
            && let Ok(existing_ver) = Version::parse(&existing.version)
            && source_ver <= existing_ver
        {
            return Err(format!(
                "promotion rejected: {} environment already has version {} >= {}",
                to.as_str(),
                existing_ver,
                source_ver,
            ));
        }
        drop(env_map);

        // Apply promotion
        self.env_policies.write().insert(to, source.clone());
        if to == PolicyEnvironment::Prod {
            // Activating prod promotes to the live handle
            self.handle.store(source.clone());
            let generation = self.handle.generation();
            let snapshot = PolicySnapshot {
                policy: source.clone(),
                loaded_at: std::time::SystemTime::now(),
                generation,
            };
            let mut history = self.history.write();
            history.push(snapshot);
            if history.len() > self.max_history {
                let excess = history.len() - self.max_history;
                history.drain(..excess);
            }
        }
        info!(
            from = from.as_str(),
            to = to.as_str(),
            version = %source.version,
            "policy promoted"
        );
        Ok(())
    }

    /// List versions in history (oldest first).
    pub fn versions(&self) -> Vec<(u64, String)> {
        self.history
            .read()
            .iter()
            .map(|s| (s.generation, s.policy.version.clone()))
            .collect()
    }

    /// Roll back to a previous generation. Returns `true` if the rollback
    /// succeeded, `false` if the target generation is not in history.
    pub fn rollback(&self, target_generation: u64) -> bool {
        let history = self.history.read();
        if let Some(snapshot) = history.iter().find(|s| s.generation == target_generation) {
            self.handle.store(snapshot.policy.clone());
            info!(
                target_gen = target_generation,
                version = %snapshot.policy.version,
                "policy rolled back"
            );
            true
        } else {
            warn!(
                target_gen = target_generation,
                "rollback failed: generation not found in history"
            );
            false
        }
    }

    /// Roll back to the previous version (one step back).
    /// Returns `true` if successful.
    pub fn rollback_previous(&self) -> bool {
        let history = self.history.read();
        if history.len() < 2 {
            warn!("rollback failed: no previous version in history");
            return false;
        }
        let current_gen = self.handle.generation();
        // Find the entry just before the current one
        if let Some(prev) = history.iter().rev().find(|s| s.generation < current_gen) {
            self.handle.store(prev.policy.clone());
            info!(
                from_gen = current_gen,
                to_gen = prev.generation,
                version = %prev.policy.version,
                "policy rolled back to previous"
            );
            true
        } else {
            false
        }
    }
}

// ─── Signature verification ───────────────────────────────────────────────────

/// Verify the Ed25519 signature of a rules file.
///
/// P1 Security: Rules must be signed by an admin key to prevent
/// unauthorized modifications that could bypass security controls.
///
/// The signature file (rules.yaml.sig) should contain the 64-byte
/// Ed25519 signature in raw bytes.
pub fn verify_rules_signature(
    rules_path: &Path,
    pubkey: &VerifyingKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let rules = std::fs::read(rules_path)?;
    let sig_path = rules_path.with_extension("yaml.sig");

    if !sig_path.exists() {
        // In production, fail if no signature. For dev, allow unsigned.
        if std::env::var("HALTCHAIN_STRICT_SIGNATURES").is_ok() {
            return Err("Rules signature required but not found".into());
        }
        // Dev mode: warn and continue
        warn!("Rules file not signed - running in dev mode");
        return Ok(());
    }

    let sig_bytes = std::fs::read(&sig_path)?;
    if sig_bytes.len() != 64 {
        return Err(format!(
            "Invalid signature length: expected 64, got {}",
            sig_bytes.len()
        )
        .into());
    }

    let signature = Signature::from_slice(&sig_bytes)?;
    pubkey.verify(&rules, &signature)?;

    info!("Rules signature verified successfully");
    Ok(())
}

/// Load the admin public key from environment or file.
pub fn load_admin_pubkey() -> Result<VerifyingKey, Box<dyn std::error::Error>> {
    // Try environment variable first
    if let Ok(pubkey_b64) = std::env::var("HALTCHAIN_RULES_PUBKEY") {
        let pubkey_bytes = general_purpose::STANDARD.decode(&pubkey_b64)?;
        if pubkey_bytes.len() != 32 {
            return Err("Invalid public key length".into());
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&pubkey_bytes);
        return Ok(VerifyingKey::from_bytes(&bytes)?);
    }

    // Try loading from file
    let pubkey_path = std::path::PathBuf::from(
        std::env::var("HALTCHAIN_RULES_PUBKEY_PATH")
            .unwrap_or_else(|_| "/etc/haltchain/rules_pubkey".to_string()),
    );

    if pubkey_path.exists() {
        let pubkey_bytes = std::fs::read(&pubkey_path)?;
        if pubkey_bytes.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&pubkey_bytes);
            return Ok(VerifyingKey::from_bytes(&bytes)?);
        }
        // Try base64 decoding
        let decoded = general_purpose::STANDARD.decode(&pubkey_bytes)?;
        if decoded.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&decoded);
            return Ok(VerifyingKey::from_bytes(&bytes)?);
        }
    }

    Err(
        "Admin public key not found. Set HALTCHAIN_RULES_PUBKEY or HALTCHAIN_RULES_PUBKEY_PATH"
            .into(),
    )
}

// ─── Watcher ─────────────────────────────────────────────────────────────────

/// Watch `path` for changes and reload the policy into `handle` on every write.
///
/// Runs in a background OS thread; the `RecommendedWatcher` drops when this
/// function's thread exits (which is never, unless the receiver is hung up).
fn spawn_watcher(path: PathBuf, handle: PolicyHandle, pubkey: Option<VerifyingKey>) {
    thread::Builder::new()
        .name("policy-watcher".into())
        .spawn(move || {
            let watched_name = path.file_name().map(|n| n.to_owned());
            let watch_target = path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| path.clone());

            let (tx, rx) = std::sync::mpsc::channel();
            let mut watcher: RecommendedWatcher = match notify::recommended_watcher(tx) {
                Ok(w) => w,
                Err(e) => {
                    error!("failed to create watcher: {e}");
                    return;
                }
            };
            if let Err(e) = watcher.watch(&watch_target, RecursiveMode::NonRecursive) {
                error!("failed to watch {watch_target:?} for {path:?}: {e}");
                return;
            }
            info!("policy watcher started for {path:?} (target {watch_target:?})");

            for msg in rx {
                match msg {
                    Ok(event) => {
                        // Match any modification or creation event since backends differ
                        // (FSEvents sends Modify(Any), kqueue sends Modify(Data(Content))).
                        let is_write =
                            matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_));
                        if !is_write {
                            continue;
                        }
                        if !event.paths.is_empty() {
                            let affects_target = event.paths.iter().any(|p| {
                                if p == &path {
                                    return true;
                                }
                                match (&watched_name, p.file_name()) {
                                    (Some(w), Some(n)) => n == w,
                                    _ => false,
                                }
                            });
                            if !affects_target {
                                continue;
                            }
                        }

                        thread::sleep(Duration::from_millis(50));
                        let mut reloaded = false;
                        let mut last_error = String::new();
                        for _ in 0..6 {
                            // P1: Verify signature before loading
                            let sig_ok = if let Some(ref pk) = pubkey {
                                verify_rules_signature(&path, pk).is_ok()
                            } else {
                                true // No pubkey configured, dev mode
                            };

                            if !sig_ok {
                                error!(
                                    "Rules signature verification failed - keeping previous policy"
                                );
                                break;
                            }

                            match PolicyFile::from_file(&path) {
                                Ok(pf) => {
                                    info!(
                                        "policy reloaded from {path:?} ({} rules)",
                                        pf.rules.len()
                                    );
                                    handle.store(pf);
                                    reloaded = true;
                                    break;
                                }
                                Err(e) => {
                                    last_error = e.to_string();
                                    thread::sleep(Duration::from_millis(40));
                                }
                            }
                        }
                        if !reloaded && !last_error.is_empty() {
                            warn!("policy reload failed: {last_error}");
                        }
                    }
                    Err(e) => error!("watcher error: {e}"),
                }
            }
        })
        .expect("failed to spawn policy-watcher thread");
}

// ─── Public entry point ───────────────────────────────────────────────────────

/// Load `path` immediately, then watch it for changes.
///
/// Returns a [`PolicyHandle`] that always reflects the latest valid policy.
/// If reloading fails, the previous policy is kept.
pub fn watch_policy(path: impl AsRef<Path>) -> Result<PolicyHandle, Box<dyn std::error::Error>> {
    let path = path.as_ref().to_path_buf();

    // P1: Load admin public key for signature verification
    let pubkey = load_admin_pubkey().ok();
    if pubkey.is_none() {
        warn!("No admin public key configured - rules signature verification disabled");
    }

    // Verify initial signature
    if let Some(ref pk) = pubkey {
        verify_rules_signature(&path, pk)?;
    }

    let initial = PolicyFile::from_file(&path)?;
    let handle = PolicyHandle::new(initial);
    spawn_watcher(path, handle.clone(), pubkey);
    Ok(handle)
}

// ─── Extension on PolicyFile ─────────────────────────────────────────────────

impl PolicyFile {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let text = std::fs::read_to_string(path.as_ref())?;
        Ok(PolicyFile::from_yaml(&text)?)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, thread::sleep, time::Instant};
    use tempfile::NamedTempFile;

    const POLICY_V1: &str = r#"
version: "1.0.0"
rules:
  - id: "r1"
    priority: safety
    description: "deny large"
    condition:
      field: amount
      op: gt
      value: 1000.0
    action: deny
    message: "too large"
"#;

    const POLICY_V2: &str = r#"
version: "2.0.0"
rules:
  - id: "r1"
    priority: safety
    description: "deny large updated"
    condition:
      field: amount
      op: gt
      value: 2000.0
    action: deny
    message: "still too large"
  - id: "r2"
    priority: compliance
    description: "flag anomaly"
    condition:
      field: is_anomaly
      op: eq
      value: true
    action: flag
    message: "anomaly flagged"
"#;

    #[test]
    fn initial_load() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(POLICY_V1.as_bytes()).unwrap();
        f.flush().unwrap();

        let handle = watch_policy(f.path()).unwrap();
        let pf = handle.load();
        assert_eq!(pf.version, "1.0.0");
        assert_eq!(pf.rules.len(), 1);
    }

    fn write_policy(path: &Path, text: &str) {
        let mut fh = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .unwrap();
        fh.write_all(text.as_bytes()).unwrap();
        fh.flush().unwrap();
        fh.sync_all().unwrap();
    }

    fn wait_for_version(
        handle: &PolicyHandle,
        path: &Path,
        target: &str,
        timeout: Duration,
    ) -> PolicyFile {
        let start = Instant::now();
        let mut next_nudge = start + Duration::from_millis(250);
        loop {
            let pf = handle.load();
            if pf.version == target {
                return pf;
            }
            let now = Instant::now();
            if now >= start + timeout {
                return pf;
            }
            if now >= next_nudge {
                write_policy(path, POLICY_V2);
                next_nudge += Duration::from_millis(250);
            }
            sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn reload_on_change() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(POLICY_V1.as_bytes()).unwrap();
        f.flush().unwrap();

        let handle = watch_policy(f.path()).unwrap();
        // Allow watcher thread to register with the OS before writing.
        sleep(Duration::from_millis(200));
        assert_eq!(handle.load().version, "1.0.0");

        write_policy(f.path(), POLICY_V2);

        let pf = wait_for_version(&handle, f.path(), "2.0.0", Duration::from_millis(3000));
        assert_eq!(
            pf.version, "2.0.0",
            "hot-reload should have updated policy to v2"
        );
        assert_eq!(pf.rules.len(), 2);
    }

    #[test]
    fn policy_store_versioning_and_rollback() {
        let v1 = PolicyFile::from_yaml(POLICY_V1).unwrap();
        let v2 = PolicyFile::from_yaml(POLICY_V2).unwrap();

        let store = PolicyStore::new(v1.clone(), 10);
        assert_eq!(store.load().version, "1.0.0");
        assert_eq!(store.versions().len(), 1);
        let gen_v1 = store.generation();

        // Push v2
        store.push(v2.clone()).unwrap();
        assert_eq!(store.load().version, "2.0.0");
        assert_eq!(store.versions().len(), 2);

        // Rollback to gen_v1 (v1)
        assert!(store.rollback(gen_v1));
        assert_eq!(store.load().version, "1.0.0");

        // Rollback to non-existent generation fails
        assert!(!store.rollback(999));
    }

    #[test]
    fn policy_store_rollback_previous() {
        let v1 = PolicyFile::from_yaml(POLICY_V1).unwrap();
        let v2 = PolicyFile::from_yaml(POLICY_V2).unwrap();

        let store = PolicyStore::new(v1.clone(), 10);
        store.push(v2.clone()).unwrap();
        assert_eq!(store.load().version, "2.0.0");

        // Rollback to previous (v1)
        assert!(store.rollback_previous());
        assert_eq!(store.load().version, "1.0.0");

        // No more previous to rollback to (only one entry before current gen)
        // rollback_previous from gen 0 should fail
    }

    #[test]
    fn policy_store_trims_history() {
        let v1 = PolicyFile::from_yaml(POLICY_V1).unwrap();
        let store = PolicyStore::new(v1.clone(), 3);

        // Push 5 versions — should only keep last 3
        for i in 2..=6u32 {
            let mut pf = v1.clone();
            pf.version = format!("{i}.0.0");
            store.push(pf).unwrap();
        }

        let versions = store.versions();
        assert_eq!(versions.len(), 3);
        // Oldest kept should be version "4.0.0" (trimmed 1.0.0, 2.0.0, 3.0.0)
        assert_eq!(versions[0].1, "4.0.0");
    }

    #[test]
    fn policy_store_semver_validation_rejects_bare_integer() {
        let mut pf = PolicyFile::from_yaml(POLICY_V1).unwrap();
        pf.version = "42".to_string(); // not semver
        let store = PolicyStore::new(PolicyFile::from_yaml(POLICY_V1).unwrap(), 10);
        assert!(
            store.push(pf).is_err(),
            "bare integer must fail semver validation"
        );
    }

    #[test]
    fn policy_store_promote_enforces_ordered_tiers() {
        let v1 = PolicyFile::from_yaml(POLICY_V1).unwrap();
        let v2 = PolicyFile::from_yaml(POLICY_V2).unwrap();
        let store = PolicyStore::new(v1.clone(), 10);
        store.push(v2.clone()).unwrap();

        // Dev → Staging: OK
        assert!(
            store
                .promote(PolicyEnvironment::Dev, PolicyEnvironment::Staging)
                .is_ok()
        );
        // Staging → Prod: OK
        assert!(
            store
                .promote(PolicyEnvironment::Staging, PolicyEnvironment::Prod)
                .is_ok()
        );
        // Dev → Prod (skip): must fail
        assert!(
            store
                .promote(PolicyEnvironment::Dev, PolicyEnvironment::Prod)
                .is_err()
        );
    }
}
