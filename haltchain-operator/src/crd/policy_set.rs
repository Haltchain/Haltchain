use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// PolicySet CRD — a versioned bundle of HaltChain enforcement rules.
///
/// When a PolicySet is created or updated the operator hot-reloads the
/// rule pack into every HaltChain sidecar whose AgentProfile references
/// this PolicySet via `policySetRef`.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "haltchain.io",
    version = "v1alpha1",
    kind = "PolicySet",
    namespaced,
    status = "PolicySetStatus",
    shortname = "pset",
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Version","type":"string","jsonPath":".spec.version"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
pub struct PolicySetSpec {
    /// Semantic version of this rule pack (e.g. "1.2.0").
    pub version: String,

    /// Enforcement mode: "enforcing", "permissive", or "shadow".
    #[serde(default = "default_enforcement_mode")]
    pub enforcement_mode: String,

    /// Inline YAML rule-pack content.
    /// Mutually exclusive with `configMapRef`.
    pub rules: Option<String>,

    /// Reference to a ConfigMap holding the rule pack YAML under key "rules.yaml".
    /// Mutually exclusive with `rules`.
    #[serde(rename = "configMapRef")]
    pub config_map_ref: Option<ConfigMapRef>,

    /// Labels to select which pods should receive this policy.
    #[serde(default)]
    pub target_labels: HashMap<String, String>,
}

fn default_enforcement_mode() -> String {
    "enforcing".to_string()
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct ConfigMapRef {
    pub name: String,
    pub namespace: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct PolicySetStatus {
    /// "Pending", "Active", "Failed"
    pub phase: Option<String>,
    /// Human-readable message.
    pub message: Option<String>,
    /// Unix timestamp of the last successful reload.
    pub last_reloaded_at: Option<i64>,
    /// Number of sidecars currently running this policy.
    pub active_sidecars: Option<i32>,
}
