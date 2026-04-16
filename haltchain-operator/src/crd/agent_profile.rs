use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// AgentProfile CRD — declares a managed AI agent and its safety requirements.
///
/// The operator watches pods labelled with `haltchain.io/agent-profile: <name>`
/// and injects a HaltChain sidecar container if one is not already present.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "haltchain.io",
    version = "v1alpha1",
    kind = "AgentProfile",
    namespaced,
    status = "AgentProfileStatus",
    shortname = "apf",
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"PolicySet","type":"string","jsonPath":".spec.policySetRef"}"#
)]
pub struct AgentProfileSpec {
    /// Name of the PolicySet to enforce for this agent.
    #[serde(rename = "policySetRef")]
    pub policy_set_ref: String,

    /// Docker image for the HaltChain sidecar.
    /// Defaults to "ghcr.io/haltchain/sidecar:latest".
    pub sidecar_image: Option<String>,

    /// Port the sidecar listens on inside the pod.
    #[serde(default = "default_sidecar_port")]
    pub sidecar_port: u16,

    /// Resource limits for the sidecar container.
    pub resources: Option<SidecarResources>,

    /// Whether to enable SQLite persistence in the sidecar (standalone mode).
    #[serde(default)]
    pub sqlite_persistence: bool,

    /// Extra environment variables passed to the sidecar.
    #[serde(default)]
    pub extra_env: Vec<EnvVar>,
}

fn default_sidecar_port() -> u16 {
    8080
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct SidecarResources {
    pub cpu_limit: Option<String>,
    pub memory_limit: Option<String>,
    pub cpu_request: Option<String>,
    pub memory_request: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct AgentProfileStatus {
    /// "Pending", "Active", "Degraded"
    pub phase: Option<String>,
    pub message: Option<String>,
    /// Number of pods currently managed by this profile.
    pub managed_pods: Option<i32>,
}
