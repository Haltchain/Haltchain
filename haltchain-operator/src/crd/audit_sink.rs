use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// AuditSink CRD — configures where HaltChain writes audit events.
///
/// Supported sinks: HTTP webhook, Kafka, and stdout (default).
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "haltchain.io",
    version = "v1alpha1",
    kind = "AuditSink",
    namespaced,
    status = "AuditSinkStatus",
    shortname = "asink",
    printcolumn = r#"{"name":"Type","type":"string","jsonPath":".spec.sink_type"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#
)]
pub struct AuditSinkSpec {
    /// Sink type: "webhook", "kafka", or "stdout".
    pub sink_type: String,

    /// Webhook config — used when sink_type = "webhook".
    pub webhook: Option<WebhookSinkConfig>,

    /// Kafka config — used when sink_type = "kafka".
    pub kafka: Option<KafkaSinkConfig>,

    /// Minimum decision severity to emit ("ALLOW", "DENY", "CIRCUIT_BREAK").
    /// Default: emit all.
    pub min_severity: Option<String>,

    /// Maximum number of events to buffer before dropping (backpressure).
    #[serde(default = "default_buffer")]
    pub buffer_size: u32,
}

fn default_buffer() -> u32 {
    1000
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct WebhookSinkConfig {
    /// HTTPS endpoint to POST audit events to.
    pub url: String,
    /// Name of a Secret containing a "token" key for Bearer auth.
    pub secret_ref: Option<String>,
    /// Timeout in seconds. Default: 5.
    #[serde(default = "default_webhook_timeout")]
    pub timeout_secs: u32,
}

fn default_webhook_timeout() -> u32 {
    5
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct KafkaSinkConfig {
    /// Bootstrap servers, e.g. "kafka:9092".
    pub bootstrap_servers: String,
    /// Topic name.
    pub topic: String,
    /// SASL username secret ref.
    pub sasl_secret_ref: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct AuditSinkStatus {
    pub phase: Option<String>,
    pub message: Option<String>,
    pub events_emitted: Option<i64>,
    pub last_event_at: Option<i64>,
}
