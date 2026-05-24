//! Shared test utilities and mock data generators for integration tests.

use std::collections::HashMap;

pub use haltchain_operator::crd::agent_profile::{
    AgentProfile, AgentProfileSpec, AgentProfileStatus, EnvVar, SidecarResources,
};
pub use haltchain_operator::crd::audit_sink::{
    AuditSink, AuditSinkSpec, AuditSinkStatus, KafkaSinkConfig, WebhookSinkConfig,
};
pub use haltchain_operator::crd::policy_set::{ConfigMapRef, PolicySet, PolicySetSpec, PolicySetStatus};

pub const TEST_NAMESPACE: &str = "test-ns";

// ── PolicySet fixtures ──────────────────────────────────────────────

pub fn sample_policy_spec_inline() -> PolicySetSpec {
    PolicySetSpec {
        version: "1.0.0".to_string(),
        enforcement_mode: "enforcing".to_string(),
        rules: Some(
            r#"
rules:
  - name: block-malicious
    action: deny
    conditions:
      - field: request.method
        operator: in
        values: [DELETE]
"#
            .to_string(),
        ),
        config_map_ref: None,
        target_labels: HashMap::from([("app".to_string(), "my-agent".to_string())]),
    }
}

pub fn sample_policy_spec_configmap() -> PolicySetSpec {
    PolicySetSpec {
        version: "2.0.0".to_string(),
        enforcement_mode: "permissive".to_string(),
        rules: None,
        config_map_ref: Some(ConfigMapRef {
            name: "my-rules-cm".to_string(),
            namespace: Some(TEST_NAMESPACE.to_string()),
        }),
        target_labels: HashMap::new(),
    }
}

pub fn sample_policy_spec_empty() -> PolicySetSpec {
    PolicySetSpec {
        version: "0.0.1".to_string(),
        enforcement_mode: "shadow".to_string(),
        rules: None,
        config_map_ref: None,
        target_labels: HashMap::new(),
    }
}

pub fn sample_policy_set(name: &str, spec: PolicySetSpec) -> PolicySet {
    PolicySet {
        metadata: kube::api::ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(TEST_NAMESPACE.to_string()),
            ..Default::default()
        },
        spec,
        status: None,
    }
}

pub fn sample_policy_status(phase: &str) -> PolicySetStatus {
    PolicySetStatus {
        phase: Some(phase.to_string()),
        message: Some("test message".to_string()),
        last_reloaded_at: Some(1_700_000_000),
        active_sidecars: Some(3),
    }
}

// ── AgentProfile fixtures ───────────────────────────────────────────

pub fn sample_agent_profile_spec() -> AgentProfileSpec {
    AgentProfileSpec {
        policy_set_ref: "my-policy-set".to_string(),
        sidecar_image: Some("ghcr.io/haltchain/sidecar:v1.2.3".to_string()),
        sidecar_port: 9090,
        resources: Some(SidecarResources {
            cpu_limit: Some("500m".to_string()),
            memory_limit: Some("256Mi".to_string()),
            cpu_request: Some("100m".to_string()),
            memory_request: Some("128Mi".to_string()),
        }),
        sqlite_persistence: true,
        extra_env: vec![EnvVar {
            name: "HALTCHAIN_LOG_LEVEL".to_string(),
            value: "debug".to_string(),
        }],
    }
}

pub fn sample_agent_profile_spec_defaults() -> AgentProfileSpec {
    AgentProfileSpec {
        policy_set_ref: "default-policy".to_string(),
        sidecar_image: None,
        sidecar_port: 8080,
        resources: None,
        sqlite_persistence: false,
        extra_env: vec![],
    }
}

pub fn sample_agent_profile(name: &str, spec: AgentProfileSpec) -> AgentProfile {
    AgentProfile {
        metadata: kube::api::ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(TEST_NAMESPACE.to_string()),
            ..Default::default()
        },
        spec,
        status: None,
    }
}

pub fn sample_agent_profile_status(phase: &str) -> AgentProfileStatus {
    AgentProfileStatus {
        phase: Some(phase.to_string()),
        message: Some("test message".to_string()),
        managed_pods: Some(5),
    }
}

// ── AuditSink fixtures ──────────────────────────────────────────────

pub fn sample_audit_sink_webhook() -> AuditSinkSpec {
    AuditSinkSpec {
        sink_type: "webhook".to_string(),
        webhook: Some(WebhookSinkConfig {
            url: "https://audit.example.com/events".to_string(),
            secret_ref: Some("webhook-token-secret".to_string()),
            timeout_secs: 10,
        }),
        kafka: None,
        min_severity: Some("DENY".to_string()),
        buffer_size: 500,
    }
}

pub fn sample_audit_sink_kafka() -> AuditSinkSpec {
    AuditSinkSpec {
        sink_type: "kafka".to_string(),
        webhook: None,
        kafka: Some(KafkaSinkConfig {
            bootstrap_servers: "kafka:9092".to_string(),
            topic: "haltchain-audit".to_string(),
            sasl_secret_ref: Some("kafka-sasl-secret".to_string()),
        }),
        min_severity: Some("ALLOW".to_string()),
        buffer_size: 2000,
    }
}

pub fn sample_audit_sink_stdout() -> AuditSinkSpec {
    AuditSinkSpec {
        sink_type: "stdout".to_string(),
        webhook: None,
        kafka: None,
        min_severity: None,
        buffer_size: 0,
    }
}

pub fn sample_audit_sink(name: &str, spec: AuditSinkSpec) -> AuditSink {
    AuditSink {
        metadata: kube::api::ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(TEST_NAMESPACE.to_string()),
            ..Default::default()
        },
        spec,
        status: None,
    }
}

pub fn sample_audit_sink_status(phase: &str) -> AuditSinkStatus {
    AuditSinkStatus {
        phase: Some(phase.to_string()),
        message: Some("test message".to_string()),
        events_emitted: Some(42),
        last_event_at: Some(1_700_000_000),
    }
}

// ── YAML helpers ────────────────────────────────────────────────────

pub fn to_yaml<T: serde::Serialize>(obj: &T) -> String {
    serde_yaml::to_string(obj).expect("failed to serialize to YAML")
}

pub fn from_yaml<T: serde::de::DeserializeOwned>(yaml: &str) -> T {
    serde_yaml::from_str(yaml).expect("failed to deserialize from YAML")
}
