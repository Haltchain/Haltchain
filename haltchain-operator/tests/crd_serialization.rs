//! Tests for CRD serialization and deserialization.

mod test_utils;

use test_utils::*;

// ── PolicySet serialization ─────────────────────────────────────────

#[test]
fn policy_set_serializes_to_yaml() {
    let spec = sample_policy_spec_inline();
    let ps = sample_policy_set("test-policy", spec);
    let yaml = to_yaml(&ps);

    assert!(yaml.contains("kind: PolicySet"));
    assert!(yaml.contains("haltchain.io/v1alpha1"));
    assert!(yaml.contains("version: 1.0.0"));
    assert!(yaml.contains("enforcing"));
    assert!(yaml.contains("block-malicious"));
}

#[test]
fn policy_set_deserializes_from_yaml() {
    let spec = sample_policy_spec_inline();
    let ps = sample_policy_set("test-policy", spec);
    let yaml = to_yaml(&ps);

    let roundtrip: PolicySet = from_yaml(&yaml);
    assert_eq!(roundtrip.metadata.name, Some("test-policy".to_string()));
    assert_eq!(roundtrip.spec.version, "1.0.0");
    assert!(roundtrip.spec.rules.is_some());
}

#[test]
fn policy_set_configmap_ref_serializes() {
    let spec = sample_policy_spec_configmap();
    let ps = sample_policy_set("cm-policy", spec);
    let yaml = to_yaml(&ps);

    assert!(yaml.contains("configMapRef"));
    assert!(yaml.contains("my-rules-cm"));
}

#[test]
fn policy_set_configmap_ref_deserializes() {
    let yaml = r#"
apiVersion: haltchain.io/v1alpha1
kind: PolicySet
metadata:
  name: cm-policy
  namespace: test-ns
spec:
  version: "2.0.0"
  configMapRef:
    name: rules-config
    namespace: config-ns
"#;

    let ps: PolicySet = serde_yaml::from_str(yaml).expect("should deserialize");
    assert_eq!(ps.spec.version, "2.0.0");
    let cmr = ps.spec.config_map_ref.expect("configMapRef should exist");
    assert_eq!(cmr.name, "rules-config");
    assert_eq!(cmr.namespace, Some("config-ns".to_string()));
}

#[test]
fn policy_set_status_round_trip() {
    let status = sample_policy_status("Active");
    let yaml = to_yaml(&status);
    let roundtrip: PolicySetStatus = from_yaml(&yaml);

    assert_eq!(roundtrip.phase, Some("Active".to_string()));
    assert_eq!(roundtrip.active_sidecars, Some(3));
    assert_eq!(roundtrip.last_reloaded_at, Some(1_700_000_000));
}

#[test]
fn policy_set_default_enforcement_mode() {
    let yaml = r#"
apiVersion: haltchain.io/v1alpha1
kind: PolicySet
metadata:
  name: test
  namespace: test-ns
spec:
  version: "1.0.0"
"#;

    let ps: PolicySet = serde_yaml::from_str(yaml).expect("should deserialize");
    assert_eq!(ps.spec.enforcement_mode, "enforcing");
}

#[test]
fn policy_set_target_labels_serializes() {
    let spec = sample_policy_spec_inline();
    let yaml = to_yaml(&spec);

    assert!(yaml.contains("app"));
    assert!(yaml.contains("my-agent"));
}

// ── AgentProfile serialization ──────────────────────────────────────

#[test]
fn agent_profile_serializes_to_yaml() {
    let spec = sample_agent_profile_spec();
    let ap = sample_agent_profile("test-profile", spec);
    let yaml = to_yaml(&ap);

    assert!(yaml.contains("kind: AgentProfile"));
    assert!(yaml.contains("policySetRef: my-policy-set"));
    assert!(yaml.contains("sidecar_image"));
    assert!(yaml.contains("v1.2.3"));
    assert!(yaml.contains("9090"));
}

#[test]
fn agent_profile_deserializes_from_yaml() {
    let yaml = r#"
apiVersion: haltchain.io/v1alpha1
kind: AgentProfile
metadata:
  name: test-profile
  namespace: test-ns
spec:
  policySetRef: my-policy
  sidecarImage: ghcr.io/haltchain/sidecar:v1.0.0
  sidecarPort: 9090
  sqlitePersistence: true
  extraEnv:
    - name: LOG_LEVEL
      value: info
"#;

    let ap: AgentProfile = serde_yaml::from_str(yaml).expect("should deserialize");
    assert_eq!(ap.spec.policy_set_ref, "my-policy");
    assert_eq!(ap.spec.sidecar_image, Some("ghcr.io/haltchain/sidecar:v1.0.0".to_string()));
    assert_eq!(ap.spec.sidecar_port, 9090);
    assert!(ap.spec.sqlite_persistence);
    assert_eq!(ap.spec.extra_env.len(), 1);
    assert_eq!(ap.spec.extra_env[0].name, "LOG_LEVEL");
}

#[test]
fn agent_profile_resources_serializes() {
    let spec = sample_agent_profile_spec();
    let yaml = to_yaml(&spec);

    assert!(yaml.contains("cpu_limit"));
    assert!(yaml.contains("500m"));
    assert!(yaml.contains("memory_limit"));
    assert!(yaml.contains("256Mi"));
}

#[test]
fn agent_profile_status_round_trip() {
    let status = sample_agent_profile_status("Active");
    let yaml = to_yaml(&status);
    let roundtrip: AgentProfileStatus = from_yaml(&yaml);

    assert_eq!(roundtrip.phase, Some("Active".to_string()));
    assert_eq!(roundtrip.managed_pods, Some(5));
}

#[test]
fn agent_profile_default_port() {
    let yaml = r#"
apiVersion: haltchain.io/v1alpha1
kind: AgentProfile
metadata:
  name: test
  namespace: test-ns
spec:
  policySetRef: default
"#;

    let ap: AgentProfile = serde_yaml::from_str(yaml).expect("should deserialize");
    assert_eq!(ap.spec.sidecar_port, 8080);
}

// ── AuditSink serialization ─────────────────────────────────────────

#[test]
fn audit_sink_webhook_serializes() {
    let spec = sample_audit_sink_webhook();
    let asink = sample_audit_sink("webhook-sink", spec);
    let yaml = to_yaml(&asink);

    assert!(yaml.contains("kind: AuditSink"));
    assert!(yaml.contains("sink_type: webhook"));
    assert!(yaml.contains("https://audit.example.com/events"));
    assert!(yaml.contains("webhook-token-secret"));
}

#[test]
fn audit_sink_webhook_deserializes() {
    let yaml = r#"
apiVersion: haltchain.io/v1alpha1
kind: AuditSink
metadata:
  name: webhook-sink
  namespace: test-ns
spec:
  sink_type: webhook
  webhook:
    url: https://events.example.com/audit
    secretRef: my-secret
    timeoutSecs: 15
  minSeverity: CIRCUIT_BREAK
  bufferSize: 100
"#;

    let asink: AuditSink = serde_yaml::from_str(yaml).expect("should deserialize");
    assert_eq!(asink.spec.sink_type, "webhook");
    let webhook = asink.spec.webhook.expect("webhook config should exist");
    assert_eq!(webhook.url, "https://events.example.com/audit");
    assert_eq!(webhook.secret_ref, Some("my-secret".to_string()));
    assert_eq!(webhook.timeout_secs, 15);
    assert_eq!(asink.spec.min_severity, Some("CIRCUIT_BREAK".to_string()));
    assert_eq!(asink.spec.buffer_size, 100);
}

#[test]
fn audit_sink_kafka_serializes() {
    let spec = sample_audit_sink_kafka();
    let yaml = to_yaml(&spec);

    assert!(yaml.contains("sink_type: kafka"));
    assert!(yaml.contains("kafka:9092"));
    assert!(yaml.contains("haltchain-audit"));
}

#[test]
fn audit_sink_kafka_deserializes() {
    let yaml = r#"
apiVersion: haltchain.io/v1alpha1
kind: AuditSink
metadata:
  name: kafka-sink
  namespace: test-ns
spec:
  sink_type: kafka
  kafka:
    bootstrapServers: broker1:9092,broker2:9092
    topic: audit-events
    saslSecretRef: kafka-creds
"#;

    let asink: AuditSink = serde_yaml::from_str(yaml).expect("should deserialize");
    assert_eq!(asink.spec.sink_type, "kafka");
    let kafka = asink.spec.kafka.expect("kafka config should exist");
    assert_eq!(kafka.bootstrap_servers, "broker1:9092,broker2:9092");
    assert_eq!(kafka.topic, "audit-events");
    assert_eq!(kafka.sasl_secret_ref, Some("kafka-creds".to_string()));
}

#[test]
fn audit_sink_stdout_serializes() {
    let spec = sample_audit_sink_stdout();
    let yaml = to_yaml(&spec);

    assert!(yaml.contains("sink_type: stdout"));
}

#[test]
fn audit_sink_stdout_deserializes() {
    let yaml = r#"
apiVersion: haltchain.io/v1alpha1
kind: AuditSink
metadata:
  name: stdout-sink
  namespace: test-ns
spec:
  sink_type: stdout
"#;

    let asink: AuditSink = serde_yaml::from_str(yaml).expect("should deserialize");
    assert_eq!(asink.spec.sink_type, "stdout");
    assert!(asink.spec.webhook.is_none());
    assert!(asink.spec.kafka.is_none());
}

#[test]
fn audit_sink_status_round_trip() {
    let status = sample_audit_sink_status("Active");
    let yaml = to_yaml(&status);
    let roundtrip: AuditSinkStatus = from_yaml(&yaml);

    assert_eq!(roundtrip.phase, Some("Active".to_string()));
    assert_eq!(roundtrip.events_emitted, Some(42));
}

#[test]
fn audit_sink_default_buffer_size() {
    let yaml = r#"
apiVersion: haltchain.io/v1alpha1
kind: AuditSink
metadata:
  name: test
  namespace: test-ns
spec:
  sink_type: stdout
"#;

    let asink: AuditSink = serde_yaml::from_str(yaml).expect("should deserialize");
    assert_eq!(asink.spec.buffer_size, 1000);
}

#[test]
fn audit_sink_default_webhook_timeout() {
    let yaml = r#"
apiVersion: haltchain.io/v1alpha1
kind: AuditSink
metadata:
  name: test
  namespace: test-ns
spec:
  sink_type: webhook
  webhook:
    url: https://example.com/audit
"#;

    let asink: AuditSink = serde_yaml::from_str(yaml).expect("should deserialize");
    let webhook = asink.spec.webhook.expect("webhook config should exist");
    assert_eq!(webhook.timeout_secs, 5);
}

// ── Validation tests ────────────────────────────────────────────────

#[test]
fn policy_set_requires_version() {
    let yaml = r#"
apiVersion: haltchain.io/v1alpha1
kind: PolicySet
metadata:
  name: test
  namespace: test-ns
spec: {}
"#;

    let result: Result<PolicySet, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err(), "version should be required");
}

#[test]
fn agent_profile_requires_policy_set_ref() {
    let yaml = r#"
apiVersion: haltchain.io/v1alpha1
kind: AgentProfile
metadata:
  name: test
  namespace: test-ns
spec: {}
"#;

    let result: Result<AgentProfile, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err(), "policySetRef should be required");
}

#[test]
fn audit_sink_requires_sink_type() {
    let yaml = r#"
apiVersion: haltchain.io/v1alpha1
kind: AuditSink
metadata:
  name: test
  namespace: test-ns
spec: {}
"#;

    let result: Result<AuditSink, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err(), "sink_type should be required");
}

#[test]
fn policy_set_enforcement_mode_enum_values() {
    for mode in &["enforcing", "permissive", "shadow"] {
        let yaml = format!(
            r#"
apiVersion: haltchain.io/v1alpha1
kind: PolicySet
metadata:
  name: test
  namespace: test-ns
spec:
  version: "1.0.0"
  enforcementMode: {}
"#,
            mode
        );

        let ps: PolicySet = serde_yaml::from_str(&yaml).expect(&format!("mode {} should parse", mode));
        assert_eq!(ps.spec.enforcement_mode, *mode);
    }
}

#[test]
fn audit_sink_type_enum_values() {
    for sink_type in &["webhook", "kafka", "stdout"] {
        let yaml = format!(
            r#"
apiVersion: haltchain.io/v1alpha1
kind: AuditSink
metadata:
  name: test
  namespace: test-ns
spec:
  sink_type: {}
"#,
            sink_type
        );

        let asink: AuditSink = serde_yaml::from_str(&yaml).expect(&format!("sink_type {} should parse", sink_type));
        assert_eq!(asink.spec.sink_type, *sink_type);
    }
}

#[test]
fn policy_set_json_round_trip() {
    let spec = sample_policy_spec_inline();
    let ps = sample_policy_set("json-test", spec);
    let json = serde_json::to_string(&ps).expect("should serialize to JSON");

    let roundtrip: PolicySet = serde_json::from_str(&json).expect("should deserialize from JSON");
    assert_eq!(roundtrip.metadata.name, ps.metadata.name);
    assert_eq!(roundtrip.spec.version, ps.spec.version);
}

#[test]
fn agent_profile_json_round_trip() {
    let spec = sample_agent_profile_spec();
    let ap = sample_agent_profile("json-test", spec);
    let json = serde_json::to_string(&ap).expect("should serialize to JSON");

    let roundtrip: AgentProfile = serde_json::from_str(&json).expect("should deserialize from JSON");
    assert_eq!(roundtrip.spec.policy_set_ref, ap.spec.policy_set_ref);
}

#[test]
fn audit_sink_json_round_trip() {
    let spec = sample_audit_sink_kafka();
    let asink = sample_audit_sink("json-test", spec);
    let json = serde_json::to_string(&asink).expect("should serialize to JSON");

    let roundtrip: AuditSink = serde_json::from_str(&json).expect("should deserialize from JSON");
    assert_eq!(roundtrip.spec.sink_type, asink.spec.sink_type);
}
