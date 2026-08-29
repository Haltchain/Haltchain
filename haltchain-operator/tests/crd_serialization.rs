use haltchain_operator::crd::{
    agent_profile::AgentProfile, audit_sink::AuditSink, policy_set::PolicySet,
};
use kube::{Resource, ResourceExt};

#[test]
fn policy_set_round_trips_through_yaml() {
    let yaml = r#"
apiVersion: haltchain.io/v1alpha1
kind: PolicySet
metadata:
  name: default-rules
  namespace: production
spec:
  version: "1.2.0"
  enforcement_mode: enforcing
  rules: |
    rules:
      - id: block_pii
        condition:
          field: content
          op: Regex
          value: "\\d{3}-\\d{2}-\\d{4}"
        action: Deny
"#;
    let ps: PolicySet = serde_yaml::from_str(yaml).expect("parse PolicySet");
    assert_eq!(ps.name_any(), "default-rules");
    assert_eq!(ps.spec.version, "1.2.0");
    assert_eq!(ps.spec.enforcement_mode, "enforcing");
    assert!(ps.spec.rules.is_some());
}

#[test]
fn policy_set_default_enforcement_mode() {
    let yaml = r#"
apiVersion: haltchain.io/v1alpha1
kind: PolicySet
metadata:
  name: default
spec:
  version: "1.0.0"
"#;
    let ps: PolicySet = serde_yaml::from_str(yaml).expect("parse PolicySet");
    assert_eq!(ps.spec.enforcement_mode, "enforcing");
}

#[test]
fn agent_profile_round_trips_through_yaml() {
    let yaml = r#"
apiVersion: haltchain.io/v1alpha1
kind: AgentProfile
metadata:
  name: support-agent
  namespace: production
spec:
  policySetRef: default-rules
  sidecar_image: ghcr.io/haltchain/sidecar:v0.4.0
  sidecar_port: 8080
  sqlite_persistence: true
  resources:
    cpu_limit: "500m"
    memory_limit: "128Mi"
    cpu_request: "100m"
    memory_request: "64Mi"
  extra_env:
    - name: RUST_LOG
      value: info
"#;
    let ap: AgentProfile = serde_yaml::from_str(yaml).expect("parse AgentProfile");
    assert_eq!(ap.name_any(), "support-agent");
    assert_eq!(ap.spec.policy_set_ref, "default-rules");
    assert_eq!(ap.spec.sidecar_port, 8080);
    assert!(ap.spec.sqlite_persistence);
    assert!(ap.spec.resources.is_some());
    assert_eq!(ap.spec.extra_env.len(), 1);
}

#[test]
fn audit_sink_round_trips_through_yaml() {
    let yaml = r#"
apiVersion: haltchain.io/v1alpha1
kind: AuditSink
metadata:
  name: siem
  namespace: production
spec:
  sink_type: webhook
  webhook:
    url: https://siem.example.com/events
    secret_ref: siem-token
    timeout_secs: 10
  min_severity: DENY
  buffer_size: 5000
"#;
    let sink: AuditSink = serde_yaml::from_str(yaml).expect("parse AuditSink");
    assert_eq!(sink.name_any(), "siem");
    assert_eq!(sink.spec.sink_type, "webhook");
    assert_eq!(sink.spec.buffer_size, 5000);
    let webhook = sink.spec.webhook.expect("webhook config");
    assert_eq!(webhook.url, "https://siem.example.com/events");
    assert_eq!(webhook.timeout_secs, 10);
}

#[test]
fn audit_sink_default_buffer_size() {
    let yaml = r#"
apiVersion: haltchain.io/v1alpha1
kind: AuditSink
metadata:
  name: stdout
spec:
  sink_type: stdout
"#;
    let sink: AuditSink = serde_yaml::from_str(yaml).expect("parse AuditSink");
    assert_eq!(sink.spec.buffer_size, 1000);
}

#[test]
fn crds_have_expected_group_and_version() {
    assert_eq!(PolicySet::group(&()), "haltchain.io");
    assert_eq!(PolicySet::version(&()), "v1alpha1");
    assert_eq!(AgentProfile::group(&()), "haltchain.io");
    assert_eq!(AgentProfile::version(&()), "v1alpha1");
    assert_eq!(AuditSink::group(&()), "haltchain.io");
    assert_eq!(AuditSink::version(&()), "v1alpha1");
}
