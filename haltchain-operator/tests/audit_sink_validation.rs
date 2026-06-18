use haltchain_operator::controllers::audit_sink::validate_sink;
use haltchain_operator::crd::audit_sink::{AuditSinkSpec, KafkaSinkConfig, WebhookSinkConfig};

fn webhook_spec() -> AuditSinkSpec {
    AuditSinkSpec {
        sink_type: "webhook".to_string(),
        webhook: Some(WebhookSinkConfig {
            url: "https://example.com".to_string(),
            secret_ref: None,
            timeout_secs: 5,
        }),
        kafka: None,
        min_severity: None,
        buffer_size: 1000,
    }
}

fn kafka_spec() -> AuditSinkSpec {
    AuditSinkSpec {
        sink_type: "kafka".to_string(),
        webhook: None,
        kafka: Some(KafkaSinkConfig {
            bootstrap_servers: "kafka:9092".to_string(),
            topic: "audit".to_string(),
            sasl_secret_ref: None,
        }),
        min_severity: None,
        buffer_size: 1000,
    }
}

fn stdout_spec() -> AuditSinkSpec {
    AuditSinkSpec {
        sink_type: "stdout".to_string(),
        webhook: None,
        kafka: None,
        min_severity: None,
        buffer_size: 1000,
    }
}

#[test]
fn valid_webhook_passes() {
    assert!(validate_sink(&webhook_spec()).is_none());
}

#[test]
fn valid_kafka_passes() {
    assert!(validate_sink(&kafka_spec()).is_none());
}

#[test]
fn valid_stdout_passes() {
    assert!(validate_sink(&stdout_spec()).is_none());
}

#[test]
fn webhook_without_config_fails() {
    let mut spec = webhook_spec();
    spec.webhook = None;
    let err = validate_sink(&spec).expect("expected error");
    assert!(err.contains("webhook config required"));
}

#[test]
fn kafka_without_config_fails() {
    let mut spec = kafka_spec();
    spec.kafka = None;
    let err = validate_sink(&spec).expect("expected error");
    assert!(err.contains("kafka config required"));
}

#[test]
fn unknown_sink_type_fails() {
    let mut spec = stdout_spec();
    spec.sink_type = "s3".to_string();
    let err = validate_sink(&spec).expect("expected error");
    assert!(err.contains("unknown sink_type"));
}
