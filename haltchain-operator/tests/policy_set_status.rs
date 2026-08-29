use haltchain_operator::crd::policy_set::{PolicySetSpec, PolicySetStatus};
use serde_json::json;

#[test]
fn policy_set_status_serializes_to_expected_shape() {
    let status = PolicySetStatus {
        phase: Some("Active".to_string()),
        message: Some("Rules v1.0 active on 3 sidecar(s)".to_string()),
        last_reloaded_at: Some(1716400000),
        active_sidecars: Some(3),
    };
    let value = json!({ "status": status });
    let obj = value.as_object().unwrap();
    let status_obj = obj["status"].as_object().unwrap();
    assert_eq!(status_obj["phase"], "Active");
    assert_eq!(status_obj["active_sidecars"], 3);
}

#[test]
fn policy_set_spec_enforcement_modes_are_known_values() {
    for mode in ["enforcing", "permissive", "shadow"] {
        let spec = PolicySetSpec {
            version: "1.0.0".to_string(),
            enforcement_mode: mode.to_string(),
            rules: None,
            config_map_ref: None,
            target_labels: Default::default(),
        };
        // Just ensure serialization succeeds for all documented modes.
        let _ = serde_json::to_value(&spec).unwrap();
    }
}
