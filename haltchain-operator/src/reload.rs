#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::HashMap;

use hmac::{Hmac, Mac};
use k8s_openapi::api::core::v1::Pod;
use sha2::Sha256;

pub const DEFAULT_SIDECAR_PORT: u16 = 8787;
pub const POLICY_SYNC_PATH: &str = "/admin/webhook/policy-sync";

pub fn sidecar_port_from_pod(pod: &Pod) -> u16 {
    pod.metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get("haltchain.io/sidecar-port"))
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_SIDECAR_PORT)
}

pub fn policy_sync_url(pod_ip: &str, port: u16) -> String {
    format!("http://{pod_ip}:{port}{POLICY_SYNC_PATH}")
}

pub fn webhook_signature(secret: &[u8], body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

pub fn pod_matches_policy_set(
    pod: &Pod,
    policy_set_name: &str,
    target_labels: &HashMap<String, String>,
) -> bool {
    let labels = pod.metadata.labels.as_ref();
    let annotations = pod.metadata.annotations.as_ref();

    if labels
        .and_then(|l| l.get("haltchain.io/policy-set"))
        .map(String::as_str)
        == Some(policy_set_name)
    {
        return true;
    }

    if annotations
        .and_then(|a| a.get("haltchain.io/policy-set"))
        .map(String::as_str)
        == Some(policy_set_name)
    {
        return true;
    }

    if target_labels.is_empty() {
        return false;
    }

    labels
        .map(|l| {
            target_labels
                .iter()
                .all(|(k, v)| l.get(k).map(String::as_str) == Some(v.as_str()))
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    #[test]
    fn policy_sync_url_uses_sidecar_port() {
        assert_eq!(
            policy_sync_url("10.0.0.5", 8787),
            "http://10.0.0.5:8787/admin/webhook/policy-sync"
        );
    }

    #[test]
    fn webhook_signature_matches_api_format() {
        let sig = webhook_signature(b"test-secret", b"rules:\n- id: x\n");
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), "sha256=".len() + 64);
    }

    #[test]
    fn pod_matches_policy_set_by_label_or_annotation() {
        let pod = Pod {
            metadata: ObjectMeta {
                labels: Some(BTreeMap::from([(
                    "haltchain.io/policy-set".to_string(),
                    "prod".to_string(),
                )])),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(pod_matches_policy_set(&pod, "prod", &HashMap::new()));
    }
}
