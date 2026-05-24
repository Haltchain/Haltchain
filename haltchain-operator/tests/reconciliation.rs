use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use axum::{extract::State, http::HeaderMap, routing::post, Router};
use k8s_openapi::api::core::v1::{Pod, PodStatus};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use tokio::sync::Mutex;

#[derive(Default)]
struct Capture {
    seen_sig: Option<String>,
    seen_body: Option<String>,
}

async fn policy_sync(
    State(capture): State<Arc<Mutex<Capture>>>,
    headers: HeaderMap,
    body: String,
) -> &'static str {
    let mut c = capture.lock().await;
    c.seen_sig = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    c.seen_body = Some(body);
    "ok"
}

#[tokio::test]
async fn reconciliation_pushes_policy_to_matching_sidecar_endpoint() {
    let capture = Arc::new(Mutex::new(Capture::default()));
    let app = Router::new()
        .route("/admin/webhook/policy-sync", post(policy_sync))
        .with_state(capture.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server");
    let port = listener.local_addr().expect("local addr").port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let pod = Pod {
        metadata: ObjectMeta {
            name: Some("agent-1".to_string()),
            labels: Some(BTreeMap::from([(
                "haltchain.io/policy-set".to_string(),
                "prod-policy".to_string(),
            )])),
            annotations: Some(BTreeMap::from([(
                "haltchain.io/sidecar-port".to_string(),
                port.to_string(),
            )])),
            ..Default::default()
        },
        status: Some(PodStatus {
            pod_ip: Some("127.0.0.1".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let count = haltchain_operator::controllers::policy_set::push_policy_to_matching_pods(
        &[pod],
        "prod-policy",
        &HashMap::new(),
        "rules:\n  - id: block-x\n",
        "test-secret",
        &reqwest::Client::new(),
    )
    .await;

    assert_eq!(count, 1);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let c = capture.lock().await;
    assert_eq!(c.seen_body.as_deref(), Some("rules:\n  - id: block-x\n"));
    let sig = c.seen_sig.as_deref().unwrap_or("");
    assert!(sig.starts_with("sha256="));
}
