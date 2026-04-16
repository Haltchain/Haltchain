//! Mutating webhook handler — injects the HaltChain sidecar into pods
//! annotated with `haltchain.io/inject-sidecar: "true"`.

use axum::{extract::Json, http::StatusCode, response::IntoResponse};
use json_patch::{AddOperation, Patch, PatchOperation};
use jsonptr::Pointer;
use k8s_openapi::api::core::v1::{Container, EnvVar, Pod, ResourceRequirements};
use kube::{
    core::{
        admission::{AdmissionRequest, AdmissionResponse, AdmissionReview},
        DynamicObject,
    },
    ResourceExt,
};
use tracing::{info, warn};

/// Axum handler for POST /mutate-pods.
pub async fn handle_mutate(
    Json(review): Json<AdmissionReview<Pod>>,
) -> impl IntoResponse {
    let req: AdmissionRequest<Pod> = match review.try_into() {
        Ok(r) => r,
        Err(e) => {
            warn!("Invalid AdmissionReview: {e}");
            return (StatusCode::BAD_REQUEST, "Invalid admission review").into_response();
        }
    };

    let response = match mutate(req).await {
        Ok(resp) => resp,
        Err(e) => {
            warn!("Mutation error: {e}");
            AdmissionResponse::invalid(format!("Mutation failed: {e}"))
        }
    };

    let review: AdmissionReview<DynamicObject> = response.into_review();
    Json(review).into_response()
}

async fn mutate(req: AdmissionRequest<Pod>) -> anyhow::Result<AdmissionResponse> {
    let pod = req.object.as_ref().ok_or_else(|| anyhow::anyhow!("No object in request"))?;
    let annotations = pod
        .metadata
        .annotations
        .as_ref()
        .cloned()
        .unwrap_or_default();

    // Only inject if the annotation is present and true.
    if annotations.get("haltchain.io/inject-sidecar").map(String::as_str) != Some("true") {
        return Ok(AdmissionResponse::from(&req));
    }

    // Skip if already injected.
    let already_injected = pod
        .spec
        .as_ref()
        .map(|s| s.containers.iter().any(|c| c.name == "haltchain-sidecar"))
        .unwrap_or(false);

    if already_injected {
        info!("Sidecar already present, skipping injection");
        return Ok(AdmissionResponse::from(&req));
    }

    let image = annotations
        .get("haltchain.io/sidecar-image")
        .map(String::as_str)
        .unwrap_or("ghcr.io/haltchain/sidecar:latest");

    let port: i32 = annotations
        .get("haltchain.io/sidecar-port")
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let policy_set = annotations
        .get("haltchain.io/policy-set")
        .cloned()
        .unwrap_or_default();

    let sidecar = build_sidecar_container(image, port, &policy_set);

    // Build a JSON Patch to append the sidecar to spec.containers.
    let patch = Patch(vec![PatchOperation::Add(AddOperation {
        path: Pointer::parse("/spec/containers/-").expect("valid pointer"),
        value: serde_json::to_value(&sidecar)?,
    })]);

    info!(image = %image, port = %port, "Injecting HaltChain sidecar");
    let name = pod.name_any();
    info!(pod = %name, "Injection patch prepared");

    Ok(AdmissionResponse::from(&req).with_patch(patch)?)
}

fn build_sidecar_container(image: &str, port: i32, policy_set: &str) -> Container {
    use k8s_openapi::api::core::v1::ContainerPort;
    use k8s_openapi::apimachinery::pkg::api::resource::Quantity;

    Container {
        name: "haltchain-sidecar".to_string(),
        image: Some(image.to_string()),
        image_pull_policy: Some("IfNotPresent".to_string()),
        ports: Some(vec![ContainerPort {
            container_port: port,
            name: Some("http".to_string()),
            protocol: Some("TCP".to_string()),
            ..Default::default()
        }]),
        env: Some(vec![
            EnvVar {
                name: "HALTCHAIN_ENV".to_string(),
                value: Some("kubernetes".to_string()),
                ..Default::default()
            },
            EnvVar {
                name: "HALTCHAIN_POLICY_SET".to_string(),
                value: Some(policy_set.to_string()),
                ..Default::default()
            },
            EnvVar {
                name: "RUST_LOG".to_string(),
                value: Some("info".to_string()),
                ..Default::default()
            },
        ]),
        resources: Some(ResourceRequirements {
            limits: Some(std::collections::BTreeMap::from([
                ("cpu".to_string(), Quantity("200m".to_string())),
                ("memory".to_string(), Quantity("128Mi".to_string())),
            ])),
            requests: Some(std::collections::BTreeMap::from([
                ("cpu".to_string(), Quantity("50m".to_string())),
                ("memory".to_string(), Quantity("64Mi".to_string())),
            ])),
            ..Default::default()
        }),
        ..Default::default()
    }
}
