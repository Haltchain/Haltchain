//! PolicySet controller — reconciles PolicySet CRs and hot-reloads rule packs
//! into all HaltChain sidecars managed by a matching AgentProfile.

use std::sync::Arc;
use std::time::Duration;
use std::collections::HashMap;

use anyhow::Result;
use futures_util::StreamExt;
use k8s_openapi::api::core::v1::{ConfigMap, Pod};
use kube::{
    Resource, ResourceExt,
    api::{Api, ListParams, Patch, PatchParams},
    client::Client,
    runtime::{
        controller::{Action, Controller},
        watcher::Config as WatcherConfig,
    },
};
use serde_json::json;
use tracing::{error, info, warn};

use crate::crd::policy_set::{PolicySet, PolicySetStatus};
use crate::reload::{pod_matches_policy_set, policy_sync_url, sidecar_port_from_pod, webhook_signature};

pub struct Ctx {
    pub client: Client,
}

/// Entry point — runs the PolicySet reconcile loop until the process exits.
pub async fn run(client: Client) -> Result<()> {
    let api: Api<PolicySet> = Api::all(client.clone());
    let ctx = Arc::new(Ctx { client });

    Controller::new(api, WatcherConfig::default())
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok((obj, _)) => info!(name = %obj.name, "PolicySet reconciled"),
                Err(e) => error!("PolicySet reconcile error: {e}"),
            }
        })
        .await;

    Ok(())
}

/// Resolves rule content from inline rules or ConfigMap reference.
/// Inline `rules` takes precedence over `configMapRef`.
pub async fn resolve_rules(
    client: &Client,
    policy_set: &PolicySet,
) -> Result<String, kube::Error> {
    let ns = policy_set
        .namespace()
        .unwrap_or_else(|| "default".to_string());

    if let Some(inline) = &policy_set.spec.rules {
        return Ok(inline.clone());
    }

    if let Some(cmr) = &policy_set.spec.config_map_ref {
        let cm_ns = cmr.namespace.as_deref().unwrap_or(&ns);
        let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), cm_ns);
        match cm_api.get(&cmr.name).await {
            Ok(cm) => Ok(cm
                .data
                .and_then(|d| d.get("rules.yaml").cloned())
                .unwrap_or_default()),
            Err(e) => {
                warn!(name = %cmr.name, "Cannot fetch ConfigMap: {e}");
                Err(e)
            }
        }
    } else {
        Ok(String::new())
    }
}

/// Determines the reconcile action based on resolved rules.
pub fn determine_reconcile_action(rules: &str) -> ReconcileDecision {
    if rules.is_empty() {
        ReconcileDecision::Fail("No rules content found".to_string())
    } else {
        ReconcileDecision::Proceed(rules.to_string())
    }
}

/// Decision from reconcile logic.
pub enum ReconcileDecision {
    Proceed(String),
    Fail(String),
}

/// Pushes rules to pods matching this PolicySet via sidecar webhook.
pub async fn push_policy_to_matching_pods(
    pods: &[Pod],
    policy_set_name: &str,
    target_labels: &HashMap<String, String>,
    rules: &str,
    webhook_secret: &str,
    http: &reqwest::Client,
) -> i32 {
    let matched: Vec<_> = pods
        .iter()
        .filter(|pod| pod_matches_policy_set(pod, policy_set_name, target_labels))
        .collect();
    let sidecar_count = matched.len() as i32;
    let sig = webhook_signature(webhook_secret.as_bytes(), rules.as_bytes());

    for pod in matched {
        let pod_name = pod.name_any();
        let Some(pod_ip) = pod.status.as_ref().and_then(|s| s.pod_ip.as_deref()) else {
            warn!(pod = %pod_name, "Pod has no IP yet; skipping hot-reload");
            continue;
        };
        let port = sidecar_port_from_pod(pod);
        let url = policy_sync_url(pod_ip, port);
        match http
            .post(&url)
            .header("Content-Type", "application/yaml")
            .header("X-Hub-Signature-256", &sig)
            .body(rules.to_string())
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                info!(pod = %pod_name, port = %port, "Policy hot-reloaded via webhook");
            }
            Ok(r) => {
                warn!(pod = %pod_name, status = %r.status(), "Policy sync returned non-2xx");
            }
            Err(e) => {
                warn!(pod = %pod_name, "Policy sync request failed: {e}");
            }
        }
    }

    sidecar_count
}

async fn reconcile(policy_set: Arc<PolicySet>, ctx: Arc<Ctx>) -> Result<Action, kube::Error> {
    let ns = policy_set
        .namespace()
        .unwrap_or_else(|| "default".to_string());
    let name = policy_set.name_any();

    info!(namespace = %ns, name = %name, "Reconciling PolicySet");

    let rules_yaml = match resolve_rules(&ctx.client, &policy_set).await {
        Ok(rules) => rules,
        Err(e) => {
            let cmr = policy_set.spec.config_map_ref.as_ref();
            let cm_name = cmr.map(|c| c.name.clone()).unwrap_or_default();
            patch_status(
                &ctx.client,
                &ns,
                &name,
                "Failed",
                &format!("ConfigMap error: {e}"),
            )
            .await?;
            return Ok(Action::requeue(Duration::from_secs(30)));
        }
    };

    match determine_reconcile_action(&rules_yaml) {
        ReconcileDecision::Fail(msg) => {
            patch_status(&ctx.client, &ns, &name, "Failed", &msg).await?;
            return Ok(Action::requeue(Duration::from_secs(60)));
        }
        ReconcileDecision::Proceed(rules) => {
            let webhook_secret = std::env::var("HALTCHAIN_WEBHOOK_SECRET").unwrap_or_default();
            if webhook_secret.is_empty() {
                warn!("HALTCHAIN_WEBHOOK_SECRET not set; policy hot-reload will fail auth");
            }

            let pods: Api<Pod> = Api::namespaced(ctx.client.clone(), &ns);
            let pod_list = pods.list(&ListParams::default()).await?;
            let http = reqwest::Client::new();
            let sidecar_count = push_policy_to_matching_pods(
                &pod_list.items,
                &name,
                &policy_set.spec.target_labels,
                &rules,
                &webhook_secret,
                &http,
            )
            .await;

            patch_status_with_count(
                &ctx.client,
                &ns,
                &name,
                "Active",
                &format!(
                    "Rules version {} active on {} sidecar(s)",
                    policy_set.spec.version, sidecar_count
                ),
                sidecar_count,
            )
            .await?;
        }
    }

    Ok(Action::requeue(Duration::from_secs(300)))
}

fn error_policy(_obj: Arc<PolicySet>, _err: &kube::Error, _ctx: Arc<Ctx>) -> Action {
    Action::requeue(Duration::from_secs(30))
}

/// Patches the PolicySet status with phase and message.
pub async fn patch_status(
    client: &Client,
    ns: &str,
    name: &str,
    phase: &str,
    message: &str,
) -> Result<(), kube::Error> {
    patch_status_with_count(client, ns, name, phase, message, 0).await
}

/// Patches the PolicySet status with phase, message, and sidecar count.
pub async fn patch_status_with_count(
    client: &Client,
    ns: &str,
    name: &str,
    phase: &str,
    message: &str,
    count: i32,
) -> Result<(), kube::Error> {
    let api: Api<PolicySet> = Api::namespaced(client.clone(), ns);
    let now = chrono::Utc::now().timestamp();
    let patch = json!({
        "status": PolicySetStatus {
            phase: Some(phase.to_string()),
            message: Some(message.to_string()),
            last_reloaded_at: Some(now),
            active_sidecars: Some(count),
        }
    });
    api.patch_status(
        name,
        &PatchParams::apply("haltchain-operator"),
        &Patch::Merge(&patch),
    )
    .await?;
    Ok(())
}

/// Builds the status patch JSON for a given phase and message.
pub fn build_status_patch(phase: &str, message: &str, count: i32) -> serde_json::Value {
    let now = chrono::Utc::now().timestamp();
    json!({
        "status": PolicySetStatus {
            phase: Some(phase.to_string()),
            message: Some(message.to_string()),
            last_reloaded_at: Some(now),
            active_sidecars: Some(count),
        }
    })
}
