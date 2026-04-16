//! PolicySet controller — reconciles PolicySet CRs and hot-reloads rule packs
//! into all HaltChain sidecars managed by a matching AgentProfile.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use futures_util::StreamExt;
use k8s_openapi::api::core::v1::{ConfigMap, Pod};
use kube::{
    api::{Api, ListParams, Patch, PatchParams},
    client::Client,
    runtime::{
        controller::{Action, Controller},
        watcher::Config as WatcherConfig,
    },
    Resource, ResourceExt,
};
use serde_json::json;
use tracing::{error, info, warn};

use crate::crd::policy_set::{PolicySet, PolicySetStatus};

struct Ctx {
    client: Client,
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

async fn reconcile(policy_set: Arc<PolicySet>, ctx: Arc<Ctx>) -> Result<Action, kube::Error> {
    let ns = policy_set.namespace().unwrap_or_else(|| "default".to_string());
    let name = policy_set.name_any();

    info!(namespace = %ns, name = %name, "Reconciling PolicySet");

    // Resolve rule content: inline `rules` takes precedence over configMapRef.
    let rules_yaml = if let Some(inline) = &policy_set.spec.rules {
        inline.clone()
    } else if let Some(cmr) = &policy_set.spec.config_map_ref {
        let cm_ns = cmr.namespace.as_deref().unwrap_or(&ns);
        let cm_api: Api<ConfigMap> = Api::namespaced(ctx.client.clone(), cm_ns);
        match cm_api.get(&cmr.name).await {
            Ok(cm) => cm
                .data
                .and_then(|d| d.get("rules.yaml").cloned())
                .unwrap_or_default(),
            Err(e) => {
                warn!(name = %cmr.name, "Cannot fetch ConfigMap: {e}");
                patch_status(&ctx.client, &ns, &name, "Failed", &format!("ConfigMap error: {e}")).await?;
                return Ok(Action::requeue(Duration::from_secs(30)));
            }
        }
    } else {
        String::new()
    };

    if rules_yaml.is_empty() {
        patch_status(&ctx.client, &ns, &name, "Failed", "No rules content found").await?;
        return Ok(Action::requeue(Duration::from_secs(60)));
    }

    // Hot-reload: send SIGHUP-equivalent to every sidecar pod in the namespace
    // that carries the label haltchain.io/policy-set=<name>.
    let pods: Api<Pod> = Api::namespaced(ctx.client.clone(), &ns);
    let lp = ListParams::default()
        .labels(&format!("haltchain.io/policy-set={}", name));
    let pod_list = pods.list(&lp).await?;
    let sidecar_count = pod_list.items.len() as i32;

    for pod in &pod_list.items {
        let pod_name = pod.name_any();
        // POST the updated rules to the sidecar's local reload endpoint.
        // The sidecar exposes POST /admin/reload-rules on port 8081.
        if let Some(pod_ip) = pod.status.as_ref().and_then(|s| s.pod_ip.as_deref()) {
            let url = format!("http://{}:8081/admin/reload-rules", pod_ip);
            let client = reqwest::Client::new();
            match client
                .post(&url)
                .header("Content-Type", "application/yaml")
                .body(rules_yaml.clone())
                .timeout(Duration::from_secs(5))
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => {
                    info!(pod = %pod_name, "Rule pack hot-reloaded successfully");
                }
                Ok(r) => {
                    warn!(pod = %pod_name, status = %r.status(), "Sidecar reload returned non-2xx");
                }
                Err(e) => {
                    warn!(pod = %pod_name, "Sidecar reload request failed: {e}");
                }
            }
        }
    }

    patch_status_with_count(
        &ctx.client,
        &ns,
        &name,
        "Active",
        &format!("Rules version {} active on {} sidecar(s)", policy_set.spec.version, sidecar_count),
        sidecar_count,
    )
    .await?;

    // Re-check every 5 minutes for drift.
    Ok(Action::requeue(Duration::from_secs(300)))
}

fn error_policy(_obj: Arc<PolicySet>, _err: &kube::Error, _ctx: Arc<Ctx>) -> Action {
    Action::requeue(Duration::from_secs(30))
}

async fn patch_status(
    client: &Client,
    ns: &str,
    name: &str,
    phase: &str,
    message: &str,
) -> Result<(), kube::Error> {
    patch_status_with_count(client, ns, name, phase, message, 0).await
}

async fn patch_status_with_count(
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
