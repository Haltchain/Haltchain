//! AgentProfile controller — watches pods labelled with
//! `haltchain.io/agent-profile: <name>` and annotates them
//! so that the mutating webhook knows which sidecar spec to inject.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use futures_util::StreamExt;
use k8s_openapi::api::core::v1::Pod;
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
use tracing::{error, info};

use crate::crd::agent_profile::{AgentProfile, AgentProfileStatus};

struct Ctx {
    client: Client,
}

/// Entry point — runs the AgentProfile reconcile loop.
pub async fn run(client: Client) -> Result<()> {
    let api: Api<AgentProfile> = Api::all(client.clone());
    let ctx = Arc::new(Ctx { client });

    Controller::new(api, WatcherConfig::default())
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok((obj, _)) => info!(name = %obj.name, "AgentProfile reconciled"),
                Err(e) => error!("AgentProfile reconcile error: {e}"),
            }
        })
        .await;

    Ok(())
}

async fn reconcile(profile: Arc<AgentProfile>, ctx: Arc<Ctx>) -> Result<Action, kube::Error> {
    let ns = profile.namespace().unwrap_or_else(|| "default".to_string());
    let name = profile.name_any();

    info!(namespace = %ns, name = %name, "Reconciling AgentProfile");

    // Find all pods in this namespace that reference this AgentProfile.
    let pods: Api<Pod> = Api::namespaced(ctx.client.clone(), &ns);
    let lp = ListParams::default().labels(&format!("haltchain.io/agent-profile={}", name));
    let pod_list = pods.list(&lp).await?;

    let mut injected = 0;
    for pod in &pod_list.items {
        let pod_name = pod.name_any();
        // Check if a haltchain sidecar container is already injected.
        let already_injected = pod
            .spec
            .as_ref()
            .map(|s| s.containers.iter().any(|c| c.name == "haltchain-sidecar"))
            .unwrap_or(false);

        if !already_injected {
            // Annotate the pod so the mutating webhook picks it up on next
            // pod restart / rollout.  We cannot inject into a running pod,
            // but the annotation ensures the next scheduling event triggers
            // the webhook.
            let patch = json!({
                "metadata": {
                    "annotations": {
                        "haltchain.io/inject-sidecar": "true",
                        "haltchain.io/policy-set": profile.spec.policy_set_ref,
                        "haltchain.io/sidecar-image": profile.spec.sidecar_image
                            .as_deref()
                            .unwrap_or("ghcr.io/haltchain/sidecar:latest"),
                        "haltchain.io/sidecar-port": profile.spec.sidecar_port.to_string(),
                    }
                }
            });
            pods.patch(
                &pod_name,
                &PatchParams::apply("haltchain-operator"),
                &Patch::Merge(&patch),
            )
            .await?;
            info!(pod = %pod_name, "Annotated pod for sidecar injection");
        }
        injected += 1;
    }

    let api: Api<AgentProfile> = Api::namespaced(ctx.client.clone(), &ns);
    let status_patch = json!({
        "status": AgentProfileStatus {
            phase: Some("Active".to_string()),
            message: Some(format!("{} pod(s) managed", injected)),
            managed_pods: Some(injected),
        }
    });
    api.patch_status(
        &name,
        &PatchParams::apply("haltchain-operator"),
        &Patch::Merge(&status_patch),
    )
    .await?;

    Ok(Action::requeue(Duration::from_secs(120)))
}

fn error_policy(_obj: Arc<AgentProfile>, _err: &kube::Error, _ctx: Arc<Ctx>) -> Action {
    Action::requeue(Duration::from_secs(30))
}
