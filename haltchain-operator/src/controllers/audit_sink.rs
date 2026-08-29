//! AuditSink controller — validates AuditSink CRs and writes their
//! resolved configuration to a ConfigMap consumed by the sidecar.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use futures_util::StreamExt;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::{
    ResourceExt,
    api::{Api, ObjectMeta, Patch, PatchParams},
    client::Client,
    runtime::{
        controller::{Action, Controller},
        watcher::Config as WatcherConfig,
    },
};
use serde_json::json;
use tracing::{error, info, warn};

use crate::crd::audit_sink::{AuditSink, AuditSinkSpec, AuditSinkStatus};

/// Validate an AuditSink spec. Returns an error message if invalid.
pub fn validate_sink(spec: &AuditSinkSpec) -> Option<String> {
    match spec.sink_type.as_str() {
        "webhook" if spec.webhook.is_none() => {
            Some("webhook config required for sink_type=webhook".to_string())
        }
        "kafka" if spec.kafka.is_none() => {
            Some("kafka config required for sink_type=kafka".to_string())
        }
        "webhook" | "kafka" | "stdout" => None,
        other => Some(format!("unknown sink_type: {}", other)),
    }
}

struct Ctx {
    client: Client,
}

pub async fn run(client: Client) -> Result<()> {
    let api: Api<AuditSink> = Api::all(client.clone());
    let ctx = Arc::new(Ctx { client });

    Controller::new(api, WatcherConfig::default())
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok((obj, _)) => info!(name = %obj.name, "AuditSink reconciled"),
                Err(e) => error!("AuditSink reconcile error: {e}"),
            }
        })
        .await;

    Ok(())
}

async fn reconcile(sink: Arc<AuditSink>, ctx: Arc<Ctx>) -> Result<Action, kube::Error> {
    let ns = sink.namespace().unwrap_or_else(|| "default".to_string());
    let name = sink.name_any();
    let cm_name = format!("haltchain-audit-sink-{}", name);

    info!(namespace = %ns, name = %name, "Reconciling AuditSink");

    // Validate sink type
    if let Some(err) = validate_sink(&sink.spec) {
        warn!("AuditSink {} validation failed: {}", name, err);
        patch_status(&ctx.client, &ns, &name, "Failed", &err).await?;
        return Ok(Action::requeue(Duration::from_secs(60)));
    }

    // Write resolved configuration to a ConfigMap.
    let config_data = serde_json::to_string(&sink.spec).unwrap_or_default();
    let cm = ConfigMap {
        metadata: ObjectMeta {
            name: Some(cm_name.clone()),
            namespace: Some(ns.clone()),
            ..Default::default()
        },
        data: Some(std::collections::BTreeMap::from([(
            "sink.json".to_string(),
            config_data,
        )])),
        ..Default::default()
    };

    let cm_api: Api<ConfigMap> = Api::namespaced(ctx.client.clone(), &ns);
    cm_api
        .patch(
            &cm_name,
            &PatchParams::apply("haltchain-operator").force(),
            &Patch::Apply(&cm),
        )
        .await?;

    info!(cm = %cm_name, "AuditSink ConfigMap written");
    patch_status(
        &ctx.client,
        &ns,
        &name,
        "Active",
        "Sink configuration applied",
    )
    .await?;

    Ok(Action::requeue(Duration::from_secs(300)))
}

fn error_policy(_obj: Arc<AuditSink>, _err: &kube::Error, _ctx: Arc<Ctx>) -> Action {
    Action::requeue(Duration::from_secs(30))
}

async fn patch_status(
    client: &Client,
    ns: &str,
    name: &str,
    phase: &str,
    message: &str,
) -> Result<(), kube::Error> {
    let api: Api<AuditSink> = Api::namespaced(client.clone(), ns);
    let now = chrono::Utc::now().timestamp();
    let patch = json!({
        "status": AuditSinkStatus {
            phase: Some(phase.to_string()),
            message: Some(message.to_string()),
            events_emitted: None,
            last_event_at: Some(now),
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
