use anyhow::Result;
use tracing::info;

use haltchain_operator::{controllers, webhook};
use kube::Client;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .compact()
        .init();

    let client = Client::try_default().await?;
    info!("HaltChain Kubernetes operator starting");

    tokio::try_join!(
        controllers::policy_set::run(client.clone()),
        controllers::agent_profile::run(client.clone()),
        controllers::audit_sink::run(client.clone()),
        webhook::server::run(),
    )?;

    Ok(())
}
