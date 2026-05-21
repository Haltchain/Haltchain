use crate::{DbError, TelemetryRecord};
use sqlx::{PgPool, Postgres, QueryBuilder};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::sync::mpsc;

pub(crate) struct TelemetryHotWriter {
    tx: mpsc::Sender<TelemetryRecord>,
    drop_on_full: bool,
    dropped_count: AtomicU64,
}

impl TelemetryHotWriter {
    pub(crate) fn start(pool: PgPool) -> Self {
        let queue_capacity = read_usize_env("HALTCHAIN_TELEMETRY_HOT_QUEUE_CAPACITY", 8_192).max(1);
        let flush_batch_size =
            read_usize_env("HALTCHAIN_TELEMETRY_HOT_FLUSH_BATCH_SIZE", 256).max(1);
        let flush_interval_ms = read_u64_env("HALTCHAIN_TELEMETRY_HOT_FLUSH_INTERVAL_MS", 5).max(1);
        let drop_on_full = read_bool_env("HALTCHAIN_TELEMETRY_HOT_DROP_ON_FULL", true);

        let (tx, mut rx) = mpsc::channel::<TelemetryRecord>(queue_capacity);
        let flush_interval = Duration::from_millis(flush_interval_ms);

        tokio::spawn(async move {
            let mut pending = Vec::<TelemetryRecord>::with_capacity(flush_batch_size);
            let mut ticker = tokio::time::interval(flush_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    msg = rx.recv() => {
                        match msg {
                            Some(record) => {
                                pending.push(record);
                                if pending.len() >= flush_batch_size {
                                    if let Err(err) = flush_batch(&pool, &mut pending).await {
                                        tracing::warn!("telemetry_hot batch flush failed: {err}");
                                        pending.clear();
                                    }
                                }
                            }
                            None => {
                                if !pending.is_empty() {
                                    if let Err(err) = flush_batch(&pool, &mut pending).await {
                                        tracing::warn!("telemetry_hot final flush failed: {err}");
                                    }
                                }
                                break;
                            }
                        }
                    }
                    _ = ticker.tick() => {
                        if !pending.is_empty() {
                            if let Err(err) = flush_batch(&pool, &mut pending).await {
                                tracing::warn!("telemetry_hot timed flush failed: {err}");
                                pending.clear();
                            }
                        }
                    }
                }
            }
        });

        Self {
            tx,
            drop_on_full,
            dropped_count: AtomicU64::new(0),
        }
    }

    pub(crate) async fn enqueue(&self, record: &TelemetryRecord) -> Result<(), DbError> {
        let msg = record.clone();
        match self.tx.try_send(msg) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(msg)) => {
                if self.drop_on_full {
                    let dropped = self.dropped_count.fetch_add(1, Ordering::Relaxed) + 1;
                    if dropped == 1 || dropped % 1_000 == 0 {
                        tracing::warn!(
                            dropped,
                            "telemetry_hot queue full; dropping fire-and-forget telemetry writes"
                        );
                    }
                    Ok(())
                } else {
                    self.tx.send(msg).await.map_err(|_| {
                        DbError::Misconfigured(
                            "telemetry_hot writer closed while enqueueing record".to_string(),
                        )
                    })
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(DbError::Misconfigured(
                "telemetry_hot writer is closed".to_string(),
            )),
        }
    }
}

async fn flush_batch(pool: &PgPool, pending: &mut Vec<TelemetryRecord>) -> Result<(), sqlx::Error> {
    if pending.is_empty() {
        return Ok(());
    }

    let mut query = QueryBuilder::<Postgres>::new(
        "INSERT INTO telemetry_hot (org_id, agent_id, metric, value, tags) ",
    );
    query.push_values(pending.iter(), |mut row, rec| {
        row.push_bind(rec.org_id)
            .push_bind(&rec.agent_id)
            .push_bind(&rec.metric)
            .push_bind(rec.value)
            .push_bind(&rec.tags);
    });

    query.build().execute(pool).await?;
    pending.clear();
    Ok(())
}

fn read_usize_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}

fn read_u64_env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn read_bool_env(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .and_then(|v| match v.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
        .unwrap_or(default)
}
