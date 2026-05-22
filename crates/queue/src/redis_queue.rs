// Prod: enable Redis AOF + RDB so queued deep-scan tasks survive restarts (Roadmap E).
use async_trait::async_trait;
use redis::AsyncCommands;
use serde_json;

use crate::{
    DeadLetterTask, DeepScanTask, QueueError, QueueId, QueueMetrics, QueuePriority, ScanQueue,
    ScanResult,
};

const QUEUE_KEY_HIGH: &str = "haltchain:scan_queue:high";
const QUEUE_KEY_NORMAL: &str = "haltchain:scan_queue:normal";
const QUEUE_KEY_LOW: &str = "haltchain:scan_queue:low";
const COMPLETED_KEY: &str = "haltchain:scan_completed";
const DEAD_LETTER_KEY: &str = "haltchain:scan_dead_letter";
const METRICS_KEY: &str = "haltchain:scan_metrics";

pub struct RedisScanQueue {
    client: redis::Client,
}

impl RedisScanQueue {
    /// Connect to Redis.  `url` is a redis:// or rediss:// connection string.
    pub fn new(url: &str) -> Result<Self, String> {
        let client = redis::Client::open(url).map_err(|e| e.to_string())?;
        Ok(Self { client })
    }

    async fn conn(&self) -> Result<redis::aio::MultiplexedConnection, QueueError> {
        self.client
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| QueueError::QueueClosed)
    }

    fn queue_key(priority: QueuePriority) -> &'static str {
        match priority {
            QueuePriority::High => QUEUE_KEY_HIGH,
            QueuePriority::Normal => QUEUE_KEY_NORMAL,
            QueuePriority::Low => QUEUE_KEY_LOW,
        }
    }

    fn pending_metric(priority: QueuePriority) -> &'static str {
        match priority {
            QueuePriority::High => "pending_high",
            QueuePriority::Normal => "pending_normal",
            QueuePriority::Low => "pending_low",
        }
    }

    async fn metric_inc(&self, field: &str, by: i64) -> Result<(), QueueError> {
        let mut conn = self.conn().await?;
        conn.hincr::<_, _, _, i64>(METRICS_KEY, field, by)
            .await
            .map_err(|_| QueueError::QueueClosed)?;
        Ok(())
    }

    async fn put_dead_letter(&self, task: DeepScanTask, reason: String) -> Result<(), QueueError> {
        let payload = serde_json::to_string(&DeadLetterTask {
            task: task.clone(),
            failed_at: chrono::Utc::now(),
            reason,
        })
        .map_err(|_| QueueError::QueueClosed)?;

        let mut conn = self.conn().await?;
        conn.hset::<_, _, _, ()>(DEAD_LETTER_KEY, task.task_id.to_string(), payload)
            .await
            .map_err(|_| QueueError::QueueClosed)?;
        self.metric_inc("dead_lettered", 1).await?;
        Ok(())
    }
}

#[async_trait]
impl ScanQueue for RedisScanQueue {
    async fn enqueue(&self, task: DeepScanTask) -> Result<QueueId, QueueError> {
        let id = task.task_id;
        let priority = task.priority;
        let payload = serde_json::to_string(&task).map_err(|_| QueueError::QueueClosed)?;
        let mut conn = self.conn().await?;
        conn.lpush::<_, _, ()>(Self::queue_key(priority), payload)
            .await
            .map_err(|_| QueueError::QueueClosed)?;
        self.metric_inc(Self::pending_metric(priority), 1).await?;
        Ok(id)
    }

    async fn dequeue(&self) -> Option<DeepScanTask> {
        loop {
            let mut conn = self.conn().await.ok()?;
            // Priority order: high -> normal -> low.
            let result: Option<(String, String)> = conn
                .brpop(&[QUEUE_KEY_HIGH, QUEUE_KEY_NORMAL, QUEUE_KEY_LOW], 5.0)
                .await
                .ok()?;
            let (queue_key, payload) = result?;
            let task: DeepScanTask = serde_json::from_str(&payload).ok()?;

            let priority = match queue_key.as_str() {
                QUEUE_KEY_HIGH => QueuePriority::High,
                QUEUE_KEY_LOW => QueuePriority::Low,
                _ => QueuePriority::Normal,
            };

            let _ = self.metric_inc(Self::pending_metric(priority), -1).await;

            if task.is_expired() {
                let _ = self
                    .put_dead_letter(task, "task expired before processing".to_string())
                    .await;
                continue;
            }

            return Some(task);
        }
    }

    async fn complete(&self, id: QueueId, result: ScanResult) -> Result<(), QueueError> {
        let payload = serde_json::to_string(&result).map_err(|_| QueueError::QueueClosed)?;
        let mut conn = self.conn().await?;
        conn.hset::<_, _, _, ()>(COMPLETED_KEY, id.to_string(), payload)
            .await
            .map_err(|_| QueueError::QueueClosed)?;
        self.metric_inc("completed", 1).await?;
        Ok(())
    }

    async fn get_completed(&self, id: QueueId) -> Option<ScanResult> {
        let mut conn = self.conn().await.ok()?;
        let payload: Option<String> = conn.hget(COMPLETED_KEY, id.to_string()).await.ok()?;
        payload.and_then(|p| serde_json::from_str(&p).ok())
    }

    async fn retry_or_dead_letter(
        &self,
        mut task: DeepScanTask,
        reason: String,
    ) -> Result<(), QueueError> {
        if task.attempts.saturating_add(1) > task.max_attempts {
            return self.put_dead_letter(task, reason).await;
        }

        task.attempts = task.attempts.saturating_add(1);
        self.metric_inc("retried", 1).await?;
        self.enqueue(task).await.map(|_| ())
    }

    async fn get_dead_letter(&self, id: QueueId) -> Option<DeadLetterTask> {
        let mut conn = self.conn().await.ok()?;
        let payload: Option<String> = conn.hget(DEAD_LETTER_KEY, id.to_string()).await.ok()?;
        payload.and_then(|p| serde_json::from_str(&p).ok())
    }

    async fn metrics(&self) -> QueueMetrics {
        async fn fetch_field(q: &RedisScanQueue, field: &str) -> u64 {
            let mut conn = match q.conn().await {
                Ok(c) => c,
                Err(_) => return 0,
            };
            let val: Result<i64, _> = conn.hget(METRICS_KEY, field).await;
            val.ok().map(|v| v.max(0) as u64).unwrap_or(0)
        }

        QueueMetrics {
            pending_high: fetch_field(self, "pending_high").await,
            pending_normal: fetch_field(self, "pending_normal").await,
            pending_low: fetch_field(self, "pending_low").await,
            completed: fetch_field(self, "completed").await,
            dead_lettered: fetch_field(self, "dead_lettered").await,
            retried: fetch_field(self, "retried").await,
        }
    }
}
