use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::{Mutex, mpsc};
use uuid::Uuid;

#[cfg(feature = "redis-queue")]
pub mod redis_queue;
#[cfg(feature = "redis-queue")]
pub use redis_queue::RedisScanQueue;

pub type QueueId = Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum QueuePriority {
    High,
    Normal,
    Low,
}

impl Default for QueuePriority {
    fn default() -> Self {
        Self::Normal
    }
}

fn default_max_attempts() -> u8 {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeepScanTask {
    pub task_id: QueueId,
    pub agent_id: String,
    pub session_id: String,
    pub reasoning_trace: String,
    pub callback_url: Option<String>,
    pub enqueued_at: DateTime<Utc>,
    #[serde(default)]
    pub priority: QueuePriority,
    #[serde(default)]
    pub attempts: u8,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u8,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

impl DeepScanTask {
    pub fn new(
        agent_id: impl Into<String>,
        session_id: impl Into<String>,
        reasoning_trace: impl Into<String>,
        callback_url: Option<String>,
    ) -> Self {
        Self {
            task_id: Uuid::new_v4(),
            agent_id: agent_id.into(),
            session_id: session_id.into(),
            reasoning_trace: reasoning_trace.into(),
            callback_url,
            enqueued_at: Utc::now(),
            priority: QueuePriority::Normal,
            attempts: 0,
            max_attempts: default_max_attempts(),
            expires_at: None,
        }
    }

    pub fn with_controls(
        mut self,
        priority: QueuePriority,
        max_attempts: u8,
        ttl_seconds: Option<i64>,
    ) -> Self {
        self.priority = priority;
        self.max_attempts = max_attempts.max(1);
        self.expires_at = ttl_seconds.map(|s| Utc::now() + chrono::TimeDelta::seconds(s));
        self
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|expires_at| Utc::now() > expires_at)
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanResult {
    pub task_id: QueueId,
    pub status: ScanStatus,
    pub summary: String,
    pub completed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScanStatus {
    Proceed,
    Flagged,
    HaltAndClarify,
    Failed,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum QueueError {
    #[error("queue is closed")]
    QueueClosed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeadLetterTask {
    pub task: DeepScanTask,
    pub failed_at: DateTime<Utc>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct QueueMetrics {
    pub pending_high: u64,
    pub pending_normal: u64,
    pub pending_low: u64,
    pub completed: u64,
    pub dead_lettered: u64,
    pub retried: u64,
}

#[async_trait]
pub trait ScanQueue: Send + Sync {
    async fn enqueue(&self, task: DeepScanTask) -> Result<QueueId, QueueError>;
    async fn dequeue(&self) -> Option<DeepScanTask>;
    async fn complete(&self, id: QueueId, result: ScanResult) -> Result<(), QueueError>;
    async fn get_completed(&self, id: QueueId) -> Option<ScanResult>;

    async fn retry_or_dead_letter(
        &self,
        _task: DeepScanTask,
        _reason: String,
    ) -> Result<(), QueueError> {
        Err(QueueError::QueueClosed)
    }

    async fn get_dead_letter(&self, _id: QueueId) -> Option<DeadLetterTask> {
        None
    }

    async fn metrics(&self) -> QueueMetrics {
        QueueMetrics::default()
    }
}

pub struct TokioChannelQueue {
    high_tx: mpsc::Sender<DeepScanTask>,
    normal_tx: mpsc::Sender<DeepScanTask>,
    low_tx: mpsc::Sender<DeepScanTask>,
    high_rx: Mutex<mpsc::Receiver<DeepScanTask>>,
    normal_rx: Mutex<mpsc::Receiver<DeepScanTask>>,
    low_rx: Mutex<mpsc::Receiver<DeepScanTask>>,
    completed: DashMap<QueueId, ScanResult>,
    dead_letter: DashMap<QueueId, DeadLetterTask>,
    pending_high: AtomicU64,
    pending_normal: AtomicU64,
    pending_low: AtomicU64,
    completed_count: AtomicU64,
    dead_letter_count: AtomicU64,
    retried_count: AtomicU64,
}

impl TokioChannelQueue {
    pub fn new(buffer: usize) -> Arc<Self> {
        let cap = buffer.max(1);
        let (high_tx, high_rx) = mpsc::channel(cap);
        let (normal_tx, normal_rx) = mpsc::channel(cap);
        let (low_tx, low_rx) = mpsc::channel(cap);
        Arc::new(Self {
            high_tx,
            normal_tx,
            low_tx,
            high_rx: Mutex::new(high_rx),
            normal_rx: Mutex::new(normal_rx),
            low_rx: Mutex::new(low_rx),
            completed: DashMap::new(),
            dead_letter: DashMap::new(),
            pending_high: AtomicU64::new(0),
            pending_normal: AtomicU64::new(0),
            pending_low: AtomicU64::new(0),
            completed_count: AtomicU64::new(0),
            dead_letter_count: AtomicU64::new(0),
            retried_count: AtomicU64::new(0),
        })
    }

    fn pending_counter(&self, priority: QueuePriority) -> &AtomicU64 {
        match priority {
            QueuePriority::High => &self.pending_high,
            QueuePriority::Normal => &self.pending_normal,
            QueuePriority::Low => &self.pending_low,
        }
    }

    fn decrement_pending(&self, priority: QueuePriority) {
        let c = self.pending_counter(priority);
        let _ = c.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_sub(1))
        });
    }

    fn move_to_dead_letter(&self, task: DeepScanTask, reason: String) {
        self.dead_letter.insert(
            task.task_id,
            DeadLetterTask {
                task,
                failed_at: Utc::now(),
                reason,
            },
        );
        self.dead_letter_count.fetch_add(1, Ordering::Relaxed);
    }
}

#[async_trait]
impl ScanQueue for TokioChannelQueue {
    async fn enqueue(&self, task: DeepScanTask) -> Result<QueueId, QueueError> {
        let id = task.task_id;
        let priority = task.priority;
        self.pending_counter(priority)
            .fetch_add(1, Ordering::Relaxed);
        let sender = match priority {
            QueuePriority::High => &self.high_tx,
            QueuePriority::Normal => &self.normal_tx,
            QueuePriority::Low => &self.low_tx,
        };
        sender.send(task).await.map_err(|_| {
            self.decrement_pending(priority);
            QueueError::QueueClosed
        })?;
        Ok(id)
    }

    async fn dequeue(&self) -> Option<DeepScanTask> {
        loop {
            let next = {
                let mut high = self.high_rx.lock().await;
                let mut normal = self.normal_rx.lock().await;
                let mut low = self.low_rx.lock().await;
                tokio::select! {
                    biased;
                    task = high.recv() => task,
                    task = normal.recv() => task,
                    task = low.recv() => task,
                }
            };

            let task = next?;
            self.decrement_pending(task.priority);

            if task.is_expired() {
                self.move_to_dead_letter(task, "task expired before processing".to_string());
                continue;
            }

            return Some(task);
        }
    }

    async fn complete(&self, id: QueueId, result: ScanResult) -> Result<(), QueueError> {
        self.completed.insert(id, result);
        self.completed_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn get_completed(&self, id: QueueId) -> Option<ScanResult> {
        self.completed.get(&id).map(|entry| entry.clone())
    }

    async fn retry_or_dead_letter(
        &self,
        mut task: DeepScanTask,
        reason: String,
    ) -> Result<(), QueueError> {
        if task.attempts.saturating_add(1) > task.max_attempts {
            self.move_to_dead_letter(task, reason);
            return Ok(());
        }

        task.attempts = task.attempts.saturating_add(1);
        self.retried_count.fetch_add(1, Ordering::Relaxed);
        self.enqueue(task).await.map(|_| ())
    }

    async fn get_dead_letter(&self, id: QueueId) -> Option<DeadLetterTask> {
        self.dead_letter.get(&id).map(|entry| entry.clone())
    }

    async fn metrics(&self) -> QueueMetrics {
        QueueMetrics {
            pending_high: self.pending_high.load(Ordering::Relaxed),
            pending_normal: self.pending_normal.load(Ordering::Relaxed),
            pending_low: self.pending_low.load(Ordering::Relaxed),
            completed: self.completed_count.load(Ordering::Relaxed),
            dead_lettered: self.dead_letter_count.load(Ordering::Relaxed),
            retried: self.retried_count.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn enqueue_dequeue_round_trip() {
        let queue = TokioChannelQueue::new(8);
        let task = DeepScanTask::new("agent-a", "session-a", "trace", None);
        let task_id = task.task_id;

        let enqueued = queue.enqueue(task.clone()).await;
        assert!(enqueued.is_ok());
        assert_eq!(enqueued.unwrap(), task_id);

        let out = queue.dequeue().await;
        assert!(out.is_some());
        assert_eq!(out.unwrap(), task);
    }

    #[tokio::test]
    async fn complete_and_lookup_result() {
        let queue = TokioChannelQueue::new(4);
        let task = DeepScanTask::new("agent-b", "session-b", "trace", None);
        let task_id = task.task_id;
        let _ = queue.enqueue(task).await;

        let result = ScanResult {
            task_id,
            status: ScanStatus::Flagged,
            summary: "requires deep scan".to_string(),
            completed_at: Utc::now(),
        };

        let complete_result = queue.complete(task_id, result.clone()).await;
        assert!(complete_result.is_ok());

        let found = queue.get_completed(task_id).await;
        assert!(found.is_some());
        assert_eq!(found.unwrap(), result);
    }

    #[tokio::test]
    async fn dequeue_prioritizes_high_priority_tasks() {
        let queue = TokioChannelQueue::new(8);

        let normal = DeepScanTask::new("agent-n", "s1", "trace", None).with_controls(
            QueuePriority::Normal,
            3,
            None,
        );
        let high = DeepScanTask::new("agent-h", "s2", "trace", None).with_controls(
            QueuePriority::High,
            3,
            None,
        );

        let _ = queue.enqueue(normal.clone()).await;
        let _ = queue.enqueue(high.clone()).await;

        let first = queue.dequeue().await;
        assert!(first.is_some());
        assert_eq!(first.unwrap().task_id, high.task_id);
    }

    #[tokio::test]
    async fn expired_task_moves_to_dead_letter() {
        let queue = TokioChannelQueue::new(8);

        let expired = DeepScanTask::new("agent-exp", "s-exp", "trace", None).with_controls(
            QueuePriority::High,
            3,
            Some(-1),
        );
        let expired_id = expired.task_id;
        let fresh = DeepScanTask::new("agent-live", "s-live", "trace", None).with_controls(
            QueuePriority::Normal,
            3,
            None,
        );

        let _ = queue.enqueue(expired).await;
        let _ = queue.enqueue(fresh.clone()).await;

        let out = queue.dequeue().await;
        assert!(out.is_some());
        assert_eq!(out.unwrap().task_id, fresh.task_id);

        let dlq = queue.get_dead_letter(expired_id).await;
        assert!(dlq.is_some());
    }

    #[tokio::test]
    async fn retry_then_dead_letter_after_max_attempts() {
        let queue = TokioChannelQueue::new(8);

        let task = DeepScanTask::new("agent-r", "s-r", "trace", None).with_controls(
            QueuePriority::Normal,
            1,
            None,
        );
        let id = task.task_id;

        let retry_once = queue
            .retry_or_dead_letter(task, "transient error".to_string())
            .await;
        assert!(retry_once.is_ok());

        let retried_task = queue.dequeue().await;
        assert!(retried_task.is_some());
        let retried_task = retried_task.unwrap();
        assert_eq!(retried_task.attempts, 1);

        let move_to_dlq = queue
            .retry_or_dead_letter(retried_task, "retry budget exhausted".to_string())
            .await;
        assert!(move_to_dlq.is_ok());

        let dlq = queue.get_dead_letter(id).await;
        assert!(dlq.is_some());

        let metrics = queue.metrics().await;
        assert_eq!(metrics.retried, 1);
        assert_eq!(metrics.dead_lettered, 1);
    }
}
