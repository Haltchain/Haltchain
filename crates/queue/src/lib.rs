use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use uuid::Uuid;

pub type QueueId = Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeepScanTask {
    pub task_id: QueueId,
    pub agent_id: String,
    pub session_id: String,
    pub reasoning_trace: String,
    pub callback_url: Option<String>,
    pub enqueued_at: DateTime<Utc>,
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
        }
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

#[async_trait]
pub trait ScanQueue: Send + Sync {
    async fn enqueue(&self, task: DeepScanTask) -> Result<QueueId, QueueError>;
    async fn dequeue(&self) -> Option<DeepScanTask>;
    async fn complete(&self, id: QueueId, result: ScanResult) -> Result<(), QueueError>;
    async fn get_completed(&self, id: QueueId) -> Option<ScanResult>;
}

pub struct TokioChannelQueue {
    tx: mpsc::Sender<DeepScanTask>,
    rx: Mutex<mpsc::Receiver<DeepScanTask>>,
    completed: DashMap<QueueId, ScanResult>,
}

impl TokioChannelQueue {
    pub fn new(buffer: usize) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(buffer.max(1));
        Arc::new(Self {
            tx,
            rx: Mutex::new(rx),
            completed: DashMap::new(),
        })
    }
}

#[async_trait]
impl ScanQueue for TokioChannelQueue {
    async fn enqueue(&self, task: DeepScanTask) -> Result<QueueId, QueueError> {
        let id = task.task_id;
        self.tx
            .send(task)
            .await
            .map_err(|_| QueueError::QueueClosed)?;
        Ok(id)
    }

    async fn dequeue(&self) -> Option<DeepScanTask> {
        self.rx.lock().await.recv().await
    }

    async fn complete(&self, id: QueueId, result: ScanResult) -> Result<(), QueueError> {
        self.completed.insert(id, result);
        Ok(())
    }

    async fn get_completed(&self, id: QueueId) -> Option<ScanResult> {
        self.completed.get(&id).map(|entry| entry.clone())
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
}
