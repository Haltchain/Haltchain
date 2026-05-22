use crate::domain::Domain;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use haltchain_db::{CapabilityTrajectoryRecord, DbError, DbStore};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;

pub type AgentId = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityEntry {
    pub agent_id: AgentId,
    pub domain: Domain,
    pub knowledge_delta: f64,
    pub created_at: DateTime<Utc>,
}

pub struct TrajectoryStore {
    entries: DashMap<(AgentId, Domain), Vec<CapabilityEntry>>,
    wal_buffer: Arc<Mutex<VecDeque<CapabilityEntry>>>,
}

impl TrajectoryStore {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            wal_buffer: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    pub fn push(&self, entry: CapabilityEntry) {
        let key = (entry.agent_id.clone(), entry.domain.clone());
        self.entries.entry(key).or_default().push(entry.clone());
        self.wal_buffer.lock().push_back(entry);
    }

    pub fn wal_len(&self) -> usize {
        self.wal_buffer.lock().len()
    }

    /// Drain up to `limit` entries from the WAL buffer for flushing to DB.
    pub fn drain_wal(&self, limit: usize) -> Vec<CapabilityEntry> {
        let mut buf = self.wal_buffer.lock();
        let n = buf.len().min(limit);
        buf.drain(..n).collect()
    }

    pub fn agent_domain_entries(&self, agent_id: &str, domain: &Domain) -> Vec<CapabilityEntry> {
        let key = (agent_id.to_string(), domain.clone());
        self.entries
            .get(&key)
            .map_or_else(Vec::new, |v| v.value().clone())
    }

    pub fn agent_entry_count(&self, agent_id: &str) -> usize {
        Domain::all()
            .iter()
            .map(|d| {
                self.entries
                    .get(&(agent_id.to_string(), d.clone()))
                    .map_or(0, |v| v.value().len())
            })
            .sum()
    }

    /// Drain the WAL buffer and persist to Postgres. Entries already in the
    /// in-memory map are not affected; only the WAL is drained.
    pub async fn flush_to_db(&self, db: &DbStore) -> Result<usize, DbError> {
        let entries = self.drain_wal(usize::MAX);
        if entries.is_empty() {
            return Ok(0);
        }
        let records: Vec<CapabilityTrajectoryRecord> = entries
            .iter()
            .map(|e| CapabilityTrajectoryRecord {
                agent_id: e.agent_id.clone(),
                domain: e.domain.to_string(),
                knowledge_delta: e.knowledge_delta,
                created_at: e.created_at,
            })
            .collect();
        db.insert_capability_trajectory_batch(&records).await?;
        Ok(records.len())
    }
}

impl Default for TrajectoryStore {
    fn default() -> Self {
        Self::new()
    }
}
