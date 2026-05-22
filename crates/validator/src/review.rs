use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewEntry {
    pub transaction_id: String,
    pub agent_id: String,
    pub decision: String,
    pub policy_code: Option<String>,
    pub reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub outcome: Option<ReviewOutcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewOutcome {
    /// One of: TRUE_POSITIVE, FALSE_POSITIVE, EXPECTED_EDGE_CASE
    pub verdict: String,
    pub impact_usd: Option<f64>,
    pub reviewer_id: Option<String>,
    pub notes: Option<String>,
    pub reviewed_at: DateTime<Utc>,
}

/// Request body for `POST /admin/review-queue/:tx_id/outcome`.
#[derive(Debug, Deserialize)]
pub struct OutcomeRequest {
    pub verdict: String,
    pub impact_usd: Option<f64>,
    pub reviewer_id: Option<String>,
    pub notes: Option<String>,
}

impl OutcomeRequest {
    pub fn into_outcome(self) -> ReviewOutcome {
        ReviewOutcome {
            verdict: self.verdict,
            impact_usd: self.impact_usd,
            reviewer_id: self.reviewer_id,
            notes: self.notes,
            reviewed_at: Utc::now(),
        }
    }
}

pub struct ReviewQueue {
    entries: DashMap<String, ReviewEntry>,
}

impl ReviewQueue {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    pub fn push(&self, entry: ReviewEntry) {
        self.entries.insert(entry.transaction_id.clone(), entry);
    }

    pub fn pending(&self) -> Vec<ReviewEntry> {
        let mut out: Vec<ReviewEntry> = self
            .entries
            .iter()
            .filter(|e| e.value().outcome.is_none())
            .map(|e| e.value().clone())
            .collect();
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        out
    }

    pub fn all(&self) -> Vec<ReviewEntry> {
        let mut out: Vec<ReviewEntry> = self.entries.iter().map(|e| e.value().clone()).collect();
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        out
    }

    pub fn submit_outcome(&self, tx_id: &str, outcome: ReviewOutcome) -> bool {
        match self.entries.get_mut(tx_id) {
            Some(mut entry) => {
                entry.outcome = Some(outcome);
                true
            }
            None => false,
        }
    }

    pub fn get(&self, tx_id: &str) -> Option<ReviewEntry> {
        self.entries.get(tx_id).map(|e| e.value().clone())
    }
}

impl Default for ReviewQueue {
    fn default() -> Self {
        Self::new()
    }
}
