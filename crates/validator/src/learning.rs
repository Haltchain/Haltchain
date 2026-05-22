use std::{collections::HashMap, sync::atomic::Ordering};

use haltchain_db::{
    AdjustmentRecommendationRecord, OutcomeLearningRecord, PolicyAdjustmentRecord,
    StoredRecommendationRecord,
};
use uuid::Uuid;

use crate::{
    AppState,
    thresholds::PolicyVariant,
    types::{
        AdjustmentRecommendation, ApproveRecommendationRequest, LearningRunReport,
        RejectRecommendationRequest, RevertRecommendationRequest,
    },
};

impl AppState {
    pub(crate) fn threshold_key_from_policy(policy_code: &str) -> Option<String> {
        if policy_code.contains(':') {
            return Some(policy_code.to_string());
        }
        match policy_code {
            "TOKEN_RATE_EXCEEDED" => Some("resource:max_tokens_per_minute".to_string()),
            "COMPUTE_EXCEEDED" => Some("resource:max_compute_seconds_per_hour".to_string()),
            _ => None,
        }
    }

    pub(crate) fn default_threshold_for_key(key: &str) -> f64 {
        match key {
            "resource:max_tokens_per_minute" => 100_000.0,
            "resource:max_compute_seconds_per_hour" => 3_600.0,
            _ => 1.0,
        }
    }

    pub(crate) fn to_adjustment_recommendation(
        row: StoredRecommendationRecord,
    ) -> AdjustmentRecommendation {
        AdjustmentRecommendation {
            id: row.id,
            recommendation_key: row.recommendation_key,
            threshold_key: row.threshold_key,
            current_threshold: row.current_threshold,
            proposed_threshold: row.proposed_threshold,
            sample_size: row.sample_size as usize,
            false_positive_count: row.false_positive_count as usize,
            true_positive_count: row.true_positive_count as usize,
            confidence: row.confidence,
            rationale: row.rationale,
            status: row.status,
            trigger_outcome_id: row.trigger_outcome_id,
            trigger_transaction_id: row.trigger_transaction_id.map(|v| v.to_string()),
            decided_by: row.decided_by,
            decision_notes: row.decision_notes,
            variant_id: row.variant_id,
            applied_adjustment_id: row.applied_adjustment_id,
        }
    }

    pub(crate) fn clamp_and_round_threshold(v: f64) -> f64 {
        let bounded = v.max(0.0001);
        (bounded * 10_000.0).round() / 10_000.0
    }

    pub async fn run_learning_loop_once(&self, max_age_hours: i64) -> LearningRunReport {
        let outcomes: Vec<OutcomeLearningRecord> = if let Some(db) = &self.db {
            match db.list_learning_outcomes(max_age_hours).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("learning-loop: outcomes query failed: {e}");
                    Vec::new()
                }
            }
        } else {
            self.review_queue
                .all()
                .into_iter()
                .enumerate()
                .filter_map(|(idx, entry)| {
                    let outcome = entry.outcome?;
                    let tx = Uuid::parse_str(&entry.transaction_id).ok()?;
                    Some(OutcomeLearningRecord {
                        outcome_id: idx as i64 + 1,
                        transaction_id: tx,
                        policy_code: entry.policy_code,
                        outcome: outcome.verdict,
                    })
                })
                .collect()
        };

        #[derive(Default)]
        struct Bucket {
            fp: usize,
            tp: usize,
            sample: usize,
            trigger_outcome_id: Option<i64>,
            trigger_tx_id: Option<Uuid>,
        }

        let mut by_threshold: HashMap<String, Bucket> = HashMap::new();
        for o in &outcomes {
            let Some(policy_code) = o.policy_code.as_deref() else {
                continue;
            };
            let Some(threshold_key) = Self::threshold_key_from_policy(policy_code) else {
                continue;
            };

            let bucket = by_threshold.entry(threshold_key).or_default();
            bucket.sample += 1;
            match o.outcome.as_str() {
                "FALSE_POSITIVE" => bucket.fp += 1,
                "TRUE_POSITIVE" => bucket.tp += 1,
                _ => {}
            }
            if bucket.trigger_outcome_id.is_none() {
                bucket.trigger_outcome_id = Some(o.outcome_id);
                bucket.trigger_tx_id = Some(o.transaction_id);
            }
        }

        let mut keys: Vec<String> = by_threshold.keys().cloned().collect();
        keys.sort();

        let mut generated = 0usize;
        for threshold_key in keys {
            let bucket = by_threshold.remove(&threshold_key).unwrap_or_default();
            if bucket.sample < 3 {
                continue;
            }

            let fp_rate = bucket.fp as f64 / bucket.sample as f64;
            let tp_rate = bucket.tp as f64 / bucket.sample as f64;
            let current = self
                .thresholds
                .get(&threshold_key)
                .unwrap_or_else(|| Self::default_threshold_for_key(&threshold_key));

            let maybe_proposed = if fp_rate >= 0.5 {
                Some(current * 1.10)
            } else if tp_rate >= 0.8 {
                Some(current * 0.90)
            } else {
                None
            };

            let Some(proposed_raw) = maybe_proposed else {
                continue;
            };
            let proposed = Self::clamp_and_round_threshold(proposed_raw);
            if (proposed - current).abs() < f64::EPSILON {
                continue;
            }

            let confidence =
                ((bucket.sample as f64 / 20.0).min(1.0) * (fp_rate.max(tp_rate))).min(1.0);
            let recommendation_key = format!(
                "{threshold_key}:{}:{}:{}",
                bucket.sample, bucket.fp, bucket.tp
            );
            let rationale = format!(
                "sample={}, fp_rate={:.3}, tp_rate={:.3}, proposed_from={:.4}",
                bucket.sample, fp_rate, tp_rate, current
            );

            let mut recommendation = AdjustmentRecommendation {
                id: self.next_recommendation_id.fetch_add(1, Ordering::SeqCst),
                recommendation_key: recommendation_key.clone(),
                threshold_key: threshold_key.clone(),
                current_threshold: current,
                proposed_threshold: proposed,
                sample_size: bucket.sample,
                false_positive_count: bucket.fp,
                true_positive_count: bucket.tp,
                confidence,
                rationale: rationale.clone(),
                status: "pending".to_string(),
                trigger_outcome_id: bucket.trigger_outcome_id,
                trigger_transaction_id: bucket.trigger_tx_id.map(|v| v.to_string()),
                decided_by: None,
                decision_notes: None,
                variant_id: None,
                applied_adjustment_id: None,
            };

            if let Some(db) = &self.db {
                let db_rec = AdjustmentRecommendationRecord {
                    recommendation_key,
                    threshold_key,
                    current_threshold: current,
                    proposed_threshold: proposed,
                    sample_size: bucket.sample as i32,
                    false_positive_count: bucket.fp as i32,
                    true_positive_count: bucket.tp as i32,
                    confidence,
                    rationale,
                    trigger_outcome_id: bucket.trigger_outcome_id,
                    trigger_transaction_id: bucket.trigger_tx_id,
                };
                match db.upsert_adjustment_recommendation(&db_rec).await {
                    Ok(id) => recommendation.id = id,
                    Err(e) => tracing::warn!("learning-loop: recommendation upsert failed: {e}"),
                }
            }

            self.recommendations
                .insert(recommendation.id, recommendation);
            generated += 1;
        }

        LearningRunReport {
            generated,
            considered_outcomes: outcomes.len(),
        }
    }

    pub async fn list_recommendations(
        &self,
        status_filter: Option<&str>,
    ) -> Vec<AdjustmentRecommendation> {
        if let Some(db) = &self.db {
            match db.list_adjustment_recommendations(status_filter).await {
                Ok(rows) => {
                    let mut out: Vec<_> = rows
                        .into_iter()
                        .map(Self::to_adjustment_recommendation)
                        .collect();
                    out.sort_by(|a, b| a.id.cmp(&b.id));
                    return out;
                }
                Err(e) => tracing::warn!("recommendation list failed: {e}"),
            }
        }

        let mut out: Vec<_> = self
            .recommendations
            .iter()
            .map(|e| e.value().clone())
            .collect();
        if let Some(status) = status_filter {
            out.retain(|r| r.status == status);
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    pub async fn approve_recommendation(
        &self,
        recommendation_id: i64,
        req: ApproveRecommendationRequest,
    ) -> Result<AdjustmentRecommendation, String> {
        if req.reviewer_id.trim().is_empty() {
            return Err("reviewer_id is required".to_string());
        }

        let mut recommendation = if let Some(db) = &self.db {
            let row = db
                .get_adjustment_recommendation(recommendation_id)
                .await
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "recommendation not found".to_string())?;
            Self::to_adjustment_recommendation(row)
        } else {
            self.recommendations
                .get(&recommendation_id)
                .map(|e| e.value().clone())
                .ok_or_else(|| "recommendation not found".to_string())?
        };

        if recommendation.status != "pending" {
            return Err("recommendation is not pending".to_string());
        }

        let (domain, rule_id) = recommendation
            .threshold_key
            .split_once(':')
            .ok_or_else(|| "invalid threshold key".to_string())?;
        if !matches!(
            domain,
            "financial" | "privacy" | "security" | "operational" | "compliance" | "resource"
        ) {
            return Err("invalid threshold domain".to_string());
        }

        let mut variant_id: Option<String> = None;
        if req.apply_as_variant {
            if req.agent_ids.is_empty() {
                return Err("agent_ids required when apply_as_variant=true".to_string());
            }
            let id = format!("rec-{recommendation_id}-{}", Uuid::new_v4());
            self.thresholds.add_variant(PolicyVariant {
                id: id.clone(),
                name: format!("Recommendation {recommendation_id}"),
                thresholds: HashMap::from([(
                    recommendation.threshold_key.clone(),
                    recommendation.proposed_threshold,
                )]),
                agent_ids: req.agent_ids.clone(),
            });
            variant_id = Some(id);
        } else {
            self.thresholds.set(
                recommendation.threshold_key.clone(),
                recommendation.proposed_threshold,
            );
        }

        let mut applied_adjustment_id = None;
        if let Some(db) = &self.db {
            let adjustment = PolicyAdjustmentRecord {
                rule_id: rule_id.to_string(),
                domain: domain.to_string(),
                old_threshold: Some(recommendation.current_threshold),
                new_threshold: Some(recommendation.proposed_threshold),
                reason: format!("Approved recommendation #{recommendation_id}"),
                adjusted_by: req.reviewer_id.clone(),
                trigger_outcome_id: recommendation.trigger_outcome_id,
                recommendation_id: Some(recommendation_id),
                variant_id: variant_id.clone(),
            };
            applied_adjustment_id = db.insert_policy_adjustment(&adjustment).await.ok();

            let status = if variant_id.is_some() {
                "applied"
            } else {
                "approved"
            };
            db.decide_adjustment_recommendation(
                recommendation_id,
                status,
                &req.reviewer_id,
                req.notes.as_deref(),
                variant_id.as_deref(),
                applied_adjustment_id,
            )
            .await
            .map_err(|e| e.to_string())?;
        }

        recommendation.status = if variant_id.is_some() {
            "applied".to_string()
        } else {
            "approved".to_string()
        };
        recommendation.decided_by = Some(req.reviewer_id);
        recommendation.decision_notes = req.notes;
        recommendation.variant_id = variant_id;
        recommendation.applied_adjustment_id = applied_adjustment_id;
        self.recommendations
            .insert(recommendation_id, recommendation.clone());
        Ok(recommendation)
    }

    pub async fn reject_recommendation(
        &self,
        recommendation_id: i64,
        req: RejectRecommendationRequest,
    ) -> Result<AdjustmentRecommendation, String> {
        if req.reviewer_id.trim().is_empty() {
            return Err("reviewer_id is required".to_string());
        }

        let mut recommendation = if let Some(db) = &self.db {
            let row = db
                .get_adjustment_recommendation(recommendation_id)
                .await
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "recommendation not found".to_string())?;
            db.decide_adjustment_recommendation(
                recommendation_id,
                "rejected",
                &req.reviewer_id,
                req.notes.as_deref(),
                None,
                None,
            )
            .await
            .map_err(|e| e.to_string())?;
            Self::to_adjustment_recommendation(row)
        } else {
            self.recommendations
                .get(&recommendation_id)
                .map(|e| e.value().clone())
                .ok_or_else(|| "recommendation not found".to_string())?
        };

        recommendation.status = "rejected".to_string();
        recommendation.decided_by = Some(req.reviewer_id);
        recommendation.decision_notes = req.notes;
        self.recommendations
            .insert(recommendation_id, recommendation.clone());
        Ok(recommendation)
    }

    pub async fn revert_recommendation(
        &self,
        recommendation_id: i64,
        req: RevertRecommendationRequest,
    ) -> Result<AdjustmentRecommendation, String> {
        if req.reviewer_id.trim().is_empty() {
            return Err("reviewer_id is required".to_string());
        }

        let mut recommendation = if let Some(db) = &self.db {
            let row = db
                .get_adjustment_recommendation(recommendation_id)
                .await
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "recommendation not found".to_string())?;
            Self::to_adjustment_recommendation(row)
        } else {
            self.recommendations
                .get(&recommendation_id)
                .map(|e| e.value().clone())
                .ok_or_else(|| "recommendation not found".to_string())?
        };

        if recommendation.status != "applied" {
            return Err("only applied recommendations can be reverted".to_string());
        }

        if let Some(variant_id) = recommendation.variant_id.clone() {
            self.thresholds.remove_variant(&variant_id);
        } else {
            self.thresholds.set(
                recommendation.threshold_key.clone(),
                recommendation.current_threshold,
            );
        }

        let (domain, rule_id) = recommendation
            .threshold_key
            .split_once(':')
            .ok_or_else(|| "invalid threshold key".to_string())?;

        let mut revert_adjustment_id = None;
        if let Some(db) = &self.db {
            let adjustment = PolicyAdjustmentRecord {
                rule_id: rule_id.to_string(),
                domain: domain.to_string(),
                old_threshold: Some(recommendation.proposed_threshold),
                new_threshold: Some(recommendation.current_threshold),
                reason: format!("Revert recommendation #{recommendation_id}"),
                adjusted_by: req.reviewer_id.clone(),
                trigger_outcome_id: recommendation.trigger_outcome_id,
                recommendation_id: Some(recommendation_id),
                variant_id: recommendation.variant_id.clone(),
            };
            revert_adjustment_id = db.insert_policy_adjustment(&adjustment).await.ok();

            db.mark_recommendation_reverted(
                recommendation_id,
                &req.reviewer_id,
                req.notes.as_deref(),
                revert_adjustment_id,
            )
            .await
            .map_err(|e| e.to_string())?;
        }

        recommendation.status = "reverted".to_string();
        recommendation.decided_by = Some(req.reviewer_id);
        recommendation.decision_notes = req.notes;
        recommendation.applied_adjustment_id = revert_adjustment_id;
        self.recommendations
            .insert(recommendation_id, recommendation.clone());
        Ok(recommendation)
    }
}
