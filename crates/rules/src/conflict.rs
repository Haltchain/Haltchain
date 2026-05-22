//! Wednesday: Conflict detection graph.
//!
//! Detects two classes of rule conflicts:
//!   1. **Shadow-conflicts** — a higher-priority rule makes a lower-priority
//!      rule unreachable because their conditions overlap and one action is
//!      ALLOW while the other is DENY/CIRCUIT_BREAK.
//!   2. **Same-tier contradictions** — two rules with identical priority, the
//!      same condition field + op + value, but opposite actions.
//!
//! Implemented as a directed graph F(rule_id) → set_of(conflicting rule_ids).

use std::collections::HashMap;

use crate::schema::{FieldValue, PolicyFile, Rule, RuleAction};

// ─── Conflict types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ConflictKind {
    /// Rule A (higher priority DENY/CB) shadows Rule B (allow) on same field.
    Shadow {
        blocker_id: String,
        shadowed_id: String,
    },
    /// Rules A and B have the same condition but opposite ALLOW vs DENY actions
    /// within the same priority tier.
    Contradiction { rule_a: String, rule_b: String },
}

// ─── Graph ────────────────────────────────────────────────────────────────────

pub struct ConflictGraph {
    conflicts: Vec<ConflictKind>,
    /// adjacency: rule_id → Vec<conflicting rule_ids>
    adjacency: HashMap<String, Vec<String>>,
}

impl ConflictGraph {
    /// Analyse all rules in `pf` and build the conflict graph.
    pub fn build(pf: &PolicyFile) -> Self {
        let active: Vec<&Rule> = pf.rules.iter().filter(|r| !r.disabled).collect();
        let mut conflicts = Vec::new();

        for i in 0..active.len() {
            for j in (i + 1)..active.len() {
                let a = active[i];
                let b = active[j];

                let same_field = a.condition.field == b.condition.field;
                let same_op = a.condition.op == b.condition.op;
                let same_val = values_equal(&a.condition.value, &b.condition.value);

                if !same_field {
                    continue;
                }

                // Shadow: higher-prio DENY/CB blocks lower-prio ALLOW on same field.
                if same_op && same_val {
                    let a_blocks = is_blocking(&a.action);
                    let b_blocks = is_blocking(&b.action);
                    let a_higher = a.priority < b.priority; // lower enum value = higher priority
                    let b_higher = b.priority < a.priority;

                    if a_blocks && !b_blocks && a_higher {
                        conflicts.push(ConflictKind::Shadow {
                            blocker_id: a.id.clone(),
                            shadowed_id: b.id.clone(),
                        });
                    } else if b_blocks && !a_blocks && b_higher {
                        conflicts.push(ConflictKind::Shadow {
                            blocker_id: b.id.clone(),
                            shadowed_id: a.id.clone(),
                        });
                    }

                    // Same-tier contradiction
                    if a.priority == b.priority && (a_blocks ^ b_blocks) {
                        conflicts.push(ConflictKind::Contradiction {
                            rule_a: a.id.clone(),
                            rule_b: b.id.clone(),
                        });
                    }
                }

                // Overlapping range: one rule is `Gt X` and another is `Lt X` on the same field —
                // common but not a conflict (they cover disjoint ranges).
                // We only flag same-op / same-value conflicts above.
            }
        }

        // Build adjacency list
        let mut adjacency: HashMap<String, Vec<String>> = HashMap::new();
        for c in &conflicts {
            match c {
                ConflictKind::Shadow {
                    blocker_id,
                    shadowed_id,
                } => {
                    adjacency
                        .entry(blocker_id.clone())
                        .or_default()
                        .push(shadowed_id.clone());
                    adjacency
                        .entry(shadowed_id.clone())
                        .or_default()
                        .push(blocker_id.clone());
                }
                ConflictKind::Contradiction { rule_a, rule_b } => {
                    adjacency
                        .entry(rule_a.clone())
                        .or_default()
                        .push(rule_b.clone());
                    adjacency
                        .entry(rule_b.clone())
                        .or_default()
                        .push(rule_a.clone());
                }
            }
        }

        Self {
            conflicts,
            adjacency,
        }
    }

    pub fn conflicts(&self) -> &[ConflictKind] {
        &self.conflicts
    }

    pub fn has_conflicts(&self) -> bool {
        !self.conflicts.is_empty()
    }

    pub fn neighbors(&self, rule_id: &str) -> &[String] {
        self.adjacency
            .get(rule_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn is_blocking(action: &RuleAction) -> bool {
    matches!(action, RuleAction::Deny | RuleAction::CircuitBreak)
}

fn values_equal(a: &FieldValue, b: &FieldValue) -> bool {
    match (a, b) {
        (FieldValue::Number(x), FieldValue::Number(y)) => (x - y).abs() < f64::EPSILON,
        (FieldValue::Text(x), FieldValue::Text(y)) => x == y,
        (FieldValue::Bool(x), FieldValue::Bool(y)) => x == y,
        _ => false,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{
        Condition, EnforcementMode, FieldValue, Op, PolicyFile, Priority, Rule, RuleAction,
    };

    fn rule(
        id: &str,
        priority: Priority,
        field: &str,
        op: Op,
        value: FieldValue,
        action: RuleAction,
    ) -> Rule {
        Rule {
            id: id.into(),
            priority,
            description: id.into(),
            condition: Condition {
                field: field.into(),
                op,
                value,
            },
            action,
            message: id.into(),
            depends_on: vec![],
            disabled: false,
        }
    }

    fn pf(rules: Vec<Rule>) -> PolicyFile {
        PolicyFile {
            version: "1".into(),
            rules,
            max_delegation_depth: None,
            enforcement_mode: EnforcementMode::default(),
        }
    }

    #[test]
    fn no_conflicts_for_unrelated_rules() {
        let rules = vec![
            rule(
                "r1",
                Priority::Safety,
                "amount",
                Op::Gt,
                FieldValue::Number(1000.0),
                RuleAction::Deny,
            ),
            rule(
                "r2",
                Priority::Compliance,
                "currency",
                Op::Eq,
                FieldValue::Text("EUR".into()),
                RuleAction::Flag,
            ),
        ];
        let g = ConflictGraph::build(&pf(rules));
        assert!(!g.has_conflicts());
    }

    #[test]
    fn detects_shadow_conflict() {
        let rules = vec![
            rule(
                "block",
                Priority::Safety,
                "amount",
                Op::Gt,
                FieldValue::Number(500.0),
                RuleAction::Deny,
            ),
            rule(
                "allow",
                Priority::Business,
                "amount",
                Op::Gt,
                FieldValue::Number(500.0),
                RuleAction::Allow,
            ),
        ];
        let g = ConflictGraph::build(&pf(rules));
        assert!(g.has_conflicts());
        assert!(
            matches!(&g.conflicts()[0], ConflictKind::Shadow { blocker_id, shadowed_id }
            if blocker_id == "block" && shadowed_id == "allow")
        );
    }

    #[test]
    fn detects_contradiction_same_tier() {
        let rules = vec![
            rule(
                "deny_big",
                Priority::Safety,
                "amount",
                Op::Gt,
                FieldValue::Number(500.0),
                RuleAction::Deny,
            ),
            rule(
                "allow_big",
                Priority::Safety,
                "amount",
                Op::Gt,
                FieldValue::Number(500.0),
                RuleAction::Allow,
            ),
        ];
        let g = ConflictGraph::build(&pf(rules));
        assert!(g.has_conflicts());
        assert!(
            g.conflicts()
                .iter()
                .any(|c| matches!(c, ConflictKind::Contradiction { .. }))
        );
    }

    #[test]
    fn no_conflict_different_thresholds() {
        let rules = vec![
            rule(
                "r1",
                Priority::Safety,
                "amount",
                Op::Gt,
                FieldValue::Number(1000.0),
                RuleAction::Deny,
            ),
            rule(
                "r2",
                Priority::Business,
                "amount",
                Op::Lte,
                FieldValue::Number(1000.0),
                RuleAction::Allow,
            ),
        ];
        let g = ConflictGraph::build(&pf(rules));
        assert!(!g.has_conflicts());
    }

    #[test]
    fn adjacency_lists_populated() {
        let rules = vec![
            rule(
                "block",
                Priority::Safety,
                "amount",
                Op::Gt,
                FieldValue::Number(500.0),
                RuleAction::Deny,
            ),
            rule(
                "allow",
                Priority::Business,
                "amount",
                Op::Gt,
                FieldValue::Number(500.0),
                RuleAction::Allow,
            ),
        ];
        let g = ConflictGraph::build(&pf(rules));
        assert!(g.neighbors("block").contains(&"allow".to_string()));
        assert!(g.neighbors("allow").contains(&"block".to_string()));
    }
}
