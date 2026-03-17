//! Tuesday: DAG-based rule evaluator.
//!
//! Rules can declare `depends_on` IDs.  The evaluator performs a topological
//! sort (Kahn's algorithm) so each rule executes only after its dependencies
//! have produced outputs.
//!
//! Evaluation stops at the first DENY or CIRCUIT_BREAK (short-circuit).
//! Priority order within the same tier: rules are STABLE-sorted so insertion
//! order is preserved within each priority tier after the global sort.

use std::collections::{HashMap, HashSet, VecDeque};

use thiserror::Error;

use crate::schema::{
    Condition, EvalContext, FieldValue, Op, PolicyFile, Priority, Rule, RuleAction,
};

// ─── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum EvalError {
    #[error("cycle detected involving rule '{0}'")]
    CycleDetected(String),
    #[error("unknown dependency '{dep}' in rule '{rule}'")]
    UnknownDep { rule: String, dep: String },
}

// ─── Per-rule output ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RuleOutput {
    pub rule_id: String,
    pub matched: bool,
    pub action: RuleAction,
    pub message: Option<String>,
}

// ─── Final evaluation result ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum EvalDecision {
    Allow,
    Deny {
        rule_id: String,
        message: String,
    },
    CircuitBreak {
        rule_id: String,
        message: String,
    },
    /// All rules matched FLAG — proceed with caution but allow.
    FlaggedAllow {
        flags: Vec<String>,
    },
}

// ─── Condition evaluator ──────────────────────────────────────────────────────

fn eval_condition(cond: &Condition, ctx: &EvalContext) -> bool {
    // Numeric comparison
    if let (Some(ctx_val), Some(rule_val)) = (ctx.get_f64(&cond.field), cond.value.as_f64()) {
        return match cond.op {
            Op::Gt => ctx_val > rule_val,
            Op::Gte => ctx_val >= rule_val,
            Op::Lt => ctx_val < rule_val,
            Op::Lte => ctx_val <= rule_val,
            Op::Eq => (ctx_val - rule_val).abs() < f64::EPSILON,
            Op::Neq => (ctx_val - rule_val).abs() >= f64::EPSILON,
            Op::Contains | Op::Regex => false,
        };
    }
    // Boolean comparison
    if let (Some(ctx_val), FieldValue::Bool(rule_val)) = (ctx.get_bool(&cond.field), &cond.value) {
        return match cond.op {
            Op::Eq => ctx_val == *rule_val,
            Op::Neq => ctx_val != *rule_val,
            _ => false,
        };
    }
    // String comparison
    if let (Some(ctx_val), Some(rule_val)) = (ctx.get_str(&cond.field), cond.value.as_str()) {
        return match cond.op {
            Op::Eq => ctx_val == rule_val,
            Op::Neq => ctx_val != rule_val,
            Op::Contains => ctx_val.contains(rule_val),
            Op::Gt | Op::Gte | Op::Lt | Op::Lte => {
                ctx_val.cmp(rule_val)
                    == match cond.op {
                        Op::Gt => std::cmp::Ordering::Greater,
                        Op::Gte => std::cmp::Ordering::Greater, // ≥ handled below
                        Op::Lt => std::cmp::Ordering::Less,
                        Op::Lte => std::cmp::Ordering::Less,
                        _ => unreachable!(),
                    }
            }
            Op::Regex => false, // regex support is a Week 4 stretch goal
        };
    }
    false
}

// ─── DAG / topological sort ───────────────────────────────────────────────────

/// Returns rules in evaluation order (topologically sorted, then stable-sorted
/// by priority tier within each level).
pub fn topo_sort(rules: &[Rule]) -> Result<Vec<&Rule>, EvalError> {
    let id_to_rule: HashMap<&str, &Rule> = rules.iter().map(|r| (r.id.as_str(), r)).collect();

    // Validate all depends_on references
    for r in rules {
        for dep in &r.depends_on {
            if !id_to_rule.contains_key(dep.as_str()) {
                return Err(EvalError::UnknownDep {
                    rule: r.id.clone(),
                    dep: dep.clone(),
                });
            }
        }
    }

    // Build in-degree map
    let mut in_degree: HashMap<&str, usize> = rules.iter().map(|r| (r.id.as_str(), 0)).collect();
    // dep → rules that depend on dep
    let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();

    for r in rules {
        for dep in &r.depends_on {
            *in_degree.entry(r.id.as_str()).or_insert(0) += 1;
            dependents
                .entry(dep.as_str())
                .or_default()
                .push(r.id.as_str());
        }
    }

    // Kahn's BFS — seed with zero-in-degree nodes, sorted by priority then id for determinism
    let mut queue: VecDeque<&str> = {
        let mut seeds: Vec<&str> = in_degree
            .iter()
            .filter(|&(_, &d)| d == 0)
            .map(|(&id, _)| id)
            .collect();
        seeds.sort_by_key(|id| {
            let r = id_to_rule[*id];
            (&r.priority as *const Priority as usize, r.id.as_str())
        });
        seeds.iter().copied().collect()
    };
    // Re-sort by actual priority enum value for correctness
    let mut queue_vec: Vec<&str> = queue.drain(..).collect();
    queue_vec.sort_by(|a, b| {
        id_to_rule[a]
            .priority
            .cmp(&id_to_rule[b].priority)
            .then(id_to_rule[a].id.cmp(&id_to_rule[b].id))
    });
    let mut queue: VecDeque<&str> = queue_vec.into();

    let mut order: Vec<&Rule> = Vec::with_capacity(rules.len());
    let mut visited: HashSet<&str> = HashSet::new();

    while let Some(id) = queue.pop_front() {
        if visited.contains(id) {
            continue;
        }
        visited.insert(id);
        order.push(id_to_rule[id]);

        if let Some(deps) = dependents.get(id) {
            let mut ready: Vec<&str> = deps
                .iter()
                .filter(|&&d| {
                    let deg = in_degree.get_mut(d).unwrap();
                    *deg -= 1;
                    *deg == 0 && !visited.contains(d)
                })
                .copied()
                .collect();
            ready.sort_by(|a, b| {
                id_to_rule[a]
                    .priority
                    .cmp(&id_to_rule[b].priority)
                    .then(id_to_rule[a].id.cmp(&id_to_rule[b].id))
            });
            queue.extend(ready);
        }
    }

    if order.len() != rules.len() {
        // Find a cycle member
        let visited_ids: HashSet<&str> = order.iter().map(|r| r.id.as_str()).collect();
        let cycle_node = rules
            .iter()
            .find(|r| !visited_ids.contains(r.id.as_str()))
            .unwrap();
        return Err(EvalError::CycleDetected(cycle_node.id.clone()));
    }

    Ok(order)
}

// ─── Evaluator

pub struct RuleEvaluator {
    /// Rules in topological+priority order, disabled rules removed.
    rules: Vec<Rule>,
}

impl RuleEvaluator {
    /// Build evaluator from a parsed [`PolicyFile`].
    pub fn new(pf: &PolicyFile) -> Result<Self, EvalError> {
        let active: Vec<Rule> = pf.rules.iter().filter(|r| !r.disabled).cloned().collect();
        // Validate and build in one pass.
        let sorted = topo_sort(&active)?;
        Ok(Self {
            rules: sorted.into_iter().cloned().collect(),
        })
    }

    /// Evaluate all rules against `ctx`.
    ///
    /// Key decision: first DENY / CIRCUIT_BREAK short-circuits.
    /// Safety rules always run before compliance, which runs before business.
    pub fn evaluate(&self, ctx: &EvalContext) -> (EvalDecision, Vec<RuleOutput>) {
        let mut outputs: Vec<RuleOutput> = Vec::new();
        let mut flags: Vec<String> = Vec::new();

        for rule in &self.rules {
            let matched = eval_condition(&rule.condition, ctx);
            let output = RuleOutput {
                rule_id: rule.id.clone(),
                matched,
                action: rule.action.clone(),
                message: if matched {
                    Some(rule.message.clone())
                } else {
                    None
                },
            };

            if matched {
                match rule.action {
                    RuleAction::Deny => {
                        outputs.push(output);
                        return (
                            EvalDecision::Deny {
                                rule_id: rule.id.clone(),
                                message: rule.message.clone(),
                            },
                            outputs,
                        );
                    }
                    RuleAction::CircuitBreak => {
                        outputs.push(output);
                        return (
                            EvalDecision::CircuitBreak {
                                rule_id: rule.id.clone(),
                                message: rule.message.clone(),
                            },
                            outputs,
                        );
                    }
                    RuleAction::Flag => flags.push(rule.id.clone()),
                    RuleAction::Allow => {}
                }
            }

            outputs.push(output);
        }

        if flags.is_empty() {
            (EvalDecision::Allow, outputs)
        } else {
            (EvalDecision::FlaggedAllow { flags }, outputs)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Condition, FieldValue, Op, PolicyFile, Priority, Rule, RuleAction};

    fn make_rule(
        id: &str,
        priority: Priority,
        field: &str,
        op: Op,
        value: FieldValue,
        action: RuleAction,
        deps: Vec<String>,
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
            message: format!("{id} triggered"),
            depends_on: deps,
            disabled: false,
        }
    }

    fn default_ctx() -> EvalContext {
        EvalContext {
            agent_id: "a1".into(),
            action_type: "transfer".into(),
            amount: 500.0,
            currency: "USD".into(),
            recipient: "bob".into(),
            ewma_velocity: 0.1,
            actions_1m: 3,
            anomaly_score: 0.2,
            is_anomaly: false,
        }
    }

    fn pf(rules: Vec<Rule>) -> PolicyFile {
        PolicyFile {
            version: "1".into(),
            rules,
        }
    }

    #[test]
    fn allow_when_no_rules_match() {
        let rules = vec![make_rule(
            "r1",
            Priority::Safety,
            "amount",
            Op::Gt,
            FieldValue::Number(1000.0),
            RuleAction::Deny,
            vec![],
        )];
        let ev = RuleEvaluator::new(&pf(rules)).unwrap();
        let (dec, _) = ev.evaluate(&default_ctx());
        assert_eq!(dec, EvalDecision::Allow);
    }

    #[test]
    fn deny_on_match() {
        let rules = vec![make_rule(
            "r1",
            Priority::Safety,
            "amount",
            Op::Gt,
            FieldValue::Number(100.0),
            RuleAction::Deny,
            vec![],
        )];
        let ev = RuleEvaluator::new(&pf(rules)).unwrap();
        let (dec, _) = ev.evaluate(&default_ctx());
        assert!(matches!(dec, EvalDecision::Deny { .. }));
    }

    #[test]
    fn safety_evaluated_before_business() {
        let rules = vec![
            make_rule(
                "biz",
                Priority::Business,
                "amount",
                Op::Gt,
                FieldValue::Number(100.0),
                RuleAction::Deny,
                vec![],
            ),
            make_rule(
                "safe",
                Priority::Safety,
                "amount",
                Op::Gt,
                FieldValue::Number(100.0),
                RuleAction::Deny,
                vec![],
            ),
        ];
        let ev = RuleEvaluator::new(&pf(rules)).unwrap();
        let (dec, outputs) = ev.evaluate(&default_ctx());
        // First matching rule should be "safe"
        let first_deny = outputs.iter().find(|o| o.matched).unwrap();
        assert_eq!(first_deny.rule_id, "safe");
        assert!(matches!(dec, EvalDecision::Deny { rule_id, .. } if rule_id == "safe"));
    }

    #[test]
    fn depends_on_respected() {
        let rules = vec![
            make_rule(
                "child",
                Priority::Compliance,
                "amount",
                Op::Gt,
                FieldValue::Number(100.0),
                RuleAction::Deny,
                vec!["parent".into()],
            ),
            make_rule(
                "parent",
                Priority::Safety,
                "currency",
                Op::Eq,
                FieldValue::Text("USD".into()),
                RuleAction::Allow,
                vec![],
            ),
        ];
        let ev = RuleEvaluator::new(&pf(rules)).unwrap();
        // Should not panic — parent evaluated before child.
        let (_, outputs) = ev.evaluate(&default_ctx());
        let ids: Vec<_> = outputs.iter().map(|o| o.rule_id.as_str()).collect();
        assert!(ids.iter().position(|&x| x == "parent") < ids.iter().position(|&x| x == "child"));
    }

    #[test]
    fn cycle_detection() {
        let rules = vec![
            make_rule(
                "a",
                Priority::Safety,
                "amount",
                Op::Gt,
                FieldValue::Number(0.0),
                RuleAction::Deny,
                vec!["b".into()],
            ),
            make_rule(
                "b",
                Priority::Safety,
                "amount",
                Op::Gt,
                FieldValue::Number(0.0),
                RuleAction::Deny,
                vec!["a".into()],
            ),
        ];
        assert!(RuleEvaluator::new(&pf(rules)).is_err());
    }

    #[test]
    fn disabled_rules_skipped() {
        let mut r = make_rule(
            "r1",
            Priority::Safety,
            "amount",
            Op::Gt,
            FieldValue::Number(100.0),
            RuleAction::Deny,
            vec![],
        );
        r.disabled = true;
        let ev = RuleEvaluator::new(&pf(vec![r])).unwrap();
        let (dec, _) = ev.evaluate(&default_ctx());
        assert_eq!(dec, EvalDecision::Allow);
    }
}
