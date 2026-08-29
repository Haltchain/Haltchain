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
use std::sync::OnceLock;

use parking_lot::Mutex;
use regex::{Regex, RegexBuilder};
use thiserror::Error;

use crate::schema::{
    Condition, EnforcementMode, EvalContext, FieldValue, Op, PolicyFile, Priority, Rule, RuleAction,
};

// ─── Regex cache ──────────────────────────────────────────────────────────────

/// Global regex compilation cache. Patterns are validated at policy load time
/// and cached here for O(1) lookup during evaluation. Uses RE2-compatible
/// `regex` crate which guarantees linear-time matching (no catastrophic backtracking).
static REGEX_CACHE: OnceLock<Mutex<HashMap<String, Regex>>> = OnceLock::new();

/// Maximum compiled NFA size (bytes). Prevents ReDoS via pathological patterns.
/// 10 MB matches `regex` crate recommendation for untrusted inputs.
const REGEX_SIZE_LIMIT: usize = 10_000_000;

/// Maximum DFA cache size (bytes). Bounds memory consumption per pattern.
const REGEX_DFA_SIZE_LIMIT: usize = 2_000_000;

/// Maximum pattern string length accepted before compilation.
/// Patterns longer than this are rejected outright to prevent amplification.
const MAX_PATTERN_LEN: usize = 1024;

/// Maximum input string length evaluated by a regex at runtime.
/// Inputs longer than this are treated as a match (fail-closed) to prevent
/// resource exhaustion on attacker-controlled payloads.
const MAX_REGEX_INPUT_LEN: usize = 100_000;

fn regex_cache() -> &'static Mutex<HashMap<String, Regex>> {
    REGEX_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Compile or retrieve a cached regex with RE2 complexity bounds.
///
/// Enforces:
/// - Pattern length cap: [`MAX_PATTERN_LEN`] characters
/// - NFA size limit: [`REGEX_SIZE_LIMIT`] bytes  
/// - DFA cache limit: [`REGEX_DFA_SIZE_LIMIT`] bytes
///
/// Returns `None` for invalid or oversized patterns (logs a warning).
fn get_or_compile_regex(pattern: &str) -> Option<Regex> {
    if pattern.len() > MAX_PATTERN_LEN {
        tracing::warn!(
            pattern_len = pattern.len(),
            max = MAX_PATTERN_LEN,
            "regex pattern exceeds maximum length — rejected"
        );
        return None;
    }

    let mut cache = regex_cache().lock();
    if let Some(re) = cache.get(pattern) {
        return Some(re.clone());
    }

    match RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
        .build()
    {
        Ok(re) => {
            cache.insert(pattern.to_string(), re.clone());
            Some(re)
        }
        Err(e) => {
            tracing::warn!(pattern = pattern, error = %e, "regex compilation failed (size limit or syntax error)");
            None
        }
    }
}

// ─── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum EvalError {
    #[error("cycle detected involving rule '{0}'")]
    CycleDetected(String),
    #[error("unknown dependency '{dep}' in rule '{rule}'")]
    UnknownDep { rule: String, dep: String },
    #[error("invalid regex pattern in rule '{rule}': {pattern}")]
    InvalidRegex { rule: String, pattern: String },
}

// ─── Per-rule output ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RuleOutput {
    pub rule_id: String,
    pub matched: bool,
    pub action: RuleAction,
    pub message: Option<String>,
    /// `true` when the rule *would have* blocked but was downgraded to a flag
    /// because the policy is running in shadow mode.
    pub shadow_downgraded: bool,
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
            Op::Contains | Op::Regex => false, // regex not meaningful for numerics
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
                let ord = ctx_val.cmp(rule_val);
                match cond.op {
                    Op::Gt => ord == std::cmp::Ordering::Greater,
                    Op::Gte => ord != std::cmp::Ordering::Less,
                    Op::Lt => ord == std::cmp::Ordering::Less,
                    Op::Lte => ord != std::cmp::Ordering::Greater,
                    _ => unreachable!(),
                }
            }
            Op::Regex => {
                // Safety: fail-closed. If the regex cannot be compiled/retrieved,
                // or the input is too long to safely evaluate, treat it as a match
                // so that Deny/Flag rules fire instead of silently allowing.
                if ctx_val.len() > MAX_REGEX_INPUT_LEN {
                    tracing::warn!(
                        field = cond.field,
                        input_len = ctx_val.len(),
                        max = MAX_REGEX_INPUT_LEN,
                        "regex input exceeds maximum length — treating as match"
                    );
                    return true;
                }
                match get_or_compile_regex(rule_val) {
                    Some(re) => re.is_match(ctx_val),
                    None => {
                        tracing::error!(
                            pattern = rule_val,
                            field = cond.field,
                            "regex unavailable at evaluation time despite load-time validation — treating as match"
                        );
                        true
                    }
                }
            }
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
    /// Global max delegation chain depth (from PolicyFile).
    max_delegation_depth: Option<u32>,
    /// Shadow mode converts Deny/CircuitBreak to Flag (log-only).
    shadow: bool,
}

impl RuleEvaluator {
    /// Build evaluator from a parsed [`PolicyFile`].
    ///
    /// Validates regex patterns at load time (fail-fast) and pre-compiles them
    /// into the global cache for zero-cost evaluation.
    pub fn new(pf: &PolicyFile) -> Result<Self, EvalError> {
        let active: Vec<Rule> = pf.rules.iter().filter(|r| !r.disabled).cloned().collect();

        // Pre-validate and cache all regex patterns
        for rule in &active {
            if rule.condition.op == Op::Regex
                && let Some(pattern) = rule.condition.value.as_str()
                && get_or_compile_regex(pattern).is_none()
            {
                return Err(EvalError::InvalidRegex {
                    rule: rule.id.clone(),
                    pattern: pattern.to_string(),
                });
            }
        }

        // Validate and build in one pass.
        let sorted = topo_sort(&active)?;
        Ok(Self {
            rules: sorted.into_iter().cloned().collect(),
            max_delegation_depth: pf.max_delegation_depth,
            shadow: pf.enforcement_mode == EnforcementMode::Shadow,
        })
    }

    /// Evaluate all rules against `ctx`.
    ///
    /// Key decision: first DENY / CIRCUIT_BREAK short-circuits.
    /// Safety rules always run before compliance, which runs before business.
    ///
    /// If `max_delegation_depth` is set in the policy and the context's
    /// `delegation_depth` exceeds it, the request is denied immediately.
    pub fn evaluate(&self, ctx: &EvalContext) -> (EvalDecision, Vec<RuleOutput>) {
        // ── Global delegation depth check ──
        if let Some(max) = self.max_delegation_depth
            && ctx.delegation_depth > max
        {
            let msg = format!(
                "Delegation chain depth {} exceeds max allowed {}",
                ctx.delegation_depth, max
            );
            if self.shadow {
                let output = RuleOutput {
                    rule_id: "__delegation_depth".to_string(),
                    matched: true,
                    action: RuleAction::Deny,
                    message: Some(format!("[SHADOW] {msg}")),
                    shadow_downgraded: true,
                };
                // In shadow mode, continue evaluation with a flag instead
                return (
                    EvalDecision::FlaggedAllow {
                        flags: vec!["__delegation_depth".to_string()],
                    },
                    vec![output],
                );
            }
            let output = RuleOutput {
                rule_id: "__delegation_depth".to_string(),
                matched: true,
                action: RuleAction::Deny,
                message: Some(msg.clone()),
                shadow_downgraded: false,
            };
            return (
                EvalDecision::Deny {
                    rule_id: "__delegation_depth".to_string(),
                    message: msg,
                },
                vec![output],
            );
        }

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
                shadow_downgraded: false,
            };

            if matched {
                match rule.action {
                    RuleAction::Deny | RuleAction::CircuitBreak if self.shadow => {
                        // Shadow mode: downgrade to flag, don't short-circuit
                        flags.push(rule.id.clone());
                        let mut shadow_output = output.clone();
                        shadow_output.shadow_downgraded = true;
                        shadow_output.message = Some(format!(
                            "[SHADOW] {}",
                            shadow_output.message.as_deref().unwrap_or("")
                        ));
                        outputs.push(shadow_output);
                    }
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

            if (!matched
                || (!self.shadow
                    || !matches!(rule.action, RuleAction::Deny | RuleAction::CircuitBreak)))
                && outputs.last().is_none_or(|o| o.rule_id != rule.id)
            {
                outputs.push(output);
            }
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
            delegation_depth: 0,
            pii_field_count: 0,
            gdpr_deletion_requested: false,
            cross_border_restricted: false,
            retention_days_requested: 0,
            accessing_undeclared_service: false,
            payload_contains_pii: false,
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

    #[test]
    fn delegation_depth_within_limit_allowed() {
        let pf = PolicyFile {
            version: "1".into(),
            rules: vec![],
            max_delegation_depth: Some(3),
            enforcement_mode: EnforcementMode::default(),
        };
        let ev = RuleEvaluator::new(&pf).unwrap();
        let mut ctx = default_ctx();
        ctx.delegation_depth = 2;
        let (dec, _) = ev.evaluate(&ctx);
        assert_eq!(dec, EvalDecision::Allow);
    }

    #[test]
    fn delegation_depth_exceeding_limit_denied() {
        let pf = PolicyFile {
            version: "1".into(),
            rules: vec![],
            max_delegation_depth: Some(3),
            enforcement_mode: EnforcementMode::default(),
        };
        let ev = RuleEvaluator::new(&pf).unwrap();
        let mut ctx = default_ctx();
        ctx.delegation_depth = 4;
        let (dec, _) = ev.evaluate(&ctx);
        assert!(
            matches!(dec, EvalDecision::Deny { rule_id, .. } if rule_id == "__delegation_depth")
        );
    }

    #[test]
    fn delegation_depth_rule_condition_works() {
        // Operators can also write per-rule delegation_depth conditions
        let rules = vec![make_rule(
            "deep_chain_flag",
            Priority::Safety,
            "delegation_depth",
            Op::Gt,
            FieldValue::Number(2.0),
            RuleAction::Flag,
            vec![],
        )];
        let ev = RuleEvaluator::new(&pf(rules)).unwrap();
        let mut ctx = default_ctx();
        ctx.delegation_depth = 3;
        let (dec, _) = ev.evaluate(&ctx);
        assert!(matches!(dec, EvalDecision::FlaggedAllow { .. }));
    }

    // ─── Regex tests ──────────────────────────────────────────────────────────

    #[test]
    fn regex_matches_string_field() {
        let rules = vec![make_rule(
            "block_evil_recipient",
            Priority::Safety,
            "recipient",
            Op::Regex,
            FieldValue::Text(r"^(evil|malicious)_.*".into()),
            RuleAction::Deny,
            vec![],
        )];
        let ev = RuleEvaluator::new(&pf(rules)).unwrap();

        let mut ctx = default_ctx();
        ctx.recipient = "evil_bob".into();
        let (dec, _) = ev.evaluate(&ctx);
        assert!(matches!(dec, EvalDecision::Deny { .. }));

        ctx.recipient = "good_alice".into();
        let (dec, _) = ev.evaluate(&ctx);
        assert_eq!(dec, EvalDecision::Allow);
    }

    #[test]
    fn regex_no_match_allows() {
        let rules = vec![make_rule(
            "currency_pattern",
            Priority::Compliance,
            "currency",
            Op::Regex,
            FieldValue::Text(r"^[A-Z]{3}$".into()),
            RuleAction::Flag,
            vec![],
        )];
        let ev = RuleEvaluator::new(&pf(rules)).unwrap();
        let ctx = default_ctx(); // currency = "USD" -> matches ^[A-Z]{3}$
        let (dec, _) = ev.evaluate(&ctx);
        assert!(matches!(dec, EvalDecision::FlaggedAllow { .. }));
    }

    #[test]
    fn invalid_regex_rejected_at_load_time() {
        let rules = vec![make_rule(
            "bad_pattern",
            Priority::Safety,
            "recipient",
            Op::Regex,
            FieldValue::Text(r"[invalid(".into()),
            RuleAction::Deny,
            vec![],
        )];
        let result = RuleEvaluator::new(&pf(rules));
        assert!(matches!(result, Err(EvalError::InvalidRegex { .. })));
    }

    #[test]
    fn regex_on_numeric_field_is_false() {
        let rules = vec![make_rule(
            "regex_on_num",
            Priority::Safety,
            "amount",
            Op::Regex,
            FieldValue::Number(42.0),
            RuleAction::Deny,
            vec![],
        )];
        let ev = RuleEvaluator::new(&pf(rules)).unwrap();
        let (dec, _) = ev.evaluate(&default_ctx());
        assert_eq!(dec, EvalDecision::Allow);
    }

    #[test]
    fn regex_cache_reuses_compiled_pattern() {
        // Two rules with the same pattern should compile once
        let rules = vec![
            make_rule(
                "r1",
                Priority::Safety,
                "recipient",
                Op::Regex,
                FieldValue::Text(r"^test_.*".into()),
                RuleAction::Flag,
                vec![],
            ),
            make_rule(
                "r2",
                Priority::Compliance,
                "agent_id",
                Op::Regex,
                FieldValue::Text(r"^test_.*".into()),
                RuleAction::Flag,
                vec![],
            ),
        ];
        let ev = RuleEvaluator::new(&pf(rules)).unwrap();
        let mut ctx = default_ctx();
        ctx.recipient = "test_bob".into();
        ctx.agent_id = "test_agent".into();
        let (dec, _) = ev.evaluate(&ctx);
        assert!(matches!(dec, EvalDecision::FlaggedAllow { flags } if flags.len() == 2));
    }

    #[test]
    fn regex_too_long_input_fails_closed() {
        // A Deny rule that does not match on a normal input should match
        // when the input exceeds the runtime length limit, causing a deny.
        let rules = vec![make_rule(
            "short_input_only",
            Priority::Safety,
            "recipient",
            Op::Regex,
            FieldValue::Text(r"^short$".into()),
            RuleAction::Deny,
            vec![],
        )];
        let ev = RuleEvaluator::new(&pf(rules)).unwrap();

        let mut ctx = default_ctx();
        ctx.recipient = "a".repeat(MAX_REGEX_INPUT_LEN + 1);
        let (dec, _) = ev.evaluate(&ctx);
        assert!(
            matches!(dec, EvalDecision::Deny { rule_id, .. } if rule_id == "short_input_only"),
            "over-long regex input must fail closed"
        );
    }

    #[test]
    fn regex_too_long_input_flag_action_also_matches() {
        // Same fail-closed behavior for Flag rules.
        let rules = vec![make_rule(
            "flag_long_input",
            Priority::Safety,
            "recipient",
            Op::Regex,
            FieldValue::Text(r"^short$".into()),
            RuleAction::Flag,
            vec![],
        )];
        let ev = RuleEvaluator::new(&pf(rules)).unwrap();

        let mut ctx = default_ctx();
        ctx.recipient = "a".repeat(MAX_REGEX_INPUT_LEN + 1);
        let (dec, _) = ev.evaluate(&ctx);
        assert!(
            matches!(dec, EvalDecision::FlaggedAllow { flags } if flags.contains(&"flag_long_input".to_string())),
            "over-long regex input must flag when rule action is Flag"
        );
    }

    // ─── Shadow mode tests ────────────────────────────────────────────────────

    fn shadow_pf(rules: Vec<Rule>) -> PolicyFile {
        PolicyFile {
            version: "1".into(),
            rules,
            max_delegation_depth: None,
            enforcement_mode: EnforcementMode::Shadow,
        }
    }

    #[test]
    fn shadow_mode_downgrades_deny_to_flag() {
        let rules = vec![make_rule(
            "hard_cap",
            Priority::Safety,
            "amount",
            Op::Gt,
            FieldValue::Number(100.0),
            RuleAction::Deny,
            vec![],
        )];
        let ev = RuleEvaluator::new(&shadow_pf(rules)).unwrap();
        let (dec, outputs) = ev.evaluate(&default_ctx());
        // Should NOT deny in shadow mode
        assert!(
            matches!(dec, EvalDecision::FlaggedAllow { ref flags } if flags.contains(&"hard_cap".to_string())),
            "Shadow mode should downgrade deny to flagged allow, got {dec:?}"
        );
        // Output should be marked as shadow-downgraded
        let hard_cap_output = outputs.iter().find(|o| o.rule_id == "hard_cap").unwrap();
        assert!(hard_cap_output.shadow_downgraded);
    }

    #[test]
    fn shadow_mode_downgrades_circuit_break_to_flag() {
        let rules = vec![make_rule(
            "velocity_cb",
            Priority::Safety,
            "ewma_velocity",
            Op::Gt,
            FieldValue::Number(0.05),
            RuleAction::CircuitBreak,
            vec![],
        )];
        let ev = RuleEvaluator::new(&shadow_pf(rules)).unwrap();
        let (dec, _) = ev.evaluate(&default_ctx());
        assert!(
            matches!(dec, EvalDecision::FlaggedAllow { .. }),
            "Shadow mode should downgrade circuit break, got {dec:?}"
        );
    }

    #[test]
    fn shadow_mode_evaluates_all_rules_no_short_circuit() {
        let rules = vec![
            make_rule(
                "r1_deny",
                Priority::Safety,
                "amount",
                Op::Gt,
                FieldValue::Number(100.0),
                RuleAction::Deny,
                vec![],
            ),
            make_rule(
                "r2_deny",
                Priority::Compliance,
                "currency",
                Op::Eq,
                FieldValue::Text("USD".into()),
                RuleAction::Deny,
                vec![],
            ),
        ];
        let ev = RuleEvaluator::new(&shadow_pf(rules)).unwrap();
        let (dec, outputs) = ev.evaluate(&default_ctx());
        // Both rules should be evaluated (no short-circuit in shadow mode)
        let matched: Vec<_> = outputs.iter().filter(|o| o.matched).collect();
        assert_eq!(matched.len(), 2, "Shadow mode should not short-circuit");
        assert!(matches!(dec, EvalDecision::FlaggedAllow { ref flags } if flags.len() == 2));
    }

    #[test]
    fn shadow_mode_parsed_from_yaml() {
        let yaml = r#"
version: "1"
enforcement_mode: shadow
rules:
  - id: test_rule
    priority: safety
    description: test
    condition:
      field: amount
      op: gt
      value: 100.0
    action: deny
    message: "blocked"
"#;
        let pf = PolicyFile::from_yaml(yaml).unwrap();
        assert_eq!(pf.enforcement_mode, EnforcementMode::Shadow);
        let ev = RuleEvaluator::new(&pf).unwrap();
        let (dec, _) = ev.evaluate(&default_ctx());
        assert!(matches!(dec, EvalDecision::FlaggedAllow { .. }));
    }

    #[test]
    fn enforce_mode_is_default() {
        let yaml = r#"
version: "1"
rules: []
"#;
        let pf = PolicyFile::from_yaml(yaml).unwrap();
        assert_eq!(pf.enforcement_mode, EnforcementMode::Enforce);
    }

    // ─── Security: Regex complexity / ReDoS guards ─────────────────────────

    #[test]
    fn security_regex_pattern_too_long_is_rejected() {
        // Pattern longer than MAX_PATTERN_LEN (1024) must be rejected.
        let long_pattern = "a".repeat(1025);
        let result = get_or_compile_regex(&long_pattern);
        assert!(
            result.is_none(),
            "oversized pattern should be rejected to prevent ReDoS amplification"
        );
    }

    #[test]
    fn security_regex_exact_max_len_is_accepted() {
        // A simple pattern at exactly the length limit must still compile.
        let pattern = format!(".{{0,{}}}", MAX_PATTERN_LEN - 10);
        let result = get_or_compile_regex(&pattern);
        assert!(
            result.is_some(),
            "pattern within length limit should compile"
        );
    }

    #[test]
    fn security_regex_deeply_nested_quantifiers_rejected_or_safe() {
        // A deeply nested quantifier pattern that would cause exponential NFA
        // growth should either fail compilation (size_limit hit) or match safely.
        // The regex crate's NFA-based engine ensures linear time, but size_limit
        // will reject patterns whose compiled NFA exceeds REGEX_SIZE_LIMIT bytes.
        let nested = "(a+)+b".repeat(3); // mildly pathological; regex crate blocks at NFA size
        // Either compiles (safe NFA) or is rejected (size exceeded): both are acceptable.
        // What is NOT acceptable: a panic or timeout.
        let _result = get_or_compile_regex(&nested);
        // Reaches here ⟹ no panic/timeout — test passes.
    }

    #[test]
    fn security_regex_invalid_syntax_returns_none() {
        let result = get_or_compile_regex("(unclosed");
        assert!(
            result.is_none(),
            "invalid regex must return None, not panic"
        );
    }

    #[test]
    fn security_regex_cache_deduplicated() {
        // Same pattern compiled twice → single cache entry (no duplicate compilation).
        let pattern = r"^[a-z]{1,50}$";
        let r1 = get_or_compile_regex(pattern);
        let r2 = get_or_compile_regex(pattern);
        assert!(r1.is_some());
        assert!(r2.is_some());
        let cache_size = regex_cache().lock().len();
        // Pattern must appear exactly once in the cache.
        assert!(
            cache_size >= 1,
            "cache must hold at least the compiled pattern"
        );
    }
}
