//! Friday: Integration tests — anomaly detector + policy cascade
//!
//! These tests exercise the full pipeline:
//!   1. YAML rules evaluated by the DAG evaluator
//!   2. Anomaly-score fields wired through EvalContext
//!   3. Conflict detection on the test policy

use haltchain_rules::{
    ConflictGraph, EvalContext, EvalDecision, FieldValue, Op, PolicyFile, Priority, Rule,
    RuleAction, RuleEvaluator, conflict::ConflictKind, schema::Condition,
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn rule(
    id: &str,
    priority: Priority,
    field: &str,
    op: Op,
    value: FieldValue,
    action: RuleAction,
    deps: Vec<&str>,
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
        depends_on: deps.into_iter().map(String::from).collect(),
        disabled: false,
    }
}

fn ctx_normal() -> EvalContext {
    EvalContext {
        agent_id: "agent-A".into(),
        action_type: "transfer".into(),
        amount: 200.0,
        currency: "USD".into(),
        recipient: "alice".into(),
        ewma_velocity: 0.05,
        actions_1m: 2,
        anomaly_score: 0.2,
        is_anomaly: false,
    }
}

// ─── Scenario 1: Anomaly score triggers circuit-break ─────────────────────────

/// An anomaly_score above 0.6 should trip the circuit breaker regardless of
/// the transfer amount being within normal bounds.
#[test]
fn anomaly_triggers_circuit_break() {
    let policy_yaml = r#"
version: "1"
rules:
  - id: anomaly_cb
    priority: safety
    description: Circuit-break on anomaly
    condition:
      field: anomaly_score
      op: gt
      value: 0.6
    action: circuit_break
    message: "Anomaly detected — circuit breaker tripped"
  - id: large_transfer
    priority: safety
    description: Deny large transfers
    condition:
      field: amount
      op: gt
      value: 1000.0
    action: deny
    message: "Transfer too large"
"#;
    let pf = PolicyFile::from_yaml(policy_yaml).unwrap();
    let ev = RuleEvaluator::new(&pf).unwrap();

    let mut ctx = ctx_normal();
    ctx.anomaly_score = 0.75;
    ctx.is_anomaly = true;

    let (dec, _) = ev.evaluate(&ctx);
    assert!(
        matches!(dec, EvalDecision::CircuitBreak { ref rule_id, .. } if rule_id == "anomaly_cb"),
        "expected circuit-break from anomaly rule, got {dec:?}"
    );
}

// ─── Scenario 2: Safety rule fires before business rule ───────────────────────

#[test]
fn safety_before_business_priority() {
    let pf = PolicyFile::from_yaml(
        r#"
version: "1"
rules:
  - id: biz_limit
    priority: business
    description: Biz limit $500
    condition:
      field: amount
      op: gt
      value: 500.0
    action: deny
    message: "Business limit exceeded"
  - id: hard_cap
    priority: safety
    description: Hard cap $1000
    condition:
      field: amount
      op: gt
      value: 1000.0
    action: deny
    message: "Hard cap exceeded"
"#,
    )
    .unwrap();

    let ev = RuleEvaluator::new(&pf).unwrap();

    // Amount 600 triggers biz_limit but not hard_cap.
    let mut ctx = ctx_normal();
    ctx.amount = 600.0;
    let (dec, outputs) = ev.evaluate(&ctx);
    assert!(matches!(dec, EvalDecision::Deny { rule_id, .. } if rule_id == "biz_limit"));
    // hard_cap should appear in outputs as not-matched.
    assert!(
        outputs
            .iter()
            .any(|o| o.rule_id == "hard_cap" && !o.matched)
    );
}

// ─── Scenario 3: DAG dependency — compliance check gates business rule ─────────

/// `biz_check` depends on `usd_only`. If `usd_only` fires (DENY), `biz_check`
/// never runs.  If currency is USD the deny doesn't fire and `biz_check` runs.
#[test]
fn dag_dependency_gates_downstream_rule() {
    let pf = PolicyFile {
        version: "1".into(),
        rules: vec![
            rule(
                "usd_only",
                Priority::Compliance,
                "currency",
                Op::Neq,
                FieldValue::Text("USD".into()),
                RuleAction::Deny,
                vec![],
            ),
            rule(
                "biz_check",
                Priority::Business,
                "amount",
                Op::Gt,
                FieldValue::Number(500.0),
                RuleAction::Deny,
                vec!["usd_only"],
            ),
        ],
    };
    let ev = RuleEvaluator::new(&pf).unwrap();

    // EUR transfer — usd_only fires first; biz_check is never reached.
    let mut ctx = ctx_normal();
    ctx.currency = "EUR".into();
    ctx.amount = 600.0;

    let (dec, outputs) = ev.evaluate(&ctx);
    assert!(
        matches!(dec, EvalDecision::Deny { ref rule_id, .. } if rule_id == "usd_only"),
        "Expected usd_only deny, got {dec:?}"
    );
    // biz_check is in the output list but should not have been the trigger.
    assert!(
        outputs
            .iter()
            .all(|o| !o.matched || o.rule_id != "biz_check")
    );
}

// ─── Scenario 4: All rules pass → ALLOW ────────────────────────────────────────

#[test]
fn all_rules_pass_returns_allow() {
    let pf = PolicyFile::from_yaml(
        r#"
version: "1"
rules:
  - id: hard_cap
    priority: safety
    condition:
      field: amount
      op: gt
      value: 1000.0
    action: deny
    message: "Hard cap"
    description: hard cap
  - id: anomaly_cb
    priority: safety
    condition:
      field: anomaly_score
      op: gt
      value: 0.6
    action: circuit_break
    message: "Anomaly"
    description: anomaly cb
"#,
    )
    .unwrap();

    let ev = RuleEvaluator::new(&pf).unwrap();
    // Normal context: amount 200, anomaly 0.2 — neither rule triggers.
    let (dec, _) = ev.evaluate(&ctx_normal());
    assert_eq!(dec, EvalDecision::Allow);
}

// ─── Scenario 5: Flagged-allow when only FLAG rules match ─────────────────────

#[test]
fn flagged_allow_for_flag_rules() {
    let pf = PolicyFile {
        version: "1".into(),
        rules: vec![rule(
            "flag_anomaly",
            Priority::Compliance,
            "is_anomaly",
            Op::Eq,
            FieldValue::Bool(true),
            RuleAction::Flag,
            vec![],
        )],
    };
    let ev = RuleEvaluator::new(&pf).unwrap();

    let mut ctx = ctx_normal();
    ctx.is_anomaly = true;

    let (dec, _) = ev.evaluate(&ctx);
    assert!(matches!(dec, EvalDecision::FlaggedAllow { .. }));
}

// ─── Scenario 6: Conflict detection on real policy ────────────────────────────

/// A policy that has a Safety DENY and a Business ALLOW on the *same* condition
/// should surface a shadow conflict.
#[test]
fn conflict_detection_on_shadow() {
    let pf = PolicyFile {
        version: "1".into(),
        rules: vec![
            rule(
                "block_large",
                Priority::Safety,
                "amount",
                Op::Gt,
                FieldValue::Number(500.0),
                RuleAction::Deny,
                vec![],
            ),
            rule(
                "allow_large",
                Priority::Business,
                "amount",
                Op::Gt,
                FieldValue::Number(500.0),
                RuleAction::Allow,
                vec![],
            ),
        ],
    };
    let graph = ConflictGraph::build(&pf);
    assert!(graph.has_conflicts());
    assert!(graph.conflicts().iter().any(
        |c| matches!(c, ConflictKind::Shadow { blocker_id, .. } if blocker_id == "block_large")
    ));
}

/// A valid policy with no overlapping same-condition opposite-action rules
/// must produce no conflicts.
#[test]
fn no_conflict_on_clean_policy() {
    let pf = PolicyFile::from_yaml(
        r#"
version: "1"
rules:
  - id: hard_cap
    priority: safety
    description: hard cap
    condition:
      field: amount
      op: gt
      value: 1000.0
    action: deny
    message: "Too large"
  - id: anomaly_cb
    priority: safety
    description: anomaly cb
    condition:
      field: anomaly_score
      op: gt
      value: 0.6
    action: circuit_break
    message: "Anomaly"
  - id: compliance_usd
    priority: compliance
    description: usd only
    condition:
      field: currency
      op: neq
      value: "USD"
    action: deny
    message: "USD only"
"#,
    )
    .unwrap();

    let graph = ConflictGraph::build(&pf);
    assert!(
        !graph.has_conflicts(),
        "Expected no conflicts, found: {:?}",
        graph.conflicts()
    );
}

// ─── Scenario 7: YAML round-trip preserves rule semantics ─────────────────────

#[test]
fn yaml_roundtrip_preserves_evaluation() {
    let original_yaml = r#"
version: "2"
rules:
  - id: velocity_spike
    priority: safety
    description: Block velocity spikes
    condition:
      field: ewma_velocity
      op: gt
      value: 0.5
    action: circuit_break
    message: "Velocity spike"
  - id: large_transfer
    priority: compliance
    description: Deny oversized transfers
    condition:
      field: amount
      op: gte
      value: 800.0
    action: deny
    message: "Transfer too large"
"#;
    let pf1 = PolicyFile::from_yaml(original_yaml).unwrap();
    let yaml2 = pf1.to_yaml().unwrap();
    let pf2 = PolicyFile::from_yaml(&yaml2).unwrap();

    assert_eq!(pf1.version, pf2.version);
    assert_eq!(pf1.rules.len(), pf2.rules.len());

    let ev1 = RuleEvaluator::new(&pf1).unwrap();
    let ev2 = RuleEvaluator::new(&pf2).unwrap();

    let mut ctx = ctx_normal();
    ctx.ewma_velocity = 0.8;
    ctx.amount = 900.0;

    let (dec1, _) = ev1.evaluate(&ctx);
    let (dec2, _) = ev2.evaluate(&ctx);
    assert_eq!(
        dec1, dec2,
        "Round-tripped policy must produce identical decisions"
    );
}
