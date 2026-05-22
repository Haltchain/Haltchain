//! Monday: Policy schema — human-readable YAML DSL.
//!
//! Example policy file:
//!
//! ```yaml
//! version: "1"
//! rules:
//!   - id: max_transfer
//!     priority: safety
//!     description: Hard cap on single transfer value
//!     condition:
//!       field: amount
//!       op: gt
//!       value: 1000.0
//!     action: deny
//!     message: "Transfer exceeds $1,000 hard limit"
//!
//!   - id: high_velocity_check
//!     priority: safety
//!     description: Block when EWMA velocity spikes
//!     condition:
//!       field: ewma_velocity
//!       op: gt
//!       value: 0.2
//!     action: circuit_break
//!     message: "Velocity spike detected"
//!     depends_on: []
//!
//!   - id: compliance_usd_only
//!     priority: compliance
//!     description: Only USD transfers allowed
//!     condition:
//!       field: currency
//!       op: neq
//!       value: "USD"
//!     action: deny
//!     message: "Only USD transfers are permitted"
//!
//!   - id: business_limit
//!     priority: business
//!     description: Business tier cap
//!     condition:
//!       field: amount
//!       op: gt
//!       value: 500.0
//!     action: deny
//!     message: "Exceeds business tier limit"
//!     depends_on: [compliance_usd_only]
//! ```

use serde::{Deserialize, Serialize};

// ─── Priority tier (evaluation order: safety → compliance → business) ─────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Safety,
    Compliance,
    Business,
}

//Comparison operators

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    /// Greater than
    Gt,
    /// Greater than or equal
    Gte,
    /// Less than
    Lt,
    /// Less than or equal
    Lte,
    /// Equal
    Eq,
    /// Not equal
    Neq,
    /// String contains
    Contains,
    /// String matches regex (validated at load time)
    Regex,
}

// ─── Field value — supports numeric and string comparisons ────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FieldValue {
    Number(f64),
    Text(String),
    Bool(bool),
}

impl FieldValue {
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            FieldValue::Number(n) => Some(*n),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            FieldValue::Text(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

//Condition

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    /// Name of the field from [`EvalContext`] to check.
    pub field: String,
    pub op: Op,
    pub value: FieldValue,
}

//Rule action

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Allow,
    Deny,
    CircuitBreak,
    /// Pass through — rule matched but defers final decision.
    Flag,
}

//Single rule

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub priority: Priority,
    pub description: String,
    pub condition: Condition,
    pub action: RuleAction,
    pub message: String,
    /// IDs of rules whose outputs must be computed first (DAG edges).
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// Disabled rules are parsed but never evaluated.
    #[serde(default)]
    pub disabled: bool,
}

//Policy file

/// Enforcement mode for a policy file.
///
/// Shadow mode evaluates all rules but converts Deny/CircuitBreak to Flag,
/// allowing operators to measure false-positive rates before enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    /// Normal enforcement — Deny and CircuitBreak halt the request.
    Enforce,
    /// Shadow / log-only — rules evaluate but never block. Denials are
    /// converted to flags. Ideal for canary-testing new rule packs.
    Shadow,
}

impl Default for EnforcementMode {
    fn default() -> Self {
        Self::Enforce
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyFile {
    pub version: String,
    pub rules: Vec<Rule>,
    /// Global constraint: maximum allowed delegation chain depth.
    /// Requests with `delegation_depth > max_delegation_depth` are denied.
    /// Default: 3 (if absent, no automatic enforcement — rely on rules).
    #[serde(default)]
    pub max_delegation_depth: Option<u32>,
    /// Enforcement mode. Defaults to `enforce`. Set to `shadow` for
    /// log-only evaluation (new policies measuring FP rates).
    #[serde(default)]
    pub enforcement_mode: EnforcementMode,
}

impl PolicyFile {
    /// Parse from a YAML string.
    pub fn from_yaml(src: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(src)
    }

    /// Serialize back to YAML (useful for round-trip tests).
    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }
}

//evaluation context

/// All fields that a rule condition can inspect.
/// Built by the validator from the incoming request + analytics state.
#[derive(Debug, Clone, Default)]
pub struct EvalContext {
    pub agent_id: String,
    pub action_type: String,
    pub amount: f64,
    pub currency: String,
    pub recipient: String,
    pub ewma_velocity: f64,
    pub actions_1m: usize,
    pub anomaly_score: f64,
    pub is_anomaly: bool,
    /// Number of hops in the agent-to-agent delegation chain.
    /// 0 = direct request (no delegation), 1 = one hop, etc.
    pub delegation_depth: u32,

    // ── Compliance pack fields ─────────────────────────────────────────────
    // GDPR / PCI-DSS / HIPAA / EU AI Act rules inspect these fields.
    // They are populated from `ValidationRequest.metadata` by the validator.
    /// Number of PII fields the agent is accessing in this action.
    /// Used by GDPR data minimisation (Art. 5(1)(c)) and PCI-DSS Req 3.2.
    pub pii_field_count: usize,
    /// True when an active GDPR erasure request (Art. 17) is in effect.
    /// Any data processing while this is set MUST be blocked.
    pub gdpr_deletion_requested: bool,
    /// True when the data destination lacks an EU adequacy decision (Art. 44-49).
    pub cross_border_restricted: bool,
    /// Number of days the agent is requesting data to be retained.
    /// GDPR Art. 5(1)(e) limits this to 2555 days (7 years).
    pub retention_days_requested: u32,
    /// True when the agent is attempting to call a service not in its declared scope.
    /// Used by PCI-DSS Req 7.1 (least privilege) and HIPAA minimum necessary.
    pub accessing_undeclared_service: bool,
    /// True when the outbound payload contains PII fields not declared in the agent schema.
    pub payload_contains_pii: bool,
}

impl EvalContext {
    /// Look up a named field by string key.  Returns `None` for unknown fields.
    pub fn get_f64(&self, field: &str) -> Option<f64> {
        match field {
            "amount" => Some(self.amount),
            "ewma_velocity" => Some(self.ewma_velocity),
            "actions_1m" => Some(self.actions_1m as f64),
            "anomaly_score" => Some(self.anomaly_score),
            "delegation_depth" => Some(self.delegation_depth as f64),
            "pii_field_count" => Some(self.pii_field_count as f64),
            "retention_days_requested" => Some(self.retention_days_requested as f64),
            _ => None,
        }
    }

    pub fn get_str<'a>(&'a self, field: &str) -> Option<&'a str> {
        match field {
            "agent_id" => Some(&self.agent_id),
            "action_type" => Some(&self.action_type),
            "currency" => Some(&self.currency),
            "recipient" => Some(&self.recipient),
            _ => None,
        }
    }

    pub fn get_bool(&self, field: &str) -> Option<bool> {
        match field {
            "is_anomaly" => Some(self.is_anomaly),
            "gdpr_deletion_requested" => Some(self.gdpr_deletion_requested),
            "cross_border_restricted" => Some(self.cross_border_restricted),
            "accessing_undeclared_service" => Some(self.accessing_undeclared_service),
            "payload_contains_pii" => Some(self.payload_contains_pii),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
version: "1"
rules:
  - id: max_transfer
    priority: safety
    description: Hard cap
    condition:
      field: amount
      op: gt
      value: 1000.0
    action: deny
    message: "Exceeds hard limit"
  - id: usd_only
    priority: compliance
    description: USD only
    condition:
      field: currency
      op: neq
      value: "USD"
    action: deny
    message: "Non-USD blocked"
    depends_on: []
"#;

    #[test]
    fn parse_roundtrip() {
        let pf = PolicyFile::from_yaml(SAMPLE).unwrap();
        assert_eq!(pf.rules.len(), 2);
        assert_eq!(pf.rules[0].id, "max_transfer");
        assert_eq!(pf.rules[0].priority, Priority::Safety);
    }

    #[test]
    fn eval_context_field_lookup() {
        let ctx = EvalContext {
            amount: 500.0,
            currency: "EUR".into(),
            ..Default::default()
        };
        assert_eq!(ctx.get_f64("amount"), Some(500.0));
        assert_eq!(ctx.get_str("currency"), Some("EUR"));
    }
}
