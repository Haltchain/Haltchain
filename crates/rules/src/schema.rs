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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyFile {
    pub version: String,
    pub rules: Vec<Rule>,
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
}

impl EvalContext {
    /// Look up a named field by string key.  Returns `None` for unknown fields.
    pub fn get_f64(&self, field: &str) -> Option<f64> {
        match field {
            "amount" => Some(self.amount),
            "ewma_velocity" => Some(self.ewma_velocity),
            "actions_1m" => Some(self.actions_1m as f64),
            "anomaly_score" => Some(self.anomaly_score),
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
