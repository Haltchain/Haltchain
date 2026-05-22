use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpToolCall {
    pub agent_id: Uuid,
    pub org_id: Uuid,
    pub tool_name: String,
    pub tool_args: serde_json::Value,
    pub context_hash: String,
    pub timestamp: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Block {
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        intent: Option<String>,
    },
    Quarantine {
        review_id: Uuid,
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        intent: Option<String>,
    },
}
