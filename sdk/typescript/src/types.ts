export type Decision =
  | "ALLOW"
  | "DENY"
  | "CIRCUIT_BREAK"
  | "GOAL_CLARIFICATION_REQUIRED";

export interface SigEnvelope {
  nonce: string;
  signed_at: string;
  signature: string;
  key_id?: string;
}

export interface ValidationResponse {
  transaction_id: string;
  decision: Decision;
  reason?: string;
  policy?: string;
  timestamp: string;
  sig?: SigEnvelope;
}

export interface RiskAdvisory {
  id: number;
  agent_id: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  category: string;
  description: string;
  recommendation: string;
  created_at: string;
  resolved_at?: string | null;
}

export interface AgentStatus {
  agent_id: string;
  circuit_breaker_active: boolean;
  actions_this_minute: number;
  rate_limit: number;
  anomaly_score?: number | null;
}

export interface PublicKeyInfo {
  public_key_b64: string;
  key_id: string;
  algorithm: string;
}

export interface HaltChainClientOptions {
  agentId: string;
  apiKey: string;
  baseUrl?: string;
  timeout?: number;
  verifySignatures?: boolean;
}
