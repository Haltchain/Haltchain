export type ReviewOutcomeStatus = "TRUE_POSITIVE" | "FALSE_POSITIVE" | "EXPECTED_EDGE_CASE";

export type ReviewEntry = {
  tx_id: string;
  agent_id: string;
  decision: "ALLOW" | "DENY" | "CIRCUIT_BREAK" | string;
  policy_code?: string | null;
  reason?: string | null;
  created_at: string;
  outcome?: {
    verdict: ReviewOutcomeStatus;
    impact_usd?: number | null;
    reviewer_id?: string | null;
    notes?: string | null;
  } | null;
};

export type RecommendationStatus = "pending" | "approved" | "applied" | "rejected" | "reverted";

export type Recommendation = {
  id: number;
  threshold_key: string;
  current_value: number;
  proposed_value: number;
  sample_size: number;
  false_positive_count: number;
  true_positive_count: number;
  confidence: number;
  rationale: string;
  status: RecommendationStatus;
};

export type AgentStatus = {
  agent_id: string;
  circuit_breaker_active: boolean;
  actions_this_minute: number;
  rate_limit: number;
  anomaly_score?: number | null;
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(init?.headers ?? {}),
    },
    credentials: "include",
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(body || `Request failed: ${res.status}`);
  }

  return (await res.json()) as T;
}

export type PublicHealth = {
  status: string;
  version: string;
  service: string;
};

export async function getPublicHealth(): Promise<PublicHealth> {
  const res = await fetch("/api/health");
  if (!res.ok) {
    throw new Error(`health failed: ${res.status}`);
  }
  return (await res.json()) as PublicHealth;
}

export function checkSession() {
  return request<{ unlocked: boolean }>("/api/auth/session");
}

export async function login(email: string, password: string) {
  const res = await fetch("/api/auth/admin/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ email, password }),
  });
  const data = (await res.json().catch(() => ({}))) as { ok?: boolean; error?: string };
  if (!res.ok) {
    throw new Error(data.error || `Login failed (${res.status})`);
  }
  return data as { ok: boolean };
}

export function getAuditLog(limit = 100) {
  const q = Math.min(500, Math.max(1, limit));
  return request<{ events: unknown[]; limit: number }>(`/api/admin/audit-log?limit=${q}`);
}

export function lockDashboard() {
  return request<{ ok: boolean }>("/api/auth/logout", {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export function getReviewQueue() {
  return request<ReviewEntry[]>("/api/admin/review-queue");
}

export function submitReviewOutcome(txId: string, payload: Record<string, unknown>) {
  return request<{ ok: boolean }>(`/api/admin/review-queue/${encodeURIComponent(txId)}/outcome`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function getRecommendations(status?: string) {
  const qs = status ? `?status=${encodeURIComponent(status)}` : "";
  return request<Recommendation[]>(`/api/admin/recommendations${qs}`);
}

export function runLearningLoop() {
  return request<{ generated: number }>("/api/admin/recommendations/run", {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export function approveRecommendation(id: number, payload: Record<string, unknown>) {
  return request<{ ok: boolean }>(`/api/admin/recommendations/${id}/approve`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function rejectRecommendation(id: number, payload: Record<string, unknown>) {
  return request<{ ok: boolean }>(`/api/admin/recommendations/${id}/reject`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function revertRecommendation(id: number, payload: Record<string, unknown>) {
  return request<{ ok: boolean }>(`/api/admin/recommendations/${id}/revert`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function getThresholds() {
  return request<Array<[string, number]>>("/api/admin/thresholds");
}

export function patchThreshold(key: string, value: number) {
  return request<{ status: string; key: string; value: number }>("/api/admin/thresholds", {
    method: "PATCH",
    body: JSON.stringify({ key, value }),
  });
}

export type RiskAdvisory = {
  id: number;
  agent_id: string;
  severity: "Critical" | "High" | "Medium" | "Low" | string;
  category: string;
  description: string;
  recommendation: string;
  created_at: string;
  resolved_at?: string | null;
};

export function getRiskAdvisories(agentId: string, sinceId?: number) {
  const qs = sinceId != null ? `?since_id=${sinceId}` : "";
  return request<{ advisories: RiskAdvisory[] }>(`/api/risk/advisories/${encodeURIComponent(agentId)}${qs}`);
}



export type DriftStatus = {
  agent_id: string;
  session_id: string;
  declared_goal?: string | null;
  drift_score?: number | null;
  last_action?: string | null;
  samples: number;
  history?: Array<{ score: number; at: string }>;
  cumulative_drift?: number | null;
};

export function getDriftStatus(agentId: string, sessionId: string) {
  return request<DriftStatus>(`/api/drift/${encodeURIComponent(agentId)}/${encodeURIComponent(sessionId)}`);
}

export type ABVariant = {
  id: string;
  name: string;
  description?: string | null;
  threshold_overrides?: Record<string, number> | null;
  traffic_pct: number;
  enabled: boolean;
  created_at?: string | null;
};

export function listVariants() {
  return request<{ variants: ABVariant[] }>("/api/admin/ab-variants");
}

export function createVariant(payload: { name: string; description?: string; traffic_pct?: number; threshold_overrides?: Record<string, number> }) {
  return request<{ status: string; id: string }>("/api/admin/ab-variants", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function getAgentStatus(agentId: string) {
  return request<AgentStatus>(`/api/status/${encodeURIComponent(agentId)}`);
}

// ── Agent Evolution (version lineage + adversarial gate) ─────────────────

export type AdversarialSuiteResult = {
  total_cases: number;
  passed: number;
  failed: number;
  pass_rate: number;
  gate_passed: boolean;
  checked_at: string;
};

export type VersionDiffSummary = {
  old_version: number;
  new_version: number;
  goal_changed: boolean;
  goal_cosine_shift: number | null;
  anomaly_model_replaced: boolean;
  max_threshold_relative_delta: number;
};

export type ImprovementDecision =
  | { decision: "approve" }
  | { decision: "reject"; reason: string }
  | { decision: "gradual_rollout"; canary_percentage: number; monitoring_duration_secs: number }
  | { decision: "require_human_approval"; diff: VersionDiffSummary };

export type VersionLineageEntry = {
  version: number;
  diff_summary: VersionDiffSummary;
  adversarial_result: AdversarialSuiteResult | null;
  decision: ImprovementDecision;
  promoted: boolean;
  recorded_at: string;
};

export function getVersionLineage(agentId: string) {
  return request<{ agent_id: string; lineage: VersionLineageEntry[] }>(
    `/api/agent/improvement/lineage/${encodeURIComponent(agentId)}`,
  );
}
