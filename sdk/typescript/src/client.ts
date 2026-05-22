import { signRequest, verifyResponse } from "./crypto.js";
import type {
  AgentStatus,
  HaltChainClientOptions,
  PublicKeyInfo,
  RiskAdvisory,
  ValidationResponse,
} from "./types.js";

const DEFAULT_BASE = "https://haltchain-consensus.fly.dev";

export class HaltChainClient {
  private readonly agentId: string;
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeout: number;
  private readonly verifySignatures: boolean;
  private publicKeyCache: PublicKeyInfo | null = null;

  constructor(opts: HaltChainClientOptions) {
    this.agentId = opts.agentId;
    this.apiKey = opts.apiKey;
    this.baseUrl = (opts.baseUrl ?? DEFAULT_BASE).replace(/\/+$/, "");
    this.timeout = opts.timeout ?? 10_000;
    this.verifySignatures = opts.verifySignatures ?? true;
  }

  // ── Core validation ─────────────────────────────────────────────────────────

  async check(
    action: Record<string, unknown>,
    options?: {
      sessionId?: string;
      context?: Record<string, unknown>;
      /** Trace ID for cross-agent audit correlation. Added to request metadata. */
      traceId?: string;
    },
  ): Promise<ValidationResponse> {
    const [nonce, timestamp, sig] = await signRequest(this.agentId, this.apiKey);

    // Merge traceId into metadata so the validator and downstream agents
    // can correlate audit events across agent boundaries.
    const metadata: Record<string, unknown> = { ...(options?.context ?? {}) };
    if (options?.traceId) {
      metadata["haltchain_trace_id"] = options.traceId;
    }

    const body = {
      agent_id: this.agentId,
      action,
      session_id: options?.sessionId,
      metadata,
      request_nonce: nonce,
      request_timestamp: timestamp,
      request_sig: sig,
    };

    const res = await this._fetch<ValidationResponse>("/validate", {
      method: "POST",
      body: JSON.stringify(body),
    });

    if (this.verifySignatures && res.sig) {
      const pubkey = await this._getPublicKey();
      const valid = await verifyResponse(res, this.agentId, pubkey.public_key_b64);
      if (!valid) {
        throw new Error("Response signature verification failed");
      }
    }

    return res;
  }

  /**
   * Wraps an async function so every call is pre-checked.
   * Throws if the validator returns DENY or CIRCUIT_BREAK.
   */
  guard<TArgs extends unknown[], TReturn>(
    fn: (...args: TArgs) => Promise<TReturn>,
    actionBuilder: (...args: TArgs) => Record<string, unknown>,
  ): (...args: TArgs) => Promise<TReturn> {
    return async (...args: TArgs): Promise<TReturn> => {
      const decision = await this.check(actionBuilder(...args));
      if (decision.decision === "DENY" || decision.decision === "CIRCUIT_BREAK") {
        throw new Error(`HaltChain blocked action: ${decision.reason ?? decision.decision}`);
      }
      return fn(...args);
    };
  }

  // ── Observability ────────────────────────────────────────────────────────────

  async getStatus(): Promise<AgentStatus> {
    return this._fetch<AgentStatus>(`/status/${encodeURIComponent(this.agentId)}`);
  }

  async getRiskAdvisories(sinceId?: number): Promise<RiskAdvisory[]> {
    const qs = sinceId != null ? `?since_id=${sinceId}` : "";
    const res = await this._fetch<{ advisories: RiskAdvisory[] }>(
      `/risk/advisories/${encodeURIComponent(this.agentId)}${qs}`,
    );
    return res.advisories;
  }

  async healthCheck(): Promise<boolean> {
    try {
      const res = await fetch(`${this.baseUrl}/health`, {
        signal: AbortSignal.timeout(this.timeout),
      });
      return res.ok;
    } catch {
      return false;
    }
  }

  // ── Internal helpers ─────────────────────────────────────────────────────────

  private async _getPublicKey(): Promise<PublicKeyInfo> {
    if (!this.publicKeyCache) {
      this.publicKeyCache = await this._fetch<PublicKeyInfo>("/public-key");
    }
    return this.publicKeyCache;
  }

  private async _fetch<T>(path: string, init?: RequestInit): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers: {
        "content-type": "application/json",
        "x-api-key": this.apiKey,
        ...(init?.headers as Record<string, string> | undefined),
      },
      signal: AbortSignal.timeout(this.timeout),
    });

    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(body || `HaltChain API error: ${res.status}`);
    }

    return res.json() as Promise<T>;
  }
}
