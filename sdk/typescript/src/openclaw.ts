/**
 * OpenClaw integration — HaltChain safety for OpenClaw agent workflows.
 *
 * Provides three levels of integration:
 * 1. Agent-level: `HaltChainOpenClawGuard.protect()` wraps an agent
 * 2. Tool-level: `guardTool()` decorator for individual tools
 * 3. Gateway-level: `HaltChainGatewayMiddleware` for mission control
 *
 * Usage:
 *
 * ```ts
 * import { HaltChainOpenClawGuard } from "@haltchain/sdk/openclaw";
 *
 * const guard = new HaltChainOpenClawGuard({ agentId: "my-agent", apiKey: "key" });
 *
 * // Protect an agent
 * const safeAgent = guard.protect(agent);
 *
 * // Guard a tool
 * const safeTool = guard.guardTool(myTool, { piiRedaction: true });
 * ```
 */

import { HaltChainClient } from "./client.js";
import type { HaltChainClientOptions, ValidationResponse } from "./types.js";

export interface OpenClawGuardOptions extends HaltChainClientOptions {
  /** Enable automatic PII redaction of tool inputs/outputs. */
  piiRedaction?: boolean;
  /** PII patterns to redact (regex strings). Defaults to common patterns. */
  piiPatterns?: string[];
}

// Common PII patterns (email, SSN, credit card, phone)
const DEFAULT_PII_PATTERNS = [
  /\b[\w.+-]+@[\w-]+\.[\w.]+\b/g,                    // email
  /\b\d{3}-\d{2}-\d{4}\b/g,                            // SSN
  /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,     // credit card
  /\b\+?1?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g, // phone
];

/**
 * HaltChain guard for OpenClaw agent workflows with PII redaction.
 */
export class HaltChainOpenClawGuard {
  private readonly client: HaltChainClient;
  private readonly piiRedaction: boolean;
  private readonly piiPatterns: RegExp[];

  constructor(opts: OpenClawGuardOptions) {
    this.client = new HaltChainClient(opts);
    this.piiRedaction = opts.piiRedaction ?? false;
    this.piiPatterns = opts.piiPatterns
      ? opts.piiPatterns.map((p) => new RegExp(p, "g"))
      : DEFAULT_PII_PATTERNS;
  }

  /**
   * Redact PII from a string using configured patterns.
   */
  redactPII(text: string): string {
    let result = text;
    for (const pattern of this.piiPatterns) {
      result = result.replace(pattern, "[REDACTED]");
    }
    return result;
  }

  /**
   * Validate an action, optionally redacting PII before sending to HaltChain.
   */
  async validate(
    action: Record<string, unknown>,
    opts?: { sessionId?: string; traceId?: string } | string,
  ): Promise<ValidationResponse> {
    let cleanAction = action;
    if (this.piiRedaction) {
      cleanAction = this.redactActionPII(action);
    }
    // Accept legacy string sessionId or new options object
    if (typeof opts === "string") {
      return this.client.check(cleanAction, { sessionId: opts });
    }
    return this.client.check(cleanAction, opts);
  }

  /**
   * Wrap an agent's execute/run method to validate before each tool call.
   */
  protect<T extends { execute?: (...args: unknown[]) => Promise<unknown>; run?: (...args: unknown[]) => Promise<unknown> }>(
    agent: T,
  ): T {
    const guard = this;

    return new Proxy(agent, {
      get(target, prop) {
        if (prop === "execute" || prop === "run") {
          const original = Reflect.get(target, prop) as (...args: unknown[]) => Promise<unknown>;
          if (typeof original !== "function") return original;

          return async (...args: unknown[]): Promise<unknown> => {
            const input = args[0] as Record<string, unknown> | undefined;
            if (input) {
              const result = await guard.validate({
                type: "agent_execute",
                ...input,
              });
              if (result.decision === "DENY" || result.decision === "CIRCUIT_BREAK") {
                throw new Error(`HaltChain blocked: ${result.reason ?? result.decision}`);
              }
            }
            return original.apply(target, args);
          };
        }
        return Reflect.get(target, prop);
      },
    });
  }

  /**
   * Decorator-style wrapper for individual tool functions.
   * Validates tool input before execution and optionally redacts PII.
   */
  guardTool<TArgs extends unknown[], TReturn>(
    toolFn: (...args: TArgs) => Promise<TReturn>,
    opts?: {
      toolName?: string;
      piiRedaction?: boolean;
      traceId?: string;
    },
  ): (...args: TArgs) => Promise<TReturn> {
    const guard = this;
    const toolName = opts?.toolName ?? toolFn.name ?? "unknown_tool";
    const redact = opts?.piiRedaction ?? this.piiRedaction;
    const traceId = opts?.traceId;

    return async (...args: TArgs): Promise<TReturn> => {
      let action: Record<string, unknown> = {
        type: "tool_call",
        tool: toolName,
        args: args.length === 1 ? args[0] : args,
      };

      if (redact) {
        action = guard.redactActionPII(action);
      }

      const result = await guard.validate(action, { traceId });
      if (result.decision === "DENY" || result.decision === "CIRCUIT_BREAK") {
        throw new Error(`HaltChain blocked tool '${toolName}': ${result.reason ?? result.decision}`);
      }

      return toolFn(...args);
    };
  }

  private redactActionPII(action: Record<string, unknown>): Record<string, unknown> {
    const cleaned: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(action)) {
      if (typeof value === "string") {
        cleaned[key] = this.redactPII(value);
      } else if (typeof value === "object" && value !== null) {
        cleaned[key] = this.redactActionPII(value as Record<string, unknown>);
      } else {
        cleaned[key] = value;
      }
    }
    return cleaned;
  }
}

/**
 * Gateway-level middleware for OpenClaw mission control.
 *
 * Intercepts all requests at the gateway layer before they reach agents.
 * Compatible with Express-style middleware pattern.
 */
export class HaltChainGatewayMiddleware {
  private readonly client: HaltChainClient;

  constructor(opts: HaltChainClientOptions) {
    this.client = new HaltChainClient(opts);
  }

  /**
   * Returns an Express-compatible middleware function.
   */
  middleware(): (
    req: { body?: Record<string, unknown>; headers?: Record<string, string> },
    res: { status: (code: number) => { json: (body: unknown) => void } },
    next: () => void,
  ) => Promise<void> {
    const client = this.client;

    return async (req, res, next) => {
      const agentId = req.headers?.["x-agent-id"] ?? "unknown";
      const action = {
        type: "gateway_request",
        agent_id: agentId,
        ...(req.body ?? {}),
      };

      try {
        const result = await client.check(action);
        if (result.decision === "DENY" || result.decision === "CIRCUIT_BREAK") {
          res.status(403).json({
            error: "Request blocked by HaltChain",
            decision: result.decision,
            reason: result.reason,
            transaction_id: result.transaction_id,
          });
          return;
        }
        next();
      } catch {
        // Fail-open: if HaltChain is unreachable, allow the request
        next();
      }
    };
  }
}

/**
 * Claw-layer interceptor for deep tool-call interception.
 *
 * Unlike `HaltChainOpenClawGuard.guardTool()` which wraps individual functions,
 * `HaltClawInterceptor` wraps any Claw-compatible object at the execution layer,
 * intercepting every `call()` / `execute()` / `run()` method automatically.
 *
 * PII redaction is applied bidirectionally:
 *  - **Inputs** are scrubbed before the safety check and before tool execution
 *  - **Outputs** are scrubbed before the result is returned to the caller
 *
 * Unified trace IDs are propagated into every API call so the entire Claw
 * execution graph can be reconstructed from HaltChain audit logs.
 *
 * Usage:
 * ```ts
 * import { HaltClawInterceptor } from "@haltchain/sdk/openclaw";
 *
 * const interceptor = new HaltClawInterceptor({ agentId: "my-agent", apiKey: "key" });
 *
 * // Wrap a Claw tool object
 * const safeClaw = interceptor.wrapClaw(rawClaw, "web_search");
 *
 * // Wrap an individual async tool function
 * const safeSearch = interceptor.interceptTool(rawSearchFn, "web_search");
 * ```
 */

export interface ClawInterceptorOptions extends OpenClawGuardOptions {
  /** Trace ID to propagate. Can also be provided per-call. */
  traceId?: string;
  /** Redact PII from tool outputs as well as inputs. Default: true. */
  redactOutputs?: boolean;
  /** Methods to treat as tool-call entry points. Default: ["call", "execute", "run", "invoke"]. */
  entryPointMethods?: string[];
}

export class HaltClawInterceptor {
  private readonly client: HaltChainClient;
  private readonly piiRedaction: boolean;
  private readonly piiPatterns: RegExp[];
  private readonly redactOutputs: boolean;
  private readonly defaultTraceId?: string;
  private readonly entryPoints: Set<string>;

  constructor(opts: ClawInterceptorOptions) {
    this.client = new HaltChainClient(opts);
    this.piiRedaction = opts.piiRedaction ?? true;
    this.piiPatterns = (opts.piiPatterns ?? []).map((p) => new RegExp(p, "g")).concat(DEFAULT_PII_PATTERNS);
    this.redactOutputs = opts.redactOutputs ?? true;
    this.defaultTraceId = opts.traceId;
    this.entryPoints = new Set(opts.entryPointMethods ?? ["call", "execute", "run", "invoke"]);
  }

  /**
   * Redact PII from a string value.
   */
  private redactString(text: string): string {
    let result = text;
    for (const pattern of this.piiPatterns) {
      result = result.replace(pattern, "[REDACTED]");
    }
    return result;
  }

  /**
   * Recursively redact PII from any value (string, object, array).
   */
  private redactValue(value: unknown): unknown {
    if (typeof value === "string") return this.redactString(value);
    if (Array.isArray(value)) return value.map((v) => this.redactValue(v));
    if (typeof value === "object" && value !== null) {
      const cleaned: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        cleaned[k] = this.redactValue(v);
      }
      return cleaned;
    }
    return value;
  }

  /**
   * Intercept a single async tool function.
   * Validates inputs, optionally redacts, then redacts outputs.
   */
  interceptTool<TArgs extends unknown[], TReturn>(
    toolFn: (...args: TArgs) => Promise<TReturn>,
    toolName: string,
    opts?: { traceId?: string },
  ): (...args: TArgs) => Promise<TReturn> {
    const self = this;
    const traceId = opts?.traceId ?? this.defaultTraceId;

    return async (...args: TArgs): Promise<TReturn> => {
      // Redact inputs for the safety check (never send raw PII to the API)
      const rawArgs = args.length === 1 ? args[0] : args;
      const safeArgs = self.piiRedaction ? self.redactValue(rawArgs) : rawArgs;

      const action: Record<string, unknown> = {
        type: "claw_tool_call",
        tool: toolName,
        args: safeArgs,
      };

      const result = await self.client.check(action, { traceId });
      if (result.decision === "DENY" || result.decision === "CIRCUIT_BREAK") {
        throw new Error(`HaltChain blocked claw tool '${toolName}': ${result.reason ?? result.decision}`);
      }

      // Execute with PII-redacted inputs if piiRedaction is enabled
      const execArgs: TArgs = self.piiRedaction
        ? ((Array.isArray(rawArgs) ? rawArgs.map((a) => self.redactValue(a)) : [self.redactValue(rawArgs)]) as TArgs)
        : args;

      const output = await toolFn(...execArgs);

      if (self.redactOutputs && typeof output === "string") {
        return self.redactString(output) as unknown as TReturn;
      }
      if (self.redactOutputs && typeof output === "object" && output !== null) {
        return self.redactValue(output) as TReturn;
      }
      return output;
    };
  }

  /**
   * Wrap any Claw-compatible object at the execution layer.
   *
   * Intercepts every method listed in `entryPointMethods` (default: call/execute/run/invoke).
   * All other methods are passed through unchanged.
   */
  wrapClaw<T extends object>(claw: T, toolName?: string, opts?: { traceId?: string }): T {
    const self = this;
    const traceId = opts?.traceId ?? this.defaultTraceId;

    return new Proxy(claw, {
      get(target, prop, receiver) {
        const value = Reflect.get(target, prop, receiver);
        const methodName = typeof prop === "string" ? prop : "";

        if (typeof value !== "function" || !self.entryPoints.has(methodName)) {
          return value;
        }

        const resolvedToolName = toolName ?? methodName;
        return async (...args: unknown[]) => {
          const rawArgs: unknown = args.length === 1 ? args[0] : args;
          const safeArgs = self.piiRedaction ? self.redactValue(rawArgs) : rawArgs;

          const action: Record<string, unknown> = {
            type: "claw_tool_call",
            tool: resolvedToolName,
            method: methodName,
            args: safeArgs,
          };

          const result = await self.client.check(action, { traceId });
          if (result.decision === "DENY" || result.decision === "CIRCUIT_BREAK") {
            throw new Error(
              `HaltChain blocked claw '${resolvedToolName}.${methodName}': ${result.reason ?? result.decision}`,
            );
          }

          const execArgs = self.piiRedaction
            ? (args.map((a) => self.redactValue(a)))
            : args;

          const output: unknown = await (value as (...a: unknown[]) => Promise<unknown>).apply(target, execArgs);

          if (self.redactOutputs && typeof output === "string") {
            return self.redactString(output);
          }
          if (self.redactOutputs && typeof output === "object" && output !== null) {
            return self.redactValue(output);
          }
          return output;
        };
      },
    });
  }
}

/**
 * Approval provider for OpenClaw workflows requiring human-in-the-loop.
 *
 * Integrates with HaltChain's GOAL_CLARIFICATION_REQUIRED decision to
 * trigger approval workflows via webhook.
 */
export class HaltChainApprovalProvider {
  private readonly client: HaltChainClient;
  private readonly webhookUrl?: string;

  constructor(opts: HaltChainClientOptions & { webhookUrl?: string }) {
    this.client = new HaltChainClient(opts);
    this.webhookUrl = opts.webhookUrl;
  }

  /**
   * Check if an action requires approval.
   */
  async requiresApproval(action: Record<string, unknown>): Promise<{
    required: boolean;
    decision: string;
    reason?: string;
  }> {
    const result = await this.client.check(action);
    return {
      required: result.decision === "GOAL_CLARIFICATION_REQUIRED",
      decision: result.decision,
      reason: result.reason,
    };
  }
}
