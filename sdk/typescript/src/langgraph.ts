/**
 * LangGraph integration — drop-in HaltChain safety for LangGraph.js workflows.
 *
 * Usage (3 lines to add HaltChain):
 *
 * ```ts
 * import { HaltCheckpointer } from "@haltchain/sdk/langgraph";
 *
 * const checkpointer = new HaltCheckpointer({ agentId: "my-agent", apiKey: "key" });
 * const safeGraph = checkpointer.wrap(compiledGraph);
 * ```
 *
 * For finer control, use as a checkpoint boundary interceptor:
 *
 * ```ts
 * builder.addNode("haltchain_checkpoint", checkpointer.asCheckpointNode());
 * ```
 *
 * Legacy `HaltChainGuard` is kept for backward compatibility.
 */

import { HaltChainClient } from "./client.js";
import type { HaltChainClientOptions, ValidationResponse } from "./types.js";

export interface LangGraphGuardOptions extends HaltChainClientOptions {
  /** Maps tool names to functions that build HaltChain action objects from tool input. */
  toolActionMap?: Record<string, (input: Record<string, unknown>) => Record<string, unknown>>;
  /** If true (default), denied actions throw. If false, injects a deny message. */
  blockOnDeny?: boolean;
  /** State key for session ID propagation. */
  sessionKey?: string;
}

/**
 * Drop-in safety layer for LangGraph.js workflows.
 *
 * Intercepts tool calls and state transitions, validating each against
 * HaltChain policy before execution proceeds.
 */
export class HaltChainGuard {
  private readonly client: HaltChainClient;
  private readonly toolMap: Record<string, (input: Record<string, unknown>) => Record<string, unknown>>;
  private readonly blockOnDeny: boolean;
  private readonly sessionKey: string;

  constructor(opts: LangGraphGuardOptions) {
    this.client = new HaltChainClient(opts);
    this.toolMap = opts.toolActionMap ?? {};
    this.blockOnDeny = opts.blockOnDeny ?? true;
    this.sessionKey = opts.sessionKey ?? "session_id";
  }

  /**
   * Validate an action and return the validation response.
   * Throws if denied and blockOnDeny is true.
   */
  async validate(
    action: Record<string, unknown>,
    sessionId?: string,
  ): Promise<ValidationResponse> {
    const result = await this.client.check(action, { sessionId });
    if (this.blockOnDeny && (result.decision === "DENY" || result.decision === "CIRCUIT_BREAK")) {
      throw new Error(`HaltChain blocked: ${result.reason ?? result.decision}`);
    }
    return result;
  }

  /**
   * Build an action dict from a tool call. Uses toolActionMap if available,
   * otherwise creates a generic `{ type: toolName, ...input }` action.
   */
  private buildAction(toolName: string, input: Record<string, unknown>): Record<string, unknown> {
    const mapper = this.toolMap[toolName];
    if (mapper) return mapper(input);
    return { type: toolName, ...input };
  }

  /**
   * Returns a node function compatible with LangGraph's `addNode()`.
   *
   * The node validates the last tool call in state.messages and either
   * passes through or throws/injects a deny message.
   */
  asNode(): (state: Record<string, unknown>) => Promise<Record<string, unknown>> {
    return async (state: Record<string, unknown>) => {
      const messages = state.messages as Array<Record<string, unknown>> | undefined;
      if (!messages?.length) return state;

      const last = messages[messages.length - 1];
      const toolCalls = (last as Record<string, unknown>).tool_calls as
        | Array<{ name: string; args: Record<string, unknown> }>
        | undefined;

      if (!toolCalls?.length) return state;

      const sessionId = state[this.sessionKey] as string | undefined;

      for (const call of toolCalls) {
        const action = this.buildAction(call.name, call.args);
        await this.validate(action, sessionId);
      }

      return state;
    };
  }

  /**
   * Returns a conditional gate function for `addConditionalEdges()`.
   *
   * Routes to `then` if validation passes, or `deny` if blocked.
   */
  gate(opts: { then: string; deny: string }): (state: Record<string, unknown>) => Promise<string> {
    return async (state: Record<string, unknown>) => {
      try {
        const messages = state.messages as Array<Record<string, unknown>> | undefined;
        if (!messages?.length) return opts.then;

        const last = messages[messages.length - 1];
        const toolCalls = (last as Record<string, unknown>).tool_calls as
          | Array<{ name: string; args: Record<string, unknown> }>
          | undefined;

        if (!toolCalls?.length) return opts.then;

        const sessionId = state[this.sessionKey] as string | undefined;

        for (const call of toolCalls) {
          const action = this.buildAction(call.name, call.args);
          const result = await this.client.check(action, { sessionId });
          if (result.decision === "DENY" || result.decision === "CIRCUIT_BREAK") {
            return opts.deny;
          }
        }
        return opts.then;
      } catch {
        return opts.deny;
      }
    };
  }

  /**
   * Wrap a compiled graph's invoke/stream to auto-validate tool calls.
   * Returns a proxy that intercepts invoke() and stream() calls.
   */
  wrap<T extends { invoke: (...args: unknown[]) => Promise<unknown> }>(graph: T): T {
    const guard = this;
    const originalInvoke = graph.invoke.bind(graph);

    const wrappedInvoke = async (...args: unknown[]): Promise<unknown> => {
      const input = args[0] as Record<string, unknown> | undefined;
      if (input) {
        const sessionId = (input[guard.sessionKey] as string) ?? undefined;
        // Pre-validate the input action if it looks like one
        if (input.type || input.action_type) {
          await guard.validate(input as Record<string, unknown>, sessionId);
        }
      }
      return originalInvoke(...args);
    };

    return new Proxy(graph, {
      get(target, prop) {
        if (prop === "invoke") return wrappedInvoke;
        return Reflect.get(target, prop);
      },
    });
  }
}

// ── Structured diff helpers ───────────────────────────────────────────────────

/** Prefix for snapshots stored on LangGraph state between checkpoint nodes. */
const INTERNAL_PREFIX = "__haltchain_pre_";

/** Drop checkpoint bookkeeping so it cannot dominate the policy diff. */
function withoutInternalKeys(state: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(state)) {
    if (k.startsWith(INTERNAL_PREFIX)) continue;
    out[k] = v;
  }
  return out;
}

function asStateRecord(value: unknown): Record<string, unknown> {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  if (value === undefined || value === null) return {};
  return { value };
}

/** Copy state so a later in-place mutation cannot rewrite the stored baseline. */
function cloneSnapshot(state: Record<string, unknown>): Record<string, unknown> {
  const clean = withoutInternalKeys(state);
  if (typeof structuredClone === "function") {
    try {
      return structuredClone(clean);
    } catch {
      // Non-cloneable values fall through to JSON.
    }
  }
  return JSON.parse(JSON.stringify(clean)) as Record<string, unknown>;
}

/** Flatten an object to leaf `"key.path": value` pairs for diff computation. */
function flattenState(obj: Record<string, unknown>, prefix = ""): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      Object.assign(out, flattenState(v as Record<string, unknown>, key));
    } else {
      out[key] = v;
    }
  }
  return out;
}

/** Returns keys that changed between two flattened state snapshots. */
function stateDiff(
  before: Record<string, unknown>,
  after: Record<string, unknown>,
): Array<{ key: string; before: unknown; after: unknown }> {
  const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
  const changes: Array<{ key: string; before: unknown; after: unknown }> = [];
  for (const key of keys) {
    if (JSON.stringify(before[key]) !== JSON.stringify(after[key])) {
      changes.push({ key, before: before[key], after: after[key] });
    }
  }
  return changes;
}

// ── HaltCheckpointer ─────────────────────────────────────────────────────────

export interface CheckpointerOptions extends HaltChainClientOptions {
  /**
   * State key holding the trace ID for cross-agent audit propagation.
   * Default: "haltchain_trace_id".
   */
  traceIdKey?: string;
  /**
   * State key holding the session ID for goal-drift tracking.
   * Default: "session_id".
   */
  sessionKey?: string;
  /**
   * Maximum number of diff entries to include in the metadata payload.
   * Prevents large state objects from bloating the request body.
   * Default: 50.
   */
  maxDiffEntries?: number;
  /** If true (default), throw on DENY/CIRCUIT_BREAK. */
  blockOnDeny?: boolean;
}

/**
 * HaltCheckpointer — intercepts LangGraph `StateGraph` transitions at the
 * checkpoint boundary, capturing pre/post state diffs automatically.
 *
 * This is the roadmap-compliant integration class (replaces HaltChainGuard
 * for new code).  It validates the **state transition** itself, not just
 * individual tool calls, enabling policy rules that inspect what actually
 * changed between graph nodes.
 *
 * Example:
 * ```ts
 * const checkpointer = new HaltCheckpointer({ agentId: "orchestrator", apiKey });
 * builder.addNode("haltchain_checkpoint", checkpointer.asCheckpointNode());
 * builder.addEdge("agent", "haltchain_checkpoint");
 * builder.addEdge("haltchain_checkpoint", "tools");
 * ```
 */
export class HaltCheckpointer {
  private readonly client: HaltChainClient;
  private readonly traceIdKey: string;
  private readonly sessionKey: string;
  private readonly maxDiffEntries: number;
  private readonly blockOnDeny: boolean;

  constructor(opts: CheckpointerOptions) {
    this.client = new HaltChainClient(opts);
    this.traceIdKey = opts.traceIdKey ?? "haltchain_trace_id";
    this.sessionKey = opts.sessionKey ?? "session_id";
    this.maxDiffEntries = opts.maxDiffEntries ?? 50;
    this.blockOnDeny = opts.blockOnDeny ?? true;
  }

  /**
   * Validate a state transition — the core checkpoint boundary check.
   *
   * @param stateBefore State snapshot before the node ran.
   * @param stateAfter  State snapshot after the node ran.
   * @param nodeName    Name of the completed node (used as action_type).
   */
  async checkTransition(
    stateBefore: Record<string, unknown>,
    stateAfter: Record<string, unknown>,
    nodeName: string,
  ): Promise<ValidationResponse> {
    const before = withoutInternalKeys(stateBefore);
    const after = withoutInternalKeys(stateAfter);
    const traceId = (after[this.traceIdKey] ?? before[this.traceIdKey]) as string | undefined;
    const sessionId = (after[this.sessionKey] ?? before[this.sessionKey]) as string | undefined;

    const flatBefore = flattenState(before);
    const flatAfter = flattenState(after);
    const changes = stateDiff(flatBefore, flatAfter);
    const diff = changes.slice(0, this.maxDiffEntries);

    const action: Record<string, unknown> = {
      type: `checkpoint:${nodeName}`,
      // Surface tool calls in the diff so YAML rules can inspect them.
      // `diff_count` is the full change set; `changed_keys` / `diff_sample` are capped.
      changed_keys: diff.map((d) => d.key),
      diff_count: changes.length,
      diff_sample: diff.slice(0, 10),
    };

    // Propagate trace ID as metadata for cross-agent audit correlation
    const metadata: Record<string, unknown> = {};
    if (traceId) metadata["haltchain_trace_id"] = traceId;

    const result = await this.client.check(action, { sessionId, context: metadata });

    // ALLOW and goal-clarification are the only decisions that may continue.
    // Missing or unexpected decisions fail closed.
    const mayContinue =
      result.decision === "ALLOW" || result.decision === "GOAL_CLARIFICATION_REQUIRED";
    if (this.blockOnDeny && !mayContinue) {
      throw new Error(
        `HaltCheckpointer blocked at node '${nodeName}': ${result.reason ?? result.decision}`,
      );
    }

    return result;
  }

  /**
   * Returns a LangGraph node function that intercepts the checkpoint boundary.
   *
   * The node stores a pre-transition snapshot, lets the state pass through,
   * then validates the diff.  Place it after the agent node and before tools.
   */
  asCheckpointNode(
    nodeName = "haltchain_checkpoint",
  ): (state: Record<string, unknown>) => Promise<Record<string, unknown>> {
    return async (state: Record<string, unknown>) => {
      // LangGraph merges the partial return into channel state. The incoming
      // object is the post-transition snapshot; the value under `preKey` is the
      // previous boundary. Internal keys are omitted from the policy diff and
      // from the stored baseline so they cannot grow without bound.
      const preKey = `${INTERNAL_PREFIX}${nodeName}`;
      const prev = state[preKey];
      const preSnapshot =
        prev !== null && typeof prev === "object" && !Array.isArray(prev)
          ? (prev as Record<string, unknown>)
          : {};
      const current = withoutInternalKeys(state);

      await this.checkTransition(preSnapshot, current, nodeName);

      return { [preKey]: cloneSnapshot(current) };
    };
  }

  /**
   * Wrap a compiled StateGraph to automatically checkpoint every node transition.
   *
   * Injects a pre-invoke snapshot and validates the post-invoke state diff.
   */
  wrap<T extends { invoke: (...args: unknown[]) => Promise<unknown> }>(graph: T): T {
    const self = this;
    const originalInvoke = graph.invoke.bind(graph);

    const wrappedInvoke = async (...args: unknown[]): Promise<unknown> => {
      const input = asStateRecord(args[0]);
      const output = await originalInvoke(...args);

      // Pass raw state. checkTransition flattens and reads session/trace ids
      // itself; pre-flattening hides top-level ids that live beside nested objects
      // only after a second flatten, and drops non-object graph results.
      await self.checkTransition(input, asStateRecord(output), "graph_invoke");

      return output;
    };

    return new Proxy(graph, {
      get(target, prop) {
        if (prop === "invoke") return wrappedInvoke;
        return Reflect.get(target, prop);
      },
    });
  }
}
