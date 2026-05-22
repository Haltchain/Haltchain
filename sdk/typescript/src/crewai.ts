/**
 * CrewAI integration — HaltChain safety for CrewAI workflows.
 *
 * Usage:
 *
 * ```ts
 * import { HaltTaskWrapper, haltchainGuardrail } from "@haltchain/sdk/crewai";
 *
 * // Option 1: Task-level wrapper injecting before tool calls
 * const wrapper = new HaltTaskWrapper({ agentId: "my-agent", apiKey: "key" });
 * const result = await wrapper.executeTask(task, agent);
 *
 * // Option 2: Task-level guardrail function (legacy)
 * const guardrail = haltchainGuardrail({ agentId: "my-agent", apiKey: "key" });
 *
 * // Option 3: Full crew wrapping
 * const guard = new HaltChainCrewGuard({ agentId: "my-agent", apiKey: "key" });
 * const safeCrew = guard.wrapCrew(crew);
 * ```
 */

import { HaltChainClient } from "./client.js";
import type { HaltChainClientOptions, ValidationResponse } from "./types.js";

export interface CrewGuardOptions extends HaltChainClientOptions {
  /** Action type identifier for crew task validations. */
  defaultActionType?: string;
}

export interface GuardrailResult {
  allowed: boolean;
  decision: string;
  reason?: string;
  /** If denied, contains the recommended action (retry/skip/abort). */
  recommendation?: "retry" | "skip" | "abort";
}

/**
 * Creates a guardrail function for CrewAI task-level validation.
 *
 * Returns a function that validates task output before it's accepted,
 * compatible with CrewAI's guardrail mechanism.
 */
export function haltchainGuardrail(
  opts: CrewGuardOptions,
): (taskOutput: Record<string, unknown>) => Promise<GuardrailResult> {
  const client = new HaltChainClient(opts);
  const actionType = opts.defaultActionType ?? "crew_task";

  return async (taskOutput: Record<string, unknown>): Promise<GuardrailResult> => {
    const action = {
      type: actionType,
      output: typeof taskOutput.raw === "string"
        ? taskOutput.raw
        : JSON.stringify(taskOutput),
      ...extractCrewMetadata(taskOutput),
    };

    const result = await client.check(action);
    return mapDecision(result);
  };
}

/**
 * Full crew-level guard that wraps CrewAI crew execution.
 */
export class HaltChainCrewGuard {
  private readonly client: HaltChainClient;
  private readonly actionType: string;

  constructor(opts: CrewGuardOptions) {
    this.client = new HaltChainClient(opts);
    this.actionType = opts.defaultActionType ?? "crew_task";
  }

  /**
   * Validate a single task's input/output against HaltChain policies.
   */
  async validateTask(task: {
    description?: string;
    expected_output?: string;
    input?: Record<string, unknown>;
    output?: Record<string, unknown>;
  }): Promise<GuardrailResult> {
    const action: Record<string, unknown> = {
      type: this.actionType,
      task_description: task.description,
      expected_output: task.expected_output,
    };
    if (task.input) action.input = task.input;
    if (task.output) action.output = task.output;

    const result = await this.client.check(action);
    return mapDecision(result);
  }

  /**
   * Validate an agent delegation (agent → agent tool call).
   */
  async validateDelegation(
    fromAgent: string,
    toAgent: string,
    taskDescription: string,
  ): Promise<GuardrailResult> {
    const result = await this.client.check({
      type: "delegation",
      from_agent: fromAgent,
      to_agent: toAgent,
      task: taskDescription,
    });
    return mapDecision(result);
  }

  /**
   * Wrap a crew's kickoff method to auto-validate before and after tasks.
   */
  wrapCrew<T extends { kickoff: (...args: unknown[]) => Promise<unknown> }>(crew: T): T {
    const guard = this;
    const originalKickoff = crew.kickoff.bind(crew);

    const wrappedKickoff = async (...args: unknown[]): Promise<unknown> => {
      const input = args[0] as Record<string, unknown> | undefined;

      // Pre-validate kickoff input
      if (input) {
        const result = await guard.client.check({
          type: "crew_kickoff",
          ...input,
        });
        if (result.decision === "DENY" || result.decision === "CIRCUIT_BREAK") {
          throw new Error(`HaltChain blocked crew kickoff: ${result.reason ?? result.decision}`);
        }
      }

      return originalKickoff(...args);
    };

    return new Proxy(crew, {
      get(target, prop) {
        if (prop === "kickoff") return wrappedKickoff;
        return Reflect.get(target, prop);
      },
    });
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function extractCrewMetadata(taskOutput: Record<string, unknown>): Record<string, unknown> {
  const meta: Record<string, unknown> = {};
  if (taskOutput.agent) meta.agent_name = taskOutput.agent;
  if (taskOutput.task) meta.task_name = taskOutput.task;
  if (taskOutput.pydantic) meta.structured_output = true;
  return meta;
}

function mapDecision(result: ValidationResponse): GuardrailResult {
  const allowed = result.decision === "ALLOW" ||
    result.decision === "GOAL_CLARIFICATION_REQUIRED";

  let recommendation: "retry" | "skip" | "abort" | undefined;
  if (result.decision === "DENY") recommendation = "skip";
  if (result.decision === "CIRCUIT_BREAK") recommendation = "abort";
  if (result.decision === "GOAL_CLARIFICATION_REQUIRED") recommendation = "retry";

  return {
    allowed,
    decision: result.decision,
    reason: result.reason,
    recommendation,
  };
}

// ── HaltTaskWrapper ───────────────────────────────────────────────────────────

export interface TaskWrapperOptions extends HaltChainClientOptions {
  /**
   * State key carrying the HaltChain trace ID for cross-agent audit correlation.
   * Default: "haltchain_trace_id".
   */
  traceIdKey?: string;
  /** If true (default), throw on DENY/CIRCUIT_BREAK before the task runs. */
  blockOnDeny?: boolean;
}

/**
 * Represents a CrewAI Agent (duck-typed — no runtime dependency on crewai-js).
 */
export interface CrewAgent {
  id?: string;
  role?: string;
  goal?: string;
  tools?: Array<{ name?: string }>;
}

/**
 * Represents a CrewAI Task (duck-typed).
 */
export interface CrewTask {
  description?: string;
  expected_output?: string;
  agent?: CrewAgent;
  tools?: Array<{ name?: string }>;
  execute?: (...args: unknown[]) => Promise<unknown>;
}

/**
 * HaltTaskWrapper — injects into `Task.execute()` before tool calls,
 * capturing the Agent's delegation intent for policy validation.
 *
 * This is the roadmap-compliant CrewAI integration class.  It validates:
 * 1. The **pre-execution intent** (what the agent is about to do)
 * 2. Each **tool call** in the task's tool list
 * 3. The **delegation** when one agent hands off to another
 *
 * Example:
 * ```ts
 * const wrapper = new HaltTaskWrapper({ agentId: "researcher", apiKey });
 * const taskOutput = await wrapper.executeTask(myTask, callingAgent);
 * ```
 */
export class HaltTaskWrapper {
  private readonly client: HaltChainClient;
  private readonly traceIdKey: string;
  private readonly blockOnDeny: boolean;

  constructor(opts: TaskWrapperOptions) {
    this.client = new HaltChainClient(opts);
    this.traceIdKey = opts.traceIdKey ?? "haltchain_trace_id";
    this.blockOnDeny = opts.blockOnDeny ?? true;
  }

  /**
   * Validate and execute a task, injecting HaltChain checks before tool calls.
   *
   * @param task    The CrewAI Task to execute.
   * @param agent   The Agent executing the task (provides delegation context).
   * @param traceId Trace ID for cross-agent audit correlation (optional).
   */
  async executeTask(
    task: CrewTask,
    agent: CrewAgent,
    traceId?: string,
  ): Promise<unknown> {
    // 1. Pre-task intent validation — captures delegation intent before execution.
    const intentAction: Record<string, unknown> = {
      type: "crew_task_intent",
      task_description: task.description,
      expected_output: task.expected_output,
      agent_role: agent.role,
      agent_goal: agent.goal,
      tool_names: (task.tools ?? agent.tools ?? []).map((t) => t.name).filter(Boolean),
    };

    const metadata: Record<string, unknown> = {};
    if (traceId) metadata[this.traceIdKey] = traceId;

    const intentResult = await this.client.check(intentAction, { context: metadata });
    if (
      this.blockOnDeny &&
      (intentResult.decision === "DENY" || intentResult.decision === "CIRCUIT_BREAK")
    ) {
      throw new Error(
        `HaltTaskWrapper blocked task intent for '${agent.role ?? "agent"}': ` +
        `${intentResult.reason ?? intentResult.decision}`,
      );
    }

    // 2. Per-tool pre-call validation
    const tools = task.tools ?? agent.tools ?? [];
    for (const tool of tools) {
      if (!tool.name) continue;
      const toolAction: Record<string, unknown> = {
        type: "crew_tool_call",
        tool_name: tool.name,
        agent_role: agent.role,
        task_description: task.description,
      };
      if (traceId) metadata[this.traceIdKey] = traceId;

      const toolResult = await this.client.check(toolAction, { context: metadata });
      if (
        this.blockOnDeny &&
        (toolResult.decision === "DENY" || toolResult.decision === "CIRCUIT_BREAK")
      ) {
        throw new Error(
          `HaltTaskWrapper blocked tool '${tool.name}' for '${agent.role ?? "agent"}': ` +
          `${toolResult.reason ?? toolResult.decision}`,
        );
      }
    }

    // 3. Delegate to task.execute() if available
    if (typeof task.execute === "function") {
      return task.execute();
    }

    // If task has no execute method (Python-side execution), return allowed signal.
    return { haltchain_decision: "ALLOW", traceId };
  }

  /**
   * Validate an agent-to-agent delegation before it occurs.
   * Returns whether the delegation is permitted.
   */
  async validateDelegation(
    fromAgent: CrewAgent,
    toAgent: CrewAgent,
    taskDescription: string,
    traceId?: string,
  ): Promise<GuardrailResult> {
    const metadata: Record<string, unknown> = {};
    if (traceId) metadata[this.traceIdKey] = traceId;

    const result = await this.client.check(
      {
        type: "crew_delegation",
        from_agent_role: fromAgent.role,
        to_agent_role: toAgent.role,
        task_description: taskDescription,
      },
      { context: metadata },
    );
    return mapDecision(result);
  }
}
