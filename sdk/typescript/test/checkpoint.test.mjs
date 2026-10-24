import assert from "node:assert/strict";
import test from "node:test";

import { HaltCheckpointer as HaltCheckpointerFromIndex } from "../dist/index.js";
import { HaltCheckpointer } from "../dist/langgraph.js";

const CLIENT = {
  agentId: "agent-1",
  apiKey: "test-key",
  baseUrl: "http://127.0.0.1:9",
  verifySignatures: false,
};

function installFetch(decide) {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    const body = init?.body ? JSON.parse(init.body) : null;
    calls.push({ url: String(url), body, headers: init?.headers });
    const decision = decide(body, calls.length);
    return new Response(
      JSON.stringify({
        transaction_id: `tx-${calls.length}`,
        decision: decision.decision,
        reason: decision.reason,
        timestamp: "2026-01-01T00:00:00Z",
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  };
  return calls;
}

test("package entry and langgraph subpath both export HaltCheckpointer", () => {
  assert.equal(HaltCheckpointerFromIndex, HaltCheckpointer);
});

test("checkTransition sends nested diffs plus session and trace ids", async () => {
  const calls = installFetch(() => ({ decision: "ALLOW" }));
  const cp = new HaltCheckpointer(CLIENT);
  const result = await cp.checkTransition(
    { session_id: "s-old", balance: { usd: 1 }, note: "a" },
    {
      session_id: "s-new",
      haltchain_trace_id: "tr-9",
      balance: { usd: 2 },
      note: "a",
    },
    "tools",
  );

  assert.equal(result.decision, "ALLOW");
  assert.equal(calls.length, 1);
  const sent = calls[0].body;
  assert.equal(sent.agent_id, "agent-1");
  assert.equal(sent.session_id, "s-new");
  assert.equal(sent.metadata.haltchain_trace_id, "tr-9");
  assert.equal(sent.action.type, "checkpoint:tools");
  assert.equal(sent.action.diff_count, 3);
  assert.deepEqual(
    [...sent.action.changed_keys].sort(),
    ["balance.usd", "haltchain_trace_id", "session_id"],
  );
  assert.equal(calls[0].headers["x-api-key"], "test-key");
});

test("diff_count keeps the full change set when the payload is capped", async () => {
  const calls = installFetch(() => ({ decision: "ALLOW" }));
  const cp = new HaltCheckpointer({ ...CLIENT, maxDiffEntries: 1 });
  await cp.checkTransition({}, { a: 1, b: 2, c: 3 }, "bulk");
  const action = calls[0].body.action;
  assert.equal(action.diff_count, 3);
  assert.equal(action.changed_keys.length, 1);
  assert.equal(action.diff_sample.length, 1);
});

test("internal snapshot keys are excluded from the policy diff", async () => {
  const calls = installFetch(() => ({ decision: "ALLOW" }));
  const cp = new HaltCheckpointer(CLIENT);
  await cp.checkTransition(
    { __haltchain_pre_haltchain_checkpoint: { old: 1, nested: { x: 1 } }, a: 1 },
    { __haltchain_pre_haltchain_checkpoint: { old: 2, nested: { x: 9 } }, a: 2 },
    "haltchain_checkpoint",
  );
  assert.deepEqual(calls[0].body.action.changed_keys, ["a"]);
  assert.equal(calls[0].body.action.diff_count, 1);
});

test("DENY, CIRCUIT_BREAK, and unknown decisions fail closed", async () => {
  const cp = new HaltCheckpointer(CLIENT);
  installFetch(() => ({ decision: "DENY", reason: "over limit" }));
  await assert.rejects(
    () => cp.checkTransition({}, { amount: 999 }, "pay"),
    /HaltCheckpointer blocked at node 'pay': over limit/,
  );

  installFetch(() => ({ decision: "CIRCUIT_BREAK", reason: "velocity" }));
  await assert.rejects(
    () => cp.checkTransition({}, { amount: 1 }, "pay"),
    /velocity/,
  );

  installFetch(() => ({ decision: "MAYBE" }));
  await assert.rejects(
    () => cp.checkTransition({}, { amount: 1 }, "pay"),
    /MAYBE/,
  );
});

test("goal clarification is returned to the caller instead of thrown", async () => {
  installFetch(() => ({
    decision: "GOAL_CLARIFICATION_REQUIRED",
    reason: "re-declare intent",
  }));
  const cp = new HaltCheckpointer(CLIENT);
  const result = await cp.checkTransition({}, { goal: "new" }, "agent");
  assert.equal(result.decision, "GOAL_CLARIFICATION_REQUIRED");
});

test("blockOnDeny false returns a deny decision", async () => {
  installFetch(() => ({ decision: "DENY", reason: "watch" }));
  const cp = new HaltCheckpointer({ ...CLIENT, blockOnDeny: false });
  const result = await cp.checkTransition({}, { x: 1 }, "pay");
  assert.equal(result.decision, "DENY");
});

test("validator outage fails closed", async () => {
  globalThis.fetch = async () => {
    throw new Error("offline");
  };
  const cp = new HaltCheckpointer(CLIENT);
  await assert.rejects(() => cp.checkTransition({ a: 1 }, { a: 2 }, "n"), /offline/);
});

test("checkpoint node diffs only the new transition and freezes the baseline", async () => {
  const calls = installFetch(() => ({ decision: "ALLOW" }));
  const cp = new HaltCheckpointer(CLIENT);
  const node = cp.asCheckpointNode("haltchain_checkpoint");

  const state = {
    balance: { usd: 10 },
    session_id: "sess",
    haltchain_trace_id: "t1",
  };
  const patch = await node(state);
  state.balance.usd = 999;

  const stored = patch.__haltchain_pre_haltchain_checkpoint;
  assert.equal(stored.balance.usd, 10);
  assert.equal(stored.__haltchain_pre_haltchain_checkpoint, undefined);
  assert.equal(calls[0].body.session_id, "sess");
  assert.equal(calls[0].body.metadata.haltchain_trace_id, "t1");
  assert.ok(calls[0].body.action.diff_count >= 3);

  await node({
    balance: { usd: 11 },
    session_id: "sess",
    haltchain_trace_id: "t1",
    ...patch,
  });

  const second = calls[1].body.action;
  assert.equal(second.type, "checkpoint:haltchain_checkpoint");
  assert.equal(second.diff_count, 1);
  assert.deepEqual(second.changed_keys, ["balance.usd"]);
  assert.equal(
    second.changed_keys.some((key) => key.includes("__haltchain")),
    false,
  );
});

test("checkpoint node does not store a baseline when the validator denies", async () => {
  installFetch(() => ({ decision: "DENY", reason: "blocked" }));
  const cp = new HaltCheckpointer(CLIENT);
  const node = cp.asCheckpointNode();
  await assert.rejects(() => node({ secret: "x" }), /blocked/);
});

test("wrap validates the raw input to output transition", async () => {
  const calls = installFetch(() => ({ decision: "ALLOW" }));
  const cp = new HaltCheckpointer(CLIENT);
  let invoked = 0;
  const graph = {
    async invoke(input) {
      invoked += 1;
      return { ...input, balance: { usd: 5 }, done: true };
    },
  };

  const wrapped = cp.wrap(graph);
  const output = await wrapped.invoke({
    session_id: "wrap-s",
    haltchain_trace_id: "wrap-t",
    balance: { usd: 1 },
  });

  assert.equal(invoked, 1);
  assert.equal(output.done, true);
  assert.equal(calls[0].body.session_id, "wrap-s");
  assert.equal(calls[0].body.metadata.haltchain_trace_id, "wrap-t");
  assert.equal(calls[0].body.action.type, "checkpoint:graph_invoke");
  assert.ok(calls[0].body.action.changed_keys.includes("balance.usd"));
  assert.ok(calls[0].body.action.changed_keys.includes("done"));

  installFetch(() => ({ decision: "DENY", reason: "stop graph" }));
  const denying = new HaltCheckpointer(CLIENT).wrap(graph);
  await assert.rejects(() => denying.invoke({ session_id: "wrap-s" }), /graph_invoke/);
  assert.equal(invoked, 2);
});
