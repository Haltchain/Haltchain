import { useEffect, useMemo, useState } from "react";

import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { DecisionBadge } from "@/components/dashboard/DecisionBadge";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import { getAgentStatus, getReviewQueue, type AgentStatus } from "@/lib/admin-api";

function clampPercent(numerator: number, denominator: number) {
  if (denominator <= 0) return 0;
  return Math.max(0, Math.min(100, Math.round((numerator / denominator) * 100)));
}

export default function AgentsPage() {
  const [manualAgentId, setManualAgentId] = useState("");
  const [agentIds, setAgentIds] = useState<string[]>([]);
  const [statuses, setStatuses] = useState<Record<string, AgentStatus>>({});
  const { toast } = useToast();

  const loadStatuses = async (ids: string[]) => {
    const next: Record<string, AgentStatus> = {};
    await Promise.all(
      ids.map(async (agentId) => {
        try {
          next[agentId] = await getAgentStatus(agentId);
        } catch {
          // Keep missing status absent; the card will not render.
        }
      }),
    );
    setStatuses(next);
  };

  const targetIds = useMemo(() => {
    const base = new Set(agentIds);
    if (manualAgentId.trim()) {
      base.add(manualAgentId.trim());
    }
    return Array.from(base);
  }, [agentIds, manualAgentId]);

  useEffect(() => {
    let active = true;

    const cycle = async () => {
      try {
        const queue = await getReviewQueue();
        if (!active) return;
        const discovered = Array.from(new Set(queue.map((q) => q.agent_id).filter(Boolean))).sort();
        setAgentIds(discovered);

        const ids = Array.from(new Set([...discovered, ...(manualAgentId.trim() ? [manualAgentId.trim()] : [])]));
        if (ids.length > 0) {
          await loadStatuses(ids);
        } else {
          setStatuses({});
        }
      } catch (err) {
        toast({ title: "Failed to load agents", description: err instanceof Error ? err.message : "Unexpected error" });
      }
    };

    void cycle();
    const id = window.setInterval(cycle, 15000);
    return () => {
      active = false;
      window.clearInterval(id);
    };
  }, [manualAgentId, toast]);

  const cards = useMemo(() => targetIds.map((agentId) => statuses[agentId]).filter(Boolean), [targetIds, statuses]);

  return (
    <DashboardLayout>
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-2xl">Agent Status Board</h1>
            <p className="text-sm text-muted-foreground">Live risk posture with circuit-breaker and anomaly telemetry.</p>
          </div>
          <Input
            className="w-full max-w-sm"
            placeholder="Add agent id"
            value={manualAgentId}
            onChange={(e) => setManualAgentId(e.target.value)}
          />
        </div>

        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {cards.map((status) => {
            const utilization = clampPercent(status.actions_this_minute, status.rate_limit);
            return (
              <article key={status.agent_id} className="rounded-xl border border-border p-4">
                <div className="mb-3 flex items-center justify-between gap-2">
                  <h2 className="font-medium">{status.agent_id}</h2>
                  <DecisionBadge value={status.circuit_breaker_active ? "CIRCUIT_BREAK" : "ALLOW"} />
                </div>

                <p className="mb-2 text-sm text-muted-foreground">
                  Actions/min: {status.actions_this_minute} / {status.rate_limit}
                </p>
                <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                  <div className="h-full bg-primary" style={{ width: `${utilization}%` }} />
                </div>

                <p className="mt-3 text-sm text-muted-foreground">
                  Anomaly score: <span className="rounded-md bg-muted px-2 py-1 text-foreground">{status.anomaly_score ?? "n/a"}</span>
                </p>
              </article>
            );
          })}

          {!cards.length && (
            <div className="rounded-xl border border-border p-8 text-center text-muted-foreground">
              No agent status available yet.
            </div>
          )}
        </div>
      </div>
    </DashboardLayout>
  );
}
