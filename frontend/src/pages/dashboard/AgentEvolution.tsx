import { useEffect, useMemo, useState } from "react";

import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import {
  getReviewQueue,
  getVersionLineage,
  type ImprovementDecision,
  type VersionLineageEntry,
} from "@/lib/admin-api";

function decisionLabel(d: ImprovementDecision): string {
  switch (d.decision) {
    case "approve":
      return "Approved";
    case "reject":
      return "Rejected";
    case "gradual_rollout":
      return `Canary ${Math.round(d.canary_percentage * 100)}%`;
    case "require_human_approval":
      return "Needs Review";
    default:
      return "Unknown";
  }
}

function decisionVariant(
  d: ImprovementDecision,
): "default" | "destructive" | "secondary" | "outline" {
  switch (d.decision) {
    case "approve":
      return "default";
    case "reject":
      return "destructive";
    case "gradual_rollout":
      return "secondary";
    case "require_human_approval":
      return "outline";
    default:
      return "secondary";
  }
}

function AdversarialBar({ passed, total }: { passed: number; total: number }) {
  const pct = total > 0 ? Math.round((passed / total) * 100) : 0;
  const ok = pct >= 95;
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-xs text-muted-foreground">
        <span>
          {passed}/{total} adversarial tests
        </span>
        <span className={ok ? "text-emerald-400" : "text-red-400"}>{pct}%</span>
      </div>
      <Progress
        value={pct}
        className={`h-1.5 ${ok ? "[&>div]:bg-emerald-500" : "[&>div]:bg-red-500"}`}
      />
    </div>
  );
}

function LineageCard({ entry }: { entry: VersionLineageEntry }) {
  const ts = new Date(entry.recorded_at).toLocaleString();
  const diff = entry.diff_summary;

  return (
    <div className="rounded-lg border border-border bg-card/50 p-3 text-sm space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-mono text-xs text-muted-foreground">
          v{diff.old_version} → v{diff.new_version}
        </span>
        <div className="flex gap-2 items-center">
          <Badge variant={decisionVariant(entry.decision)}>{decisionLabel(entry.decision)}</Badge>
          {entry.promoted && (
            <Badge variant="outline" className="text-emerald-400 border-emerald-600">
              Promoted
            </Badge>
          )}
        </div>
      </div>

      {entry.adversarial_result && (
        <AdversarialBar
          passed={entry.adversarial_result.passed}
          total={entry.adversarial_result.total_cases}
        />
      )}

      <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-xs text-muted-foreground">
        <span>Goal changed: {diff.goal_changed ? "Yes" : "No"}</span>
        <span>
          Cosine shift:{" "}
          {diff.goal_cosine_shift != null
            ? (1 - diff.goal_cosine_shift).toFixed(3)
            : "n/a"}
        </span>
        <span>Model replaced: {diff.anomaly_model_replaced ? "Yes" : "No"}</span>
        <span>Max Δ threshold: {(diff.max_threshold_relative_delta * 100).toFixed(1)}%</span>
      </div>

      {entry.decision.decision === "reject" && (
        <p className="text-xs text-red-400 break-all">↳ {entry.decision.reason}</p>
      )}

      <p className="text-xs text-muted-foreground/60">{ts}</p>
    </div>
  );
}

function AgentLineagePanel({ agentId }: { agentId: string }) {
  const [lineage, setLineage] = useState<VersionLineageEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    let active = true;
    const load = async () => {
      setLoading(true);
      try {
        const data = await getVersionLineage(agentId);
        if (active) setLineage([...data.lineage].reverse());
      } catch (err) {
        if (active)
          toast({
            title: `Failed to load lineage for ${agentId}`,
            description: err instanceof Error ? err.message : "Unexpected error",
          });
      } finally {
        if (active) setLoading(false);
      }
    };
    void load();
    const id = window.setInterval(load, 20_000);
    return () => {
      active = false;
      window.clearInterval(id);
    };
  }, [agentId, toast]);

  return (
    <Card className="w-full">
      <CardHeader className="pb-2">
        <CardTitle className="text-base font-mono">{agentId}</CardTitle>
        <p className="text-xs text-muted-foreground">
          {lineage.length} version event{lineage.length !== 1 ? "s" : ""} recorded
        </p>
      </CardHeader>
      <CardContent className="space-y-2">
        {loading && lineage.length === 0 && (
          <p className="text-sm text-muted-foreground">Loading…</p>
        )}
        {lineage.length === 0 && !loading && (
          <p className="text-sm text-muted-foreground">No version submissions yet.</p>
        )}
        {lineage.map((entry, i) => (
          <LineageCard key={`${entry.version}-${i}`} entry={entry} />
        ))}
      </CardContent>
    </Card>
  );
}

export default function AgentEvolutionPage() {
  const [manualAgentId, setManualAgentId] = useState("");
  const [queueAgentIds, setQueueAgentIds] = useState<string[]>([]);
  const { toast } = useToast();

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const queue = await getReviewQueue();
        if (!active) return;
        const ids = Array.from(new Set(queue.map((q) => q.agent_id).filter(Boolean))).sort();
        setQueueAgentIds(ids);
      } catch (err) {
        toast({
          title: "Failed to load agent list",
          description: err instanceof Error ? err.message : "Unexpected error",
        });
      }
    };
    void load();
    const id = window.setInterval(load, 30_000);
    return () => {
      active = false;
      window.clearInterval(id);
    };
  }, [toast]);

  const agentIds = useMemo(() => {
    const base = new Set(queueAgentIds);
    if (manualAgentId.trim()) base.add(manualAgentId.trim());
    return Array.from(base).sort();
  }, [queueAgentIds, manualAgentId]);

  return (
    <DashboardLayout>
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-2xl">Agent Evolution</h1>
            <p className="text-sm text-muted-foreground">
              Version lineage with adversarial gate results (1 000 synthetic attack scenarios per
              submission).
            </p>
          </div>
          <Input
            placeholder="Add agent ID…"
            className="max-w-xs"
            value={manualAgentId}
            onChange={(e) => setManualAgentId(e.target.value)}
          />
        </div>

        {agentIds.length === 0 && (
          <p className="text-sm text-muted-foreground">
            No agents found in the review queue. Enter an agent ID above to inspect it directly.
          </p>
        )}

        <div className="grid gap-4 sm:grid-cols-1 lg:grid-cols-2">
          {agentIds.map((id) => (
            <AgentLineagePanel key={id} agentId={id} />
          ))}
        </div>
      </div>
    </DashboardLayout>
  );
}
