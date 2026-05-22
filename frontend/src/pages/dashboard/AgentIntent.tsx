import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from "recharts";

import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";
import { getDriftStatus, type DriftStatus } from "@/lib/admin-api";

function driftColor(score: number | null | undefined): string {
  if (score == null) return "text-muted-foreground";
  if (score >= 0.8) return "text-red-400";
  if (score >= 0.5) return "text-orange-400";
  if (score >= 0.25) return "text-yellow-400";
  return "text-emerald-400";
}

function driftLabel(score: number | null | undefined): string {
  if (score == null) return "Unknown";
  if (score >= 0.8) return "Critical Drift";
  if (score >= 0.5) return "High Drift";
  if (score >= 0.25) return "Moderate Drift";
  return "On Target";
}

export default function AgentIntentPage() {
  const [agentId, setAgentId] = useState("");
  const [sessionId, setSessionId] = useState("default");
  const [status, setStatus] = useState<DriftStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();

  const fetch = async () => {
    if (!agentId.trim()) return;
    setLoading(true);
    try {
      const data = await getDriftStatus(agentId.trim(), sessionId.trim() || "default");
      setStatus(data);
    } catch (err) {
      toast({ title: "Failed to load drift status", description: err instanceof Error ? err.message : "Error" });
    } finally {
      setLoading(false);
    }
  };

  const chartData = status?.history?.map((pt, i) => ({
    t: i,
    score: Math.round(pt.score * 1000) / 1000,
    label: pt.at,
  })) ?? (
    status?.drift_score != null
      ? [{ t: 0, score: status.drift_score, label: "current" }]
      : []
  );

  return (
    <DashboardLayout>
      <div className="space-y-5">
        <div>
          <h1 className="text-2xl">Agent Intent Report</h1>
          <p className="text-sm text-muted-foreground">Declared goal vs. actual behaviour — goal drift detection over time.</p>
        </div>

        <div className="flex flex-wrap gap-2">
          <Input
            className="max-w-xs"
            placeholder="Agent ID"
            value={agentId}
            onChange={(e) => setAgentId(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && void fetch()}
          />
          <Input
            className="max-w-[180px]"
            placeholder="Session ID (optional)"
            value={sessionId}
            onChange={(e) => setSessionId(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && void fetch()}
          />
          <Button onClick={() => void fetch()} disabled={loading || !agentId.trim()}>
            {loading ? "Loading…" : "Fetch Drift"}
          </Button>
        </div>

        <Separator />

        <AnimatePresence mode="wait">
          {status && (
            <motion.div
              key={`${status.agent_id}-${status.session_id}`}
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="space-y-5"
            >
              {/* Summary cards row */}
              <div className="grid gap-3 sm:grid-cols-3">
                <div className="rounded-xl border border-border bg-card/60 p-4">
                  <p className="text-xs text-muted-foreground uppercase tracking-wide mb-1">Drift Score</p>
                  <p className={`text-3xl font-bold tabular-nums ${driftColor(status.drift_score)}`}>
                    {status.drift_score != null ? status.drift_score.toFixed(3) : "—"}
                  </p>
                  <p className={`mt-0.5 text-xs ${driftColor(status.drift_score)}`}>{driftLabel(status.drift_score)}</p>
                </div>

                <div className="rounded-xl border border-border bg-card/60 p-4">
                  <p className="text-xs text-muted-foreground uppercase tracking-wide mb-1">Samples</p>
                  <p className="text-3xl font-bold tabular-nums">{status.samples}</p>
                  <p className="mt-0.5 text-xs text-muted-foreground">actions evaluated</p>
                </div>

                <div className="rounded-xl border border-border bg-card/60 p-4">
                  <p className="text-xs text-muted-foreground uppercase tracking-wide mb-1">Status</p>
                  <Badge
                    variant="outline"
                    className={`mt-1 border ${driftColor(status.drift_score)}`}
                  >
                    {driftLabel(status.drift_score)}
                  </Badge>
                </div>
              </div>

              {/* Declared goal */}
              {status.declared_goal && (
                <div className="rounded-xl border border-border bg-card/60 p-4 space-y-1">
                  <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Declared Goal</p>
                  <p className="text-sm">{status.declared_goal}</p>
                </div>
              )}

              {/* Drift timeline */}
              {chartData.length > 1 && (
                <div className="rounded-xl border border-border bg-card/60 p-4 space-y-3">
                  <p className="text-sm font-medium">Drift Score Timeline</p>
                  <ResponsiveContainer width="100%" height={180}>
                    <LineChart data={chartData} margin={{ top: 4, right: 8, bottom: 0, left: -24 }}>
                      <XAxis dataKey="t" tick={{ fontSize: 10 }} hide />
                      <YAxis domain={[0, 1]} tick={{ fontSize: 10 }} tickCount={5} />
                      <Tooltip
                        contentStyle={{ fontSize: 12, background: "hsl(var(--card))", border: "1px solid hsl(var(--border))" }}
                        formatter={(v: number) => [v.toFixed(3), "drift"]}
                        labelFormatter={(_, pl) => pl[0]?.payload?.label ?? ""}
                      />
                      <ReferenceLine y={0.5} stroke="hsl(var(--destructive))" strokeDasharray="4 2" strokeOpacity={0.5} />
                      <Line
                        type="monotone"
                        dataKey="score"
                        stroke="hsl(var(--primary))"
                        strokeWidth={2}
                        dot={false}
                        activeDot={{ r: 4 }}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                  <p className="text-xs text-muted-foreground text-right">
                    Dashed line = 0.5 alert threshold
                  </p>
                </div>
              )}

              {/* Last action */}
              {status.last_action && (
                <div className="rounded-xl border border-border bg-card/60 p-4 space-y-1">
                  <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Last Action</p>
                  <p className="font-mono text-sm">{status.last_action}</p>
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </DashboardLayout>
  );
}
