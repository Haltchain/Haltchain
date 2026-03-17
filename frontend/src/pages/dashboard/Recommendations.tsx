import { useEffect, useMemo, useState } from "react";
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis } from "recharts";

import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { ConfirmModal, type ConfirmPayload } from "@/components/dashboard/ConfirmModal";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import {
  approveRecommendation,
  getRecommendations,
  getThresholds,
  rejectRecommendation,
  revertRecommendation,
  runLearningLoop,
  type Recommendation,
  type RecommendationStatus,
} from "@/lib/admin-api";

const STATUSES: RecommendationStatus[] = ["pending", "approved", "applied", "rejected", "reverted"];

type ModalAction = "approve" | "reject" | "revert";

export default function RecommendationsPage() {
  const [status, setStatus] = useState<RecommendationStatus>("pending");
  const [items, setItems] = useState<Recommendation[]>([]);
  const [thresholds, setThresholds] = useState<Array<[string, number]>>([]);
  const [selected, setSelected] = useState<Recommendation | null>(null);
  const [action, setAction] = useState<ModalAction | null>(null);
  const { toast } = useToast();

  const load = async () => {
    try {
      const [recs, activeThresholds] = await Promise.all([getRecommendations(status), getThresholds()]);
      setItems(recs);
      setThresholds(activeThresholds);
    } catch (err) {
      toast({ title: "Failed to load recommendations", description: err instanceof Error ? err.message : "Unexpected error" });
    }
  };

  useEffect(() => {
    void load();
  }, [status]);

  const openModal = (item: Recommendation, kind: ModalAction) => {
    setSelected(item);
    setAction(kind);
  };

  const modalCopy = useMemo(() => {
    if (!selected || !action) return null;
    const map: Record<ModalAction, { title: string; description: string }> = {
      approve: {
        title: `Approve recommendation #${selected.id}`,
        description: "This will approve and potentially apply the threshold recommendation.",
      },
      reject: {
        title: `Reject recommendation #${selected.id}`,
        description: "This will reject the recommendation and keep current thresholds.",
      },
      revert: {
        title: `Revert recommendation #${selected.id}`,
        description: "This will revert an applied recommendation.",
      },
    };

    return map[action];
  }, [selected, action]);

  const runLoop = async () => {
    try {
      const result = await runLearningLoop();
      toast({ title: "Learning loop complete", description: `Generated ${result.generated} recommendation(s).` });
      await load();
    } catch (err) {
      toast({ title: "Learning loop failed", description: err instanceof Error ? err.message : "Unexpected error" });
    }
  };

  const executeAction = async (payload: ConfirmPayload) => {
    if (!selected || !action) return;

    const body = {
      reviewer_id: payload.reviewer_id,
      notes: payload.notes,
      apply_as_variant: true,
    };

    if (action === "approve") await approveRecommendation(selected.id, body);
    if (action === "reject") await rejectRecommendation(selected.id, body);
    if (action === "revert") await revertRecommendation(selected.id, body);

    toast({ title: "Updated", description: `Recommendation ${selected.id} ${action}d.` });
    setAction(null);
    setSelected(null);
    await load();
  };

  return (
    <DashboardLayout>
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-2xl">Threshold Recommendation Inbox</h1>
            <p className="text-sm text-muted-foreground">Review model-learned threshold changes and apply safely.</p>
          </div>
          <Button onClick={runLoop}>Run Learning Loop</Button>
        </div>

        <Tabs value={status} onValueChange={(v) => setStatus(v as RecommendationStatus)}>
          <TabsList>
            {STATUSES.map((item) => (
              <TabsTrigger key={item} value={item}>
                {item}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>

        <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
          <section className="space-y-3">
            {items.map((item) => (
              <article key={item.id} className="rounded-xl border border-border p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="font-medium">{item.threshold_key}</p>
                    <p className="text-sm text-muted-foreground">
                      {item.current_value} → {item.proposed_value}
                    </p>
                  </div>
                  <p className="rounded-md border border-border px-2 py-1 text-xs uppercase text-muted-foreground">{item.status}</p>
                </div>

                <div className="mt-3 grid gap-3 md:grid-cols-2">
                  <p className="text-sm text-muted-foreground">Sample: {item.sample_size}</p>
                  <p className="text-sm text-muted-foreground">FP/TP: {item.false_positive_count}/{item.true_positive_count}</p>
                </div>

                <div className="mt-3 h-24 rounded-lg border border-border/70 p-2">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={[{ name: "confidence", value: Math.round(item.confidence * 100) }]}>
                      <XAxis dataKey="name" hide />
                      <Tooltip />
                      <Bar dataKey="value" fill="hsl(var(--primary))" radius={6} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                <p className="mt-3 text-sm text-muted-foreground">{item.rationale}</p>

                <div className="mt-4 flex flex-wrap gap-2">
                  <Button size="sm" onClick={() => openModal(item, "approve")}>
                    Approve
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => openModal(item, "reject")}>
                    Reject
                  </Button>
                  {item.status === "applied" && (
                    <Button size="sm" variant="outline" onClick={() => openModal(item, "revert")}>
                      Revert
                    </Button>
                  )}
                </div>
              </article>
            ))}

            {!items.length && (
              <div className="rounded-xl border border-border p-8 text-center text-muted-foreground">No recommendations for this status.</div>
            )}
          </section>

          <aside className="rounded-xl border border-border p-4">
            <h2 className="mb-3 text-lg">Active Thresholds</h2>
            <div className="space-y-2 text-sm">
              {thresholds.map(([key, value]) => (
                <div key={key} className="flex items-center justify-between gap-2 border-b border-border/50 pb-2">
                  <span className="text-muted-foreground">{key}</span>
                  <span>{value}</span>
                </div>
              ))}
              {!thresholds.length && <p className="text-muted-foreground">No threshold overrides found.</p>}
            </div>
          </aside>
        </div>
      </div>

      <ConfirmModal
        open={Boolean(selected && action)}
        onOpenChange={(open) => {
          if (!open) {
            setSelected(null);
            setAction(null);
          }
        }}
        title={modalCopy?.title ?? "Confirm"}
        description={modalCopy?.description ?? "Please confirm this action."}
        onConfirm={executeAction}
      />
    </DashboardLayout>
  );
}
