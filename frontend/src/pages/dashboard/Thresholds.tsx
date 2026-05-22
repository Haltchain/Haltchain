import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { z } from "zod";

import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Slider } from "@/components/ui/slider";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";
import { getThresholds, patchThreshold } from "@/lib/admin-api";

type ThresholdRow = { key: string; current: number; draft: number; dirty: boolean; error: string | null };

function guessRange(key: string): [number, number, number] {
  if (key.includes("rate") || key.includes("limit")) return [1, 1000, 1];
  if (key.includes("pct") || key.includes("percent") || key.includes("threshold")) return [0, 1, 0.01];
  if (key.includes("score") || key.includes("anomaly")) return [0, 10, 0.1];
  if (key.includes("window") || key.includes("seconds") || key.includes("ttl")) return [1, 3600, 1];
  return [0, 100, 0.01];
}

function validateDraft(key: string, value: number): string | null {
  const [min, max] = guessRange(key);
  const result = z.number().min(min, `Min ${min}`).max(max, `Max ${max}`).safeParse(value);
  return result.success ? null : (result.error.issues[0]?.message ?? "Invalid value");
}

export default function ThresholdsPage() {
  const [rows, setRows] = useState<ThresholdRow[]>([]);
  const [saving, setSaving] = useState<string | null>(null);
  const { toast } = useToast();

  const load = async () => {
    try {
      const data = await getThresholds();
      setRows(data.map(([key, val]) => ({ key, current: val, draft: val, dirty: false, error: null })));
    } catch (err) {
      toast({ title: "Failed to load thresholds", description: err instanceof Error ? err.message : "Error" });
    }
  };

  useEffect(() => { void load(); }, []);

  const updateDraft = (key: string, value: number) => {
    setRows((prev) =>
      prev.map((r) => (r.key === key ? { ...r, draft: value, dirty: value !== r.current, error: validateDraft(key, value) } : r)),
    );
  };

  const save = async (row: ThresholdRow) => {
    setSaving(row.key);
    try {
      await patchThreshold(row.key, row.draft);
      setRows((prev) =>
        prev.map((r) => (r.key === row.key ? { ...r, current: row.draft, dirty: false } : r)),
      );
      toast({ title: "Saved", description: `${row.key} → ${row.draft}` });
    } catch (err) {
      toast({ title: "Save failed", description: err instanceof Error ? err.message : "Error", variant: "destructive" });
    } finally {
      setSaving(null);
    }
  };

  const reset = (key: string) => {
    setRows((prev) => prev.map((r) => (r.key === key ? { ...r, draft: r.current, dirty: false, error: null } : r)));
  };

  const dirtyCount = rows.filter((r) => r.dirty && !r.error).length;

  return (
    <DashboardLayout>
      <div className="space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-2xl">Threshold Configuration</h1>
            <p className="text-sm text-muted-foreground">Tune risk controls without redeployment. Changes take effect immediately.</p>
          </div>
          <AnimatePresence>
            {dirtyCount > 0 && (
              <motion.div
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.9 }}
              >
                <Badge variant="secondary">{dirtyCount} unsaved change{dirtyCount > 1 ? "s" : ""}</Badge>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        <Separator />

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {rows.length === 0 && (
            <p className="col-span-full text-sm text-muted-foreground">No threshold overrides found. Defaults are in effect.</p>
          )}
          {rows.map((row) => {
            const [min, max, step] = guessRange(row.key);
            return (
              <motion.article
                key={row.key}
                layout
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                className={`rounded-xl border p-4 transition-colors ${row.dirty ? "border-primary/50 bg-primary/5" : "border-border bg-card/60"}`}
              >
                <div className="mb-3 flex items-start justify-between gap-2">
                  <div>
                    <p className="font-mono text-sm font-medium leading-tight">{row.key}</p>
                    <p className="mt-0.5 text-xs text-muted-foreground">
                      current: <span className="font-semibold text-foreground">{row.current}</span>
                    </p>
                  </div>
                  {row.dirty && (
                    <Badge className="shrink-0 text-xs" variant="outline">
                      unsaved
                    </Badge>
                  )}
                </div>

                <Slider
                  min={min}
                  max={max}
                  step={step}
                  value={[row.draft]}
                  onValueChange={([v]) => updateDraft(row.key, v)}
                  className="mb-3"
                />

                <div className="flex items-center gap-2">
                  <Input
                    type="number"
                    min={min}
                    max={max}
                    step={step}
                    value={row.draft}
                    onChange={(e) => {
                      const v = parseFloat(e.target.value);
                      if (!Number.isNaN(v)) updateDraft(row.key, v);
                    }}
                    className={`h-8 w-28 font-mono text-sm ${row.error ? "border-destructive" : ""}`}
                  />
                  <Button
                    size="sm"
                    disabled={!row.dirty || !!row.error || saving === row.key}
                    onClick={() => save(row)}
                  >
                    {saving === row.key ? "Saving…" : "Apply"}
                  </Button>
                  {row.dirty && (
                    <Button size="sm" variant="ghost" onClick={() => reset(row.key)}>
                      Reset
                    </Button>
                  )}
                </div>
                {row.error && (
                  <p className="mt-1.5 text-xs text-destructive">{row.error}</p>
                )}
              </motion.article>
            );
          })}
        </div>
      </div>
    </DashboardLayout>
  );
}
