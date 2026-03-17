import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { listVariants, createVariant, type ABVariant } from "@/lib/admin-api";

function TrafficBar({ pct }: { pct: number }) {
  const clamped = Math.max(0, Math.min(100, pct));
  return (
    <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-muted">
      <motion.div
        className="h-full rounded-full bg-primary"
        initial={{ width: 0 }}
        animate={{ width: `${clamped}%` }}
        transition={{ duration: 0.5, ease: "easeOut" }}
      />
    </div>
  );
}

function VariantCard({ variant }: { variant: ABVariant }) {
  const overrides = variant.threshold_overrides ? Object.entries(variant.threshold_overrides) : [];
  return (
    <motion.article
      layout
      initial={{ opacity: 0, scale: 0.97 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.95 }}
      className="rounded-xl border border-border bg-card/60 p-4 space-y-3"
    >
      <div className="flex items-start justify-between gap-2">
        <div>
          <p className="font-medium">{variant.name}</p>
          {variant.description && (
            <p className="text-xs text-muted-foreground mt-0.5">{variant.description}</p>
          )}
        </div>
        <Badge variant={variant.enabled ? "default" : "secondary"} className="shrink-0">
          {variant.enabled ? "Active" : "Paused"}
        </Badge>
      </div>

      <div className="space-y-0.5">
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>Traffic split</span>
          <span className="font-mono font-semibold text-foreground">{variant.traffic_pct}%</span>
        </div>
        <TrafficBar pct={variant.traffic_pct} />
      </div>

      {overrides.length > 0 && (
        <div className="rounded-md border border-border/60 bg-muted/30 px-3 py-2 space-y-1">
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1.5">Threshold Overrides</p>
          {overrides.map(([k, v]) => (
            <div key={k} className="flex items-center justify-between text-xs">
              <span className="font-mono text-muted-foreground">{k}</span>
              <span className="font-mono font-semibold">{v}</span>
            </div>
          ))}
        </div>
      )}

      <p className="text-xs text-muted-foreground font-mono truncate">ID: {variant.id}</p>
    </motion.article>
  );
}

export default function ABVariantsPage() {
  const [variants, setVariants] = useState<ABVariant[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const { toast } = useToast();

  // New variant form state
  const [name, setName] = useState("");
  const [desc, setDesc] = useState("");
  const [trafficPct, setTrafficPct] = useState(10);
  const [overrideKey, setOverrideKey] = useState("");
  const [overrideVal, setOverrideVal] = useState("");
  const [overrides, setOverrides] = useState<Record<string, number>>({});
  const [creating, setCreating] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const res = await listVariants();
      setVariants(res.variants);
    } catch (err) {
      toast({ title: "Failed to load variants", description: err instanceof Error ? err.message : "Error" });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, []);

  const addOverride = () => {
    const v = parseFloat(overrideVal);
    if (!overrideKey.trim() || Number.isNaN(v)) return;
    setOverrides((prev) => ({ ...prev, [overrideKey.trim()]: v }));
    setOverrideKey("");
    setOverrideVal("");
  };

  const removeOverride = (key: string) => {
    setOverrides((prev) => { const next = { ...prev }; delete next[key]; return next; });
  };

  const handleCreate = async () => {
    if (!name.trim()) return;
    setCreating(true);
    try {
      await createVariant({
        name: name.trim(),
        description: desc.trim() || undefined,
        traffic_pct: trafficPct,
        threshold_overrides: Object.keys(overrides).length > 0 ? overrides : undefined,
      });
      toast({ title: "Variant created", description: name });
      setShowCreate(false);
      setName(""); setDesc(""); setTrafficPct(10); setOverrides({});
      await load();
    } catch (err) {
      toast({ title: "Create failed", description: err instanceof Error ? err.message : "Error", variant: "destructive" });
    } finally {
      setCreating(false);
    }
  };

  return (
    <DashboardLayout>
      <div className="space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-2xl">A/B Variants</h1>
            <p className="text-sm text-muted-foreground">Continuously improve safety thresholds with controlled rollouts.</p>
          </div>
          <Button onClick={() => setShowCreate(true)}>New Variant</Button>
        </div>

        <Separator />

        {loading && <p className="text-sm text-muted-foreground">Loading variants…</p>}

        {!loading && variants.length === 0 && (
          <p className="text-sm text-muted-foreground">No variants configured. Create one to start A/B testing threshold policies.</p>
        )}

        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          <AnimatePresence>
            {variants.map((v) => <VariantCard key={v.id} variant={v} />)}
          </AnimatePresence>
        </div>
      </div>

      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Create A/B Variant</DialogTitle>
          </DialogHeader>

          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <Label htmlFor="vname">Name *</Label>
              <Input id="vname" placeholder="e.g. low-volatility-cohort" value={name} onChange={(e) => setName(e.target.value)} />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="vdesc">Description</Label>
              <Input id="vdesc" placeholder="Optional description" value={desc} onChange={(e) => setDesc(e.target.value)} />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="vpct">Traffic % (0–100)</Label>
              <Input
                id="vpct"
                type="number"
                min={0}
                max={100}
                value={trafficPct}
                onChange={(e) => setTrafficPct(Math.max(0, Math.min(100, parseInt(e.target.value) || 0)))}
              />
            </div>

            <div className="space-y-2">
              <Label>Threshold Overrides</Label>
              <div className="flex gap-2">
                <Input
                  placeholder="threshold key"
                  value={overrideKey}
                  onChange={(e) => setOverrideKey(e.target.value)}
                  className="text-xs font-mono"
                />
                <Input
                  type="number"
                  placeholder="value"
                  value={overrideVal}
                  onChange={(e) => setOverrideVal(e.target.value)}
                  className="w-24 text-xs font-mono"
                />
                <Button variant="outline" size="sm" onClick={addOverride} type="button">Add</Button>
              </div>
              {Object.entries(overrides).length > 0 && (
                <div className="rounded-md border border-border bg-muted/30 px-3 py-2 space-y-1">
                  {Object.entries(overrides).map(([k, v]) => (
                    <div key={k} className="flex items-center justify-between text-xs">
                      <span className="font-mono">{k} = {v}</span>
                      <button onClick={() => removeOverride(k)} className="text-muted-foreground hover:text-destructive ml-2">✕</button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button onClick={() => void handleCreate()} disabled={creating || !name.trim()}>
              {creating ? "Creating…" : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </DashboardLayout>
  );
}
