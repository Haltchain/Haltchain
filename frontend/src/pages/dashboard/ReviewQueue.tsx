import { useEffect, useMemo, useState } from "react";
import { Copy, RefreshCw } from "lucide-react";

import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { DecisionBadge } from "@/components/dashboard/DecisionBadge";
import { OutcomeModal } from "@/components/dashboard/OutcomeModal";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useToast } from "@/hooks/use-toast";
import { getReviewQueue, submitReviewOutcome, type ReviewEntry } from "@/lib/admin-api";

function shortId(id: string) {
  if (id.length <= 12) return id;
  return `${id.slice(0, 6)}...${id.slice(-4)}`;
}

const SKELETON_ROWS = 5;

export default function ReviewQueuePage() {
  const [rows, setRows] = useState<ReviewEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [pendingOnly, setPendingOnly] = useState(true);
  const [selectedTxId, setSelectedTxId] = useState<string | null>(null);
  const { toast } = useToast();

  const load = async (silent = false) => {
    if (!silent) setLoading(true);
    setError(null);
    try {
      setRows(await getReviewQueue());
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Unexpected error";
      setError(msg);
      if (silent) {
        toast({ title: "Failed to refresh review queue", description: msg });
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
    const id = window.setInterval(() => load(true), 30000);
    return () => window.clearInterval(id);
  }, []);

  const filtered = useMemo(
    () => (pendingOnly ? rows.filter((row) => !row.outcome) : rows),
    [rows, pendingOnly],
  );

  return (
    <DashboardLayout>
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl">Decision Review Queue</h1>
            <p className="text-sm text-muted-foreground">Review blocked decisions and submit outcomes for learning.</p>
          </div>
          <div className="flex items-center gap-3 text-sm text-muted-foreground">
            <span>Pending only</span>
            <Switch checked={pendingOnly} onCheckedChange={setPendingOnly} />
            <Button variant="ghost" size="sm" onClick={() => load()} disabled={loading}>
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            </Button>
          </div>
        </div>

        {error ? (
          <div className="rounded-xl border border-destructive/40 bg-destructive/10 p-8 text-center space-y-3">
            <p className="text-sm text-destructive">{error}</p>
            <Button variant="outline" size="sm" onClick={() => load()}>
              Retry
            </Button>
          </div>
        ) : (
        <div className="rounded-xl border border-border/80">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>tx_id</TableHead>
                <TableHead>agent_id</TableHead>
                <TableHead>decision</TableHead>
                <TableHead>policy code</TableHead>
                <TableHead>reason</TableHead>
                <TableHead>timestamp</TableHead>
                <TableHead>outcome</TableHead>
                <TableHead className="text-right">actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                Array.from({ length: SKELETON_ROWS }).map((_, i) => (
                  <TableRow key={i}>
                    {Array.from({ length: 8 }).map((__, j) => (
                      <TableCell key={j}>
                        <Skeleton className="h-4 w-full" />
                      </TableCell>
                    ))}
                  </TableRow>
                ))
              ) : filtered.length > 0 ? (
                filtered.map((row) => (
                  <TableRow key={row.tx_id}>
                    <TableCell>
                      <button
                        className="inline-flex items-center gap-1 text-primary"
                        onClick={async () => {
                          await navigator.clipboard.writeText(row.tx_id);
                          toast({ title: "Copied", description: row.tx_id });
                        }}
                      >
                        {shortId(row.tx_id)} <Copy className="h-3.5 w-3.5" />
                      </button>
                    </TableCell>
                    <TableCell>{row.agent_id}</TableCell>
                    <TableCell>
                      <DecisionBadge value={row.decision} />
                    </TableCell>
                    <TableCell>{row.policy_code ?? "-"}</TableCell>
                    <TableCell className="max-w-60 truncate">{row.reason ?? "-"}</TableCell>
                    <TableCell>{new Date(row.created_at).toLocaleString()}</TableCell>
                    <TableCell>{row.outcome?.verdict ?? "PENDING"}</TableCell>
                    <TableCell className="text-right">
                      {!row.outcome && (
                        <Button variant="outline" size="sm" onClick={() => setSelectedTxId(row.tx_id)}>
                          Review
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={8} className="py-12 text-center">
                    <div className="space-y-2">
                      <p className="text-muted-foreground">No review entries found.</p>
                      <p className="text-xs text-muted-foreground/60">
                        {pendingOnly ? "Toggle off 'Pending only' to see all entries." : "Decisions blocked by policy will appear here."}
                      </p>
                    </div>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
        )}
      </div>

      <OutcomeModal
        open={Boolean(selectedTxId)}
        onOpenChange={(open) => {
          if (!open) setSelectedTxId(null);
        }}
        txId={selectedTxId ?? ""}
        onSubmit={async (payload) => {
          if (!selectedTxId) return;
          await submitReviewOutcome(selectedTxId, payload);
          toast({ title: "Outcome submitted", description: "Review queue updated." });
          await load();
        }}
      />
    </DashboardLayout>
  );
}
