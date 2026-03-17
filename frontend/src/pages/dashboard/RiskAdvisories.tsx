import { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { type RiskAdvisory } from "@/lib/admin-api";

const SEVERITY_STYLES: Record<string, { border: string; bg: string; badge: string }> = {
  Critical: { border: "border-red-500/60", bg: "bg-red-500/8", badge: "bg-red-500/15 text-red-400 border-red-500/30" },
  High:     { border: "border-orange-500/60", bg: "bg-orange-500/8", badge: "bg-orange-500/15 text-orange-400 border-orange-500/30" },
  Medium:   { border: "border-yellow-500/60", bg: "bg-yellow-500/8", badge: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" },
  Low:      { border: "border-blue-500/40", bg: "bg-blue-500/5", badge: "bg-blue-500/10 text-blue-400 border-blue-500/20" },
};

function severityStyle(sev: string) {
  return SEVERITY_STYLES[sev] ?? SEVERITY_STYLES.Low;
}

function timeAgo(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export default function RiskAdvisoriesPage() {
  const [query, setQuery] = useState("");
  const [agentId, setAgentId] = useState("");
  const [advisories, setAdvisories] = useState<RiskAdvisory[]>([]);
  const [live, setLive] = useState(false);
  const esRef = useRef<EventSource | null>(null);

  // Open/replace SSE connection whenever agentId changes.
  useEffect(() => {
    if (esRef.current) { esRef.current.close(); esRef.current = null; }
    setAdvisories([]);
    setLive(false);
    if (!agentId) return;

    const es = new EventSource(`/api/risk/advisories/${encodeURIComponent(agentId)}/stream`);
    esRef.current = es;

    es.addEventListener("advisory", (e) => {
      try {
        const adv: RiskAdvisory = JSON.parse(e.data);
        setAdvisories((prev) => {
          if (prev.some((a) => a.id === adv.id)) return prev;
          return [adv, ...prev].sort((a, b) => b.id - a.id);
        });
      } catch { /* ignore parse errors */ }
    });

    es.onopen = () => setLive(true);
    es.onerror = () => setLive(false);

    return () => { es.close(); esRef.current = null; setLive(false); };
  }, [agentId]);

  const handleSearch = () => setAgentId(query.trim());

  const counts = advisories.reduce<Record<string, number>>(
    (acc, a) => { acc[a.severity] = (acc[a.severity] ?? 0) + 1; return acc; },
    {},
  );

  const criticalCount = counts["Critical"] ?? 0;
  const highCount = counts["High"] ?? 0;

  return (
    <DashboardLayout>
      <div className="space-y-5">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl">Risk Advisories</h1>
            {live && (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-xs font-medium text-emerald-400">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                Live
              </span>
            )}
          </div>
          <p className="text-sm text-muted-foreground">Understand why decisions were made — streams in real-time per agent.</p>
        </div>

        <div className="flex gap-2">
          <Input
            className="max-w-sm"
            placeholder="Agent ID"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSearch()}
          />
          <Button onClick={handleSearch} disabled={!query.trim()}>
            Connect
          </Button>
          {agentId && (
            <Button variant="ghost" onClick={() => { setAgentId(""); setQuery(""); }}>
              Disconnect
            </Button>
          )}
        </div>

        {agentId && advisories.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {(["Critical", "High", "Medium", "Low"] as const).map((sev) =>
              counts[sev] ? (
                <span
                  key={sev}
                  className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium ${severityStyle(sev).badge}`}
                >
                  {sev} <span className="font-bold">{counts[sev]}</span>
                </span>
              ) : null,
            )}
          </div>
        )}

        {agentId && criticalCount + highCount > 0 && (
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            className="rounded-lg border border-red-500/40 bg-red-500/8 px-4 py-3 text-sm text-red-400"
          >
            {criticalCount > 0 && <span className="font-semibold">{criticalCount} Critical</span>}
            {criticalCount > 0 && highCount > 0 && " and "}
            {highCount > 0 && <span className="font-semibold">{highCount} High</span>}
            {" "}advisories require immediate attention for <span className="font-mono">{agentId}</span>.
          </motion.div>
        )}

        <Separator />

        <AnimatePresence mode="popLayout">
          {advisories.length === 0 && agentId && (
            <motion.p
              key="empty"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="text-sm text-muted-foreground"
            >
              No advisories found for <span className="font-mono">{agentId}</span> — waiting for events.
            </motion.p>
          )}

          {advisories.map((advisory, i) => {
            const style = severityStyle(advisory.severity);
            return (
              <motion.article
                key={advisory.id}
                layout
                initial={{ opacity: 0, x: -16 }}
                animate={{ opacity: 1, x: 0, transition: { delay: i * 0.04 } }}
                exit={{ opacity: 0, x: 16 }}
                className={`rounded-xl border p-4 ${style.border} ${style.bg}`}
              >
                <div className="mb-2 flex flex-wrap items-center gap-2">
                  <Badge className={`border text-xs ${style.badge}`} variant="outline">
                    {advisory.severity}
                  </Badge>
                  <span className="rounded bg-muted/50 px-2 py-0.5 font-mono text-xs text-muted-foreground">
                    {advisory.category}
                  </span>
                  <span className="ml-auto text-xs text-muted-foreground">{timeAgo(advisory.created_at)}</span>
                </div>
                <p className="mb-1 text-sm font-medium">{advisory.description}</p>
                <p className="text-xs text-muted-foreground">{advisory.recommendation}</p>
                {advisory.resolved_at && (
                  <p className="mt-1.5 text-xs text-emerald-400">Resolved {timeAgo(advisory.resolved_at)}</p>
                )}
              </motion.article>
            );
          })}
        </AnimatePresence>
      </div>
    </DashboardLayout>
  );
}
