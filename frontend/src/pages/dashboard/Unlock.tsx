import { Link } from "wouter";

import { AuthGate } from "@/components/dashboard/AuthGate";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

const hubs = [
  { href: "/dashboard/compliance", title: "Compliance & evidence", body: "Operator posture, links to review and audit." },
  { href: "/dashboard/review-queue", title: "Review queue", body: "Human outcomes on DENY / circuit-break." },
  { href: "/dashboard/recommendations", title: "Recommendations", body: "Learning loop threshold suggestions." },
  { href: "/dashboard/thresholds", title: "Thresholds", body: "Live guardrail values from the API." },
  { href: "/dashboard/audit-log", title: "Audit log", body: "Tamper-evident admin API events." },
  { href: "/dashboard/risk-advisories", title: "Risk advisories", body: "GET history + live SSE per agent." },
  { href: "/dashboard/agents", title: "Agents", body: "Status and circuit breaker per agent id." },
  { href: "/dashboard/agent-intent", title: "Agent intent / drift", body: "Declared goals vs drift scores." },
  { href: "/dashboard/ab-variants", title: "A/B variants", body: "Traffic splits and threshold overrides." },
  { href: "/dashboard/agent-evolution", title: "Agent evolution", body: "Version lineage and adversarial gate from API." },
];

export default function UnlockPage() {
  return (
    <div className="min-h-screen bg-background px-4 py-16">
      <div className="mx-auto max-w-6xl rounded-2xl border border-border bg-card/40 p-8">
        <h1 className="mb-2 text-3xl">Haltchain control plane</h1>
        <p className="mb-4 text-sm text-muted-foreground max-w-xl">
          Sign in with your <strong>bootstrap admin email and password</strong> (not the agent <code className="text-xs bg-muted px-1 rounded">X-API-Key</code>).
          The API stores a short-lived JWT in an <strong>HttpOnly</strong> cookie (SameSite strict; Secure when NODE_ENV=production).
        </p>
        <p className="mb-8 text-sm text-muted-foreground">
          Same routes the production operator UI uses: review, tuning, advisories, and agent tooling (all backed by the Rust API via this BFF).
        </p>

        <AuthGate forceOpen>
          <div className="rounded-xl border border-border bg-background/40 p-6 text-sm text-muted-foreground">
            <p className="mb-4">Dashboard unlocked. Open any card below — each maps to a live API-backed screen.</p>
            <div className="grid gap-3 sm:grid-cols-2">
              {hubs.map((x) => (
                <Link key={x.href} href={x.href}>
                  <Card className="h-full transition-colors hover:border-primary/50 cursor-pointer">
                    <CardHeader className="py-3">
                      <CardTitle className="text-base">{x.title}</CardTitle>
                      <CardDescription className="text-xs">{x.body}</CardDescription>
                    </CardHeader>
                  </Card>
                </Link>
              ))}
            </div>
          </div>
        </AuthGate>
      </div>
    </div>
  );
}
