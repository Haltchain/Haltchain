import { useEffect, useState } from "react";
import { Link } from "wouter";

import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { getPublicHealth, type PublicHealth } from "@/lib/admin-api";

const links = [
  { href: "/dashboard/review-queue", title: "Decision review queue", body: "Human outcomes on DENY / circuit-break for audit trail." },
  { href: "/dashboard/recommendations", title: "Threshold recommendations", body: "Learning loop suggestions from FP/TP-style signals." },
  { href: "/dashboard/thresholds", title: "Threshold config", body: "Live guardrail values (API-backed)." },
  { href: "/dashboard/audit-log", title: "Operator audit log", body: "Recent tamper-evident admin API events (encrypted at rest on server)." },
  { href: "/dashboard/risk-advisories", title: "Risk advisories", body: "Cross-agent signals when patterns repeat." },
];

export default function CompliancePage() {
  const [health, setHealth] = useState<PublicHealth | null>(null);
  const [healthErr, setHealthErr] = useState<string | null>(null);

  useEffect(() => {
    getPublicHealth()
      .then((h) => {
        setHealth(h);
        setHealthErr(null);
      })
      .catch((e) => setHealthErr(e instanceof Error ? e.message : String(e)));
  }, []);

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-semibold">Compliance &amp; evidence</h1>
          <p className="mt-1 text-sm text-muted-foreground max-w-2xl">
            This dashboard is for <strong>operators</strong>: review, tuning, and audit-friendly logs. It is <strong>not</strong> the same credential as{" "}
            <code className="text-xs bg-muted px-1 rounded">X-API-Key</code> used by agents on <code className="text-xs bg-muted px-1 rounded">POST /validate</code>.
            Validation keys stay on the integration side; admin access uses email/password and an HttpOnly session cookie.
          </p>
        </div>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Validator (live)</CardTitle>
            <CardDescription>
              {healthErr && <span className="text-destructive">{healthErr}</span>}
              {health && (
                <span className="font-mono text-xs">
                  {health.service} v{health.version} — {health.status}
                </span>
              )}
              {!health && !healthErr && <span className="text-xs">Loading /health via BFF…</span>}
            </CardDescription>
          </CardHeader>
        </Card>

        <Card className="border-primary/20 bg-primary/5">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Security posture (summary)</CardTitle>
            <CardDescription>
              Server uses Argon2/bcrypt for admin passwords, JWT in HttpOnly cookies (SameSite strict; Secure in production), optional TOTP MFA and Ed25519 request signing for validation traffic.
              Wire up TLS termination in production; do not ship admin login over plain HTTP.
            </CardDescription>
          </CardHeader>
        </Card>

        <div className="grid gap-4 sm:grid-cols-2">
          {links.map((x) => (
            <Link key={x.href} href={x.href}>
              <Card className="h-full transition-colors hover:border-primary/40 cursor-pointer">
                <CardHeader>
                  <CardTitle className="text-lg">{x.title}</CardTitle>
                  <CardDescription>{x.body}</CardDescription>
                </CardHeader>
              </Card>
            </Link>
          ))}
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Beyond this UI</CardTitle>
            <CardDescription className="space-y-1 text-xs">
              <p>Policy YAML lives in GitOps; raw evidence also lands in your DB and SIEM. PDF exporters and tier SKUs stay on the product roadmap.</p>
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    </DashboardLayout>
  );
}
