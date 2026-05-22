import { PropsWithChildren, useEffect, useState } from "react";
import { Link, useLocation } from "wouter";

import { lockDashboard } from "@/lib/admin-api";
import { AuthGate } from "@/components/dashboard/AuthGate";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";

const NAV_ITEMS = [
  { href: "/dashboard/compliance", label: "Compliance & evidence" },
  { href: "/dashboard/audit-log", label: "Operator audit log" },
  { href: "/dashboard/review-queue", label: "Decision Review Queue" },
  { href: "/dashboard/recommendations", label: "Threshold Recommendations" },
  { href: "/dashboard/agents", label: "Agent Status Board" },
  { href: "/dashboard/thresholds", label: "Threshold Config" },
  { href: "/dashboard/risk-advisories", label: "Risk Advisories" },
  { href: "/dashboard/agent-intent", label: "Agent Intent" },
  { href: "/dashboard/ab-variants", label: "A/B Variants" },
  { href: "/dashboard/agent-evolution", label: "Agent Evolution" },
];

export function DashboardLayout({ children }: PropsWithChildren) {
  const [location, navigate] = useLocation();
  const [healthy, setHealthy] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await fetch("/api/health", { credentials: "include" });
        setHealthy(res.ok);
      } catch {
        setHealthy(false);
      }
    };

    void checkHealth();
    const id = window.setInterval(checkHealth, 15000);
    return () => window.clearInterval(id);
  }, []);

  const logout = async () => {
    await lockDashboard();
    toast({ title: "Dashboard locked", description: "Session cookie cleared." });
    navigate("/");
  };

  return (
    <AuthGate>
      <div className="min-h-screen bg-background text-foreground">
        <div className="mx-auto grid max-w-7xl grid-cols-1 gap-4 px-4 py-6 lg:grid-cols-[260px_1fr]">
          <aside className="rounded-2xl border border-border bg-card/60 p-4 lg:sticky lg:top-6 lg:h-[calc(100vh-3rem)]">
            <Link href="/" className="mb-6 block text-xl font-display font-bold tracking-tight">
              Halt<span className="text-primary">chain</span>
            </Link>
            <nav className="space-y-2">
              {NAV_ITEMS.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`block rounded-md px-3 py-2 text-sm transition ${
                    location === item.href
                      ? "bg-primary/15 text-primary"
                      : "text-muted-foreground hover:bg-muted/40 hover:text-foreground"
                  }`}
                >
                  {item.label}
                </Link>
              ))}
            </nav>
            <div className="mt-6 flex items-center gap-2 text-sm text-muted-foreground">
              <span className={`h-2.5 w-2.5 rounded-full ${healthy ? "bg-emerald-400" : "bg-red-400"}`} />
              API {healthy ? "healthy" : "offline"}
            </div>
            <Button variant="outline" className="mt-6 w-full" onClick={logout}>
              Lock
            </Button>
          </aside>

          <main className="rounded-2xl border border-border bg-card/40 p-4 lg:p-6">{children}</main>
        </div>
      </div>
    </AuthGate>
  );
}
