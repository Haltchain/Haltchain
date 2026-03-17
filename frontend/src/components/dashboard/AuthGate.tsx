import { PropsWithChildren, useEffect, useMemo, useState } from "react";
import { useLocation } from "wouter";

import { checkSession, login } from "@/lib/admin-api";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";

type AuthGateProps = PropsWithChildren<{
  forceOpen?: boolean;
}>;

export function AuthGate({ children, forceOpen = false }: AuthGateProps) {
  const [checking, setChecking] = useState(true);
  const [unlocked, setUnlocked] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showUnlock, setShowUnlock] = useState(forceOpen);
  const [submitting, setSubmitting] = useState(false);
  const [, navigate] = useLocation();
  const { toast } = useToast();

  useEffect(() => {
    let mounted = true;
    checkSession()
      .then((res) => {
        if (!mounted) return;
        setUnlocked(res.unlocked);
      })
      .catch(() => {
        if (!mounted) return;
        setUnlocked(false);
      })
      .finally(() => {
        if (!mounted) return;
        setChecking(false);
      });

    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    if (forceOpen) {
      setShowUnlock(true);
    }
  }, [forceOpen]);

  const handleLogin = async () => {
    setSubmitting(true);
    try {
      await login(email, password);
      setUnlocked(true);
      setShowUnlock(false);
      toast({ title: "Signed in", description: "Welcome back." });
      navigate("/dashboard/review-queue");
    } catch (err) {
      toast({
        title: "Sign in failed",
        description: err instanceof Error ? err.message : "Invalid email or password",
        variant: "destructive",
      });
    } finally {
      setSubmitting(false);
    }
  };

  const overlay = useMemo(() => {
    if (checking) {
      return <div className="rounded-xl border border-border bg-card/40 p-8 text-center text-muted-foreground">Checking session...</div>;
    }

    return (
      <div className="relative">
        <div className="pointer-events-none blur-[6px] opacity-50">{children}</div>
        <div className="absolute inset-0 flex items-center justify-center">
          <Button className="px-8" onClick={() => setShowUnlock(true)}>
            Sign In
          </Button>
        </div>
      </div>
    );
  }, [checking, children]);

  return (
    <>
      {unlocked ? children : overlay}
      <Dialog open={showUnlock} onOpenChange={setShowUnlock}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Admin Sign In</DialogTitle>
            <DialogDescription>Enter your admin email and password to access the dashboard.</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <Input
              type="email"
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="admin@example.com"
            />
            <Input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password"
              onKeyDown={(e) => { if (e.key === "Enter" && email && password) handleLogin(); }}
            />
            <Button className="w-full" disabled={!email || !password || submitting} onClick={handleLogin}>
              {submitting ? "Signing in..." : "Sign In"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
