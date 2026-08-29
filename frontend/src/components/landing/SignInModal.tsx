import { useState } from "react";
import { KeyRound, Eye, EyeOff } from "lucide-react";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { customerLogin } from "@/lib/admin-api";

type Props = {
  open: boolean;
  onOpenChange: (v: boolean) => void;
};

export function SignInModal({ open, onOpenChange }: Props) {
  const [email, setEmail] = useState("");
  const [hwKey, setHwKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const { toast } = useToast();

  const canSubmit = email.trim().length > 0 && hwKey.trim().length > 0 && !submitting;

  const handleSubmit = async () => {
    if (!canSubmit) return;
    setSubmitting(true);
    try {
      await customerLogin(email.trim(), hwKey.trim());
      toast({ title: "Signed in", description: "Welcome to HaltChain." });
      onOpenChange(false);
      // backend will set session cookie — navigate to dashboard once backend is live
      window.location.assign("/dashboard");
    } catch (err) {
      toast({
        title: "Sign in failed",
        description: err instanceof Error ? err.message : "Invalid credentials or hardware key.",
        variant: "destructive",
      });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <KeyRound className="w-5 h-5 text-primary" />
            Sign In to HaltChain
          </DialogTitle>
          <DialogDescription>
            Enter your email and the hardware key issued when you subscribed.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 pt-2">
          <div className="space-y-1.5">
            <Label htmlFor="hc-email">Email</Label>
            <Input
              id="hc-email"
              type="email"
              autoComplete="email"
              placeholder="you@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="hc-hwkey">Hardware Key</Label>
            <div className="relative">
              <Input
                id="hc-hwkey"
                type={showKey ? "text" : "password"}
                autoComplete="off"
                placeholder="hk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                value={hwKey}
                onChange={(e) => setHwKey(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") void handleSubmit(); }}
                className="font-mono pr-10 text-sm tracking-wider"
              />
              <button
                type="button"
                onClick={() => setShowKey((v) => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                tabIndex={-1}
              >
                {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            <p className="text-xs text-muted-foreground">
              Your hardware key was sent to your email when you subscribed. It starts with <code className="bg-muted px-1 rounded">hk-</code>.
            </p>
          </div>

          <Button
            className="w-full"
            disabled={!canSubmit}
            onClick={() => void handleSubmit()}
          >
            {submitting ? "Signing in…" : "Sign In"}
          </Button>

          <p className="text-center text-xs text-muted-foreground">
            Don&apos;t have a key yet?{" "}
            <a
              href="#pricing"
              onClick={() => onOpenChange(false)}
              className="text-primary hover:underline"
            >
              Subscribe to get access
            </a>
          </p>
        </div>
      </DialogContent>
    </Dialog>
  );
}
