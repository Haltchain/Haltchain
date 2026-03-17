import { AuthGate } from "@/components/dashboard/AuthGate";

export default function UnlockPage() {
  return (
    <div className="min-h-screen bg-background px-4 py-16">
      <div className="mx-auto max-w-6xl rounded-2xl border border-border bg-card/40 p-8">
        <h1 className="mb-2 text-3xl">Haltchain Dashboard</h1>
        <p className="mb-8 text-sm text-muted-foreground">
          Unlock with your admin key to access the review queue, recommendation inbox, and agent status board.
        </p>

        <AuthGate forceOpen>
          <div className="rounded-xl border border-border bg-background/40 p-8 text-sm text-muted-foreground">
            Dashboard unlocked. Use sidebar routes to open review queue, recommendations, and agent board.
          </div>
        </AuthGate>
      </div>
    </div>
  );
}
