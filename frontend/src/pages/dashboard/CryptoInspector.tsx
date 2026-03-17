import { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";

import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";
import { getPublicKey, getMerkleRoot, type PublicKeyInfo, type MerkleStatus } from "@/lib/admin-api";

function CopyField({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    void navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    });
  };
  return (
    <div className="space-y-1.5">
      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
      <div className="flex items-start gap-2">
        <code className="flex-1 break-all rounded-md border border-border bg-muted/50 px-3 py-2 font-mono text-xs leading-relaxed">
          {value}
        </code>
        <Button size="sm" variant="outline" onClick={copy} className="shrink-0">
          {copied ? "Copied!" : "Copy"}
        </Button>
      </div>
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="flex items-center justify-between py-1.5 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-mono font-medium">{String(value)}</span>
    </div>
  );
}

export default function CryptoInspectorPage() {
  const [pubKey, setPubKey] = useState<PublicKeyInfo | null>(null);
  const [merkle, setMerkle] = useState<MerkleStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const load = async () => {
    try {
      const [pk, mr] = await Promise.all([getPublicKey(), getMerkleRoot()]);
      setPubKey(pk);
      setMerkle(mr);
    } catch (err) {
      toast({ title: "Failed to load crypto data", description: err instanceof Error ? err.message : "Error" });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
    intervalRef.current = setInterval(() => void load(), 30000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, []);

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl">Crypto Inspector</h1>
          <p className="text-sm text-muted-foreground">Public signing key and Merkle root for on-chain verification.</p>
        </div>

        {loading && <p className="text-sm text-muted-foreground">Loading…</p>}

        {pubKey && (
          <motion.section
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            className="rounded-xl border border-border bg-card/60 p-5 space-y-4"
          >
            <h2 className="text-base font-semibold">Signing Key</h2>
            <Separator />
            <div className="space-y-3">
              <InfoRow label="Algorithm" value={pubKey.algorithm} />
              <InfoRow label="Key ID" value={pubKey.key_id} />
            </div>
            <CopyField label="Public Key (base64)" value={pubKey.public_key_b64} />
          </motion.section>
        )}

        {merkle && (
          <motion.section
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0, transition: { delay: 0.08 } }}
            className="rounded-xl border border-border bg-card/60 p-5 space-y-4"
          >
            <h2 className="text-base font-semibold">Merkle Attestation</h2>
            <Separator />
            <div className="space-y-1">
              <InfoRow label="Leaf count" value={merkle.leaf_count} />
              <InfoRow label="Day of year" value={merkle.day_of_year} />
              {merkle.last_updated && <InfoRow label="Last updated" value={merkle.last_updated} />}
            </div>
            {merkle.root_hex ? (
              <CopyField label="Merkle Root (hex)" value={merkle.root_hex} />
            ) : (
              <p className="text-sm text-muted-foreground">No Merkle root available yet — submit some transactions first.</p>
            )}
            <div className="flex justify-end">
              <Button variant="outline" size="sm" onClick={() => void load()}>
                Refresh
              </Button>
            </div>
          </motion.section>
        )}
      </div>
    </DashboardLayout>
  );
}
